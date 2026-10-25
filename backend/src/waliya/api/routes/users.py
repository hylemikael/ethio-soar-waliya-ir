"""User account administration and identity management endpoints.

Restricted to ADMIN role.
Implements:
- NIST SP 800-63B-4 password policy enforcement on user creation
- Role-based authorization assignment (ADMIN, OPERATOR, ANALYST, AUDITOR)
- Account deactivation and immediate session revocation
- Progressive lockout clearing
- Audit ledger logging of all identity management operations
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.audit.ledger_service import AuditLedgerService
from waliya.core.auth import AuthenticatedActor, UserRole, require_admin
from waliya.core.password import (
    PasswordPolicyError,
    hash_password,
    validate_password_complexity,
)
from waliya.core.session import revoke_all_user_sessions
from waliya.db.models import UserModel
from waliya.db.session import get_db_session

logger = logging.getLogger("waliya.api.routes.users")

router = APIRouter(prefix="/users", tags=["users"])


# --- Schemas ---

class UserResponse(BaseModel):
    id: UUID
    username: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool
    is_mfa_enabled: bool
    failed_login_attempts: int
    locked_until: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, description="Unique username")
    email: str = Field(..., max_length=255, description="Unique email address")
    full_name: Optional[str] = Field(None, max_length=128)
    password: str = Field(..., min_length=12, max_length=128, description="Initial NIST-compliant password")
    role: UserRole = Field(default=UserRole.ANALYST, description="Assigned organizational role")


class UpdateUserRequest(BaseModel):
    email: Optional[str] = Field(None, max_length=255)
    full_name: Optional[str] = Field(None, max_length=128)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


# --- Endpoints ---

@router.get(
    "",
    response_model=List[UserResponse],
    status_code=status.HTTP_200_OK,
    summary="List all registered platform users",
)
async def list_users(
    _admin: AuthenticatedActor = Depends(require_admin),
    session: AsyncSession = Depends(get_db_session),
) -> List[UserResponse]:
    """Retrieve all user accounts. Restricted to administrators."""
    res = await session.execute(select(UserModel).order_by(UserModel.created_at))
    users = res.scalars().all()
    return [
        UserResponse(
            id=u.id,
            username=u.username,
            email=u.email,
            full_name=u.full_name,
            role=u.role,
            is_active=u.is_active,
            is_mfa_enabled=u.is_mfa_enabled,
            failed_login_attempts=u.failed_login_attempts,
            locked_until=u.locked_until,
            created_at=u.created_at,
            updated_at=u.updated_at,
        )
        for u in users
    ]


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Provision a new user account with role assignment",
)
async def create_user(
    payload: CreateUserRequest,
    admin: AuthenticatedActor = Depends(require_admin),
    session: AsyncSession = Depends(get_db_session),
) -> UserResponse:
    """Create a new user account enforcing NIST password policy."""
    # Check uniqueness of username and email
    existing = await session.execute(
        select(UserModel).where(
            (UserModel.username == payload.username.strip()) | (UserModel.email == payload.email.strip().lower())
        )
    )
    if existing.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this username or email already exists.",
        )

    # Validate NIST password complexity
    try:
        validate_password_complexity(payload.password, username=payload.username.strip())
    except PasswordPolicyError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))

    new_user = UserModel(
        id=uuid4(),
        username=payload.username.strip(),
        email=payload.email.strip().lower(),
        full_name=payload.full_name.strip() if payload.full_name else None,
        password_hash=hash_password(payload.password),
        password_algo="pbkdf2_sha256",
        role=payload.role.value,
        is_active=True,
        is_mfa_enabled=False,
    )
    session.add(new_user)
    await session.commit()

    await AuditLedgerService.record_action(
        session=session,
        actor_id=admin.actor_id,
        action="USER_PROVISIONED",
        target_entity=f"user:{new_user.id}",
        payload={"username": new_user.username, "role": new_user.role, "email": new_user.email},
        actor_role=admin.role,
    )
    logger.info("Admin '%s' provisioned new user '%s' (role=%s)", admin.username, new_user.username, new_user.role)

    return UserResponse(
        id=new_user.id,
        username=new_user.username,
        email=new_user.email,
        full_name=new_user.full_name,
        role=new_user.role,
        is_active=new_user.is_active,
        is_mfa_enabled=new_user.is_mfa_enabled,
        failed_login_attempts=new_user.failed_login_attempts,
        locked_until=new_user.locked_until,
        created_at=new_user.created_at,
        updated_at=new_user.updated_at,
    )


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get user account details",
)
async def get_user_detail(
    user_id: UUID,
    admin: AuthenticatedActor = Depends(require_admin),
    session: AsyncSession = Depends(get_db_session),
) -> UserResponse:
    """Retrieve details for a specific user."""
    res = await session.execute(select(UserModel).where(UserModel.id == user_id))
    user = res.scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        is_mfa_enabled=user.is_mfa_enabled,
        failed_login_attempts=user.failed_login_attempts,
        locked_until=user.locked_until,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Update user profile, status, or role",
)
async def update_user(
    user_id: UUID,
    payload: UpdateUserRequest,
    admin: AuthenticatedActor = Depends(require_admin),
    session: AsyncSession = Depends(get_db_session),
) -> UserResponse:
    """Modify user attributes. Revokes active sessions if role is changed or user deactivated."""
    res = await session.execute(select(UserModel).where(UserModel.id == user_id))
    user = res.scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    revocation_needed = False

    if payload.email is not None:
        user.email = payload.email.strip().lower()
    if payload.full_name is not None:
        user.full_name = payload.full_name.strip()
    if payload.role is not None and payload.role.value != user.role:
        user.role = payload.role.value
        revocation_needed = True
    if payload.is_active is not None and payload.is_active != user.is_active:
        user.is_active = payload.is_active
        if not user.is_active:
            revocation_needed = True

    if revocation_needed:
        revoke_all_user_sessions(str(user.id))

    await session.commit()

    await AuditLedgerService.record_action(
        session=session,
        actor_id=admin.actor_id,
        action="USER_MODIFIED",
        target_entity=f"user:{user.id}",
        payload={"username": user.username, "role": user.role, "is_active": user.is_active},
        actor_role=admin.role,
    )
    logger.info("Admin '%s' updated user '%s' (role=%s, active=%s)", admin.username, user.username, user.role, user.is_active)

    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        is_mfa_enabled=user.is_mfa_enabled,
        failed_login_attempts=user.failed_login_attempts,
        locked_until=user.locked_until,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


@router.post(
    "/{user_id}/unlock",
    status_code=status.HTTP_200_OK,
    summary="Clear progressive lockout on a user account",
)
async def unlock_user_account(
    user_id: UUID,
    admin: AuthenticatedActor = Depends(require_admin),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Manually unlock an account locked by failed login attempts."""
    res = await session.execute(select(UserModel).where(UserModel.id == user_id))
    user = res.scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    user.failed_login_attempts = 0
    user.locked_until = None
    await session.commit()

    await AuditLedgerService.record_action(
        session=session,
        actor_id=admin.actor_id,
        action="USER_ACCOUNT_UNLOCKED",
        target_entity=f"user:{user.id}",
        payload={"username": user.username},
        actor_role=admin.role,
    )
    logger.info("Admin '%s' unlocked user account '%s'", admin.username, user.username)
    return {"status": "UNLOCKED", "message": f"Account '{user.username}' has been unlocked."}


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_200_OK,
    summary="Deactivate user and revoke all active sessions",
)
async def deactivate_user(
    user_id: UUID,
    admin: AuthenticatedActor = Depends(require_admin),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Deactivate user account and revoke all sessions immediately."""
    res = await session.execute(select(UserModel).where(UserModel.id == user_id))
    user = res.scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    if user.username == "admin" and admin.actor_id == str(user.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate the active root administrator account.",
        )

    user.is_active = False
    revoke_all_user_sessions(str(user.id))
    await session.commit()

    await AuditLedgerService.record_action(
        session=session,
        actor_id=admin.actor_id,
        action="USER_DEACTIVATED",
        target_entity=f"user:{user.id}",
        payload={"username": user.username},
        actor_role=admin.role,
    )
    logger.info("Admin '%s' deactivated user '%s'", admin.username, user.username)
    return {"status": "DEACTIVATED", "message": f"User '{user.username}' has been deactivated."}
