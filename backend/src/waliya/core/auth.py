"""Authentication dependencies, role-based authorization, and credential verification.

Specifications:
- Roles: ADMIN, OPERATOR, ANALYST, AUDITOR (Principle of Least Privilege)
- Multi-Method Authentication:
  1. Administrative pre-shared API key ('X-Admin-Key' or 'Authorization: Bearer <key>') for automation.
  2. Cryptographically signed, HttpOnly browser session cookie ('waliya_session') with server-side revocation.
  3. Endpoint Agent Bearer token authentication with SHA-256 peppered hashing.
- CSRF Protection: Constant-time double-submit cookie validation on state-changing browser methods.
- Constant-time string comparison to prevent timing side channels.
"""

from enum import Enum
import hmac
from typing import Any, Callable, Dict, List, Optional
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.config import settings
from waliya.core.crypto import hash_agent_token
from waliya.core.session import verify_csrf_token, verify_session_token
from waliya.db.models import AgentModel, UserModel
from waliya.db.session import get_db_session


class UserRole(str, Enum):
    """Platform access roles enforcing least privilege."""
    ADMIN = "ADMIN"        # Full system administration, user management, rule/integration config
    OPERATOR = "OPERATOR"  # Response action approval/execution, incident triage, simulation runs
    ANALYST = "ANALYST"    # Read-only access to incidents, findings, telemetry, threat intel
    AUDITOR = "AUDITOR"    # Read-only access to audit ledger, diagnostics, compliance reports


class AuthenticatedActor(BaseModel):
    """Validated identity context representing the calling subject."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    actor_id: str
    username: str
    role: str
    auth_method: str  # "api_key", "session"
    user_id: Optional[UUID] = None
    mfa_authenticated: bool = True


async def get_authenticated_agent(
    authorization: Optional[str] = Header(None, description="Bearer token authentication header"),
    x_agent_id: Optional[str] = Header(None, description="Optional agent UUID header for identity verification"),
    session: AsyncSession = Depends(get_db_session),
) -> AgentModel:
    """Authenticate an endpoint agent via its Bearer API token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header. Expected 'Bearer <token>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.split("Bearer ", 1)[1].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Empty bearer token supplied",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Compute deterministic SHA-256 hash using the server pepper
    token_hash = hash_agent_token(token, pepper=settings.AGENT_TOKEN_PEPPER)

    # Query agent by token hash
    query = select(AgentModel).where(AgentModel.api_token_hash == token_hash)
    if x_agent_id:
        try:
            agent_uuid = UUID(x_agent_id)
            query = query.where(AgentModel.id == agent_uuid)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid X-Agent-ID header format; expected UUID",
            )

    result = await session.execute(query)
    agent = result.scalars().first()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or unrecognized agent credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if agent.status == "REVOKED":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent credentials have been revoked",
        )

    return agent


async def get_authenticated_actor(
    request: Request,
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key", description="Admin pre-shared API key"),
    authorization: Optional[str] = Header(None, description="Admin Bearer token"),
) -> AuthenticatedActor:
    """Authenticate the caller via pre-shared API key or browser session cookie.

    Fails closed when credentials are missing or invalid.
    """
    # 1. Check pre-shared administrative API key
    supplied_key: Optional[str] = None
    if x_admin_key:
        supplied_key = x_admin_key.strip()
    elif authorization and authorization.startswith("Bearer "):
        candidate = authorization.split("Bearer ", 1)[1].strip()
        # Only treat as API key if matching admin key; otherwise could be bearer session
        if hmac.compare_digest(candidate, settings.ADMIN_API_KEY):
            supplied_key = candidate

    if supplied_key:
        if not hmac.compare_digest(supplied_key, settings.ADMIN_API_KEY):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid administrative credentials",
            )
        return AuthenticatedActor(
            actor_id="admin",
            username="admin",
            role=UserRole.ADMIN.value,
            auth_method="api_key",
            user_id=None,
            mfa_authenticated=True,
        )

    # 2. Check browser session cookie
    session_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if session_token:
        session_data = verify_session_token(
            token=session_token,
            secret_key=settings.SECRET_KEY,
            ttl_seconds=settings.SESSION_TTL_SECONDS,
        )
        if not session_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has expired or is invalid. Please log in again.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Enforce CSRF protection for state-changing browser methods
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            header_csrf = request.headers.get("X-CSRF-Token")
            cookie_csrf = request.cookies.get(settings.CSRF_COOKIE_NAME)
            if not verify_csrf_token(cookie_csrf, header_csrf):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="CSRF validation failed for state-changing request",
                )

        raw_uid = session_data.get("user_id")
        parsed_uid: Optional[UUID] = None
        if raw_uid:
            try:
                parsed_uid = UUID(raw_uid)
            except ValueError:
                pass

        return AuthenticatedActor(
            actor_id=raw_uid or session_data.get("actor", "admin"),
            username=session_data.get("actor", "admin"),
            role=session_data.get("role", UserRole.ADMIN.value),
            auth_method="session",
            user_id=parsed_uid,
            mfa_authenticated=session_data.get("mfa_authenticated", True),
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing authentication credentials. Supply 'X-Admin-Key' header, 'Authorization: Bearer <key>', or authenticate via browser session.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_role(allowed_roles: List[str]) -> Callable[..., Any]:
    """Dependency factory enforcing server-side Role-Based Access Control (RBAC).

    Admin role is superuser and satisfies all role requirements.
    """
    async def _role_verifier(
        actor: AuthenticatedActor = Depends(get_authenticated_actor),
    ) -> AuthenticatedActor:
        if actor.role != UserRole.ADMIN.value and actor.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required role in {allowed_roles}, but caller has role '{actor.role}'",
            )
        return actor

    return _role_verifier


# Role dependency conveniences
require_admin = require_role([UserRole.ADMIN.value])
require_operator = require_role([UserRole.ADMIN.value, UserRole.OPERATOR.value])
require_analyst_or_above = require_role([
    UserRole.ADMIN.value,
    UserRole.OPERATOR.value,
    UserRole.ANALYST.value,
])
require_auditor_or_above = require_role([
    UserRole.ADMIN.value,
    UserRole.AUDITOR.value,
])


async def verify_admin_key(
    actor: AuthenticatedActor = Depends(get_authenticated_actor),
) -> str:
    """Authorize administrative platform requests. Enforces caller has ADMIN role."""
    if actor.role != UserRole.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action requires administrative privileges. Caller role is '{actor.role}'.",
        )
    return actor.username


async def verify_operator_or_admin(
    actor: AuthenticatedActor = Depends(get_authenticated_actor),
) -> str:
    """Authorize operational platform requests. Enforces caller has ADMIN or OPERATOR role."""
    if actor.role not in (UserRole.ADMIN.value, UserRole.OPERATOR.value):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action requires operator or administrative privileges. Caller role is '{actor.role}'.",
        )
    return actor.username


async def verify_analyst_or_above(
    actor: AuthenticatedActor = Depends(get_authenticated_actor),
) -> str:
    """Authorize analyst platform requests. Enforces caller has ADMIN, OPERATOR, or ANALYST role."""
    if actor.role not in (UserRole.ADMIN.value, UserRole.OPERATOR.value, UserRole.ANALYST.value):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action requires analyst privileges. Caller role is '{actor.role}'.",
        )
    return actor.username
