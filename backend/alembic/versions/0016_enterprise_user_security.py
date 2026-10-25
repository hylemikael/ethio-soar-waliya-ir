"""0016_enterprise_user_security

Revision ID: 0016_enterprise_user_security
Revises: 0015_performance_indexes
Create Date: 2026-10-25 21:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision: str = "0016_enterprise_user_security"
down_revision: Union[str, None] = "0015_performance_indexes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = set(inspector.get_table_names())

    # 1. Create users table
    if "users" not in existing_tables:
        op.create_table(
            "users",
            sa.Column("id", UUID(as_uuid=True), primary_key=True),
            sa.Column("username", sa.String(64), nullable=False),
            sa.Column("email", sa.String(255), nullable=False),
            sa.Column("full_name", sa.String(128), nullable=True),
            sa.Column("password_hash", sa.String(255), nullable=False),
            sa.Column("password_algo", sa.String(32), server_default="pbkdf2_sha256", nullable=False),
            sa.Column("role", sa.String(32), server_default="ANALYST", nullable=False),
            sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
            sa.Column("is_mfa_enabled", sa.Boolean(), server_default=sa.text("false"), nullable=False),
            sa.Column("mfa_secret_encrypted", sa.Text(), nullable=True),
            sa.Column("mfa_recovery_codes_encrypted", sa.Text(), nullable=True),
            sa.Column("failed_login_attempts", sa.Integer(), server_default="0", nullable=False),
            sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
            sa.Column("password_changed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_users_username", "users", ["username"], unique=True)
        op.create_index("ix_users_email", "users", ["email"], unique=True)
        op.create_index("ix_users_role", "users", ["role"], unique=False)
        op.create_index("ix_users_is_active", "users", ["is_active"], unique=False)

    # 2. Create password_reset_tokens table
    if "password_reset_tokens" not in existing_tables:
        op.create_table(
            "password_reset_tokens",
            sa.Column("id", UUID(as_uuid=True), primary_key=True),
            sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("token_hash", sa.String(64), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("is_used", sa.Boolean(), server_default=sa.text("false"), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
        op.create_index("ix_password_reset_tokens_user_id", "password_reset_tokens", ["user_id"], unique=False)
        op.create_index("ix_password_reset_tokens_token_hash", "password_reset_tokens", ["token_hash"], unique=True)
        op.create_index("ix_password_reset_tokens_expires_at", "password_reset_tokens", ["expires_at"], unique=False)

    # 3. Create revoked_sessions table
    if "revoked_sessions" not in existing_tables:
        op.create_table(
            "revoked_sessions",
            sa.Column("id", UUID(as_uuid=True), primary_key=True),
            sa.Column("session_id", sa.String(64), nullable=False),
            sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
            sa.Column("reason", sa.String(64), server_default="LOGOUT", nullable=False),
            sa.Column("revoked_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index("ix_revoked_sessions_session_id", "revoked_sessions", ["session_id"], unique=True)
        op.create_index("ix_revoked_sessions_user_id", "revoked_sessions", ["user_id"], unique=False)
        op.create_index("ix_revoked_sessions_expires_at", "revoked_sessions", ["expires_at"], unique=False)


def downgrade() -> None:
    op.drop_table("revoked_sessions")
    op.drop_table("password_reset_tokens")
    op.drop_table("users")
