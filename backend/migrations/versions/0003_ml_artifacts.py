"""Persistent storage for trained ML models.

Revision ID: 0003_ml_artifacts
Revises: 0002_skip_synthetic_automation

Creates ``ml_artifacts`` (one row per model plus metadata and training history; payloads are
HMAC-signed, see app.ml.store). Skipped if the table already exists (the app's create_all may have
made it). On PostgreSQL, row level security is enabled without policies so Supabase's REST roles
(anon/authenticated) cannot read or write it; the owner role used by the application is unaffected.
No ticket data is touched.
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_ml_artifacts"
down_revision = "0002_skip_synthetic_automation"
branch_labels = None
depends_on = None

TABLE = "ml_artifacts"


def upgrade():
    bind = op.get_bind()
    if not sa.inspect(bind).has_table(TABLE):
        op.create_table(
            TABLE,
            sa.Column("name", sa.String(40), primary_key=True),
            sa.Column("version", sa.String(60), nullable=False),
            sa.Column("payload", sa.LargeBinary(), nullable=False),
            sa.Column("signature", sa.String(64), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
    if bind.dialect.name == "postgresql":
        op.execute(sa.text(f"ALTER TABLE {TABLE} ENABLE ROW LEVEL SECURITY"))


def downgrade():
    op.drop_table(TABLE)
