"""Initial FixIT schema.

Revision ID: 0001_initial
Revises:
"""
from alembic import op
import sqlalchemy as sa

revision="0001_initial"
down_revision=None
branch_labels=None
depends_on=None

def upgrade():
    # Metadata is the authoritative schema; this migration creates it for the initial release.
    from app.core.database import Base
    import app.models
    bind=op.get_bind()
    Base.metadata.create_all(bind=bind)

def downgrade():
    from app.core.database import Base
    bind=op.get_bind()
    Base.metadata.drop_all(bind=bind)

