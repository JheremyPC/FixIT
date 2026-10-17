"""AI agents and LLM observability.

Revision ID: 0004_agents_observability
Revises: 0003_ml_artifacts

Creates ``agent_states`` (enablement, schedule, execution lock), ``agent_runs`` (execution log),
``agent_alerts`` (deduplicated alerts) and ``llm_calls`` (LLM request metadata: no prompts,
answers or keys). Tables that already exist (created by the app's create_all) are skipped. On
PostgreSQL row level security is enabled without policies, so Supabase's REST roles cannot reach
them; the owner role used by the application is unaffected. No ticket data is touched.
"""
from alembic import op
import sqlalchemy as sa

revision = "0004_agents_observability"
down_revision = "0003_ml_artifacts"
branch_labels = None
depends_on = None

TABLES = ("agent_states", "agent_runs", "agent_alerts", "llm_calls")


def _tables():
    tz = sa.DateTime(timezone=True)
    return {
        "agent_states": [
            sa.Column("agent", sa.String(30), primary_key=True),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("schedule_minutes", sa.Integer()),
            sa.Column("lock_run_id", sa.String(36)),
            sa.Column("lock_expires_at", tz),
            sa.Column("last_run_at", tz),
            sa.Column("updated_at", tz, server_default=sa.func.now(), nullable=False),
        ],
        "agent_runs": [
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("agent", sa.String(30), nullable=False),
            sa.Column("trigger", sa.String(20), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("actor_id", sa.String(36), sa.ForeignKey("users.id")),
            sa.Column("ticket_id", sa.String(36), sa.ForeignKey("tickets.id")),
            sa.Column("params", sa.JSON()),
            sa.Column("summary", sa.String(500)),
            sa.Column("result", sa.JSON()),
            sa.Column("error", sa.String(500)),
            sa.Column("started_at", tz, nullable=False, index=True),
            sa.Column("finished_at", tz),
            sa.Column("duration_ms", sa.Integer()),
            sa.Index("ix_agent_runs_agent_started", "agent", "started_at"),
        ],
        "agent_alerts": [
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("dedup_key", sa.String(120), nullable=False, unique=True),
            sa.Column("agent", sa.String(30), nullable=False),
            sa.Column("kind", sa.String(30), nullable=False),
            sa.Column("level", sa.String(20), nullable=False),
            sa.Column("ticket_id", sa.String(36), sa.ForeignKey("tickets.id"), index=True),
            sa.Column("run_id", sa.String(36), sa.ForeignKey("agent_runs.id")),
            sa.Column("message", sa.String(300), nullable=False),
            sa.Column("value", sa.Float()),
            sa.Column("created_at", tz, server_default=sa.func.now(), nullable=False, index=True),
        ],
        "llm_calls": [
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("created_at", tz, nullable=False, index=True),
            sa.Column("source", sa.String(40), nullable=False),
            sa.Column("provider", sa.String(40)),
            sa.Column("model", sa.String(100)),
            sa.Column("fallback_used", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("duration_ms", sa.Integer(), nullable=False),
            sa.Column("error", sa.String(300)),
            sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id")),
            sa.Column("run_id", sa.String(36), sa.ForeignKey("agent_runs.id")),
        ],
    }


def upgrade():
    bind = op.get_bind()
    existing = sa.inspect(bind)
    for name, columns in _tables().items():
        if not existing.has_table(name):
            op.create_table(name, *columns)
        if bind.dialect.name == "postgresql":
            op.execute(sa.text(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY"))


def downgrade():
    for name in reversed(TABLES):
        op.drop_table(name)
