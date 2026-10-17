import uuid
from datetime import datetime
from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, ForeignKey, Index, Integer, JSON, LargeBinary, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


def uid() -> str:
    return str(uuid.uuid4())


class Timestamped:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class Role(Base):
    __tablename__ = "roles"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    code: Mapped[str] = mapped_column(String(30), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(80), nullable=False)


class User(Base, Timestamped):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    full_name: Mapped[str] = mapped_column(String(150), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"), nullable=False)
    area_id: Mapped[str | None] = mapped_column(ForeignKey("areas.id"))
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    role: Mapped[Role] = relationship()
    area: Mapped["Area | None"] = relationship()
    technician: Mapped["Technician | None"] = relationship(back_populates="user", uselist=False)


class Area(Base, Timestamped):
    __tablename__ = "areas"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Specialty(Base):
    __tablename__ = "specialties"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)


class Technician(Base, Timestamped):
    __tablename__ = "technicians"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), unique=True, nullable=False)
    available: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    max_load: Mapped[int] = mapped_column(Integer, default=8, nullable=False)
    user: Mapped[User] = relationship(back_populates="technician")
    specialties: Mapped[list["TechnicianSpecialty"]] = relationship(cascade="all, delete-orphan")


class TechnicianSpecialty(Base):
    __tablename__ = "technician_specialties"
    technician_id: Mapped[str] = mapped_column(ForeignKey("technicians.id"), primary_key=True)
    specialty_id: Mapped[str] = mapped_column(ForeignKey("specialties.id"), primary_key=True)
    specialty: Mapped[Specialty] = relationship()


class Category(Base, Timestamped):
    __tablename__ = "categories"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    specialty_id: Mapped[str | None] = mapped_column(ForeignKey("specialties.id"))
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    specialty: Mapped[Specialty | None] = relationship()


class Priority(Base):
    __tablename__ = "priorities"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    code: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    level: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)
    sla_hours: Mapped[int] = mapped_column(Integer, nullable=False)
    color: Mapped[str] = mapped_column(String(10), default="#64748b", nullable=False)


class TicketState(Base):
    __tablename__ = "ticket_states"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    code: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    terminal: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class Ticket(Base, Timestamped):
    __tablename__ = "tickets"
    __table_args__ = (Index("ix_tickets_operational", "state_id", "priority_id", "technician_id", "created_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    number: Mapped[str] = mapped_column(String(20), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(180), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    requester_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    technician_id: Mapped[str | None] = mapped_column(ForeignKey("technicians.id"), index=True)
    area_id: Mapped[str] = mapped_column(ForeignKey("areas.id"), nullable=False)
    category_id: Mapped[str] = mapped_column(ForeignKey("categories.id"), nullable=False)
    priority_id: Mapped[str] = mapped_column(ForeignKey("priorities.id"), nullable=False)
    state_id: Mapped[str] = mapped_column(ForeignKey("ticket_states.id"), nullable=False, index=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    diagnosis: Mapped[str | None] = mapped_column(Text)
    solution: Mapped[str | None] = mapped_column(Text)
    requester: Mapped[User] = relationship(foreign_keys=[requester_id])
    technician: Mapped[Technician | None] = relationship()
    area: Mapped[Area] = relationship()
    category: Mapped[Category] = relationship()
    priority: Mapped[Priority] = relationship()
    state: Mapped[TicketState] = relationship()
    assignments: Mapped[list["TicketAssignment"]] = relationship(cascade="all, delete-orphan")
    comments: Mapped[list["TicketComment"]] = relationship(cascade="all, delete-orphan")
    history: Mapped[list["TicketHistory"]] = relationship(cascade="all, delete-orphan")
    rating: Mapped["Rating | None"] = relationship(back_populates="ticket", uselist=False, cascade="all, delete-orphan")


class TicketAssignment(Base):
    __tablename__ = "ticket_assignments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id"), nullable=False)
    technician_id: Mapped[str] = mapped_column(ForeignKey("technicians.id"), nullable=False)
    assigned_by_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    assignment_type: Mapped[str] = mapped_column(String(20), nullable=False)
    score: Mapped[float | None] = mapped_column(Float)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    technician: Mapped[Technician] = relationship()


class TicketComment(Base):
    __tablename__ = "ticket_comments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id"), nullable=False)
    author_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    internal: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    author: Mapped[User] = relationship()


class TicketAttachment(Base):
    __tablename__ = "ticket_attachments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id"), nullable=False)
    uploader_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    original_name: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    content_type: Mapped[str] = mapped_column(String(100), nullable=False)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class TicketHistory(Base):
    __tablename__ = "ticket_history"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id"), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    event: Mapped[str] = mapped_column(String(80), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    old_value: Mapped[dict | None] = mapped_column(JSON)
    new_value: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    actor: Mapped[User | None] = relationship()


class Rating(Base):
    __tablename__ = "ratings"
    __table_args__ = (CheckConstraint("score >= 1 AND score <= 5", name="rating_score_range"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id"), unique=True, nullable=False)
    technician_id: Mapped[str] = mapped_column(ForeignKey("technicians.id"), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    solved: Mapped[bool] = mapped_column(Boolean, nullable=False)
    comment: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    ticket: Mapped[Ticket] = relationship(back_populates="rating")


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(180), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    ticket_id: Mapped[str | None] = mapped_column(ForeignKey("tickets.id"))
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), index=True)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    module: Mapped[str] = mapped_column(String(80), nullable=False)
    entity: Mapped[str] = mapped_column(String(80), nullable=False)
    entity_id: Mapped[str | None] = mapped_column(String(36))
    old_value: Mapped[dict | None] = mapped_column(JSON)
    new_value: Mapped[dict | None] = mapped_column(JSON)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    user: Mapped[User | None] = relationship()


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)



class MLArtifact(Base):
    """Trained ML artifacts (joblib) and their metadata (JSON), signed with HMAC; see app.ml.store."""
    __tablename__ = "ml_artifacts"
    name: Mapped[str] = mapped_column(String(40), primary_key=True)
    version: Mapped[str] = mapped_column(String(60), nullable=False)
    payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    signature: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class AgentState(Base):
    """One row per agent: enablement, schedule and the cross-process execution lock (see app.agents.runner)."""
    __tablename__ = "agent_states"
    agent: Mapped[str] = mapped_column(String(30), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    schedule_minutes: Mapped[int | None] = mapped_column(Integer)
    lock_run_id: Mapped[str | None] = mapped_column(String(36))
    lock_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)


class AgentRun(Base):
    """Execution log of an agent. ``result`` holds counts and item references, never prompts or LLM answers."""
    __tablename__ = "agent_runs"
    __table_args__ = (Index("ix_agent_runs_agent_started", "agent", "started_at"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    agent: Mapped[str] = mapped_column(String(30), nullable=False)
    trigger: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    ticket_id: Mapped[str | None] = mapped_column(ForeignKey("tickets.id"))
    params: Mapped[dict | None] = mapped_column(JSON)
    summary: Mapped[str | None] = mapped_column(String(500))
    result: Mapped[dict | None] = mapped_column(JSON)
    error: Mapped[str | None] = mapped_column(String(500))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    actor: Mapped[User | None] = relationship()


class AgentAlert(Base):
    """Alerts raised by agents. ``dedup_key`` is unique, so the same alert is never raised twice."""
    __tablename__ = "agent_alerts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    dedup_key: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    agent: Mapped[str] = mapped_column(String(30), nullable=False)
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    level: Mapped[str] = mapped_column(String(20), nullable=False)
    ticket_id: Mapped[str | None] = mapped_column(ForeignKey("tickets.id"), index=True)
    run_id: Mapped[str | None] = mapped_column(ForeignKey("agent_runs.id"))
    message: Mapped[str] = mapped_column(String(300), nullable=False)
    value: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)


class LLMCall(Base):
    """Observability of LLM requests: metadata only (no prompts, answers, keys or conversations)."""
    __tablename__ = "llm_calls"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(40), nullable=False)
    provider: Mapped[str | None] = mapped_column(String(40))
    model: Mapped[str | None] = mapped_column(String(100))
    fallback_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    error: Mapped[str | None] = mapped_column(String(300))
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"))
    run_id: Mapped[str | None] = mapped_column(ForeignKey("agent_runs.id"))
