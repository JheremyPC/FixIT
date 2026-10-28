from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class Input(BaseModel):
    """Base of every request body. NUL characters are rejected in any text field (PostgreSQL cannot store them,
    and they are a common way to smuggle input past filters)."""

    @field_validator("*", mode="before")
    @classmethod
    def no_nul(cls, value):
        items = value if isinstance(value, list) else [value]
        if any(isinstance(v, str) and "\x00" in v for v in items): raise ValueError("Contiene caracteres no permitidos")
        return value


class LoginIn(Input):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class RefreshIn(Input):
    refresh_token: str = Field(max_length=4096)


class UserCreate(Input):
    full_name: str = Field(min_length=2, max_length=150)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role_code: str = "USUARIO"
    area_id: str | None = None


class RegisterIn(UserCreate):
    """Self-registration: the role is always USUARIO and the current terms must be accepted expressly."""
    accept_terms: bool = False
    terms_version: str | None = Field(default=None, max_length=30)


class AcceptanceIn(Input):
    document: Literal["terminos"]
    version: str = Field(min_length=1, max_length=30)


class UserUpdate(Input):
    full_name: str | None = Field(default=None, min_length=2, max_length=150)
    role_code: str | None = None
    area_id: str | None = None
    active: bool | None = None


class EntityIn(Input):
    name: str = Field(min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=1000)
    specialty_id: str | None = None


class PriorityIn(Input):
    code: str = Field(min_length=2, max_length=20)
    name: str = Field(min_length=2, max_length=80)
    level: int = Field(ge=1, le=10)
    sla_hours: int = Field(ge=1, le=720)
    color: str = Field(default="#64748b", pattern=r"^#[0-9a-fA-F]{6}$")


class TechnicianIn(Input):
    user_id: str
    available: bool = True
    max_load: int = Field(default=8, ge=1, le=100)
    specialty_ids: list[str] = []


class TicketCreate(Input):
    title: str = Field(min_length=5, max_length=180)
    description: str = Field(min_length=10, max_length=8000)
    area_id: str
    category_id: str
    priority_id: str | None = None


class TicketUpdate(Input):
    title: str | None = Field(default=None, min_length=5, max_length=180)
    description: str | None = Field(default=None, min_length=10, max_length=8000)
    priority_id: str | None = None


class AssignIn(Input):
    technician_id: str | None = None
    reason: str | None = Field(default=None, max_length=1000)


class CommentIn(Input):
    body: str = Field(min_length=1, max_length=5000)
    internal: bool = False


class TransitionIn(Input):
    state: str
    diagnosis: str | None = Field(default=None, max_length=6000)
    solution: str | None = Field(default=None, max_length=6000)


class RatingIn(Input):
    score: int = Field(ge=1, le=5)
    solved: bool
    comment: str | None = Field(default=None, max_length=2000)


class SettingIn(Input):
    value: str = Field(min_length=1, max_length=4000)
    description: str | None = Field(default=None, max_length=1000)


class Output(BaseModel):
    model_config = ConfigDict(from_attributes=True)

class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: dict


class TrainIn(Input):
    include_synthetic: bool = True


class PredictIn(Input):
    title: str = Field(min_length=5, max_length=180)
    description: str = Field(min_length=10, max_length=8000)
    area_id: str = Field(min_length=1, max_length=36)
    category_id: str = Field(min_length=1, max_length=36)
    priority_id: str | None = Field(default=None, max_length=36)


class ChatTurn(Input):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=6000)


class ChatIn(Input):
    message: str = Field(min_length=2, max_length=2000)
    history: list[ChatTurn] = Field(default_factory=list, max_length=20)


class AgentRunIn(Input):
    """Parameters accepted by the agents; anything else is rejected."""
    model_config = ConfigDict(extra="forbid")
    ticket_id: str | None = Field(default=None, max_length=36)
    mode: Literal["recomendar", "ejecutar"] = "recomendar"
    limit: int = Field(default=20, ge=1, le=50)
    threshold: float = Field(default=0.6, ge=0.3, le=0.95)
    tasks: list[Literal["alertas_sla", "seguimiento_atrasados", "seguimiento_inactivos", "resumen_operativo"]] | None = None
    inactive_hours: int = Field(default=48, ge=4, le=720)


class AgentConfigIn(Input):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    schedule_minutes: int | None = Field(default=None, ge=5, le=1440)
    clear_schedule: bool = False


class TriageSuggestIn(Input):
    title: str = Field(min_length=3, max_length=180)
    description: str = Field(default="", max_length=8000)
    area_id: str | None = Field(default=None, max_length=36)
    category_id: str | None = Field(default=None, max_length=36)
