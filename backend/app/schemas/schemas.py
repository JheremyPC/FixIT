from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, EmailStr, Field


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class RefreshIn(BaseModel):
    refresh_token: str


class UserCreate(BaseModel):
    full_name: str = Field(min_length=2, max_length=150)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role_code: str = "USUARIO"
    area_id: str | None = None


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=150)
    role_code: str | None = None
    area_id: str | None = None
    active: bool | None = None


class EntityIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    description: str | None = Field(default=None, max_length=1000)
    specialty_id: str | None = None


class PriorityIn(BaseModel):
    code: str = Field(min_length=2, max_length=20)
    name: str = Field(min_length=2, max_length=80)
    level: int = Field(ge=1, le=10)
    sla_hours: int = Field(ge=1, le=720)
    color: str = Field(default="#64748b", pattern=r"^#[0-9a-fA-F]{6}$")


class TechnicianIn(BaseModel):
    user_id: str
    available: bool = True
    max_load: int = Field(default=8, ge=1, le=100)
    specialty_ids: list[str] = []


class TicketCreate(BaseModel):
    title: str = Field(min_length=5, max_length=180)
    description: str = Field(min_length=10, max_length=8000)
    area_id: str
    category_id: str
    priority_id: str | None = None


class TicketUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=5, max_length=180)
    description: str | None = Field(default=None, min_length=10, max_length=8000)
    priority_id: str | None = None


class AssignIn(BaseModel):
    technician_id: str | None = None
    reason: str | None = Field(default=None, max_length=1000)


class CommentIn(BaseModel):
    body: str = Field(min_length=1, max_length=5000)
    internal: bool = False


class TransitionIn(BaseModel):
    state: str
    diagnosis: str | None = Field(default=None, max_length=6000)
    solution: str | None = Field(default=None, max_length=6000)


class RatingIn(BaseModel):
    score: int = Field(ge=1, le=5)
    solved: bool
    comment: str | None = Field(default=None, max_length=2000)


class SettingIn(BaseModel):
    value: str = Field(min_length=1, max_length=4000)
    description: str | None = Field(default=None, max_length=1000)


class Output(BaseModel):
    model_config = ConfigDict(from_attributes=True)

class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: dict


class TrainIn(BaseModel):
    include_synthetic: bool = True


class PredictIn(BaseModel):
    title: str = Field(min_length=5, max_length=180)
    description: str = Field(min_length=10, max_length=8000)
    area_id: str = Field(min_length=1, max_length=36)
    category_id: str = Field(min_length=1, max_length=36)
    priority_id: str | None = Field(default=None, max_length=36)


class ChatTurn(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(min_length=1, max_length=6000)


class ChatIn(BaseModel):
    message: str = Field(min_length=2, max_length=2000)
    history: list[ChatTurn] = Field(default_factory=list, max_length=20)


class AgentRunIn(BaseModel):
    """Parameters accepted by the agents; anything else is rejected."""
    model_config = ConfigDict(extra="forbid")
    ticket_id: str | None = Field(default=None, max_length=36)
    mode: Literal["recomendar", "ejecutar"] = "recomendar"
    limit: int = Field(default=20, ge=1, le=50)
    threshold: float = Field(default=0.6, ge=0.3, le=0.95)
    tasks: list[Literal["alertas_sla", "seguimiento_atrasados", "seguimiento_inactivos", "resumen_operativo"]] | None = None
    inactive_hours: int = Field(default=48, ge=4, le=720)


class AgentConfigIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    schedule_minutes: int | None = Field(default=None, ge=5, le=1440)
    clear_schedule: bool = False


class TriageSuggestIn(BaseModel):
    title: str = Field(min_length=3, max_length=180)
    description: str = Field(default="", max_length=8000)
    area_id: str | None = Field(default=None, max_length=36)
    category_id: str | None = Field(default=None, max_length=36)
