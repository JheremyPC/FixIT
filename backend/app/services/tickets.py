import uuid
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from sqlalchemy.orm import Session
from app.models import Priority, Ticket, TicketAssignment, TicketState
from app.services.audit import history, notify

TRANSITIONS = {
    "NUEVO": {"ASIGNADO", "CANCELADO"}, "ASIGNADO": {"EN_ATENCION", "CANCELADO", "ESCALADO"},
    "EN_ATENCION": {"EN_ESPERA", "RESUELTO", "ESCALADO"}, "EN_ESPERA": {"EN_ATENCION", "CANCELADO"},
    "RESUELTO": {"CERRADO", "REABIERTO"}, "REABIERTO": {"ASIGNADO", "EN_ATENCION", "CANCELADO"},
    "ESCALADO": {"ASIGNADO", "EN_ATENCION", "CANCELADO"}, "CERRADO": set(), "CANCELADO": set(),
}

def state(db: Session, code: str) -> TicketState:
    result = db.query(TicketState).filter_by(code=code).first()
    if not result: raise RuntimeError(f"Estado no configurado: {code}")
    return result

def next_number(db: Session) -> str:
    # Avoids collisions across concurrent workers; database uniqueness is retained as final guard.
    # 3 (FIX) + 2 hyphens + 8 (date) + 7 random characters = 20, matching
    # the indexed database column while remaining collision-resistant.
    return f"FIX-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:7].upper()}"

def set_state(db: Session, ticket: Ticket, target: str, actor_id: str, diagnosis: str | None = None, solution: str | None = None):
    old = ticket.state.code
    if target not in TRANSITIONS.get(old, set()):
        raise HTTPException(422, f"Transición no permitida: {old} → {target}")
    ticket.state = state(db, target)
    now = datetime.now(timezone.utc)
    if target == "EN_ATENCION" and not ticket.started_at: ticket.started_at = now
    if target == "RESUELTO":
        if not solution: raise HTTPException(422, "La solución es obligatoria al resolver")
        ticket.diagnosis, ticket.solution, ticket.resolved_at = diagnosis or ticket.diagnosis, solution, now
    if target == "CERRADO": ticket.closed_at = now
    history(db, ticket.id, actor_id, "ESTADO_CAMBIADO", f"Estado: {old} → {target}", {"state": old}, {"state": target})
    notify(db, ticket.requester_id, "TICKET_ESTADO", f"Ticket {ticket.number}: {target}", f"El estado de su ticket cambió a {target}.", ticket.id)

def assign(db: Session, ticket: Ticket, technician, actor_id: str | None, type_: str, score: float | None, reason: str):
    ticket.technician_id = technician.id
    if ticket.state.code in {"NUEVO", "REABIERTO", "ESCALADO"}: ticket.state = state(db, "ASIGNADO")
    db.add(TicketAssignment(ticket_id=ticket.id, technician_id=technician.id, assigned_by_id=actor_id, assignment_type=type_, score=score, reason=reason))
    history(db, ticket.id, actor_id, "ASIGNADO", f"Asignado a {technician.user.full_name}: {reason}", new={"technician_id": technician.id, "score": score})
    notify(db, technician.user_id, "ASIGNACION", f"Nuevo ticket {ticket.number}", f"Se le asignó: {ticket.title}", ticket.id)

def initial_due(priority: Priority):
    return datetime.now(timezone.utc) + timedelta(hours=priority.sla_hours)
