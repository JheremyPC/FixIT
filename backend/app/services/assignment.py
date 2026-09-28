from dataclasses import dataclass
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.models import Rating, Setting, Technician, Ticket, TicketState

WEIGHT_DEFAULTS = {
    "assignment.rating": 0.30, "assignment.sla": 0.20, "assignment.speed": 0.15,
    "assignment.specialty": 0.15, "assignment.resolved": 0.10, "assignment.reopened": 0.10,
    "assignment.load_penalty": 0.20,
}

@dataclass
class Candidate:
    technician: Technician
    score: float
    reason: str


class AssignmentService:
    """Deterministic, configurable selection. Integration point for future prediction services."""
    def __init__(self, db: Session):
        self.db = db
        values = {s.key: s.value for s in db.query(Setting).filter(Setting.key.in_(WEIGHT_DEFAULTS)).all()}
        self.weights = {key: float(values.get(key, default)) for key, default in WEIGHT_DEFAULTS.items()}

    def _metrics(self, technician: Technician) -> dict:
        tickets = self.db.query(Ticket).filter(Ticket.technician_id == technician.id).all()
        active = [t for t in tickets if t.state.code in {"ASIGNADO", "EN_ATENCION", "EN_ESPERA", "ESCALADO", "REABIERTO"}]
        resolved = [t for t in tickets if t.state.code in {"RESUELTO", "CERRADO"}]
        reopened = [t for t in tickets if t.state.code == "REABIERTO"]
        ratings = self.db.query(func.avg(Rating.score)).filter(Rating.technician_id == technician.id).scalar() or 3
        on_sla = sum(1 for t in resolved if t.due_at and t.resolved_at and t.resolved_at <= t.due_at)
        sla = on_sla / len(resolved) if resolved else 0.5
        speed = 0.5
        times = [(t.resolved_at - t.started_at).total_seconds() / 3600 for t in resolved if t.started_at and t.resolved_at]
        if times: speed = max(0, min(1, 1 - (sum(times) / len(times)) / 72))
        return {"rating": float(ratings) / 5, "sla": sla, "speed": speed,
                "resolved": min(1, len(resolved) / 20), "reopened": len(reopened) / max(1, len(resolved)),
                "load": len(active) / max(1, technician.max_load)}

    def select(self, ticket: Ticket) -> Candidate | None:
        required = ticket.category.specialty_id
        technicians = self.db.query(Technician).join(Technician.user).filter(Technician.available.is_(True)).all()
        candidates = []
        for tech in technicians:
            specialty_ids = {row.specialty_id for row in tech.specialties}
            if required and required not in specialty_ids: continue
            m = self._metrics(tech)
            if m["load"] >= 1: continue
            specialty = 1 if required else 0.6
            score = (self.weights["assignment.rating"] * m["rating"] + self.weights["assignment.sla"] * m["sla"] +
                     self.weights["assignment.speed"] * m["speed"] + self.weights["assignment.specialty"] * specialty +
                     self.weights["assignment.resolved"] * m["resolved"] - self.weights["assignment.reopened"] * m["reopened"] -
                     self.weights["assignment.load_penalty"] * m["load"])
            reason = f"Especialidad {'compatible' if required else 'no requerida'}; carga {m['load']:.0%}; SLA {m['sla']:.0%}; calificación {m['rating'] * 5:.1f}/5"
            candidates.append(Candidate(tech, round(score * 100, 2), reason))
        return max(candidates, key=lambda c: (c.score, c.technician.id)) if candidates else None

