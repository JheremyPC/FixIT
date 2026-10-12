"""Ticket records and leakage-free features for the ML pipeline.

Every feature of a ticket is computed *as of its creation time*: only facts that were
already known at that moment are used (catalog data, text written by the requester, the
assigned technician, workload of tickets still open and statistics of tickets that had
already finished). Outcome fields (state, started/resolved/closed timestamps, diagnosis,
solution, rating, comments) are never features; they only produce the targets.
"""
from __future__ import annotations

import unicodedata
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, aliased

from app.models import Area, Category, Priority, Rating, Technician, TechnicianSpecialty, Ticket, TicketState, User
from app.synthetic.catalog import SYNTHETIC_TICKET_PREFIX

UTC = timezone.utc
OPEN_STATES = {"NUEVO", "ASIGNADO", "EN_ATENCION", "EN_ESPERA", "REABIERTO", "ESCALADO"}
NO_TECH = "NINGUNO"
NO_SPECIALTY = "NINGUNA"
URGENT_WORDS = ("urgente", "detiene", "afecta", "varias personas", "cierre", "clientes", "no puedo", "bloque",
                "virus", "sospechoso", "caido", "no funciona", "no enciende", "inmediato")

CAT_FEATURES = ["area", "category", "priority", "technician", "specialty"]
NUM_FEATURES = ["priority_level", "sla_hours", "hour", "weekday", "is_weekend", "off_hours", "month", "title_len",
                "desc_len", "urgent_hits", "tech_open", "global_open", "tech_hist_hours", "tech_hist_breach",
                "cat_hist_hours", "tech_specialty_match"]
FEATURES = CAT_FEATURES + NUM_FEATURES

# Groups used to explain individual predictions (feature names → human readable factor).
FEATURE_GROUPS = {
    "priority": ["priority", "priority_level", "sla_hours"],
    "category": ["category", "specialty", "cat_hist_hours"],
    "area": ["area"],
    "technician": ["technician", "tech_hist_hours", "tech_hist_breach", "tech_specialty_match"],
    "tech_load": ["tech_open"],
    "global_load": ["global_open"],
    "schedule": ["hour", "weekday", "is_weekend", "off_hours"],
    "season": ["month"],
    "text": ["title_len", "desc_len", "urgent_hits"],
}


def utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def normalize_text(text: str) -> str:
    text = unicodedata.normalize("NFKD", text or "").encode("ascii", "ignore").decode("ascii")
    return text.lower()


def is_synthetic(number: str) -> bool:
    return (number or "").startswith(SYNTHETIC_TICKET_PREFIX)


def load_technicians(db: Session) -> dict[str, dict]:
    rows = db.execute(select(Technician.id, User.full_name, Technician.available, Technician.max_load, User.active)
                      .join(User, User.id == Technician.user_id)).all()
    specs: dict[str, set[str]] = {}
    for tech_id, spec_id in db.execute(select(TechnicianSpecialty.technician_id, TechnicianSpecialty.specialty_id)).all():
        specs.setdefault(tech_id, set()).add(spec_id)
    return {r[0]: {"id": r[0], "name": r[1], "available": bool(r[2]) and bool(r[4]), "max_load": int(r[3]),
                   "specialties": specs.get(r[0], set())} for r in rows}


def load_records(db: Session, include_synthetic: bool = True) -> list[dict]:
    query = (select(Ticket.id, Ticket.number, Ticket.title, Ticket.description, Ticket.created_at, Ticket.updated_at,
                    Ticket.due_at, Ticket.started_at, Ticket.resolved_at, Ticket.closed_at, Ticket.technician_id,
                    Ticket.area_id, Area.name, Ticket.category_id, Category.name, Category.specialty_id, Ticket.priority_id,
                    Priority.code, Priority.level, Priority.sla_hours, TicketState.code)
             .join(Area, Area.id == Ticket.area_id).join(Category, Category.id == Ticket.category_id)
             .join(Priority, Priority.id == Ticket.priority_id).join(TicketState, TicketState.id == Ticket.state_id))
    if not include_synthetic:
        query = query.where(~Ticket.number.like(f"{SYNTHETIC_TICKET_PREFIX}%"))
    records = []
    for r in db.execute(query).all():
        created = utc(r[4])
        records.append({
            "id": r[0], "number": r[1], "title": r[2] or "", "description": r[3] or "", "created_at": created,
            "updated_at": utc(r[5]), "due_at": utc(r[6]) or None, "started_at": utc(r[7]), "resolved_at": utc(r[8]),
            "closed_at": utc(r[9]), "technician_id": r[10], "area_id": r[11], "area": r[12], "category_id": r[13],
            "category": r[14], "specialty_id": r[15], "priority_id": r[16], "priority": r[17], "priority_level": int(r[18]),
            "sla_hours": int(r[19]), "state": r[20], "synthetic": is_synthetic(r[1]),
        })
    return records


def load_ratings(db: Session) -> dict[str, int]:
    return {tid: score for tid, score in db.execute(select(Rating.ticket_id, Rating.score)).all()}


def _labels(rec: dict, now: datetime) -> None:
    from datetime import timedelta

    due = rec["due_at"] or rec["created_at"] + timedelta(hours=rec["sla_hours"])
    rec["due_at"] = due
    resolved = rec["resolved_at"]
    rec["y_hours"] = max(0.01, (resolved - rec["created_at"]).total_seconds() / 3600) if resolved and rec["state"] != "CANCELADO" else None
    if rec["state"] == "CANCELADO":
        rec["y_breach"] = None
    elif resolved:
        rec["y_breach"] = int(resolved > due)
    elif rec["state"] in OPEN_STATES and due < now:
        rec["y_breach"] = 1  # still open after the deadline: the breach is already a fact
    else:
        rec["y_breach"] = None
    # When the ticket stopped occupying its technician (used for workload features).
    if resolved:
        rec["ended_at"] = resolved
    elif rec["state"] in {"CERRADO", "CANCELADO"}:
        rec["ended_at"] = rec["closed_at"] or rec["updated_at"] or rec["created_at"]
    else:
        rec["ended_at"] = None


class Tracker:
    """Running statistics of finished tickets and open workload during a time sweep."""

    def __init__(self):
        self.open_by_tech: dict[str, int] = {}
        self.open_total = 0
        self.tech_hours: dict[str, list[float]] = {}
        self.tech_breach: dict[str, list[int]] = {}
        self.cat_hours: dict[str, list[float]] = {}
        self.global_hours: list[float] = [0.0, 0]
        self.global_breach: list[float] = [0.0, 0]

    def global_mean(self) -> float:
        return self.global_hours[0] / self.global_hours[1] if self.global_hours[1] else 24.0

    def global_rate(self) -> float:
        return self.global_breach[0] / self.global_breach[1] if self.global_breach[1] else 0.2

    def tech_stats(self, tech_id: str | None) -> tuple[float, float]:
        hours = self.tech_hours.get(tech_id)
        breach = self.tech_breach.get(tech_id)
        mean_h = hours[0] / hours[1] if hours and hours[1] >= 3 else self.global_mean()
        rate = breach[0] / breach[1] if breach and breach[1] >= 3 else self.global_rate()
        return mean_h, rate

    def cat_mean(self, cat_id: str) -> float:
        hours = self.cat_hours.get(cat_id)
        return hours[0] / hours[1] if hours and hours[1] >= 3 else self.global_mean()

    def finish(self, rec: dict) -> None:
        if rec.get("_open"):
            rec["_open"] = False
            self.open_total -= 1
            if rec["technician_id"]:
                self.open_by_tech[rec["technician_id"]] -= 1
        if rec["y_hours"] is not None:
            for store, key in ((self.tech_hours, rec["technician_id"]), (self.cat_hours, rec["category_id"])):
                if key:
                    bucket = store.setdefault(key, [0.0, 0])
                    bucket[0] += rec["y_hours"]
                    bucket[1] += 1
            self.global_hours[0] += rec["y_hours"]
            self.global_hours[1] += 1
            breach = int(rec["resolved_at"] > rec["due_at"])
            if rec["technician_id"]:
                bucket = self.tech_breach.setdefault(rec["technician_id"], [0, 0])
                bucket[0] += breach
                bucket[1] += 1
            self.global_breach[0] += breach
            self.global_breach[1] += 1

    def start(self, rec: dict) -> None:
        if rec.get("_finished_early"):
            return
        rec["_open"] = True
        self.open_total += 1
        if rec["technician_id"]:
            self.open_by_tech[rec["technician_id"]] = self.open_by_tech.get(rec["technician_id"], 0) + 1


def base_features(rec: dict) -> dict:
    created = rec["created_at"]
    text = normalize_text(f"{rec['title']} {rec['description']}")
    off = created.weekday() >= 5 or not (8 <= created.hour < 19)
    return {"area": rec["area"], "category": rec["category"], "priority": rec["priority"],
            "specialty": rec["specialty_id"] or NO_SPECIALTY, "priority_level": rec["priority_level"],
            "sla_hours": rec["sla_hours"], "hour": created.hour, "weekday": created.weekday(),
            "is_weekend": int(created.weekday() >= 5), "off_hours": int(off), "month": created.month,
            "title_len": len(rec["title"]), "desc_len": len(rec["description"]),
            "urgent_hits": sum(text.count(w) for w in URGENT_WORDS)}


def technician_features(rec: dict, tech_id: str | None, tracker: Tracker, techs: dict[str, dict]) -> dict:
    mean_h, rate = tracker.tech_stats(tech_id)
    if tech_id and rec["specialty_id"]:
        match = 1.0 if rec["specialty_id"] in techs.get(tech_id, {}).get("specialties", set()) else 0.0
    else:
        match = 0.5
    return {"technician": tech_id or NO_TECH, "tech_open": tracker.open_by_tech.get(tech_id, 0) if tech_id else 0,
            "tech_hist_hours": mean_h, "tech_hist_breach": rate, "tech_specialty_match": match}


def build_features(records: list[dict], techs: dict[str, dict], now: datetime | None = None,
                   snapshot: bool = False) -> Tracker:
    """Adds ``x`` (features) and labels to each record in place. Returns the tracker as of ``now``.

    With ``snapshot=True`` each record also keeps the per-technician state at its creation time,
    used to backtest technician recommendations without looking into the future.
    """
    now = now or datetime.now(UTC)
    for rec in records:
        _labels(rec, now)
    records.sort(key=lambda r: (r["created_at"], r["id"]))
    endings = sorted((r for r in records if r["ended_at"] is not None), key=lambda r: r["ended_at"])
    tracker = Tracker()
    pointer = 0
    for rec in records:
        moment = rec["created_at"]
        while pointer < len(endings) and endings[pointer]["ended_at"] <= moment:
            ended = endings[pointer]
            pointer += 1
            if ended.get("_open"):
                tracker.finish(ended)
            elif ended is not rec and ended["created_at"] >= moment:
                ended["_finished_early"] = True
                tracker.finish(ended)
        x = base_features(rec)
        x.update(technician_features(rec, rec["technician_id"], tracker, techs))
        x["global_open"] = tracker.open_total
        x["cat_hist_hours"] = tracker.cat_mean(rec["category_id"])
        rec["x"] = x
        if snapshot:
            rec["_snap"] = {tid: (tracker.open_by_tech.get(tid, 0), *tracker.tech_stats(tid)) for tid in techs}
        tracker.start(rec)
        if rec["ended_at"] is not None and rec["ended_at"] <= moment and rec.get("_open"):
            tracker.finish(rec)  # its ending was consumed above, before it had started
    while pointer < len(endings) and endings[pointer]["ended_at"] <= now:
        if endings[pointer].get("_open"):
            tracker.finish(endings[pointer])
        pointer += 1
    return tracker


def candidate_technicians(rec: dict, techs: dict[str, dict], only_available: bool = True) -> list[str]:
    pool = [t for t in techs.values() if t["available"] or not only_available]
    if rec.get("specialty_id"):
        matching = [t for t in pool if rec["specialty_id"] in t["specialties"]]
        pool = matching or pool
    return [t["id"] for t in pool]
