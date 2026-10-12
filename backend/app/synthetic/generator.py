"""Reproducible simulation of FixIT tickets.

The generator is pure: it does not touch any database. It returns plain dictionaries
that reference users by synthetic keys and catalogs by name; ``importer.py`` resolves
them against a (local) database. The same ``seed`` and ``end_date`` always produce the
same dataset.

Lifecycles follow the real transition rules in ``services/tickets.py``:
NUEVO → ASIGNADO → EN_ATENCION (→ EN_ESPERA → EN_ATENCION) → RESUELTO → CERRADO,
with reopenings (RESUELTO → REABIERTO → EN_ATENCION → RESUELTO), escalations and
cancellations only from states where cancelling is allowed.
"""
from __future__ import annotations

import math
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone

import numpy as np

from app.synthetic import catalog as C

UTC = timezone.utc
HOUR_WEIGHTS = np.array([0.2, 0.1, 0.1, 0.1, 0.1, 0.2, 0.5, 1.5, 4.0, 6.0, 6.5, 6.0,
                         4.0, 4.5, 5.5, 5.5, 4.5, 3.0, 1.5, 0.8, 0.5, 0.4, 0.3, 0.2])
WEEKDAY_FACTOR = [1.15, 1.12, 1.08, 1.0, 0.92, 0.22, 0.08]
MONTH_FACTOR = {1: 0.9, 2: 0.95, 3: 1.15, 4: 1.05, 5: 1.0, 6: 0.95, 7: 1.05, 8: 1.1, 9: 1.0, 10: 1.05, 11: 1.1, 12: 0.8}


@dataclass
class SyntheticDataset:
    params: dict
    requesters: list[dict] = field(default_factory=list)
    technicians: list[dict] = field(default_factory=list)
    tickets: list[dict] = field(default_factory=list)
    assignments: list[dict] = field(default_factory=list)
    history: list[dict] = field(default_factory=list)
    comments: list[dict] = field(default_factory=list)
    ratings: list[dict] = field(default_factory=list)

    def summary(self) -> dict:
        states: dict[str, int] = {}
        for t in self.tickets:
            states[t["state"]] = states.get(t["state"], 0) + 1
        labelled = [t for t in self.tickets if t["sla_met"] is not None]
        return {
            "tickets": len(self.tickets), "requesters": len(self.requesters), "technicians": len(self.technicians),
            "assignments": len(self.assignments), "history": len(self.history), "comments": len(self.comments),
            "ratings": len(self.ratings), "states": dict(sorted(states.items())),
            "sla_breach_rate": round(sum(1 for t in labelled if not t["sla_met"]) / max(1, len(labelled)), 3),
            "first_created": min(t["created_at"] for t in self.tickets).isoformat() if self.tickets else None,
            "last_created": max(t["created_at"] for t in self.tickets).isoformat() if self.tickets else None,
        }


def _slug(text: str) -> str:
    table = str.maketrans("áéíóúñüÁÉÍÓÚÑÜ", "aeiounuAEIOUNU")
    return "".join(ch for ch in text.translate(table).lower().replace(" ", ".") if ch.isalnum() or ch == ".")


def _hours_until_business(moment: datetime) -> float:
    """Calendar hours until the next business window (Mon-Fri 08:00-19:00)."""
    cursor = moment
    for _ in range(14 * 24):
        if cursor.weekday() < 5 and 8 <= cursor.hour < 19:
            return max(0.0, (cursor - moment).total_seconds() / 3600)
        cursor = (cursor + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
    return 0.0


def generate(count: int = 5000, seed: int = 42, end_date: date | None = None, days: int = 540) -> SyntheticDataset:
    if count < 1 or count > 200_000:
        raise ValueError("count debe estar entre 1 y 200000")
    if days < 30:
        raise ValueError("days debe ser al menos 30")
    end_date = end_date or (datetime.now(UTC).date() - timedelta(days=1))
    anchor = datetime.combine(end_date, time(17, 0), tzinfo=UTC)  # "now" of the simulation (business hours)
    start_date = end_date - timedelta(days=days - 1)
    rng = np.random.default_rng(seed)

    def new_id() -> str:
        return str(uuid.UUID(bytes=rng.bytes(16), version=4))

    def pick(options, weights=None):
        if weights is None:
            return options[int(rng.integers(len(options)))]
        w = np.asarray(weights, dtype=float)
        return options[int(rng.choice(len(options), p=w / w.sum()))]

    ds = SyntheticDataset(params={"count": count, "seed": seed, "end_date": end_date.isoformat(), "days": days,
                                  "generator": "fixit-synthetic-v1"})

    # --- People -----------------------------------------------------------------------
    area_names = list(C.AREAS)
    area_weights = [C.AREAS[a][0] for a in area_names]
    requesters_by_area: dict[str, list[dict]] = {a: [] for a in area_names}
    for i in range(150):
        first, last = pick(C.FIRST_NAMES), pick(C.LAST_NAMES)
        area = pick(area_names, area_weights)
        req = {"key": f"req:{i}", "full_name": f"{first} {last}", "area": area,
               "email": f"{_slug(first)}.{_slug(last)}.{i:03d}@{C.SYNTHETIC_EMAIL_DOMAIN}",
               "activity": float(rng.pareto(2.0) + 0.3)}
        ds.requesters.append(req)
        requesters_by_area[area].append(req)
    for area, people in requesters_by_area.items():  # every area needs at least one requester
        if not people:
            req = dict(ds.requesters[len(requesters_by_area) % len(ds.requesters)])
            people.append(req)

    unavailable_from = anchor - timedelta(days=60)
    for i, (name, specialties, speed, quality, max_load, available) in enumerate(C.TECHNICIANS):
        ds.technicians.append({"key": f"tech:{i}", "full_name": name, "email": f"{_slug(name)}.tec@{C.SYNTHETIC_EMAIL_DOMAIN}",
                               "specialties": specialties, "speed": speed, "quality": quality, "max_load": max_load,
                               "available": available, "open_until": []})
    techs_by_specialty: dict[str, list[dict]] = {}
    for tech in ds.technicians:
        for sp in tech["specialties"]:
            techs_by_specialty.setdefault(sp, []).append(tech)

    # --- Creation timestamps (trend + weekday + seasonality + incident days) -----------
    dates = [start_date + timedelta(days=i) for i in range(days)]
    t_axis = np.linspace(0, 1, days)
    weights = np.array([(0.75 + 0.5 * t_axis[i]) * WEEKDAY_FACTOR[d.weekday()] * MONTH_FACTOR[d.month] for i, d in enumerate(dates)])
    weights *= rng.gamma(20, 1 / 20, size=days)
    incident_days = set(int(x) for x in rng.choice(days, size=max(1, days // 120), replace=False))
    for i in incident_days:
        weights[i] *= 2.2
    per_day = rng.multinomial(count, weights / weights.sum())
    created_list: list[tuple[datetime, bool]] = []
    for i, n in enumerate(per_day):
        for _ in range(int(n)):
            hw = HOUR_WEIGHTS if dates[i] != end_date else np.where(np.arange(24) < anchor.hour, HOUR_WEIGHTS, 0.0)
            hour = int(rng.choice(24, p=hw / hw.sum()))
            moment = datetime.combine(dates[i], time(hour, int(rng.integers(60)), int(rng.integers(60))), tzinfo=UTC)
            created_list.append((moment, i in incident_days))
    created_list.sort(key=lambda x: x[0])

    category_names = list(C.CATEGORIES)
    rating_rows = 0
    for index, (created, incident) in enumerate(created_list, start=1):
        area = pick(area_names, area_weights)
        pool = requesters_by_area[area]
        requester = pick(pool, [r["activity"] for r in pool])
        affinity = C.AREA_CATEGORY_AFFINITY.get(area, {})
        cat_weights = [C.CATEGORIES[c][2] * affinity.get(c, 1.0) * (6.0 if incident and c in {"Conectividad de red", "Correo electrónico"} else 1.0)
                       for c in category_names]
        category = pick(category_names, cat_weights)
        specialty, base_hours, _, prio_w = C.CATEGORIES[category]
        bias = C.AREAS[area][1]
        pw = np.array([max(0.01, prio_w[0] - bias), prio_w[1], prio_w[2] + bias * 0.6, max(0.01, prio_w[3] + bias * 0.4)])
        priority = pick(list(C.PRIORITY_CODES), pw)
        sla = C.PRIORITY_SLA[priority]

        # Text: symptoms, location, urgency cues (noisy, so text is informative but not decisive).
        n_sym = int(rng.integers(1, 4))
        symptoms = list(rng.choice(C.SYMPTOMS[category], size=min(n_sym, len(C.SYMPTOMS[category])), replace=False))
        complex_case = n_sym >= 3 or rng.random() < 0.12
        title = pick(C.TITLES[category]) + (f" en {pick(C.LOCATIONS)}" if rng.random() < 0.35 else "")
        parts = [f"Reporto el siguiente problema en {pick(C.LOCATIONS)}."] + symptoms
        if (priority in {"ALTA", "CRITICA"} and rng.random() < 0.7) or rng.random() < 0.08:
            parts.append(pick(C.URGENT_PHRASES))
        elif priority in {"BAJA", "MEDIA"} and rng.random() < 0.5:
            parts.append(pick(C.CALM_PHRASES))
        if complex_case:
            parts.append("Ya intenté reiniciar y el problema persiste; adjunto capturas si es necesario.")
        description = " ".join(parts)

        # Technician choice: specialty match, availability at that time, load-aware.
        candidates = [t for t in techs_by_specialty.get(specialty, ds.technicians)
                      if t["available"] or created < unavailable_from] or ds.technicians
        loads = []
        for tech in candidates:
            tech["open_until"] = [end for end in tech["open_until"] if end > created]
            loads.append(len(tech["open_until"]))
        recent = (anchor - created).total_seconds() < 6 * 3600
        tech = None
        load = 0
        if not (recent and rng.random() < 0.4):
            scores = [math.exp(-l / 2.5) / math.sqrt(t["speed"]) for t, l in zip(candidates, loads)]
            choice = int(rng.choice(len(candidates), p=np.array(scores) / sum(scores)))
            tech, load = candidates[choice], loads[choice]

        off_hours = created.weekday() >= 5 or not (8 <= created.hour < 19)
        attention = float(rng.lognormal(math.log(C.PRIORITY_ATTENTION[priority]), 0.7)) * (1 + 0.06 * load)
        if off_hours:
            attention += 0.5 if priority == "CRITICA" else _hours_until_business(created)
        speed = tech["speed"] if tech else 1.0
        work_median = base_hours * C.PRIORITY_WORK[priority] * speed * (1 + 0.07 * load) * (1.3 if complex_case else 1.0) * (1.2 if incident else 1.0)
        work = float(rng.lognormal(math.log(work_median), 0.55))
        # Waiting for spare parts / vendors happens more in hardware-like categories.
        wait_prob = 0.18 if specialty in {"Hardware", "Software y aplicaciones", "Telefonía", "Seguridad informática"} else 0.07
        wait = float(rng.lognormal(math.log(40), 0.7)) if work > 3 and rng.random() < wait_prob else 0.0

        ticket_id = new_id()
        number = f"{C.SYNTHETIC_TICKET_PREFIX}{index:06d}"
        due_at = created + timedelta(hours=sla)
        events: list[tuple[datetime, str, str | None, str, dict | None, dict | None]] = []
        events.append((created, "CREADO", requester["key"], "Ticket creado", None, {"priority": priority}))

        state = "NUEVO"
        assigned_at = started = resolved_stored = closed = final_resolved = None
        diagnosis = solution = None
        reopened = cancelled = False
        if tech:
            assigned_at = created + timedelta(minutes=float(rng.uniform(1, 10)))
            if assigned_at > anchor:
                tech = None
        if tech:
            reason = "Asignación simulada (dataset sintético)"
            ds.assignments.append({"id": new_id(), "ticket_id": ticket_id, "technician_key": tech["key"], "assigned_by_key": None,
                                   "assignment_type": "AUTOMATICA", "score": None, "reason": reason, "assigned_at": assigned_at})
            events.append((assigned_at, "ASIGNADO", None, f"Asignado a {tech['full_name']}: {reason}", None, {"technician_key": tech["key"]}))
            state = "ASIGNADO"
            started = max(created + timedelta(hours=attention), assigned_at + timedelta(minutes=2))  # never before assignment
            final_resolved = started + timedelta(hours=work + wait)
            tech["open_until"].append(final_resolved)

            cancel_at = created + timedelta(hours=float(rng.uniform(0.5, 24)))
            if rng.random() < 0.03 and cancel_at < started and cancel_at <= anchor:
                cancelled = True
                events.append((cancel_at, "ESTADO_CAMBIADO", None, "Estado: ASIGNADO → CANCELADO", {"state": "ASIGNADO"}, {"state": "CANCELADO"}))
                tech["open_until"].remove(final_resolved)
                state, started, final_resolved = "CANCELADO", None, None
            elif started <= anchor:
                events.append((started, "ESTADO_CAMBIADO", tech["key"], "Estado: ASIGNADO → EN_ATENCION", {"state": "ASIGNADO"}, {"state": "EN_ATENCION"}))
                state = "EN_ATENCION"
                escalated = rng.random() < 0.05
                if wait:
                    w_start = started + timedelta(hours=work * 0.4)
                    w_end = w_start + timedelta(hours=wait)
                    if w_start <= anchor:
                        events.append((w_start, "ESTADO_CAMBIADO", tech["key"], "Estado: EN_ATENCION → EN_ESPERA", {"state": "EN_ATENCION"}, {"state": "EN_ESPERA"}))
                        state = "EN_ESPERA"
                    if w_end <= anchor:
                        events.append((w_end, "ESTADO_CAMBIADO", tech["key"], "Estado: EN_ESPERA → EN_ATENCION", {"state": "EN_ESPERA"}, {"state": "EN_ATENCION"}))
                        state = "EN_ATENCION"
                elif escalated and final_resolved > anchor:
                    esc_at = started + timedelta(hours=min(work * 0.4, (anchor - started).total_seconds() / 3600))
                    events.append((esc_at, "ESTADO_CAMBIADO", tech["key"], "Estado: EN_ATENCION → ESCALADO", {"state": "EN_ATENCION"}, {"state": "ESCALADO"}))
                    state = "ESCALADO"
                if final_resolved <= anchor:
                    diagnosis, solution = pick(C.DIAGNOSES[category])
                    resolved_stored = final_resolved
                    events.append((final_resolved, "ESTADO_CAMBIADO", tech["key"], f"Estado: {state} → RESUELTO", {"state": state}, {"state": "RESUELTO"}))
                    state = "RESUELTO"
                    if rng.random() < 0.04:  # reopening
                        reopen_at = final_resolved + timedelta(hours=float(rng.uniform(2, 48)))
                        if reopen_at <= anchor:
                            reopened = True
                            events.append((reopen_at, "ESTADO_CAMBIADO", requester["key"], "Estado: RESUELTO → REABIERTO", {"state": "RESUELTO"}, {"state": "REABIERTO"}))
                            state = "REABIERTO"
                            restart = reopen_at + timedelta(hours=float(rng.lognormal(math.log(2.0), 0.6)))
                            second = restart + timedelta(hours=float(rng.lognormal(math.log(max(0.5, work * 0.4)), 0.5)))
                            if restart <= anchor:
                                events.append((restart, "ESTADO_CAMBIADO", tech["key"], "Estado: REABIERTO → EN_ATENCION", {"state": "REABIERTO"}, {"state": "EN_ATENCION"}))
                                state = "EN_ATENCION"
                            if second <= anchor:
                                events.append((second, "ESTADO_CAMBIADO", tech["key"], "Estado: EN_ATENCION → RESUELTO", {"state": "EN_ATENCION"}, {"state": "RESUELTO"}))
                                state, resolved_stored, final_resolved = "RESUELTO", second, second
                    if state == "RESUELTO" and rng.random() < 0.85:
                        close_at = resolved_stored + timedelta(hours=float(rng.lognormal(math.log(20), 0.8)))
                        if close_at <= anchor:
                            closed = close_at
                            events.append((close_at, "ESTADO_CAMBIADO", requester["key"], "Estado: RESUELTO → CERRADO", {"state": "RESUELTO"}, {"state": "CERRADO"}))
                            state = "CERRADO"
                elif rng.random() < 0.3:
                    diagnosis = pick(C.DIAGNOSES[category])[0]

        # Comments (public and internal) within the active lifetime of the ticket.
        horizon_end = min(anchor, final_resolved or anchor)
        span_h = max(0.1, (horizon_end - created).total_seconds() / 3600)
        for _ in range(min(4, int(rng.poisson(1.1)))):
            at = created + timedelta(hours=float(rng.uniform(0.05, span_h)))
            if at > anchor:
                continue
            if tech and rng.random() < 0.6:
                internal = rng.random() < 0.3
                body = pick(C.INTERNAL_COMMENTS if internal else C.TECH_COMMENTS)
                author = tech["key"]
            else:
                internal, body, author = False, pick(C.REQUESTER_COMMENTS), requester["key"]
            ds.comments.append({"id": new_id(), "ticket_id": ticket_id, "author_key": author, "body": body, "internal": internal, "created_at": at})
            events.append((at, "COMENTARIO", author, "Comentario agregado", None, None))

        resolution_hours = (final_resolved - created).total_seconds() / 3600 if final_resolved and final_resolved <= anchor and not cancelled else None
        sla_met = None
        if resolved_stored is not None:
            sla_met = resolved_stored <= due_at
        elif state not in {"CANCELADO"} and due_at < anchor:
            sla_met = False

        rating_score = None
        if tech and state in {"RESUELTO", "CERRADO"} and rng.random() < 0.6:
            rated_at = (closed or resolved_stored) + timedelta(hours=float(rng.uniform(0.1, 30)))
            if rated_at <= anchor:
                mean = tech["quality"] - (1.2 if sla_met is False else 0) - (0.8 if reopened else 0) - (0.15 if (resolution_hours or 0) > 72 else 0)
                rating_score = int(min(5, max(1, round(float(rng.normal(mean, 0.7))))))
                ds.ratings.append({"id": new_id(), "ticket_id": ticket_id, "technician_key": tech["key"], "user_key": requester["key"],
                                   "score": rating_score, "solved": bool(rating_score >= 3 or rng.random() < 0.3),
                                   "comment": C.RATING_COMMENTS[rating_score], "created_at": rated_at})
                events.append((rated_at, "CALIFICADO", requester["key"], f"Calificación {rating_score}/5", None, {"score": rating_score}))
                rating_rows += 1

        events.sort(key=lambda e: e[0])
        for at, event, actor, detail, old, new in events:
            ds.history.append({"id": new_id(), "ticket_id": ticket_id, "actor_key": actor, "event": event, "detail": detail,
                               "old_value": old, "new_value": new, "created_at": at})

        ds.tickets.append({
            "id": ticket_id, "number": number, "title": title[:180], "description": description,
            "requester_key": requester["key"], "technician_key": tech["key"] if tech else None,
            "area": area, "category": category, "specialty": specialty, "priority": priority, "sla_hours": sla,
            "state": state, "due_at": due_at, "accepted_at": started if started and started <= anchor else None,
            "started_at": started if started and started <= anchor else None, "resolved_at": resolved_stored,
            "closed_at": closed, "diagnosis": diagnosis, "solution": solution, "created_at": created,
            "updated_at": events[-1][0],
            # Analysis-only columns (exported to CSV, not stored in the tickets table).
            "attention_hours": round(attention, 3) if started and started <= anchor else None,
            "resolution_hours": round(resolution_hours, 3) if resolution_hours is not None else None,
            "sla_met": sla_met, "rating": rating_score, "reopened": reopened, "cancelled": cancelled,
            "incident_day": incident, "technician_name": tech["full_name"] if tech else None,
            "requester_email": requester["email"],
        })

    for tech in ds.technicians:
        tech.pop("open_until", None)
    ds.params["anchor"] = anchor.isoformat()
    return ds


CSV_COLUMNS = ["number", "created_at", "area", "category", "specialty", "priority", "sla_hours", "state", "technician_name",
               "requester_email", "title", "description", "due_at", "started_at", "resolved_at", "closed_at", "attention_hours",
               "resolution_hours", "sla_met", "rating", "reopened", "cancelled", "incident_day", "diagnosis", "solution", "synthetic"]


def write_csv(dataset: SyntheticDataset, path) -> int:
    import csv
    from pathlib import Path

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for t in dataset.tickets:
            row = {k: t.get(k) for k in CSV_COLUMNS if k != "synthetic"}
            for key in ("created_at", "due_at", "started_at", "resolved_at", "closed_at"):
                row[key] = row[key].isoformat() if row[key] else ""
            row["synthetic"] = 1
            writer.writerow(row)
    return len(dataset.tickets)
