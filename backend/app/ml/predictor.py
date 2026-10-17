"""Inference on top of the trained models. Nothing here invents numbers: when a model is not
trained (or the data is insufficient) a ``ModelNotTrained`` error explains why."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import numpy as np
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ml import store
from app.ml.dataset import (FEATURE_GROUPS, NO_TECH, OPEN_STATES, Tracker, base_features, build_features,
                            candidate_technicians, load_records, load_technicians, technician_features)
from app.ml.training import matrix, priority_matrix
from app.models import Category, Priority, Ticket, Area
from app.synthetic.catalog import SYNTHETIC_TICKET_PREFIX

UTC = timezone.utc
WEEKDAYS = ["lunes", "martes", "miércoles", "jueves", "viernes", "sábado", "domingo"]
MONTHS = ["enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre"]


class ModelNotTrained(RuntimeError):
    pass


def risk_level(p: float) -> str:
    return "alto" if p >= 0.6 else ("medio" if p >= 0.3 else "bajo")


class Predictor:
    def __init__(self):
        self.reg = store.load_bundle("resolution")
        self.cls = store.load_bundle("sla_risk")
        self.prio = store.load_bundle("priority")
        self.meta = store.load_metadata()

    def require(self) -> None:
        missing = [name for name, b in (("tiempo de resolución", self.reg), ("riesgo SLA", self.cls)) if b is None]
        if missing:
            detail = ""
            if self.meta:
                reasons = [m.get("message") for m in self.meta["models"].values() if m.get("status") != "trained" and m.get("message")]
                detail = " " + " ".join(dict.fromkeys(reasons))
            raise ModelNotTrained(f"Modelo no entrenado: {', '.join(missing)}. Entrene los modelos desde el panel de IA.{detail}".strip())

    def model_info(self) -> dict:
        return {"version": self.meta.get("version") if self.meta else None, "trained_at": self.meta.get("trained_at") if self.meta else None,
                "data_source": self.meta["data"]["source"] if self.meta else None,
                "synthetic_share": self.meta["data"]["synthetic_share"] if self.meta else None}

    def predict(self, xs: list[dict]) -> tuple[np.ndarray, np.ndarray]:
        X = matrix(xs)
        hours = np.clip(np.expm1(self.reg["pipeline"].predict(X)), 0.01, None)
        probs = self.cls["pipeline"].predict_proba(X)[:, 1]
        return hours, probs

    def explain(self, xs: list[dict], techs: dict) -> list[list[dict]]:
        """Local explanation: change in predicted breach probability when one factor group is
        replaced by its typical (training) value. Positive = the factor raises the risk."""
        if not xs:
            return []
        ref = self.cls["reference"]
        groups = list(FEATURE_GROUPS)
        rows = []
        for x in xs:
            rows.append(x)
            for g in groups:
                rows.append(dict(x, **{f: ref[f] for f in FEATURE_GROUPS[g]}))
        probs = self.cls["pipeline"].predict_proba(matrix(rows))[:, 1]
        out = []
        width = len(groups) + 1
        for i, x in enumerate(xs):
            base = probs[i * width]
            factors = []
            for j, g in enumerate(groups):
                delta = float(base - probs[i * width + 1 + j])
                if abs(delta) >= 0.01:
                    factors.append({"factor": g, "label": factor_label(g, x, techs), "impact": round(delta, 3),
                                    "direction": "aumenta" if delta > 0 else "reduce"})
            factors.sort(key=lambda f: -abs(f["impact"]))
            out.append(factors[:4])
        return out

    def suggest_priority(self, title: str, description: str, area: str, category: str) -> dict | None:
        if not self.prio:
            return None
        pipe = self.prio["pipeline"]
        probs = pipe.predict_proba(priority_matrix([{"title": title, "description": description, "area": area, "category": category}]))[0]
        ranked = sorted(zip(pipe.classes_, probs), key=lambda p: -p[1])
        return {"code": ranked[0][0], "probabilities": {c: round(float(p), 3) for c, p in ranked}}


def factor_label(group: str, x: dict, techs: dict) -> str:
    if group == "priority":
        return f"Prioridad {x['priority']} (SLA {x['sla_hours']} h)"
    if group == "category":
        return f"Categoría «{x['category']}» (promedio histórico {x['cat_hist_hours']:.0f} h)"
    if group == "area":
        return f"Área {x['area']}"
    if group == "technician":
        if x["technician"] == NO_TECH:
            return "Sin técnico asignado al crearse"
        name = techs.get(x["technician"], {}).get("name", "técnico")
        return f"Técnico {name} (histórico {x['tech_hist_hours']:.0f} h, {x['tech_hist_breach']:.0%} fuera de SLA)"
    if group == "tech_load":
        return f"Carga del técnico al crearse: {x['tech_open']} tickets abiertos"
    if group == "global_load":
        return f"Cola total al crearse: {x['global_open']} tickets abiertos"
    if group == "schedule":
        return f"Creado el {WEEKDAYS[x['weekday']]} a las {x['hour']:02d}:00" + (" (fuera de horario)" if x["off_hours"] else "")
    if group == "season":
        return f"Mes de creación: {MONTHS[x['month'] - 1]}"
    if group == "text":
        return f"Descripción de {x['desc_len']} caracteres con {x['urgent_hits']} señales de urgencia"
    return group


def recommend(predictor: Predictor, rec: dict, tracker: Tracker, techs: dict, top: int = 3) -> list[dict]:
    """Rank available technicians for a ticket using the trained models and current workload."""
    candidates = candidate_technicians(rec, techs)
    if not candidates:
        return []
    rows = []
    for tid in candidates:
        x = dict(rec["x"])
        x.update(technician_features(rec, tid, tracker, techs))
        x["global_open"] = tracker.open_total
        rows.append(x)
    hours, probs = predictor.predict(rows)
    items = []
    for tid, x, h, p in zip(candidates, rows, hours, probs):
        tech = techs[tid]
        full = x["tech_open"] >= tech["max_load"]
        items.append({
            "technician_id": tid, "name": tech["name"], "sla_risk": round(float(p), 3), "predicted_hours": round(float(h), 1),
            "open_tickets": int(x["tech_open"]), "max_load": tech["max_load"], "at_capacity": full,
            "historical_hours": round(float(x["tech_hist_hours"]), 1), "historical_breach_rate": round(float(x["tech_hist_breach"]), 3),
            "specialty_match": x["tech_specialty_match"] == 1.0,
            "reason": (f"Riesgo SLA estimado {p:.0%}, tiempo estimado {h:.1f} h, carga {int(x['tech_open'])}/{tech['max_load']}, "
                       f"histórico {x['tech_hist_hours']:.0f} h" + (" — sin capacidad" if full else "")),
        })
    items.sort(key=lambda i: (i["at_capacity"], round(i["sla_risk"], 2), i["predicted_hours"]))
    return items[:top]


def _context(db: Session, include_synthetic: bool = True):
    now = datetime.now(UTC)
    techs = load_technicians(db)
    records = load_records(db, include_synthetic=include_synthetic)
    tracker = build_features(records, techs, now)
    return now, techs, records, tracker


def _filter(records: list[dict], filters: dict) -> list[dict]:
    out = records
    if filters.get("area_id"):
        out = [r for r in out if r["area_id"] == filters["area_id"]]
    if filters.get("category_id"):
        out = [r for r in out if r["category_id"] == filters["category_id"]]
    if filters.get("priority"):
        out = [r for r in out if r["priority"] == filters["priority"]]
    if filters.get("technician_id"):
        out = [r for r in out if r["technician_id"] == filters["technician_id"]]
    source = filters.get("source") or "all"
    if source == "real":
        out = [r for r in out if not r["synthetic"]]
    elif source == "synthetic":
        out = [r for r in out if r["synthetic"]]
    return out


def _ticket_row(rec: dict, hours: float, prob: float, now: datetime, techs: dict) -> dict:
    elapsed = (now - rec["created_at"]).total_seconds() / 3600
    predicted_end = rec["created_at"] + timedelta(hours=float(hours))
    return {
        "id": rec["id"], "number": rec["number"], "title": rec["title"], "area": rec["area"], "category": rec["category"],
        "priority": rec["priority"], "state": rec["state"], "synthetic": rec["synthetic"],
        "technician": techs.get(rec["technician_id"], {}).get("name") if rec["technician_id"] else None,
        "technician_id": rec["technician_id"], "created_at": rec["created_at"].isoformat(), "due_at": rec["due_at"].isoformat(),
        "elapsed_hours": round(elapsed, 1), "predicted_hours": round(float(hours), 1), "predicted_resolution_at": predicted_end.isoformat(),
        "predicted_remaining_hours": round(max(0.0, float(hours) - elapsed), 1), "sla_risk": round(float(prob), 3),
        "risk_level": risk_level(float(prob)), "overdue": rec["due_at"] < now,
    }


def open_predictions(db: Session, filters: dict, limit: int = 50) -> dict:
    predictor = Predictor()
    predictor.require()
    now, techs, records, tracker = _context(db)
    open_recs = _filter([r for r in records if r["state"] in OPEN_STATES], filters)
    if not open_recs:
        return {"model": predictor.model_info(), "summary": {"open": 0, "high_risk": 0, "expected_breaches": 0, "overdue": 0}, "tickets": []}
    hours, probs = predictor.predict([r["x"] for r in open_recs])
    order = np.argsort(-probs)
    top_idx = list(order[:limit])
    factors = predictor.explain([open_recs[i]["x"] for i in top_idx], techs)
    tickets = []
    for i, f in zip(top_idx, factors):
        row = _ticket_row(open_recs[i], hours[i], probs[i], now, techs)
        row["factors"] = f
        recs = recommend(predictor, open_recs[i], tracker, techs, top=1)
        row["recommended"] = recs[0] if recs else None
        tickets.append(row)
    return {"model": predictor.model_info(), "generated_at": now.isoformat(),
            "summary": {"open": len(open_recs), "high_risk": int((probs >= 0.6).sum()), "medium_risk": int(((probs >= 0.3) & (probs < 0.6)).sum()),
                        "expected_breaches": round(float(probs.sum()), 1), "overdue": sum(1 for r in open_recs if r["due_at"] < now),
                        "avg_predicted_hours": round(float(hours.mean()), 1)},
            "tickets": tickets}


def score_open(db: Session) -> dict:
    """Predicted hours and SLA risk of every open ticket (no explanations), for the agents."""
    predictor = Predictor()
    predictor.require()
    now, techs, records, tracker = _context(db)
    open_recs = [r for r in records if r["state"] in OPEN_STATES]
    hours, probs = predictor.predict([r["x"] for r in open_recs]) if open_recs else (np.array([]), np.array([]))
    return {"predictor": predictor, "now": now, "techs": techs, "tracker": tracker,
            "rows": [_ticket_row(r, h, p, now, techs) for r, h, p in zip(open_recs, hours, probs)], "records": open_recs}


def ticket_prediction(db: Session, ticket_id: str) -> dict:
    predictor = Predictor()
    predictor.require()
    now, techs, records, tracker = _context(db)
    rec = next((r for r in records if r["id"] == ticket_id), None)
    if rec is None:
        raise LookupError("Ticket no encontrado")
    hours, probs = predictor.predict([rec["x"]])
    row = _ticket_row(rec, hours[0], probs[0], now, techs)
    row["factors"] = predictor.explain([rec["x"]], techs)[0]
    row["recommendations"] = recommend(predictor, rec, tracker, techs, top=3) if rec["state"] in OPEN_STATES else []
    trained_at = datetime.fromisoformat(predictor.meta["trained_at"]) if predictor.meta else None
    if rec["y_hours"] is not None or rec["y_breach"] is not None:
        known_at = rec["resolved_at"] or rec["due_at"]
        row["actual"] = {"hours": round(rec["y_hours"], 1) if rec["y_hours"] is not None else None,
                         "sla_breached": bool(rec["y_breach"]) if rec["y_breach"] is not None else None,
                         "in_training_data": bool(trained_at and known_at and known_at <= trained_at)}
    row["model"] = predictor.model_info()
    return row


def predict_new(db: Session, payload: dict) -> dict:
    predictor = Predictor()
    predictor.require()
    now, techs, records, tracker = _context(db)
    area = db.get(Area, payload["area_id"])
    category = db.get(Category, payload["category_id"])
    if not area or not category:
        raise LookupError("Área o categoría inválida")
    suggestion = predictor.suggest_priority(payload["title"], payload["description"], area.name, category.name)
    priority = db.get(Priority, payload["priority_id"]) if payload.get("priority_id") else None
    if priority is None:
        code = suggestion["code"] if suggestion else "MEDIA"
        priority = db.scalar(select(Priority).where(Priority.code == code)) or db.scalar(select(Priority).order_by(Priority.level))
    rec = {"id": "simulado", "title": payload["title"], "description": payload["description"], "created_at": now,
           "area": area.name, "area_id": area.id, "category": category.name, "category_id": category.id,
           "specialty_id": category.specialty_id, "priority": priority.code, "priority_level": priority.level,
           "sla_hours": priority.sla_hours, "technician_id": None}
    x = base_features(rec)
    x.update(technician_features(rec, None, tracker, techs))
    x["global_open"] = tracker.open_total
    x["cat_hist_hours"] = tracker.cat_mean(category.id)
    rec["x"] = x
    recommendations = recommend(predictor, rec, tracker, techs, top=3)
    hours, probs = predictor.predict([x])
    return {"model": predictor.model_info(), "priority_suggestion": suggestion, "priority_used": priority.code,
            "sla_hours": priority.sla_hours, "without_technician": {"predicted_hours": round(float(hours[0]), 1), "sla_risk": round(float(probs[0]), 3)},
            "recommendations": recommendations, "factors": predictor.explain([x], techs)[0]}


def recommendations(db: Session, limit: int = 30) -> dict:
    predictor = Predictor()
    predictor.require()
    now, techs, records, tracker = _context(db)
    open_recs = [r for r in records if r["state"] in OPEN_STATES]
    needs = lambda r: (r["technician_id"] is None or r["state"] in {"NUEVO", "REABIERTO", "ESCALADO"})
    open_recs.sort(key=lambda r: (not needs(r), r["due_at"]))
    items = []
    for rec in open_recs[:limit]:
        options = recommend(predictor, rec, tracker, techs, top=3)
        current = None
        if rec["technician_id"]:
            hours, probs = predictor.predict([rec["x"]])
            current = {"technician_id": rec["technician_id"], "name": techs.get(rec["technician_id"], {}).get("name"),
                       "sla_risk": round(float(probs[0]), 3), "predicted_hours": round(float(hours[0]), 1)}
        better = bool(options and current and options[0]["technician_id"] != current["technician_id"]
                      and current["sla_risk"] - options[0]["sla_risk"] >= 0.1)
        items.append({"id": rec["id"], "number": rec["number"], "title": rec["title"], "category": rec["category"],
                      "priority": rec["priority"], "state": rec["state"], "synthetic": rec["synthetic"],
                      "needs_assignment": needs(rec), "current": current, "options": options, "better_option": better})
    workload = sorted(({"technician_id": t["id"], "name": t["name"], "available": t["available"], "open": tracker.open_by_tech.get(t["id"], 0),
                        "max_load": t["max_load"], "historical_hours": round(tracker.tech_stats(t["id"])[0], 1),
                        "historical_breach_rate": round(tracker.tech_stats(t["id"])[1], 3)} for t in techs.values()), key=lambda w: w["name"])
    return {"model": predictor.model_info(), "items": items, "workload": workload}


def forecast() -> dict:
    bundle = store.load_bundle("forecast")
    meta = store.load_metadata()
    if bundle is None:
        reason = meta["models"]["forecast"].get("message") if meta and "forecast" in meta["models"] else None
        raise ModelNotTrained(reason or "El modelo de demanda no está entrenado. Entrene los modelos desde el panel de IA.")
    out = dict(bundle)
    out["data_source"] = meta["data"]["source"] if meta else None
    out["synthetic_share"] = meta["data"]["synthetic_share"] if meta else None
    return out


def dataset_counts(db: Session) -> dict:
    total = db.scalar(select(func.count()).select_from(Ticket)) or 0
    synthetic = db.scalar(select(func.count()).select_from(Ticket).where(Ticket.number.like(f"{SYNTHETIC_TICKET_PREFIX}%"))) or 0
    return {"tickets_total": total, "tickets_synthetic": synthetic, "tickets_real": total - synthetic}


def status(db: Session) -> dict:
    meta = store.load_metadata()
    available = {name: store.load_bundle(name) is not None for name in store.MODEL_NAMES}
    return {"trained": bool(meta) and available["resolution"] and available["sla_risk"], "metadata": meta, "available": available,
            "dataset": dataset_counts(db), "history": store.load_history()[:10], "training_in_progress": store.TRAIN_LOCK.locked()}
