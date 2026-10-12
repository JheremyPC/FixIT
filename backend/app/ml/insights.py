"""Descriptive analytics of priorities, categories, periods and technicians.

These are historical aggregates computed directly from the database (no model involved), used
by the predictive dashboard to study patterns and trends.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.ml.dataset import OPEN_STATES, build_features, load_ratings, load_records, load_technicians
from app.ml.predictor import _filter
from app.ml.training import PRIORITY_ORDER

UTC = timezone.utc
WEEKDAYS = ["Lun", "Mar", "Mié", "Jue", "Vie", "Sáb", "Dom"]


def _period_key(moment: datetime, period: str) -> str:
    if period == "day":
        return moment.date().isoformat()
    if period == "week":
        return (moment.date() - timedelta(days=moment.weekday())).isoformat()
    return moment.strftime("%Y-%m")


def _agg() -> dict:
    return {"count": 0, "resolved": 0, "hours": 0.0, "breach": 0, "labelled": 0, "open": 0}


def _add(bucket: dict, rec: dict) -> None:
    bucket["count"] += 1
    if rec["y_hours"] is not None:
        bucket["resolved"] += 1
        bucket["hours"] += rec["y_hours"]
    if rec["y_breach"] is not None:
        bucket["labelled"] += 1
        bucket["breach"] += rec["y_breach"]
    if rec["state"] in OPEN_STATES:
        bucket["open"] += 1


def _out(bucket: dict) -> dict:
    return {"count": bucket["count"], "resolved": bucket["resolved"], "open": bucket["open"],
            "avg_resolution_hours": round(bucket["hours"] / bucket["resolved"], 1) if bucket["resolved"] else None,
            "breach_rate": round(bucket["breach"] / bucket["labelled"], 3) if bucket["labelled"] else None}


def insights(db: Session, filters: dict, period: str = "month", days: int = 365) -> dict:
    now = datetime.now(UTC)
    techs = load_technicians(db)
    records = load_records(db)
    build_features(records, techs, now)
    ratings = load_ratings(db)
    records = _filter(records, filters)
    since = now - timedelta(days=days) if days else None
    if since:
        records = [r for r in records if r["created_at"] >= since]
    if period not in {"day", "week", "month"}:
        period = "month"

    by_period, by_category, by_priority, by_tech, by_area = (defaultdict(_agg) for _ in range(5))
    matrix: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    weekday_hour = [[0] * 24 for _ in range(7)]
    tech_ratings: dict[str, list[int]] = defaultdict(list)
    for r in records:
        _add(by_period[_period_key(r["created_at"], period)], r)
        _add(by_category[r["category"]], r)
        _add(by_priority[r["priority"]], r)
        _add(by_area[r["area"]], r)
        matrix[r["category"]][r["priority"]] += 1
        weekday_hour[r["created_at"].weekday()][r["created_at"].hour] += 1
        if r["technician_id"]:
            _add(by_tech[r["technician_id"]], r)
            if r["id"] in ratings:
                tech_ratings[r["technician_id"]].append(ratings[r["id"]])

    labelled = [r for r in records if r["y_breach"] is not None]
    resolved = [r for r in records if r["y_hours"] is not None]
    synthetic = sum(1 for r in records if r["synthetic"])
    categories = sorted(by_category, key=lambda c: -by_category[c]["count"])
    return {
        "filters": filters, "period": period, "days": days, "generated_at": now.isoformat(),
        "totals": {"tickets": len(records), "synthetic": synthetic, "real": len(records) - synthetic,
                   "open": sum(1 for r in records if r["state"] in OPEN_STATES),
                   "avg_resolution_hours": round(sum(r["y_hours"] for r in resolved) / len(resolved), 1) if resolved else None,
                   "breach_rate": round(sum(r["y_breach"] for r in labelled) / len(labelled), 3) if labelled else None},
        "by_period": [{"period": k, **_out(v)} for k, v in sorted(by_period.items())],
        "by_category": [{"name": c, **_out(by_category[c])} for c in categories],
        "by_priority": [{"name": p, **_out(by_priority[p])} for p in PRIORITY_ORDER if p in by_priority]
                       + [{"name": p, **_out(v)} for p, v in by_priority.items() if p not in PRIORITY_ORDER],
        "by_area": sorted(({"name": a, **_out(v)} for a, v in by_area.items()), key=lambda x: -x["count"]),
        "by_technician": sorted(({"technician_id": t, "name": techs.get(t, {}).get("name", "—"), **_out(v),
                                  "rating": round(sum(tech_ratings[t]) / len(tech_ratings[t]), 2) if tech_ratings[t] else None}
                                 for t, v in by_tech.items()), key=lambda x: -x["count"]),
        "category_priority": {"categories": categories, "priorities": [p for p in PRIORITY_ORDER if p in by_priority],
                              "values": [[matrix[c].get(p, 0) for p in PRIORITY_ORDER if p in by_priority] for c in categories]},
        "weekday_hour": {"weekdays": WEEKDAYS, "values": weekday_hour},
    }
