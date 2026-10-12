"""Daily ticket-volume forecasting with temporal (out-of-time) evaluation.

Model: Ridge regression on weekday, trend and lagged volumes (lags >= 7 days), applied
recursively for multi-step horizons. It is evaluated on the last ``HORIZON`` days that the
model never saw, exactly as it would be used, and compared with a seasonal-naive baseline
(repeat the last observed week).
"""
from __future__ import annotations

from collections import Counter
from datetime import date, timedelta

import numpy as np
from sklearn.linear_model import Ridge

LAGS = (7, 14, 21, 28)
WINDOW = 34          # oldest lag used by the rolling mean feature
HORIZON = 28
MIN_DAYS = WINDOW + 2 * HORIZON + 7


def daily_series(records: list[dict]) -> tuple[list[date], np.ndarray]:
    counts = Counter(r["created_at"].date() for r in records)
    if not counts:
        return [], np.array([])
    first, last = min(counts), max(counts)
    last -= timedelta(days=1)  # the most recent day may be incomplete
    if last < first:
        return [], np.array([])
    days = [first + timedelta(days=i) for i in range((last - first).days + 1)]
    return days, np.array([counts.get(d, 0) for d in days], dtype=float)


def _row(values: list[float], i: int, day: date) -> list[float]:
    dow = [0.0] * 7
    dow[day.weekday()] = 1.0
    lags = [values[i - lag] for lag in LAGS]
    roll = float(np.mean(values[i - WINDOW:i - 6]))
    return dow + [i / 365.0] + lags + [roll]


def _fit(values: list[float], days: list[date], end: int) -> Ridge:
    X = [_row(values, i, days[i]) for i in range(WINDOW, end)]
    y = values[WINDOW:end]
    return Ridge(alpha=1.0).fit(np.array(X), np.array(y))


def _recursive(model: Ridge, known: list[float], start_day: date, horizon: int) -> list[float]:
    values = list(known)
    out = []
    for k in range(horizon):
        i = len(values)
        pred = max(0.0, float(model.predict(np.array([_row(values, i, start_day + timedelta(days=k))]))[0]))
        values.append(pred)
        out.append(pred)
    return out


def _metrics(actual: np.ndarray, pred: np.ndarray) -> dict:
    err = pred - actual
    nonzero = actual > 0
    smape = float(np.mean(2 * np.abs(err) / np.maximum(1e-9, np.abs(actual) + np.abs(pred)))) * 100
    return {"mae": round(float(np.mean(np.abs(err))), 3), "rmse": round(float(np.sqrt(np.mean(err ** 2))), 3),
            "mape_pct": round(float(np.mean(np.abs(err[nonzero]) / actual[nonzero]) * 100), 2) if nonzero.any() else None,
            "smape_pct": round(smape, 2)}


def _weekly(days: list[date], values) -> list[dict]:
    weeks: dict[date, float] = {}
    for d, v in zip(days, values):
        monday = d - timedelta(days=d.weekday())
        weeks[monday] = weeks.get(monday, 0.0) + float(v)
    return [{"week": k.isoformat(), "value": round(v, 2)} for k, v in sorted(weeks.items())]


def train_forecast(records: list[dict]) -> dict:
    days, series = daily_series(records)
    if len(days) < MIN_DAYS:
        return {"status": "insufficient_data", "message": f"Se necesitan al menos {MIN_DAYS} días de historia (hay {len(days)}).",
                "n_days": len(days)}
    values = series.tolist()
    n = len(values)
    split = n - HORIZON
    eval_model = _fit(values, days, split)
    pred = np.array(_recursive(eval_model, values[:split], days[split], HORIZON))
    actual = series[split:]
    baseline = np.array([values[split - 7 + (k % 7)] for k in range(HORIZON)])
    m_model, m_base = _metrics(actual, pred), _metrics(actual, baseline)
    weekly_actual = sum(actual)
    metrics = {**m_model, "baseline_mae": m_base["mae"], "baseline_smape_pct": m_base["smape_pct"],
               "improvement_vs_baseline_pct": round((1 - m_model["mae"] / m_base["mae"]) * 100, 1) if m_base["mae"] else None,
               "holdout_days": HORIZON, "holdout_total_actual": int(weekly_actual), "holdout_total_predicted": round(float(pred.sum()), 1),
               "train_days": split - WINDOW}

    final = _fit(values, days, n)
    start = days[-1] + timedelta(days=1)
    future = _recursive(final, values, start, HORIZON)
    band = 1.2816 * m_model["rmse"]  # ~80% interval from out-of-time residuals
    future_days = [start + timedelta(days=k) for k in range(HORIZON)]

    # Category split of the projection, derived from the share of the last 90 days.
    recent_from = days[-1] - timedelta(days=90)
    shares = Counter(r["category"] for r in records if r["created_at"].date() > recent_from)
    total_recent = sum(shares.values()) or 1
    total_future = sum(future)
    by_category = [{"category": c, "share": round(v / total_recent, 4), "projected": round(total_future * v / total_recent, 1)}
                   for c, v in shares.most_common()]
    return {
        "status": "trained",
        "headline": f"MAE {m_model['mae']:.2f} tickets/día (base estacional {m_base['mae']:.2f})",
        "metrics": metrics,
        "algorithm": "Ridge (lags 7-28 días, día de semana, tendencia) recursivo",
        "data_until": days[-1].isoformat(),
        "history_daily": [{"date": d.isoformat(), "value": int(v)} for d, v in zip(days[-120:], values[-120:])],
        "history_weekly": _weekly(days, values)[-52:],
        "holdout": [{"date": days[split + k].isoformat(), "actual": int(actual[k]), "predicted": round(float(pred[k]), 2),
                     "baseline": int(baseline[k])} for k in range(HORIZON)],
        "forecast_daily": [{"date": d.isoformat(), "value": round(v, 2), "low": round(max(0.0, v - band), 2), "high": round(v + band, 2)}
                           for d, v in zip(future_days, future)],
        "forecast_weekly": _weekly(future_days, future),
        "forecast_total": round(total_future, 1),
        "by_category": by_category,
    }
