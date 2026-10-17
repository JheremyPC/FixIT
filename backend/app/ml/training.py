"""Reproducible training pipeline for FixIT.

Models
* ``resolution``: HistGradientBoostingRegressor on log(hours) → hours to resolve (MAE).
* ``sla_risk``:   HistGradientBoostingClassifier (balanced) → P(SLA breach) (precision/recall/F1/AUC).
* ``priority``:   TF-IDF + logistic regression on the requester's text → suggested priority (macro F1).
* ``forecast``:   Ridge on lagged daily volume → demand projection (out-of-time MAE vs seasonal naive).
* Technician recommendation reuses ``resolution`` + ``sla_risk`` per candidate; it is backtested
  on the hold-out period with the technicians' state at each ticket's creation time.

Evaluation is always temporal: models are fitted on the oldest 80 % of tickets whose outcome was
already known at the cut-off and scored on the most recent 20 %. Final models are then refitted
on all labelled data. Random seeds are fixed.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from statistics import median

import numpy as np
import sklearn
from sklearn import metrics as M
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingClassifier, HistGradientBoostingRegressor
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder
from sqlalchemy.orm import Session

from app.ml import store
from app.ml.dataset import (CAT_FEATURES, FEATURES, NUM_FEATURES, build_features, candidate_technicians, load_records,
                            load_technicians, normalize_text)
from app.ml.forecast import train_forecast

UTC = timezone.utc
MIN_RESOLUTION = 150
MIN_SLA = 150
MIN_CLASS = 15
MIN_PRIORITY = 200
TEST_FRACTION = 0.2
SEED = 0
PRIORITY_ORDER = ["BAJA", "MEDIA", "ALTA", "CRITICA"]

FEATURE_LABELS = {
    "area": "Área", "category": "Categoría", "priority": "Prioridad", "technician": "Técnico asignado",
    "specialty": "Especialidad requerida", "priority_level": "Nivel de prioridad", "sla_hours": "Horas de SLA",
    "hour": "Hora de creación", "weekday": "Día de la semana", "is_weekend": "Fin de semana", "off_hours": "Fuera de horario",
    "month": "Mes", "title_len": "Longitud del título", "desc_len": "Longitud de la descripción",
    "urgent_hits": "Señales de urgencia en el texto", "tech_open": "Carga del técnico", "global_open": "Cola total abierta",
    "tech_hist_hours": "Tiempo histórico del técnico", "tech_hist_breach": "Incumplimiento histórico del técnico",
    "cat_hist_hours": "Tiempo histórico de la categoría", "tech_specialty_match": "Especialidad del técnico compatible",
}


class TrainingInProgress(RuntimeError):
    pass


def to_float(X):
    return np.asarray(X, dtype=float)


def matrix(xs: list[dict]) -> np.ndarray:
    return np.array([[x[f] for f in FEATURES] for x in xs], dtype=object)


def _preprocessor() -> ColumnTransformer:
    n_cat = len(CAT_FEATURES)
    return ColumnTransformer([
        ("cat", OneHotEncoder(handle_unknown="infrequent_if_exist", min_frequency=5, sparse_output=False), list(range(n_cat))),
        ("num", FunctionTransformer(to_float), list(range(n_cat, len(FEATURES)))),
    ])


def _hgb_params() -> dict:
    return {"max_iter": 300, "learning_rate": 0.05, "max_leaf_nodes": 31, "min_samples_leaf": 20,
            "l2_regularization": 1.0, "early_stopping": False, "random_state": SEED}


def _outcome_time(rec: dict, target: str):
    if target == "hours" or rec["resolved_at"]:
        return rec["resolved_at"]
    return rec["due_at"]  # open tickets past their deadline: breach known since due_at


def temporal_split(rows: list[dict], target: str) -> tuple[list[dict], list[dict], datetime]:
    rows = sorted(rows, key=lambda r: (r["created_at"], r["id"]))
    cut = int(len(rows) * (1 - TEST_FRACTION))
    cut_time = rows[cut]["created_at"]
    # Only outcomes already known at the cut-off may be used for training (no look-ahead).
    train = [r for r in rows[:cut] if _outcome_time(r, target) and _outcome_time(r, target) <= cut_time]
    return train, rows[cut:], cut_time


def reference_values(xs: list[dict]) -> dict:
    ref = {}
    for f in CAT_FEATURES:
        ref[f] = Counter(x[f] for x in xs).most_common(1)[0][0]
    for f in NUM_FEATURES:
        ref[f] = float(median(float(x[f]) for x in xs))
    return ref


def _importance(pipe, X, y, scoring) -> list[dict]:
    result = permutation_importance(pipe, X, y, n_repeats=5, random_state=SEED, scoring=scoring, n_jobs=1)
    pairs = sorted(zip(FEATURES, result.importances_mean), key=lambda p: -p[1])
    return [{"feature": f, "label": FEATURE_LABELS.get(f, f), "importance": round(float(v), 4)} for f, v in pairs[:10]]


def _insufficient(message: str, **extra) -> dict:
    return {"status": "insufficient_data", "message": message, **extra}


def _evenly(items: list, limit: int) -> list:
    if len(items) <= limit:
        return items
    step = len(items) / limit
    return [items[int(i * step)] for i in range(limit)]


def train_resolution(records: list[dict]) -> tuple[dict, Pipeline | None, dict | None]:
    rows = [r for r in records if r["y_hours"] is not None]
    if len(rows) < MIN_RESOLUTION:
        return _insufficient(f"Se necesitan al menos {MIN_RESOLUTION} tickets resueltos (hay {len(rows)})."), None, None
    train, test, cut = temporal_split(rows, "hours")
    if len(train) < MIN_RESOLUTION * 0.6 or len(test) < 30:
        return _insufficient("No hay suficientes tickets resueltos en los periodos de entrenamiento y evaluación."), None, None
    Xtr, ytr = matrix([r["x"] for r in train]), np.log1p([r["y_hours"] for r in train])
    Xte, yte = matrix([r["x"] for r in test]), np.array([r["y_hours"] for r in test])
    pipe = Pipeline([("prep", _preprocessor()), ("model", HistGradientBoostingRegressor(**_hgb_params()))]).fit(Xtr, ytr)
    pred = np.clip(np.expm1(pipe.predict(Xte)), 0.01, None)

    by_prio = defaultdict(list)
    for r in train:
        by_prio[r["priority"]].append(r["y_hours"])
    global_median = float(median(r["y_hours"] for r in train))
    base = np.array([median(by_prio[r["priority"]]) if by_prio.get(r["priority"]) else global_median for r in test])
    mae, mae_base = M.mean_absolute_error(yte, pred), M.mean_absolute_error(yte, base)
    per_priority = []
    for code in PRIORITY_ORDER:
        idx = [i for i, r in enumerate(test) if r["priority"] == code]
        if idx:
            per_priority.append({"priority": code, "n": len(idx), "mae_hours": round(float(np.mean(np.abs(pred[idx] - yte[idx]))), 2),
                                 "median_actual_hours": round(float(np.median(yte[idx])), 2)})
    metrics = {
        "mae_hours": round(float(mae), 2), "median_ae_hours": round(float(M.median_absolute_error(yte, pred)), 2),
        "baseline_mae_hours": round(float(mae_base), 2), "baseline": "Mediana histórica por prioridad",
        "improvement_vs_baseline_pct": round((1 - mae / mae_base) * 100, 1) if mae_base else None,
        "rmse_hours": round(float(np.sqrt(M.mean_squared_error(yte, pred))), 2),
        "r2_hours": round(float(M.r2_score(yte, pred)), 3),
        "r2_log": round(float(M.r2_score(np.log1p(yte), np.log1p(pred))), 3),
        "within_50pct": round(float(np.mean(np.abs(pred - yte) <= 0.5 * yte)), 3),
        "per_priority": per_priority,
    }
    scatter = _evenly([{"actual": round(float(a), 2), "predicted": round(float(p), 2), "priority": r["priority"]}
                       for a, p, r in zip(yte, pred, test)], 400)
    importance = _importance(pipe, Xte, np.log1p(yte), "neg_mean_absolute_error")

    final = Pipeline([("prep", _preprocessor()), ("model", HistGradientBoostingRegressor(**_hgb_params()))])
    final.fit(matrix([r["x"] for r in rows]), np.log1p([r["y_hours"] for r in rows]))
    result = {"status": "trained", "algorithm": "HistGradientBoostingRegressor (objetivo log-horas)",
              "headline": f"MAE {metrics['mae_hours']} h (referencia {metrics['baseline_mae_hours']} h)",
              "n_train": len(train), "n_test": len(test), "n_final": len(rows), "cutoff": cut.isoformat(),
              "test_period": {"from": test[0]["created_at"].isoformat(), "to": test[-1]["created_at"].isoformat()},
              "metrics": metrics, "importance": importance, "scatter": scatter}
    bundle = {"pipeline": final, "features": FEATURES, "reference": reference_values([r["x"] for r in rows])}
    return result, pipe, bundle


def train_sla(records: list[dict]) -> tuple[dict, Pipeline | None, dict | None]:
    rows = [r for r in records if r["y_breach"] is not None]
    positives = sum(r["y_breach"] for r in rows)
    if len(rows) < MIN_SLA or positives < MIN_CLASS or len(rows) - positives < MIN_CLASS:
        return _insufficient(f"Se necesitan {MIN_SLA} tickets con resultado SLA conocido y al menos {MIN_CLASS} de cada clase "
                             f"(hay {len(rows)}; incumplidos {positives})."), None, None
    train, test, cut = temporal_split(rows, "breach")
    ytr, yte = np.array([r["y_breach"] for r in train]), np.array([r["y_breach"] for r in test])
    if len(set(ytr)) < 2 or len(set(yte)) < 2 or len(test) < 30:
        return _insufficient("El periodo de entrenamiento o de evaluación no contiene ambas clases (cumple / incumple)."), None, None
    Xtr, Xte = matrix([r["x"] for r in train]), matrix([r["x"] for r in test])
    params = {**_hgb_params(), "class_weight": "balanced"}
    pipe = Pipeline([("prep", _preprocessor()), ("model", HistGradientBoostingClassifier(**params))]).fit(Xtr, ytr)
    proba = pipe.predict_proba(Xte)[:, 1]
    pred = (proba >= 0.5).astype(int)
    base_pred = np.array([1 if r["priority"] in {"ALTA", "CRITICA"} else 0 for r in test])
    tn, fp, fn, tp = M.confusion_matrix(yte, pred, labels=[0, 1]).ravel()
    metrics = {
        "precision": round(float(M.precision_score(yte, pred, zero_division=0)), 3),
        "recall": round(float(M.recall_score(yte, pred, zero_division=0)), 3),
        "f1": round(float(M.f1_score(yte, pred, zero_division=0)), 3),
        "roc_auc": round(float(M.roc_auc_score(yte, proba)), 3),
        "accuracy": round(float(M.accuracy_score(yte, pred)), 3),
        "threshold": 0.5, "positive_rate_test": round(float(yte.mean()), 3),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "baseline": "Regla: prioridad ALTA o CRÍTICA = riesgo",
        "baseline_precision": round(float(M.precision_score(yte, base_pred, zero_division=0)), 3),
        "baseline_recall": round(float(M.recall_score(yte, base_pred, zero_division=0)), 3),
        "baseline_f1": round(float(M.f1_score(yte, base_pred, zero_division=0)), 3),
    }
    # Reliability: observed breach rate per predicted-probability bucket.
    calibration = []
    for lo in np.arange(0, 1, 0.2):
        idx = (proba >= lo) & (proba < lo + 0.2 + (1e-9 if lo >= 0.8 else 0))
        if idx.any():
            calibration.append({"bucket": f"{int(lo * 100)}–{int(lo * 100 + 20)} %", "n": int(idx.sum()),
                                "predicted": round(float(proba[idx].mean()), 3), "observed": round(float(yte[idx].mean()), 3)})
    importance = _importance(pipe, Xte, yte, "roc_auc")
    final = Pipeline([("prep", _preprocessor()), ("model", HistGradientBoostingClassifier(**params))])
    final.fit(matrix([r["x"] for r in rows]), np.array([r["y_breach"] for r in rows]))
    result = {"status": "trained", "algorithm": "HistGradientBoostingClassifier (clases balanceadas)",
              "headline": f"F1 {metrics['f1']} · recall {metrics['recall']} · AUC {metrics['roc_auc']}",
              "n_train": len(train), "n_test": len(test), "n_final": len(rows), "cutoff": cut.isoformat(),
              "test_period": {"from": test[0]["created_at"].isoformat(), "to": test[-1]["created_at"].isoformat()},
              "metrics": metrics, "calibration": calibration, "importance": importance}
    bundle = {"pipeline": final, "features": FEATURES, "reference": reference_values([r["x"] for r in rows])}
    return result, pipe, bundle


def priority_matrix(records: list[dict]) -> np.ndarray:
    return np.array([[normalize_text(f"{r['title']} {r['description']}"), r["area"], r["category"]] for r in records], dtype=object)


def _priority_pipeline() -> Pipeline:
    prep = ColumnTransformer([
        ("text", TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=6000, sublinear_tf=True), 0),
        ("cat", OneHotEncoder(handle_unknown="ignore"), [1, 2]),
    ])
    return Pipeline([("prep", prep), ("model", LogisticRegression(max_iter=2000, class_weight="balanced", C=2.0, random_state=SEED))])


def train_priority(records: list[dict]) -> tuple[dict, dict | None]:
    rows = sorted(records, key=lambda r: (r["created_at"], r["id"]))
    counts = Counter(r["priority"] for r in rows)
    if len(rows) < MIN_PRIORITY or sum(1 for v in counts.values() if v >= 10) < 2:
        return _insufficient(f"Se necesitan al menos {MIN_PRIORITY} tickets y dos prioridades con 10 casos (hay {len(rows)})."), None
    cut = int(len(rows) * (1 - TEST_FRACTION))
    train, test = rows[:cut], rows[cut:]
    ytr, yte = [r["priority"] for r in train], [r["priority"] for r in test]
    if len(set(ytr)) < 2:
        return _insufficient("El periodo de entrenamiento solo contiene una prioridad."), None
    pipe = _priority_pipeline().fit(priority_matrix(train), ytr)
    pred = pipe.predict(priority_matrix(test))
    labels = [p for p in PRIORITY_ORDER if p in set(ytr) | set(yte)]
    by_cat = defaultdict(Counter)
    for r in train:
        by_cat[r["category"]][r["priority"]] += 1
    overall = Counter(ytr).most_common(1)[0][0]
    base = [by_cat[r["category"]].most_common(1)[0][0] if by_cat.get(r["category"]) else overall for r in test]
    p, rc, f, s = M.precision_recall_fscore_support(yte, pred, labels=labels, zero_division=0)
    metrics = {
        "accuracy": round(float(M.accuracy_score(yte, pred)), 3),
        "macro_precision": round(float(np.mean(p)), 3), "macro_recall": round(float(np.mean(rc)), 3),
        "macro_f1": round(float(np.mean(f)), 3),
        "baseline": "Prioridad más frecuente de la categoría",
        "baseline_accuracy": round(float(M.accuracy_score(yte, base)), 3),
        "baseline_macro_f1": round(float(M.f1_score(yte, base, labels=labels, average="macro", zero_division=0)), 3),
        "per_class": [{"priority": lab, "precision": round(float(a), 3), "recall": round(float(b), 3), "f1": round(float(c), 3), "n": int(d)}
                      for lab, a, b, c, d in zip(labels, p, rc, f, s)],
        "confusion": {"labels": labels, "matrix": M.confusion_matrix(yte, pred, labels=labels).tolist()},
    }
    final = _priority_pipeline().fit(priority_matrix(rows), [r["priority"] for r in rows])
    result = {"status": "trained", "algorithm": "TF-IDF + regresión logística (texto, área y categoría)",
              "headline": f"F1 macro {metrics['macro_f1']} (referencia {metrics['baseline_macro_f1']})",
              "n_train": len(train), "n_test": len(test), "n_final": len(rows),
              "test_period": {"from": test[0]["created_at"].isoformat(), "to": test[-1]["created_at"].isoformat()},
              "metrics": metrics}
    return result, {"pipeline": final, "labels": labels}


def backtest_recommender(records: list[dict], techs: dict, reg: Pipeline, cls: Pipeline, cut: datetime) -> dict:
    """Observational backtest: would the recommender have picked technicians that did better?"""
    test = [r for r in records if r["created_at"] >= cut and r["technician_id"] and r["y_hours"] is not None
            and r["y_breach"] is not None and "_snap" in r][-600:]
    if len(test) < 30:
        return _insufficient("No hay suficientes tickets resueltos en el periodo de evaluación para el backtest.")
    rows, owners = [], []
    for i, r in enumerate(test):
        for tid in candidate_technicians(r, techs, only_available=False):
            open_, mean_h, rate = r["_snap"].get(tid, (0, r["x"]["tech_hist_hours"], r["x"]["tech_hist_breach"]))
            x = dict(r["x"], technician=tid, tech_open=open_, tech_hist_hours=mean_h, tech_hist_breach=rate,
                     tech_specialty_match=1.0 if not r["specialty_id"] or r["specialty_id"] in techs[tid]["specialties"] else 0.0)
            rows.append(x)
            owners.append((i, tid))
    X = matrix(rows)
    probs, hours = cls.predict_proba(X)[:, 1], np.expm1(reg.predict(X))
    ranking = defaultdict(list)
    for (i, tid), p, h in zip(owners, probs, hours):
        ranking[i].append((round(float(p), 3), float(h), tid))
    top1 = top3 = 0
    matched_h, other_h, matched_b, other_b = [], [], [], []
    for i, r in enumerate(test):
        ranked = [tid for _, _, tid in sorted(ranking[i])]
        if ranked and ranked[0] == r["technician_id"]:
            top1 += 1
            matched_h.append(r["y_hours"])
            matched_b.append(r["y_breach"])
        else:
            other_h.append(r["y_hours"])
            other_b.append(r["y_breach"])
        top3 += r["technician_id"] in ranked[:3]
    mean = lambda v: round(float(np.mean(v)), 2) if v else None
    return {"status": "trained", "headline": f"Coincidencia top-3 {top3 / len(test):.0%}",
            "algorithm": "Ranking por riesgo SLA y tiempo estimado (modelos de resolución y SLA) con filtro de especialidad y carga",
            "metrics": {"n": len(test), "avg_candidates": round(len(rows) / len(test), 2), "top1_match_rate": round(top1 / len(test), 3), "top3_match_rate": round(top3 / len(test), 3),
                        "avg_hours_when_top1_assigned": mean(matched_h), "avg_hours_otherwise": mean(other_h),
                        "breach_rate_when_top1_assigned": mean(matched_b), "breach_rate_otherwise": mean(other_b)},
            "note": "Backtest observacional: compara tickets cuyo técnico real coincidió con la recomendación frente al resto. "
                    "No es un experimento controlado; la coincidencia top-3 depende del número de candidatos por especialidad."}


def data_summary(records: list[dict]) -> dict:
    synthetic = sum(1 for r in records if r["synthetic"])
    total = len(records)
    share = synthetic / total if total else 0.0
    source = "sin datos" if not total else ("sintético" if share >= 0.99 else ("real" if synthetic == 0 else "mixto"))
    return {"tickets_used": total, "synthetic": synthetic, "real": total - synthetic, "synthetic_share": round(share, 4),
            "source": source, "resolved": sum(1 for r in records if r["y_hours"] is not None),
            "sla_labelled": sum(1 for r in records if r["y_breach"] is not None),
            "first_created": min(r["created_at"] for r in records).isoformat() if records else None,
            "last_created": max(r["created_at"] for r in records).isoformat() if records else None}


def train_all(db: Session, include_synthetic: bool = True, actor_name: str | None = None) -> dict:
    if not store.TRAIN_LOCK.acquire(blocking=False):
        raise TrainingInProgress("Ya hay un entrenamiento en curso. Espere a que termine.")
    try:
        started = datetime.now(UTC)
        techs = load_technicians(db)
        records = load_records(db, include_synthetic=include_synthetic)
        build_features(records, techs, started, snapshot=True)
        models: dict[str, dict] = {}

        res_result, res_eval, res_bundle = train_resolution(records)
        sla_result, sla_eval, sla_bundle = train_sla(records)
        prio_result, prio_bundle = train_priority(records)
        fc_result = train_forecast(records) if records else _insufficient("No hay tickets.")
        models.update({"resolution": res_result, "sla_risk": sla_result, "priority": prio_result, "forecast": fc_result})
        if res_eval is not None and sla_eval is not None:
            cut = min(datetime.fromisoformat(res_result["cutoff"]), datetime.fromisoformat(sla_result["cutoff"]))
            models["recommendation"] = backtest_recommender(records, techs, res_eval, sla_eval, cut)
        else:
            models["recommendation"] = _insufficient("Requiere los modelos de resolución y de riesgo SLA entrenados.")

        version = f"fixit-ml-{started:%Y%m%d-%H%M%S}"
        bundles = {"resolution": res_bundle, "sla_risk": sla_bundle, "priority": prio_bundle,
                   "forecast": dict(fc_result) if fc_result.get("status") == "trained" else None}
        for bundle in bundles.values():
            if bundle is not None:
                bundle.update({"version": version, "trained_at": started.isoformat()})

        meta = {"format": store.FORMAT_VERSION, "version": version, "trained_at": started.isoformat(), "trained_by": actor_name,
                "duration_seconds": round((datetime.now(UTC) - started).total_seconds(), 2),
                "include_synthetic": include_synthetic, "data": data_summary(records),
                "split": {"method": "temporal", "test_fraction": TEST_FRACTION,
                          "rule": "Entrena con el 80 % más antiguo cuyo resultado ya se conocía en la fecha de corte; evalúa con el 20 % más reciente."},
                "libraries": {"scikit-learn": sklearn.__version__, "numpy": np.__version__},
                "models": {k: {kk: vv for kk, vv in v.items() if kk not in {"history_daily", "history_weekly", "holdout", "forecast_daily",
                                                                           "forecast_weekly", "by_category"}}
                           for k, v in models.items()}}
        store.persist(db, bundles, meta)
        return meta
    finally:
        store.TRAIN_LOCK.release()


def ensure_ready(db: Session) -> str:
    """Startup: load the stored models; train them only when they are missing, altered or
    incompatible with this version (or nothing could be trained before and there are new tickets)."""
    meta = store.restore(db)
    include = meta.get("include_synthetic", True) if meta else True
    if meta:
        nothing_trained = all(m.get("status") != "trained" for m in meta["models"].values())
        if not nothing_trained or len(load_records(db, include_synthetic=include)) <= meta["data"]["tickets_used"]:
            return "loaded"
    train_all(db, include_synthetic=include, actor_name="Arranque automático")
    return "trained"
