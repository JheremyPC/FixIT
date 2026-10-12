"""Machine Learning endpoints. Restricted to ADMIN and JEFE_TI (training, predictions, analytics)."""
import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.ml import insights as ml_insights
from app.ml import predictor
from app.ml.dataset import FEATURES, build_features, load_records, load_technicians
from app.ml.training import TrainingInProgress, train_all
from app.models import User
from app.schemas import PredictIn, TrainIn
from app.security.auth import require_roles
from app.services.audit import audit

ml_api = APIRouter(prefix="/api/ml", tags=["machine-learning"])
ml_roles = require_roles("ADMIN", "JEFE_TI")
SOURCE = Query("all", pattern="^(all|real|synthetic)$")
PRIORITY = Query(None, pattern="^[A-Z_]{2,20}$")


def _not_trained(exc: Exception):
    raise HTTPException(409, str(exc))


def _filters(area_id, category_id, priority, technician_id, source) -> dict:
    return {"area_id": area_id, "category_id": category_id, "priority": priority, "technician_id": technician_id, "source": source}


@ml_api.get("/status")
def status(_: User = Depends(ml_roles), db: Session = Depends(get_db)):
    return predictor.status(db)


@ml_api.post("/train")
def train(payload: TrainIn, request: Request, actor: User = Depends(ml_roles), db: Session = Depends(get_db)):
    try:
        meta = train_all(db, include_synthetic=payload.include_synthetic, actor_name=actor.full_name)
    except TrainingInProgress as exc:
        raise HTTPException(409, str(exc))
    audit(db, actor.id, "ENTRENAR", "IA", "ML_MODEL", None, new={"version": meta["version"], "source": meta["data"]["source"],
                                                                  "tickets": meta["data"]["tickets_used"]}, request=request)
    db.commit()
    return meta


@ml_api.get("/predictions")
def predictions(area_id: str | None = None, category_id: str | None = None, priority: str | None = PRIORITY,
                technician_id: str | None = None, source: str = SOURCE, limit: int = Query(50, ge=1, le=200),
                _: User = Depends(ml_roles), db: Session = Depends(get_db)):
    try:
        return predictor.open_predictions(db, _filters(area_id, category_id, priority, technician_id, source), limit)
    except predictor.ModelNotTrained as exc:
        _not_trained(exc)


@ml_api.get("/tickets/{ticket_id}")
def ticket(ticket_id: str, _: User = Depends(ml_roles), db: Session = Depends(get_db)):
    try:
        return predictor.ticket_prediction(db, ticket_id)
    except predictor.ModelNotTrained as exc:
        _not_trained(exc)
    except LookupError:
        raise HTTPException(404, "Ticket no encontrado")


@ml_api.post("/predict")
def predict(payload: PredictIn, _: User = Depends(ml_roles), db: Session = Depends(get_db)):
    try:
        return predictor.predict_new(db, payload.model_dump())
    except predictor.ModelNotTrained as exc:
        _not_trained(exc)
    except LookupError as exc:
        raise HTTPException(422, str(exc))


@ml_api.get("/recommendations")
def recommendations(limit: int = Query(30, ge=1, le=100), _: User = Depends(ml_roles), db: Session = Depends(get_db)):
    try:
        return predictor.recommendations(db, limit)
    except predictor.ModelNotTrained as exc:
        _not_trained(exc)


@ml_api.get("/forecast")
def forecast(_: User = Depends(ml_roles)):
    try:
        return predictor.forecast()
    except predictor.ModelNotTrained as exc:
        _not_trained(exc)


@ml_api.get("/insights")
def insights(period: str = Query("month", pattern="^(day|week|month)$"), days: int = Query(365, ge=0, le=1825),
             area_id: str | None = None, category_id: str | None = None, priority: str | None = PRIORITY,
             technician_id: str | None = None, source: str = SOURCE, _: User = Depends(ml_roles), db: Session = Depends(get_db)):
    return ml_insights.insights(db, _filters(area_id, category_id, priority, technician_id, source), period, days)


@ml_api.get("/dataset.csv")
def dataset_csv(source: str = SOURCE, _: User = Depends(ml_roles), db: Session = Depends(get_db)):
    """Leakage-free feature table with targets, ready for external analysis (no personal data)."""
    techs = load_technicians(db)
    records = load_records(db, include_synthetic=source != "real")
    build_features(records, techs)
    if source == "synthetic":
        records = [r for r in records if r["synthetic"]]
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["number", "synthetic", "created_at", "state", *FEATURES, "target_resolution_hours", "target_sla_breach"])
    for r in records:
        x = r["x"]
        writer.writerow([r["number"], int(r["synthetic"]), r["created_at"].isoformat(), r["state"],
                         *[techs.get(x[f], {}).get("name", x[f]) if f == "technician" else x[f] for f in FEATURES],
                         round(r["y_hours"], 3) if r["y_hours"] is not None else "", "" if r["y_breach"] is None else r["y_breach"]])
    return StreamingResponse(iter([out.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=fixit-ml-dataset.csv"})
