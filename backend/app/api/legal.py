"""Terms of use and privacy notice (content in app.legal) and the express acceptance of the terms.

Acceptance is only recorded when the user asks for it (registration form or the "Aceptar" button); reading the
privacy notice is never treated as consent.
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.legal import DOCUMENTS, public_documents
from app.models import TermsAcceptance, User
from app.schemas import AcceptanceIn
from app.security.auth import current_user
from app.security.hardening import client_ip
from app.services.audit import audit, iso

legal_api = APIRouter(prefix="/api/legal", tags=["legal"])


@legal_api.get("")
def documents():
    return public_documents()


def record_acceptance(db: Session, user: User, document: str, version: str, request: Request | None) -> TermsAcceptance:
    """Validate and add an acceptance of the current version of ``document`` (caller commits)."""
    doc = DOCUMENTS.get(document)
    if not doc or not doc["requires_acceptance"]: raise HTTPException(422, "Este documento no requiere aceptación")
    if version != doc["version"]: raise HTTPException(409, f"La versión vigente es {doc['version']}; vuelve a cargar la página")
    row = TermsAcceptance(user_id=user.id, document=document, version=version, accepted_at=datetime.now(timezone.utc),
                          ip=client_ip(request), user_agent=(request.headers.get("user-agent") or "")[:500] if request else None)
    db.add(row)
    audit(db, user.id, "ACEPTAR_TERMINOS", "LEGAL", "TERMS", None, new={"documento": document, "version": version}, request=request)
    return row


def acceptance_data(db: Session, user: User) -> dict:
    rows = db.query(TermsAcceptance).filter_by(user_id=user.id).order_by(TermsAcceptance.accepted_at.desc()).all()
    accepted = [{"document": r.document, "version": r.version, "accepted_at": iso(r.accepted_at)} for r in rows]
    pending = [{"document": d["id"], "title": d["title"], "version": d["version"]} for d in DOCUMENTS.values()
               if d["requires_acceptance"] and not any(a["document"] == d["id"] and a["version"] == d["version"] for a in accepted)]
    return {"accepted": accepted, "pending": pending}


@legal_api.get("/acceptances")
def my_acceptances(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return acceptance_data(db, user)


@legal_api.post("/acceptances", status_code=201)
def accept(payload: AcceptanceIn, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if db.query(TermsAcceptance).filter_by(user_id=user.id, document=payload.document, version=payload.version).first():
        return acceptance_data(db, user)
    record_acceptance(db, user, payload.document, payload.version, request)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()  # accepted concurrently from another tab
    return acceptance_data(db, user)
