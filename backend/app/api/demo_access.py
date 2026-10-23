"""DEMO_ACCESS_TEMPORARY: endpoints of the "Accesos de demostración" panel. Both answer 404 unless
DEMO_ACCESS_ENABLED=true. The session issued is the regular JWT pair, so routes and permissions are the real ones."""
import secrets
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload
from app.api.router import user_data
from app.core.config import settings
from app.core.database import get_db
from app.models import Role, Technician, User
from app.schemas import TokenOut
from app.security.auth import create_token, hash_password
from app.security.demo_access import DEMO_ACCOUNTS
from app.services.audit import audit

demo_api = APIRouter(prefix="/api/auth/demo")


def require_enabled():
    if not settings.demo_access_enabled: raise HTTPException(404, "No encontrado")


def demo_user(db: Session, role_code: str) -> User:
    spec = DEMO_ACCOUNTS[role_code]
    query = db.query(User).options(joinedload(User.role)).filter(User.email == spec["email"])
    user = query.first()
    if user: return user
    # Random password nobody knows: the account is reachable only through this endpoint.
    user = User(full_name=spec["full_name"], email=spec["email"], password_hash=hash_password(secrets.token_urlsafe(32)),
                role_id=db.query(Role).filter_by(code=role_code).one().id)
    db.add(user)
    try:
        db.flush()
        if role_code == "TECNICO":
            # Not available: automatic assignment never routes real tickets to the demo technician.
            db.add(Technician(user_id=user.id, available=False))
        audit(db, None, "CREAR_DEMO", "AUTH", "USER", user.id, new={"email": user.email, "role": role_code})
        db.commit()
    except IntegrityError:
        db.rollback()  # created concurrently by another request
    return query.one()


@demo_api.get("", dependencies=[Depends(require_enabled)])
def demo_roles():
    return {"enabled": True, "roles": [{"role": code, "label": x["label"], "description": x["description"]} for code, x in DEMO_ACCOUNTS.items()]}


@demo_api.post("/{role_code}", response_model=TokenOut, dependencies=[Depends(require_enabled)])
def demo_login(role_code: str, request: Request, db: Session = Depends(get_db)):
    if role_code not in DEMO_ACCOUNTS: raise HTTPException(404, "Acceso de demostración no disponible")
    user = demo_user(db, role_code)
    if not user.active or user.role.code != role_code:
        raise HTTPException(409, "La cuenta de demostración fue desactivada o modificada")
    audit(db, user.id, "LOGIN_DEMO", "AUTH", "USER", user.id, request=request); db.commit()
    return {"access_token": create_token(user, "access"), "refresh_token": create_token(user, "refresh"), "user": user_data(user)}
