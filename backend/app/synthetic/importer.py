"""Import / purge synthetic data with a hard guard against remote databases.

Safety rules (see docs/datos-sinteticos.md):
* Only local databases are accepted by default (SQLite or PostgreSQL on localhost / the
  docker-compose ``db`` service). Supabase, Render and any other host are rejected.
* Writing to any other destination requires the separate ``import-remote`` command, the
  exact host typed again in ``--confirm-host`` and ``FIXIT_ALLOW_REMOTE_SYNTHETIC=1``.
* Synthetic rows are identified by the ``SYN-`` ticket prefix and the
  ``@sintetico.fixit.example`` e-mail domain. Purging only touches those rows; real tickets
  are never deleted.
* Where Supabase's automation triggers exist, demo rows must not enqueue automation events
  (notifications/audit entries for fake activity): the import requires migration
  0002_skip_synthetic_automation and turns its flag on only inside the import transaction.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from sqlalchemy import Engine, delete, func, insert, select, text, update
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.core.database import Base
from app.models import (Area, AuditLog, Category, Notification, Priority, Rating, Role, Setting, Specialty, Technician,
                        TechnicianSpecialty, Ticket, TicketAssignment, TicketAttachment, TicketComment, TicketHistory,
                        TicketState, User)
from app.services.audit import sealed_fields
from app.synthetic import catalog as C
from app.synthetic.generator import SyntheticDataset

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "db", "postgres", "fixit-db", "host.docker.internal"}
REMOTE_MARKERS = ("supabase.", "render.com", "amazonaws.com", "azure.com", "neon.tech", "railway.app", "elephantsql",
                  "googleapis.com", "aivencloud.com", "digitalocean")
BATCH = 1000
AUTOMATION_FUNCTION = "fixit_enqueue_automation_event"
AUTOMATION_SKIP_SETTING = "fixit.synthetic_import"  # see migrations/versions/0002_skip_synthetic_automation.py


class UnsafeTargetError(RuntimeError):
    pass


class SyntheticDataExists(RuntimeError):
    pass


class AutomationGuardMissing(RuntimeError):
    pass


def describe_target(url: str) -> dict:
    """Classify a database URL as local or remote without exposing credentials."""
    parsed = make_url(url)
    backend = parsed.get_backend_name()
    if backend == "sqlite":
        return {"backend": backend, "host": "sqlite-file", "local": True, "safe_url": parsed.render_as_string(hide_password=True)}
    host = (parsed.host or "").lower()
    extra = {h.strip().lower() for h in os.getenv("FIXIT_LOCAL_DB_HOSTS", "").split(",") if h.strip()}
    remote_marker = any(marker in host for marker in REMOTE_MARKERS)
    local = (host in LOCAL_HOSTS or host in extra) and not remote_marker
    return {"backend": backend, "host": host or "(sin host)", "local": local, "safe_url": parsed.render_as_string(hide_password=True)}


def assert_local(url: str) -> dict:
    info = describe_target(url)
    if not info["local"]:
        raise UnsafeTargetError(
            f"Destino rechazado: '{info['host']}' no es una base local. Los datos sintéticos solo se importan en "
            "SQLite o PostgreSQL local (localhost / servicio 'db' de docker compose). Para otro destino use el "
            "comando separado 'import-remote' (ver docs/datos-sinteticos.md).")
    return info


def assert_remote_confirmed(url: str, confirm_host: str | None) -> dict:
    info = describe_target(url)
    if info["local"]:
        return info
    if os.getenv("FIXIT_ALLOW_REMOTE_SYNTHETIC") != "1":
        raise UnsafeTargetError("Importación remota bloqueada: defina FIXIT_ALLOW_REMOTE_SYNTHETIC=1 solo para esta ejecución.")
    if not confirm_host or confirm_host.strip().lower() != info["host"]:
        raise UnsafeTargetError(f"Importación remota bloqueada: --confirm-host debe coincidir exactamente con '{info['host']}'.")
    return info


def synthetic_ticket_filter():
    return Ticket.number.like(f"{C.SYNTHETIC_TICKET_PREFIX}%")


def synthetic_user_filter():
    return User.email.like(f"%@{C.SYNTHETIC_EMAIL_DOMAIN}")


def status(engine: Engine) -> dict:
    with Session(engine) as db:
        total = db.scalar(select(func.count()).select_from(Ticket)) or 0
        synthetic = db.scalar(select(func.count()).select_from(Ticket).where(synthetic_ticket_filter())) or 0
        users = db.scalar(select(func.count()).select_from(User).where(synthetic_user_filter())) or 0
        meta = db.get(Setting, C.SYNTHETIC_SETTING_KEY)
        return {"tickets_total": total, "tickets_synthetic": synthetic, "tickets_real": total - synthetic,
                "synthetic_users": users, "dataset": json.loads(meta.value) if meta else None}


def _ensure_base(engine: Engine) -> None:
    """Tables and base catalogs (roles, priorities, states) exactly as the API creates them."""
    Base.metadata.create_all(bind=engine)
    from app.services.seed import seed

    with Session(engine) as db:
        seed(db)


def _automation_guard_required(engine: Engine) -> bool:
    """True when the automation trigger exists and honours the skip flag; raises if it exists without it."""
    if engine.dialect.name != "postgresql":
        return False
    with engine.connect() as conn:
        body = conn.scalar(text("SELECT prosrc FROM pg_proc WHERE oid = to_regprocedure(:sig)"),
                           {"sig": f"{AUTOMATION_FUNCTION}()"})
    if body is None:
        return False  # no automation triggers (local databases created by Alembic)
    if AUTOMATION_SKIP_SETTING not in body:
        raise AutomationGuardMissing(
            f"La base tiene {AUTOMATION_FUNCTION}() sin la protección para datos sintéticos: la importación generaría "
            "miles de eventos de automatización. Aplique antes la migración 0002_skip_synthetic_automation "
            "(alembic upgrade head). No se escribió nada.")
    return True


def _get_or_create(db: Session, model, name: str, **extra):
    item = db.scalar(select(model).where(model.name == name))
    if item:
        return item
    item = model(name=name, **extra)
    db.add(item)
    db.flush()
    return item


def purge(engine: Engine) -> dict:
    """Delete synthetic tickets and their children. Real tickets are never touched."""
    with Session(engine) as db, db.begin():
        return _purge(db)


def _purge(db: Session) -> dict:
    syn_ids = select(Ticket.id).where(synthetic_ticket_filter()).scalar_subquery()
    removed = {}
    for model in (Rating, TicketComment, TicketHistory, TicketAssignment, TicketAttachment, Notification):
        removed[model.__tablename__] = db.execute(delete(model).where(model.ticket_id.in_(syn_ids))).rowcount
    removed["tickets"] = db.execute(delete(Ticket).where(synthetic_ticket_filter())).rowcount

    deactivated = deleted = 0
    for user in db.scalars(select(User).where(synthetic_user_filter())).all():
        db.execute(delete(Notification).where(Notification.user_id == user.id))
        tech = db.scalar(select(Technician).where(Technician.user_id == user.id))
        refs = [
            select(func.count()).select_from(Ticket).where(Ticket.requester_id == user.id),
            select(func.count()).select_from(TicketComment).where(TicketComment.author_id == user.id),
            select(func.count()).select_from(TicketHistory).where(TicketHistory.actor_id == user.id),
            select(func.count()).select_from(Rating).where(Rating.user_id == user.id),
            select(func.count()).select_from(TicketAttachment).where(TicketAttachment.uploader_id == user.id),
            select(func.count()).select_from(TicketAssignment).where(TicketAssignment.assigned_by_id == user.id),
            select(func.count()).select_from(AuditLog).where(AuditLog.user_id == user.id),
        ]
        if tech:
            refs += [select(func.count()).select_from(Ticket).where(Ticket.technician_id == tech.id),
                     select(func.count()).select_from(TicketAssignment).where(TicketAssignment.technician_id == tech.id),
                     select(func.count()).select_from(Rating).where(Rating.technician_id == tech.id)]
        if any(db.scalar(q) for q in refs):
            # Still referenced by real activity (e.g. someone logged in with a demo account): keep, but disable.
            user.active = False
            if tech:
                tech.available = False
            deactivated += 1
            continue
        if tech:
            db.execute(delete(TechnicianSpecialty).where(TechnicianSpecialty.technician_id == tech.id))
            db.delete(tech)
            db.flush()
        db.delete(user)
        deleted += 1
    db.execute(delete(Setting).where(Setting.key == C.SYNTHETIC_SETTING_KEY))
    removed.update({"users_deleted": deleted, "users_deactivated": deactivated})
    return removed


def import_dataset(engine: Engine, ds: SyntheticDataset, replace: bool = False) -> dict:
    skip_automation = _automation_guard_required(engine)  # checked before any write
    _ensure_base(engine)
    from app.security.auth import hash_password

    password_hash = hash_password(os.getenv("FIXIT_SYNTHETIC_PASSWORD", "Demo!2026"))
    with Session(engine) as db, db.begin():
        if skip_automation:
            # is_local=true: the flag ends with this transaction; the trigger still requires a SYN- ticket.
            db.execute(text("SELECT set_config(:key, 'on', true)"), {"key": AUTOMATION_SKIP_SETTING})
        existing = db.scalar(select(func.count()).select_from(Ticket).where(synthetic_ticket_filter())) or 0
        purged = None
        if existing:
            if not replace:
                raise SyntheticDataExists(f"Ya existen {existing} tickets sintéticos. Use --replace para regenerarlos "
                                          "(solo se eliminan registros SYN-; los tickets reales no se tocan).")
            purged = _purge(db)

        roles = {r.code: r.id for r in db.scalars(select(Role)).all()}
        priorities = {p.code: p.id for p in db.scalars(select(Priority)).all()}
        states = {s.code: s.id for s in db.scalars(select(TicketState)).all()}
        missing = [code for code in C.PRIORITY_CODES if code not in priorities]
        if missing:
            raise RuntimeError(f"Faltan prioridades base: {missing}")

        areas = {name: _get_or_create(db, Area, name).id for name in C.AREAS}
        specialties = {name: _get_or_create(db, Specialty, name, description=desc).id for name, desc in C.SPECIALTIES.items()}
        categories = {}
        for name, (specialty, *_rest) in C.CATEGORIES.items():
            categories[name] = _get_or_create(db, Category, name, description=f"Categoría de {specialty.lower()}",
                                              specialty_id=specialties[specialty]).id

        start = min(t["created_at"] for t in ds.tickets)
        user_ids: dict[str, str] = {}
        for person in ds.requesters:
            user = db.scalar(select(User).where(User.email == person["email"]))
            if not user:
                user = User(full_name=person["full_name"], email=person["email"], password_hash=password_hash,
                            role_id=roles["USUARIO"], area_id=areas[person["area"]], created_at=start, updated_at=start)
                db.add(user)
            user.active = True
            db.flush()
            user_ids[person["key"]] = user.id
        tech_ids: dict[str, str] = {}
        for person in ds.technicians:
            user = db.scalar(select(User).where(User.email == person["email"]))
            if not user:
                user = User(full_name=person["full_name"], email=person["email"], password_hash=password_hash,
                            role_id=roles["TECNICO"], area_id=areas["Tecnología"], created_at=start, updated_at=start)
                db.add(user)
                db.flush()
            user.active = True
            tech = db.scalar(select(Technician).where(Technician.user_id == user.id))
            if not tech:
                tech = Technician(user_id=user.id)
                db.add(tech)
            tech.available, tech.max_load = person["available"], person["max_load"]
            db.flush()
            linked = set(db.scalars(select(TechnicianSpecialty.specialty_id).where(TechnicianSpecialty.technician_id == tech.id)).all())
            for sp in person["specialties"]:
                if specialties[sp] not in linked:
                    db.add(TechnicianSpecialty(technician_id=tech.id, specialty_id=specialties[sp]))
            db.flush()
            user_ids[person["key"]] = user.id
            tech_ids[person["key"]] = tech.id

        ticket_rows = [{
            "id": t["id"], "number": t["number"], "title": t["title"], "description": t["description"],
            "requester_id": user_ids[t["requester_key"]], "technician_id": tech_ids.get(t["technician_key"]),
            "area_id": areas[t["area"]], "category_id": categories[t["category"]], "priority_id": priorities[t["priority"]],
            "state_id": states[t["state"]], "due_at": t["due_at"], "accepted_at": t["accepted_at"], "started_at": t["started_at"],
            "resolved_at": t["resolved_at"], "closed_at": t["closed_at"], "diagnosis": t["diagnosis"], "solution": t["solution"],
            "created_at": t["created_at"], "updated_at": t["updated_at"]} for t in ds.tickets]
        assignment_rows = [{"id": a["id"], "ticket_id": a["ticket_id"], "technician_id": tech_ids[a["technician_key"]],
                            "assigned_by_id": None, "assignment_type": a["assignment_type"], "score": a["score"],
                            "reason": a["reason"], "assigned_at": a["assigned_at"]} for a in ds.assignments]
        history_rows = []
        for h in ds.history:
            new_value = h["new_value"]
            if new_value and "technician_key" in new_value:
                new_value = {"technician_id": tech_ids[new_value["technician_key"]], "score": None}
            history_rows.append({"id": h["id"], "ticket_id": h["ticket_id"], "actor_id": user_ids.get(h["actor_key"]) if h["actor_key"] else None,
                                 "event": h["event"], "detail": h["detail"], "old_value": h["old_value"], "new_value": new_value,
                                 "created_at": h["created_at"]})
        comment_rows = [{"id": c["id"], "ticket_id": c["ticket_id"], "author_id": user_ids[c["author_key"]], "body": c["body"],
                         "internal": c["internal"], "created_at": c["created_at"]} for c in ds.comments]
        rating_rows = [{"id": r["id"], "ticket_id": r["ticket_id"], "technician_id": tech_ids[r["technician_key"]],
                        "user_id": user_ids[r["user_key"]], "score": r["score"], "solved": r["solved"], "comment": r["comment"],
                        "created_at": r["created_at"]} for r in ds.ratings]
        for table, rows in ((Ticket.__table__, ticket_rows), (TicketAssignment.__table__, assignment_rows),
                            (TicketHistory.__table__, history_rows), (TicketComment.__table__, comment_rows),
                            (Rating.__table__, rating_rows)):
            for i in range(0, len(rows), BATCH):
                db.execute(insert(table), rows[i:i + BATCH])

        summary = ds.summary()
        meta = {"params": ds.params, "summary": summary, "imported_at": datetime.now(timezone.utc).isoformat(),
                "marker": {"ticket_prefix": C.SYNTHETIC_TICKET_PREFIX, "email_domain": C.SYNTHETIC_EMAIL_DOMAIN}}
        setting = db.get(Setting, C.SYNTHETIC_SETTING_KEY)
        if setting:
            setting.value = json.dumps(meta, ensure_ascii=False)
        else:
            db.add(Setting(key=C.SYNTHETIC_SETTING_KEY, value=json.dumps(meta, ensure_ascii=False),
                           description="Metadatos del dataset sintético importado (solo entorno local)"))
        db.add(AuditLog(**sealed_fields(None, "IMPORTAR_SINTETICOS", "DATOS", "DATASET", None,
                                        new={"params": ds.params, "tickets": summary["tickets"]}, ip="CLI", user_agent="fixit-synthetic")))
        db.execute(update(User).where(synthetic_user_filter()).values(active=True))
    return {"imported": summary, "purged_before": purged}
