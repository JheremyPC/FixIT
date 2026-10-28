"""Audit trail, ticket history and notifications.

Audit records are append-only (no endpoint updates or deletes them; on PostgreSQL a trigger rejects UPDATE,
DELETE and TRUNCATE, migration 0005). Each record carries a seal: HMAC-SHA256 over its canonical content with
a server-side key, so a record edited directly in the database no longer verifies. The seal detects changes
to a record; it cannot detect a record deleted by someone able to disable the trigger, and it proves nothing
about who wrote the record. See docs/auditoria.md.
"""
import hashlib
import hmac
import json
import re
import uuid
from datetime import datetime, timezone
from fastapi import Request
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models import AuditLog, Notification, TicketHistory
from app.security.hardening import client_ip

SEAL_VERSION = "v1"
REDACTED = "[REDACTADO]"
# Keys whose values never belong in an audit record (passwords, tokens, keys, cookies...).
SENSITIVE_KEY = re.compile(r"pass|contrase|token|secret|clave|api[_-]?key|private[_-]?key|cookie|authori[sz]ation|credential|session", re.I)
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]")
OUTCOMES = ("EXITO", "FALLO", "DENEGADO")
INTEGRITY = {"VALIDO": "Sello válido", "ALTERADO": "El contenido no coincide con su sello",
             "SIN_SELLO": "Registro sin sello (anterior a la versión 0005 o insertado fuera de la aplicación)",
             "CLAVE_DISTINTA": "Sellado con otra clave (p. ej., antes de rotar JWT_SECRET_KEY o AUDIT_HMAC_KEY)"}


def clean_text(value, limit: int | None = None):
    """Control characters (CR, LF, tabs, ANSI escapes...) become visible escapes, so a value cannot forge extra
    lines or records when the trail is read as text, a log or a CSV."""
    if value is None: return None
    text = CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}" if ord(m.group()) < 0x100 else f"\\u{ord(m.group()):04x}", str(value))
    return text[:limit] if limit else text


def redact(value):
    if isinstance(value, dict):
        return {k: REDACTED if SENSITIVE_KEY.search(str(k)) else redact(v) for k, v in value.items()}
    if isinstance(value, list): return [redact(v) for v in value]
    return value


def _jsonable(value):
    # What the JSON column stores and returns, so the seal is computed over exactly the persisted value.
    return None if value is None else json.loads(json.dumps(redact(value), default=str, ensure_ascii=False))


def utc(moment: datetime | None) -> datetime | None:
    if moment is None: return None
    return moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment.astimezone(timezone.utc)


def iso(moment: datetime | None) -> str | None:
    return utc(moment).strftime("%Y-%m-%dT%H:%M:%S.%fZ") if moment else None


def _key() -> bytes:
    if settings.audit_hmac_key and settings.audit_hmac_key.get_secret_value():
        return hashlib.sha256(b"fixit-audit-seal:" + settings.audit_hmac_key.get_secret_value().encode()).digest()
    return hashlib.sha256(b"fixit-audit-seal:" + settings.jwt_secret_key.encode()).digest()


def key_id() -> str:
    """Public fingerprint of the sealing key (not the key): tells which key sealed a record."""
    return hashlib.sha256(b"fixit-audit-key-id:" + _key()).hexdigest()[:8]


def _canonical(fields: dict) -> bytes:
    data = [fields.get(k) for k in ("id", "user_id", "action", "module", "entity", "entity_id", "old_value", "new_value",
                                    "ip", "user_agent", "outcome")] + [iso(fields.get("created_at"))]
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def seal(fields: dict) -> str:
    return f"{SEAL_VERSION}:{key_id()}:{hmac.new(_key(), _canonical(fields), hashlib.sha256).hexdigest()}"


def verify(row: AuditLog) -> str:
    """VALIDO, ALTERADO, SIN_SELLO or CLAVE_DISTINTA (see INTEGRITY)."""
    if not row.integrity_hash: return "SIN_SELLO"
    parts = row.integrity_hash.split(":")
    if len(parts) != 3 or parts[0] != SEAL_VERSION: return "ALTERADO"
    if parts[1] != key_id(): return "CLAVE_DISTINTA"
    fields = {c: getattr(row, c) for c in ("id", "user_id", "action", "module", "entity", "entity_id", "old_value", "new_value",
                                           "ip", "user_agent", "outcome", "created_at")}
    return "VALIDO" if hmac.compare_digest(row.integrity_hash, seal(fields)) else "ALTERADO"


def sealed_fields(user_id: str | None, action: str, module: str, entity: str, entity_id: str | None, old=None, new=None,
                  ip: str | None = None, user_agent: str | None = None, outcome: str = "EXITO") -> dict:
    """Normalized, sealed column values of a new audit record (also used by raw-SQL writers such as the worker)."""
    if outcome not in OUTCOMES: raise ValueError(f"Resultado de auditoría inválido: {outcome}")
    fields = {"id": str(uuid.uuid4()), "user_id": user_id, "action": clean_text(action, 80), "module": clean_text(module, 80),
              "entity": clean_text(entity, 80), "entity_id": clean_text(entity_id, 36), "old_value": _jsonable(old),
              "new_value": _jsonable(new), "ip": clean_text(ip, 64), "user_agent": clean_text(user_agent, 500), "outcome": outcome,
              # Microseconds are kept by PostgreSQL and SQLite alike, so the sealed timestamp round-trips exactly.
              "created_at": datetime.now(timezone.utc)}
    fields["integrity_hash"] = seal(fields)
    return fields


def audit(db: Session, user_id: str | None, action: str, module: str, entity: str, entity_id: str | None, old=None, new=None,
          request: Request | None = None, outcome: str = "EXITO") -> AuditLog:
    row = AuditLog(**sealed_fields(user_id, action, module, entity, entity_id, old, new, client_ip(request),
                                   request.headers.get("user-agent") if request else None, outcome))
    db.add(row)
    return row


def history(db: Session, ticket_id: str, actor_id: str | None, event: str, detail: str, old=None, new=None):
    db.add(TicketHistory(ticket_id=ticket_id, actor_id=actor_id, event=event, detail=detail, old_value=old, new_value=new))


def notify(db: Session, user_id: str, type_: str, title: str, body: str, ticket_id: str | None = None):
    db.add(Notification(user_id=user_id, type=type_, title=title, body=body, ticket_id=ticket_id))
