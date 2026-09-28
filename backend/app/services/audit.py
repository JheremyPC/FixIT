from fastapi import Request
from sqlalchemy.orm import Session
from app.models import AuditLog, Notification, TicketHistory


def audit(db: Session, user_id: str | None, action: str, module: str, entity: str, entity_id: str | None, old=None, new=None, request: Request | None = None):
    db.add(AuditLog(user_id=user_id, action=action, module=module, entity=entity, entity_id=entity_id, old_value=old, new_value=new,
                    ip=request.client.host if request and request.client else None,
                    user_agent=request.headers.get("user-agent") if request else None))


def history(db: Session, ticket_id: str, actor_id: str | None, event: str, detail: str, old=None, new=None):
    db.add(TicketHistory(ticket_id=ticket_id, actor_id=actor_id, event=event, detail=detail, old_value=old, new_value=new))


def notify(db: Session, user_id: str, type_: str, title: str, body: str, ticket_id: str | None = None):
    db.add(Notification(user_id=user_id, type=type_, title=title, body=body, ticket_id=ticket_id))

