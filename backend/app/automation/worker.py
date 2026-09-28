from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import create_engine, text

logger = logging.getLogger("fixit.automation")


def _db_url() -> str:
    value = os.getenv("DATABASE_URL")
    if not value:
        raise RuntimeError("DATABASE_URL no está configurada")
    return value


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _pick_id(data: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = data.get(key)
        if value:
            return str(value)
    return None


class AutomationWorker:
    """Procesa automation_events y ejecuta acciones de negocio seguras."""

    def __init__(self, poll_seconds: float = 1.0) -> None:
        self.poll_seconds = poll_seconds
        self.engine = create_engine(_db_url(), pool_pre_ping=True)
        self._stop = asyncio.Event()

    def stop(self) -> None:
        self._stop.set()

    def _claim_one(self) -> dict[str, Any] | None:
        with self.engine.begin() as conn:
            row = conn.execute(
                text(
                    """
                    WITH next_event AS (
                        SELECT id
                        FROM automation_events
                        WHERE status = 'PENDING'
                          AND available_at <= NOW()
                        ORDER BY created_at
                        FOR UPDATE SKIP LOCKED
                        LIMIT 1
                    )
                    UPDATE automation_events e
                       SET status = 'PROCESSING',
                           attempts = attempts + 1
                      FROM next_event n
                     WHERE e.id = n.id
                    RETURNING e.id, e.event_type, e.source_table,
                              e.aggregate_id, e.payload, e.attempts
                    """
                )
            ).mappings().first()
            return dict(row) if row else None

    def _finish(self, event_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                text(
                    """
                    UPDATE automation_events
                       SET status = 'DONE',
                           processed_at = NOW(),
                           last_error = NULL
                     WHERE id = :id
                    """
                ),
                {"id": event_id},
            )

    def _fail(self, event_id: str, attempts: int, error: str) -> None:
        delay = min(300, 5 * (3 ** max(attempts - 1, 0)))
        with self.engine.begin() as conn:
            conn.execute(
                text(
                    """
                    UPDATE automation_events
                       SET status = CASE
                           WHEN attempts >= 5 THEN 'FAILED'
                           ELSE 'PENDING'
                       END,
                           available_at = NOW() + make_interval(secs => :delay),
                           last_error = :error
                     WHERE id = :id
                    """
                ),
                {"id": event_id, "delay": delay, "error": error[:4000]},
            )

    def _resolve_state_code(self, conn, value: Any) -> str | None:
        if value is None:
            return None
        value = str(value)
        if value in {
            "NUEVO", "ASIGNADO", "EN_ATENCION", "EN_ESPERA",
            "RESUELTO", "CERRADO", "REABIERTO", "CANCELADO", "ESCALADO",
        }:
            return value
        row = conn.execute(
            text("SELECT code FROM ticket_states WHERE id = :id LIMIT 1"),
            {"id": value},
        ).first()
        return row[0] if row else None

    def _insert_audit(
        self,
        conn,
        *,
        event: dict[str, Any],
        actor_id: str | None,
        action: str,
        entity_id: str | None,
        old_value: Any,
        new_value: Any,
    ) -> None:
        payload = {
            "automation_event_id": str(event["id"]),
            "event_type": event["event_type"],
            "source_table": event["source_table"],
        }
        conn.execute(
            text(
                """
                INSERT INTO audit_logs(
                    id, user_id, action, module, entity, entity_id,
                    old_value, new_value, ip, user_agent, created_at
                )
                VALUES(
                    :id, :user_id, :action, 'AUTOMATION', 'TICKET', :entity_id,
                    CAST(:old_value AS json), CAST(:new_value AS json),
                    'SYSTEM', 'FixIT Automation Worker', NOW()
                )
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "user_id": actor_id,
                "action": action[:80],
                "entity_id": entity_id,
                "old_value": _json(old_value),
                "new_value": _json({**payload, "data": new_value}),
            },
        )

    def _insert_notification(
        self,
        conn,
        *,
        user_id: str | None,
        ticket_id: str | None,
        notification_type: str,
        title: str,
        body: str,
    ) -> None:
        if not user_id:
            return
        conn.execute(
            text(
                """
                INSERT INTO notifications(
                    id, user_id, type, title, body, ticket_id, created_at
                )
                VALUES(
                    :id, :user_id, :type, :title, :body, :ticket_id, NOW()
                )
                """
            ),
            {
                "id": str(uuid.uuid4()),
                "user_id": user_id,
                "type": notification_type[:40],
                "title": title[:180],
                "body": body,
                "ticket_id": ticket_id,
            },
        )

    def _technician_user_id(self, conn, technician_id: str | None) -> str | None:
        if not technician_id:
            return None
        row = conn.execute(
            text("SELECT user_id FROM technicians WHERE id = :id LIMIT 1"),
            {"id": technician_id},
        ).first()
        return str(row[0]) if row and row[0] else None

    def process_one(self, event: dict[str, Any]) -> None:
        event_type = str(event["event_type"])
        payload = event.get("payload") or {}
        new = payload.get("new") or {}
        old = payload.get("old") or {}
        ticket_id = str(event.get("aggregate_id")) if event.get("aggregate_id") else _pick_id(new, "ticket_id", "id")
        actor_id = _pick_id(
            new,
            "user_id", "actor_id", "created_by_id", "assigned_by_id",
            "author_id", "requester_id", "rated_by_id",
        )

        with self.engine.begin() as conn:
            if event_type == "TICKET_CREADO":
                requester_id = _pick_id(new, "requester_id", "user_id", "created_by_id")
                self._insert_notification(
                    conn,
                    user_id=requester_id,
                    ticket_id=ticket_id,
                    notification_type="TICKET",
                    title="Ticket creado",
                    body="Tu solicitud fue registrada correctamente. El sistema iniciará su gestión.",
                )
                self._insert_audit(
                    conn,
                    event=event,
                    actor_id=requester_id or actor_id,
                    action="AUTOMATION_TICKET_CREADO",
                    entity_id=ticket_id,
                    old_value=None,
                    new_value=new,
                )

            elif event_type == "TICKET_ASIGNADO":
                technician_id = _pick_id(new, "technician_id")
                technician_user_id = self._technician_user_id(conn, technician_id)
                requester_id = _pick_id(new, "requester_id", "user_id")

                if not requester_id and ticket_id:
                    row = conn.execute(
                        text("SELECT requester_id FROM tickets WHERE id = :id LIMIT 1"),
                        {"id": ticket_id},
                    ).first()
                    requester_id = str(row[0]) if row and row[0] else None

                self._insert_notification(
                    conn,
                    user_id=technician_user_id,
                    ticket_id=ticket_id,
                    notification_type="ASIGNACION",
                    title="Nuevo ticket asignado",
                    body="Tienes un nuevo ticket asignado en FixIT.",
                )
                self._insert_notification(
                    conn,
                    user_id=requester_id,
                    ticket_id=ticket_id,
                    notification_type="ASIGNACION",
                    title="Técnico asignado",
                    body="Tu ticket ya tiene un técnico asignado y será atendido.",
                )
                self._insert_audit(
                    conn,
                    event=event,
                    actor_id=actor_id,
                    action="AUTOMATION_TICKET_ASIGNADO",
                    entity_id=ticket_id,
                    old_value=old,
                    new_value=new,
                )

            elif event_type == "TICKET_ACTUALIZADO":
                before = self._resolve_state_code(
                    conn, old.get("state") or old.get("status") or old.get("state_id")
                )
                after = self._resolve_state_code(
                    conn, new.get("state") or new.get("status") or new.get("state_id")
                )

                if after == "RESUELTO" and before != "RESUELTO":
                    requester_id = _pick_id(new, "requester_id", "user_id")
                    if not requester_id and ticket_id:
                        row = conn.execute(
                            text("SELECT requester_id FROM tickets WHERE id = :id LIMIT 1"),
                            {"id": ticket_id},
                        ).first()
                        requester_id = str(row[0]) if row and row[0] else None

                    self._insert_notification(
                        conn,
                        user_id=requester_id,
                        ticket_id=ticket_id,
                        notification_type="RESOLUCION",
                        title="Ticket resuelto",
                        body="Tu ticket fue marcado como resuelto. Revisa la solución y califica la atención.",
                    )

                self._insert_audit(
                    conn,
                    event=event,
                    actor_id=actor_id,
                    action="AUTOMATION_TICKET_ACTUALIZADO",
                    entity_id=ticket_id,
                    old_value={"state": before, **old},
                    new_value={"state": after, **new},
                )

            elif event_type == "TICKET_CALIFICADO":
                self._insert_audit(
                    conn,
                    event=event,
                    actor_id=actor_id,
                    action="AUTOMATION_TICKET_CALIFICADO",
                    entity_id=ticket_id,
                    old_value=None,
                    new_value=new,
                )

            elif event_type == "TICKET_COMENTADO":
                self._insert_audit(
                    conn,
                    event=event,
                    actor_id=actor_id,
                    action="AUTOMATION_TICKET_COMENTADO",
                    entity_id=ticket_id,
                    old_value=None,
                    new_value=new,
                )

            else:
                self._insert_audit(
                    conn,
                    event=event,
                    actor_id=actor_id,
                    action=f"AUTOMATION_{event_type}"[:80],
                    entity_id=ticket_id,
                    old_value=old,
                    new_value=new,
                )

            logger.info("FixIT automation procesó %s (%s)", event_type, event["id"])

    async def run(self) -> None:
        logger.info("FixIT Automation Worker iniciado")
        while not self._stop.is_set():
            event = None
            try:
                event = await asyncio.to_thread(self._claim_one)
                if event:
                    try:
                        await asyncio.to_thread(self.process_one, event)
                    except Exception as exc:
                        logger.exception("Error procesando evento %s", event["id"])
                        await asyncio.to_thread(
                            self._fail,
                            str(event["id"]),
                            int(event["attempts"]),
                            str(exc),
                        )
                    else:
                        await asyncio.to_thread(self._finish, str(event["id"]))
                else:
                    try:
                        await asyncio.wait_for(self._stop.wait(), timeout=self.poll_seconds)
                    except asyncio.TimeoutError:
                        pass
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error general del worker de automatización")
                await asyncio.sleep(2)

        logger.info("FixIT Automation Worker detenido")
