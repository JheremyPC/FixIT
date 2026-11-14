"""Centro Integral de Auditoría: permissions, engine, read-only execution, findings life cycle, evidence, imports, reports.

Runs on the isolated SQLite database of tests/conftest.py. PostgreSQL-specific controls and migrations are covered by
tests/test_audit_center_pg.py (local PostgreSQL only).
"""
import csv
import hashlib
import io
import json
import time
import uuid
import zipfile
from datetime import date, datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text

from app.auditing import engine, readonly
from app.auditing.redaction import mask_email, mask_ip, redact_text, relative_source, safe_error
from app.auditing.registry import Control, Outcome, RunInfo
from app.core.database import SessionLocal
from app.main import app
from app.models import (AuditLog, AuditReport, AuditResult, AuditRun, Rating, Ticket,
                        TicketAssignment, TicketComment, TicketHistory, User)
from app.security.hardening import login_throttle
from app.services.audit import audit

PASSWORD = "Secure!123"
PDF = b"%PDF-1.4\n% evidencia de prueba\n"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
FINAL = ("COMPLETADA", "COMPLETADA_CON_ERRORES", "CANCELADA", "INTERRUMPIDA")


def auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def fresh_throttle():
    login_throttle.clear()
    yield


def login(client, email, password=PASSWORD):
    r = client.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def admin(client):
    return auth(login(client, "admin@fixit.org", "FixIT!2026"))


@pytest.fixture(scope="module")
def people(client, admin):
    suffix = uuid.uuid4().hex[:8]
    out = {"ADMIN": {"headers": admin, "id": client.get("/api/auth/me", headers=admin).json()["id"]}}
    for role, key in [("JEFE_TI", "JEFE_TI"), ("TECNICO", "TECNICO"), ("TECNICO", "TECNICO_2"), ("USUARIO", "USUARIO")]:
        email = f"ac-{key.lower()}-{suffix}@fixit.org"
        user_id = client.post("/api/users", headers=admin, json={"full_name": f"Auditoría {key}", "email": email, "password": PASSWORD,
                                                                 "role_code": role}).json()["id"]
        out[key] = {"id": user_id, "email": email, "headers": auth(login(client, email))}
    return out


def wait(client, headers, run_id, timeout=240):
    deadline = time.time() + timeout
    while time.time() < deadline:
        run = client.get(f"/api/audit-center/runs/{run_id}", headers=headers).json()
        if run["status"] in FINAL: return run
        time.sleep(0.3)
    raise AssertionError(f"La auditoría {run_id} no terminó a tiempo")


def start(client, headers, **body):
    body.setdefault("name", "Prueba automatizada")
    r = client.post("/api/audit-center/runs", headers=headers, json=body)
    assert r.status_code == 202, r.text
    return r.json()


def result(run, code):
    return next(x for x in run["results"] if x["control"] == code)


def business_snapshot():
    """Row count and content digest of the business tables (the audit must never change them)."""
    db = SessionLocal()
    try:
        out = {}
        for model in (User, Ticket, TicketHistory, TicketAssignment, TicketComment, Rating):
            rows = db.execute(select(model.__table__)).all()
            out[model.__tablename__] = (len(rows), hashlib.sha256(repr(sorted(map(repr, rows))).encode()).hexdigest())
        logs = db.execute(select(AuditLog.__table__)).all()
        out["audit_logs_previos"] = {r.id: hashlib.sha256(repr(r).encode()).hexdigest() for r in logs}
        return out
    finally:
        db.close()


# --- Permissions -----------------------------------------------------------------------------------------------------
def test_anonymous_and_requester_are_rejected_and_denials_are_audited(client, people):
    assert client.get("/api/audit-center/overview").status_code == 401
    user = people["USUARIO"]
    for method, path in [("GET", "/api/audit-center/meta"), ("GET", "/api/audit-center/overview"), ("GET", "/api/audit-center/findings"),
                         ("POST", "/api/audit-center/runs"), ("GET", "/api/audit-center/reports"), ("GET", "/api/audit-center/my")]:
        r = client.request(method, path, headers=user["headers"], json={"name": "x", "categories": ["ACCESOS"]} if method == "POST" else None)
        assert r.status_code == 403, (method, path, r.status_code)
    db = SessionLocal()
    try:
        denied = db.scalar(select(func.count(AuditLog.id)).where(AuditLog.user_id == user["id"], AuditLog.module == "CENTRO_AUDITORIA",
                                                                 AuditLog.outcome == "DENEGADO"))
        assert denied >= 6
    finally:
        db.close()


def test_technician_only_reaches_own_work(client, people):
    tech = people["TECNICO"]["headers"]
    for path in ("/api/audit-center/overview", "/api/audit-center/runs", "/api/audit-center/reports", "/api/audit-center/imports",
                 "/api/audit-center/categories/BASE_DATOS", "/api/audit-center/external-logs", "/api/audit-center/evidences"):
        assert client.get(path, headers=tech).status_code == 403, path
    assert client.post("/api/audit-center/runs", headers=tech, json={"name": "No", "categories": ["ACCESOS"]}).status_code == 403
    meta = client.get("/api/audit-center/meta", headers=tech).json()
    assert meta["can_manage"] is False and meta["controls"] == []
    assert client.get("/api/audit-center/my", headers=tech).status_code == 200
    assert client.get("/api/audit-center/findings", headers=tech).json() == []
    assert client.patch("/api/audit-center/controls/ACC-01", headers=people["JEFE_TI"]["headers"], json={"enabled": False}).status_code == 403


def test_input_validation_rejects_unknown_fields_and_sql(client, people):
    chief = people["JEFE_TI"]["headers"]
    assert client.post("/api/audit-center/runs", headers=chief, json={"name": "x", "categories": ["ACCESOS"], "sql": "DROP TABLE users"}).status_code == 422
    assert client.post("/api/audit-center/runs", headers=chief, json={"name": "Inválida", "categories": ["NO_EXISTE"]}).status_code == 422
    assert client.post("/api/audit-center/runs", headers=chief, json={"name": "Sin alcance", "categories": []}).status_code == 422
    assert client.post("/api/audit-center/runs", headers=chief, json={"name": "Desconocido", "control_codes": ["XX-99"]}).status_code == 422


# --- Engine ------------------------------------------------------------------------------------------------------------
def test_full_audit_runs_in_background_without_touching_business_data(client, admin, people):
    before = business_snapshot()
    meta = client.get("/api/audit-center/meta", headers=admin).json()
    run = start(client, people["JEFE_TI"]["headers"], name="Auditoría integral de prueba", categories=[c["code"] for c in meta["categories"]])
    assert run["status"] in ("PENDIENTE", "EN_CURSO", "COMPLETADA")
    done = wait(client, admin, run["id"])
    assert done["status"] in ("COMPLETADA", "COMPLETADA_CON_ERRORES")
    assert done["progress"]["done"] == done["progress"]["total"] == len(done["control_codes"]) >= 100
    statuses = {r["status"] for r in done["results"]}
    assert statuses <= {"APROBADO", "FALLIDO", "ADVERTENCIA", "NO_APLICABLE", "NO_VERIFICADO", "ERROR_EJECUCION"}
    assert not [r["control"] for r in done["results"] if r["status"] == "ERROR_EJECUCION"], [r for r in done["results"] if r["status"] == "ERROR_EJECUCION"]
    # PostgreSQL-only controls are never approved on SQLite; manual controls without evidence are never approved.
    assert result(done, "BD-SEG-01")["status"] == "NO_APLICABLE"
    for code in ("CON-01", "CON-02", "CON-04", "INF-10", "REG-07"):
        assert result(done, code)["status"] == "NO_VERIFICADO", code
    assert result(done, "SEG-DEP-02")["status"] == "NO_VERIFICADO"  # no pip-audit report imported yet
    assert result(done, "SEG-JWT-01")["status"] == "FALLIDO"  # the pytest secret is published in this repository
    assert result(done, "SEG-AUT-01")["status"] == "APROBADO" and result(done, "SEG-AUT-01")["details"]["rutas"] > 60
    assert done["seal_status"] == "VALIDO" and done["result"] in ("DESFAVORABLE", "CON_OBSERVACIONES", "NO_CONCLUYENTE")
    assert done["connection"]["modo"].startswith("SQLite con PRAGMA query_only")
    after = business_snapshot()
    for table in ("users", "tickets", "ticket_history", "ticket_assignments", "ticket_comments", "ratings"):
        assert before[table] == after[table], table
    for record_id, digest in before["audit_logs_previos"].items():
        assert after["audit_logs_previos"][record_id] == digest  # existing audit records untouched
    overview = client.get("/api/audit-center/overview", headers=admin).json()
    assert overview["kpis"]["runs_executed"] >= 1 and overview["kpis"]["controls_failed"] >= 1


def test_read_only_connection_rejects_writes():
    with readonly.read_only() as conn:
        assert conn.exec_driver_sql("PRAGMA query_only").scalar() == 1
        with pytest.raises(Exception, match="readonly|read-only|query_only"):
            conn.exec_driver_sql("INSERT INTO settings(key, value) VALUES ('auditoria.intento', 'x')")
    db = SessionLocal()
    try:
        assert db.execute(text("SELECT count(*) FROM settings WHERE key = 'auditoria.intento'")).scalar() == 0
        db.execute(text("SELECT 1"))  # the application's own connections remain writable
    finally:
        db.close()


def test_a_control_that_writes_is_an_execution_error_never_approved():
    def writer(ctx):
        ctx.conn.exec_driver_sql("DELETE FROM users")
        return Outcome("APROBADO", "No debería llegar aquí")
    ctrl = Control("TST-01", "ACCESOS", "Control defectuoso", "Prueba", "SQL", "ALTO", writer)
    out, _, _ = engine.run_control(ctrl, RunInfo("x", "AUD-T", None, None, {}), "")
    assert out.status == "ERROR_EJECUCION"
    db = SessionLocal()
    try:
        assert db.scalar(select(func.count(User.id))) > 0
    finally:
        db.close()


def test_duplicate_runs_are_rejected_and_pending_runs_can_be_cancelled(people):
    db = SessionLocal()
    try:
        actor = db.get(User, people["JEFE_TI"]["id"])
        run = engine.create_run(db, actor, "Duplicada", ["ACCESOS"])
        db.commit()
        with pytest.raises(engine.RunConflict):
            engine.create_run(db, actor, "Duplicada otra vez", ["ACCESOS"])
        db.rollback()
        assert engine.request_cancel(db, db.get(AuditRun, run.id)) == "CANCELADA"
        run = db.get(AuditRun, run.id)
        results = db.scalars(select(AuditResult).where(AuditResult.run_id == run.id)).all()
        assert run.status == "CANCELADA" and len(results) == len(run.control_codes)
        assert {r.status for r in results} == {"NO_VERIFICADO"}
        engine.execute(run.id)  # a cancelled run is never executed afterwards
        assert db.get(AuditRun, run.id).status == "CANCELADA"
    finally:
        db.close()


def test_stale_running_runs_are_closed_as_interrupted(people):
    db = SessionLocal()
    try:
        run = engine.create_run(db, db.get(User, people["JEFE_TI"]["id"]), "Interrumpida", [], ["ACC-01", "ACC-02"])
        old = datetime.now(timezone.utc) - timedelta(hours=3)
        run.status, run.started_at, run.heartbeat_at = "EN_CURSO", old, old
        db.commit()
        assert engine.recover_stale(db) >= 1
        run = db.get(AuditRun, run.id)
        assert run.status == "INTERRUMPIDA"
        assert {r.status for r in db.scalars(select(AuditResult).where(AuditResult.run_id == run.id))} == {"NO_VERIFICADO"}
    finally:
        db.close()


def test_results_seal_detects_tampering(client, admin):
    run = wait(client, admin, start(client, admin, name="Sello", control_codes=["PRI-01", "PRI-02"])["id"])
    db = SessionLocal()
    try:
        stored = db.scalars(select(AuditResult).where(AuditResult.run_id == run["id"])).all()
        assert engine.verify_seal(db.get(AuditRun, run["id"]), stored) == "VALIDO"
        row = next(r for r in stored if r.control_code == "PRI-01")
        db.execute(text("UPDATE audit_results SET status = 'APROBADO' WHERE id = :id"), {"id": row.id})
        db.commit()
        results = db.scalars(select(AuditResult).where(AuditResult.run_id == run["id"])).all()
        assert engine.verify_seal(db.get(AuditRun, run["id"]), results) == "ALTERADO"
    finally:
        db.close()
    reg = wait(client, admin, start(client, admin, name="Verificar sellos", control_codes=["REG-08"])["id"])
    assert result(reg, "REG-08")["status"] == "FALLIDO" and run["code"] in result(reg, "REG-08")["details"]["alteradas"]


def test_hmac_verification_control_detects_an_altered_activity_record(client, admin):
    db = SessionLocal()
    try:
        row = audit(db, None, "PRUEBA_SELLO", "PRUEBAS", "TEST", None, new={"valor": 1})
        db.commit()
        db.execute(text("UPDATE audit_logs SET action = 'MANIPULADO' WHERE id = :id"), {"id": row.id})  # SQLite has no append-only trigger
        db.commit()
    finally:
        db.close()
    run = wait(client, admin, start(client, admin, name="HMAC", control_codes=["REG-01"])["id"])
    assert result(run, "REG-01")["status"] == "FALLIDO" and result(run, "REG-01")["details"]["por_estado"]["ALTERADO"] >= 1


# --- Findings -------------------------------------------------------------------------------------------------------
def test_findings_are_deduplicated_and_need_evidence_and_verification_to_close(client, admin, people):
    chief, tech = people["JEFE_TI"]["headers"], people["TECNICO"]["headers"]
    admins = sum(1 for u in client.get("/api/users", headers=admin).json() if u["role"] == "ADMIN" and u["active"])
    extra = client.post("/api/users", headers=admin, json={"full_name": "Admin adicional", "email": f"ac-admin-{uuid.uuid4().hex[:6]}@fixit.org",
                                                            "password": PASSWORD, "role_code": "ADMIN"}).json()["id"]
    options = {"max_admins": admins}  # exceeded only while the extra administrator is active
    first = wait(client, chief, start(client, chief, name="Admins 1", control_codes=["ACC-02"], options=options)["id"])
    assert result(first, "ACC-02")["status"] == "ADVERTENCIA"
    second = wait(client, chief, start(client, chief, name="Admins 2", control_codes=["ACC-02"], options=options)["id"])
    found = [f for f in client.get("/api/audit-center/findings?control=ACC-02", headers=chief).json() if f["resource"] == "cuentas:admins"]
    assert len(found) == 1 and found[0]["occurrences"] == 2  # same finding, not a duplicate
    fid = found[0]["id"]
    assert client.get(f"/api/audit-center/findings/{fid}", headers=tech).status_code == 404  # not assigned yet
    assert client.patch(f"/api/audit-center/findings/{fid}", headers=chief, json={"owner_id": people["TECNICO"]["id"],
                        "due_date": (date.today() + timedelta(days=10)).isoformat()}).status_code == 200
    assert client.get(f"/api/audit-center/findings/{fid}", headers=people["TECNICO_2"]["headers"]).status_code == 404
    detail = client.get(f"/api/audit-center/findings/{fid}", headers=tech).json()
    assert detail["allowed_transitions"] == ["EN_CORRECCION"]
    status = lambda h, s, **kw: client.post(f"/api/audit-center/findings/{fid}/status", headers=h, json={"status": s, "note": "Cambio de prueba", **kw})  # noqa: E731
    assert status(tech, "RIESGO_ACEPTADO", justification="x" * 30, review_date=(date.today() + timedelta(days=30)).isoformat()).status_code == 403
    assert status(tech, "EN_CORRECCION").status_code == 200
    assert status(tech, "CORREGIDO_PENDIENTE_VERIFICACION").status_code == 422  # no correction evidence yet
    ev = client.post("/api/audit-center/evidences", headers=tech, data={"kind": "CORRECCION", "title": "Cuenta adicional desactivada", "finding_id": fid},
                     files={"file": ("acta.pdf", PDF, "application/pdf")})
    assert ev.status_code == 201, ev.text
    assert status(tech, "CORREGIDO_PENDIENTE_VERIFICACION").status_code == 200
    assert status(tech, "CERRADO").status_code == 403  # technicians never close
    assert status(chief, "CERRADO").status_code == 422  # no verification after the correction
    assert client.patch(f"/api/users/{extra}", headers=admin, json={"active": False}).status_code == 200
    third = wait(client, chief, start(client, chief, name="Admins 3", control_codes=["ACC-02"], options=options)["id"])
    assert client.get(f"/api/audit-center/findings/{fid}", headers=chief).json()["last_verification"] == "NO_REPRODUCIDO"
    closed = status(chief, "CERRADO")
    assert closed.status_code == 200 and closed.json()["status"] == "CERRADO"
    # The condition comes back: the closed finding is reopened, never duplicated, and its history is kept.
    assert client.patch(f"/api/users/{extra}", headers=admin, json={"active": True}).status_code == 200
    wait(client, chief, start(client, chief, name="Admins 4", control_codes=["ACC-02"], options=options)["id"])
    again = client.get(f"/api/audit-center/findings/{fid}", headers=chief).json()
    assert again["status"] == "ABIERTO" and again["occurrences"] == 3
    assert [e["event"] for e in again["events"]][:1] == ["DETECTADO"] and "REAPARECIDO" in [e["event"] for e in again["events"]]
    assert len([f for f in client.get("/api/audit-center/findings?control=ACC-02", headers=chief).json() if f["resource"] == "cuentas:admins"]) == 1
    assert {second["code"], third["code"]} and first["id"] != third["id"]
    client.patch(f"/api/users/{extra}", headers=admin, json={"active": False})


def test_risk_acceptance_requires_justification_and_review_date(client, people):
    chief = people["JEFE_TI"]["headers"]
    run = wait(client, chief, start(client, chief, name="Legal", control_codes=["PRI-02"])["id"])
    fid = next(f["id"] for f in run["findings"] if f["control"] == "PRI-02")
    url = f"/api/audit-center/findings/{fid}/status"
    assert client.post(url, headers=chief, json={"status": "RIESGO_ACEPTADO", "note": "Aceptado"}).status_code == 422
    assert client.post(url, headers=chief, json={"status": "RIESGO_ACEPTADO", "note": "Aceptado", "justification": "corta"}).status_code == 422
    assert client.post(url, headers=chief, json={"status": "RIESGO_ACEPTADO", "note": "Aceptado", "justification": "La entidad completará los datos en el próximo trimestre.",
                                                  "review_date": (date.today() - timedelta(days=1)).isoformat()}).status_code == 422
    ok = client.post(url, headers=chief, json={"status": "RIESGO_ACEPTADO", "note": "Aceptado", "justification": "La entidad completará los datos en el próximo trimestre.",
                                                "review_date": (date.today() + timedelta(days=90)).isoformat()})
    assert ok.status_code == 200 and ok.json()["risk"]["review_date"]
    assert client.post(url, headers=chief, json={"status": "CERRADO", "note": "No"}).status_code == 422  # not a valid transition


def test_action_plan_tasks_respect_ownership(client, people):
    chief, tech, other = people["JEFE_TI"]["headers"], people["TECNICO"]["headers"], people["TECNICO_2"]["headers"]
    run = wait(client, chief, start(client, chief, name="Tareas", control_codes=["PRI-01"])["id"])
    fid = next(f["id"] for f in run["findings"] if f["control"] == "PRI-01")
    task = client.post(f"/api/audit-center/findings/{fid}/actions", headers=chief, json={"description": "Revisar los documentos con el área legal",
                                                                                        "owner_id": people["TECNICO"]["id"]})
    assert task.status_code == 201
    tid = task.json()["id"]
    assert client.patch(f"/api/audit-center/actions/{tid}", headers=other, json={"status": "EN_CURSO"}).status_code == 404
    assert client.patch(f"/api/audit-center/actions/{tid}", headers=tech, json={"owner_id": people["TECNICO_2"]["id"]}).status_code == 403
    assert client.patch(f"/api/audit-center/actions/{tid}", headers=tech, json={"status": "EN_CURSO", "note": "Iniciado"}).json()["status"] == "EN_CURSO"
    assert any(a["id"] == tid for a in client.get("/api/audit-center/my", headers=tech).json()["actions"])
    assert client.get(f"/api/audit-center/findings/{fid}", headers=tech).status_code == 200  # visible through the task
    assert client.post(f"/api/audit-center/findings/{fid}/actions", headers=tech, json={"description": "No permitido"}).status_code == 403


# --- Evidence ---------------------------------------------------------------------------------------------------------
def test_evidence_files_are_validated_by_content(client, people):
    chief = people["JEFE_TI"]["headers"]
    base = {"kind": "MANUAL", "title": "Captura del panel", "control_code": "CON-02", "declared_result": "APROBADO", "evidence_date": date.today().isoformat()}
    assert client.post("/api/audit-center/evidences", headers=chief, data=base, files={"file": ("x.pdf", PNG, "application/pdf")}).status_code == 415
    assert client.post("/api/audit-center/evidences", headers=chief, data=base, files={"file": ("x.html", b"<html><script>alert(1)</script>", "text/html")}).status_code == 415
    assert client.post("/api/audit-center/evidences", headers=chief, data=base, files={"file": ("x.txt", b"<script>alert(1)</script>", "text/plain")}).status_code == 415
    assert client.post("/api/audit-center/evidences", headers=chief, data=base, files={"file": ("x.json", b"{malo", "application/json")}).status_code == 415
    assert client.post("/api/audit-center/evidences", headers=chief, data=base).status_code == 422  # manual evidence needs a file
    assert client.post("/api/audit-center/evidences", headers=chief, data={**base, "control_code": "ACC-01"}, files={"file": ("x.pdf", PDF, "application/pdf")}).status_code == 422
    future = {**base, "evidence_date": (date.today() + timedelta(days=2)).isoformat()}
    assert client.post("/api/audit-center/evidences", headers=chief, data=future, files={"file": ("x.pdf", PDF, "application/pdf")}).status_code == 422
    assert client.post("/api/audit-center/evidences", headers=people["TECNICO"]["headers"], data=base, files={"file": ("x.pdf", PDF, "application/pdf")}).status_code == 403
    ok = client.post("/api/audit-center/evidences", headers=chief, data=base, files={"file": ("../../respaldo.pdf", PDF, "application/pdf")})
    assert ok.status_code == 201 and ok.json()["file"] == "respaldo.pdf" and ok.json()["sha256"] == hashlib.sha256(PDF).hexdigest()


def test_manual_controls_use_evidence_and_expire(client, people):
    chief = people["JEFE_TI"]["headers"]
    old = {"kind": "MANUAL", "title": "Respaldo antiguo", "control_code": "CON-04", "declared_result": "APROBADO",
           "evidence_date": (date.today() - timedelta(days=400)).isoformat()}
    assert client.post("/api/audit-center/evidences", headers=chief, data=old, files={"file": ("prueba.pdf", PDF, "application/pdf")}).status_code == 201
    fresh = {"kind": "MANUAL", "title": "Captura de respaldos de hoy", "control_code": "CON-02", "declared_result": "APROBADO", "evidence_date": date.today().isoformat()}
    assert client.post("/api/audit-center/evidences", headers=chief, data=fresh, files={"file": ("hoy.pdf", PDF, "application/pdf")}).status_code == 201
    run = wait(client, chief, start(client, chief, name="Continuidad", control_codes=["CON-02", "CON-04"])["id"])
    con2, con4 = result(run, "CON-02"), result(run, "CON-04")
    assert con2["status"] == "APROBADO" and con2["method"] == "MANUAL" and con2["details"]["evidencia"]["titulo"] == fresh["title"]
    assert con4["status"] == "NO_VERIFICADO" and "180" in con4["summary"]  # evidence older than the control allows


def test_evidence_download_is_authorized_and_audited(client, people):
    chief = people["JEFE_TI"]["headers"]
    evidences = client.get("/api/audit-center/evidences?kind=MANUAL", headers=chief).json()
    target = next(e for e in evidences if e["has_file"])
    r = client.get(f"/api/audit-center/evidences/{target['id']}/download", headers=chief)
    assert r.status_code == 200 and r.content.startswith(b"%PDF") and "attachment" in r.headers["content-disposition"]
    assert client.get(f"/api/audit-center/evidences/{target['id']}/download", headers=people["TECNICO_2"]["headers"]).status_code == 404
    assert client.get(f"/api/audit-center/evidences/{target['id']}/download", headers=people["USUARIO"]["headers"]).status_code == 403
    db = SessionLocal()
    try:
        assert db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == "DESCARGAR_EVIDENCIA", AuditLog.entity_id == target["id"])) >= 1
    finally:
        db.close()


# --- Imports ------------------------------------------------------------------------------------------------------
def _supabase_csv(lines):
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["timestamp", "event_message", "user_name", "database_name"])
    for row in lines: writer.writerow(row)
    return out.getvalue().encode()


def test_database_log_import_sanitizes_redacts_and_deduplicates(client, people):
    chief = people["JEFE_TI"]["headers"]
    now = datetime.now(timezone.utc)
    stamp = lambda m: int((now - timedelta(minutes=m)).timestamp() * 1_000_000)  # noqa: E731 - Supabase exports microseconds
    lines = [[stamp(30), 'AUDIT: SESSION,1,1,ROLE,ALTER ROLE,,,"ALTER ROLE app_user WITH PASSWORD \'Sup3rS3creta\'",<not logged>', "postgres", "postgres"],
             [stamp(20), 'AUDIT: SESSION,2,1,DDL,CREATE TABLE,TABLE,public.tmp_x,"create table tmp_x(id int)",<not logged>', "postgres", "postgres"],
             [stamp(10), 'AUDIT: SESSION,3,1,WRITE,UPDATE,TABLE,public.users,"update users set full_name = $1 where id = $2","Ana Pérez,123"', "app", "postgres"],
             [stamp(5), "connection authorized: user=app database=postgres SSL enabled", "app", "postgres"],
             [stamp(4), "password authentication failed for user \"intruso\"", "intruso", "postgres"],
             [stamp(3), "checkpoint complete: wrote 3 buffers", "", ""]]
    r = client.post("/api/audit-center/imports", headers=chief, data={"kind": "LOGS_BD", "notes": "Exportación de prueba"},
                    files={"file": ("supabase-logs.csv", _supabase_csv(lines), "text/csv")})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["rows"] == {"total": 6, "imported": 5, "duplicated": 0, "rejected": 0} and body["summary"]["descartados_sin_interes"] == 1
    assert client.post("/api/audit-center/imports", headers=chief, data={"kind": "LOGS_BD"},
                       files={"file": ("otra.csv", _supabase_csv(lines), "text/csv")}).status_code == 409  # same file
    overlap = client.post("/api/audit-center/imports", headers=chief, data={"kind": "LOGS_BD"},
                          files={"file": ("solapada.csv", _supabase_csv(lines[:2] + [[stamp(1), "disconnection: session time: 0:00:01", "app", "postgres"]]), "text/csv")}).json()
    assert overlap["rows"]["imported"] == 1 and overlap["rows"]["duplicated"] == 2
    logs = client.get("/api/audit-center/external-logs?limit=50", headers=chief).json()
    blob = json.dumps(logs, ensure_ascii=False)
    assert "Sup3rS3creta" not in blob and "Ana Pérez" not in blob and "[PARAMETROS NO ALMACENADOS]" in blob
    role = next(x for x in logs if x["class"] == "ROLE")
    assert role["redacted"] is True and "[REDACTADO]" in role["statement"]
    write = next(x for x in logs if x["class"] == "WRITE")
    assert write["object"] == "public.users" and write["command"] == "UPDATE" and write["original"]["event_message"].endswith("[PARAMETROS NO ALMACENADOS]")
    assert client.post("/api/audit-center/imports", headers=chief, data={"kind": "LOGS_BD"},
                       files={"file": ("malo.csv", b"columna_a,columna_b\n1,2\n", "text/csv")}).status_code == 422
    rejected = [i for i in client.get("/api/audit-center/imports?kind=LOGS_BD", headers=chief).json() if i["file"] == "malo.csv"]
    assert rejected and rejected[0]["status"] == "RECHAZADA"
    run = wait(client, chief, start(client, chief, name="Actividad SQL", control_codes=["BD-ACT-04"])["id"])
    act = result(run, "BD-ACT-04")
    assert act["status"] == "ADVERTENCIA" and act["details"]["por_clase"]["DDL"] >= 1 and act["details"]["por_clase"]["AUTENTICACION_FALLIDA"] >= 1


def test_tool_reports_are_imported_as_summaries(client, people):
    chief = people["JEFE_TI"]["headers"]
    bandit = {"generated_at": "2026-11-14T10:00:00Z", "errors": [], "metrics": {"_totals": {"loc": 1000}},
              "results": [{"test_id": "B608", "test_name": "hardcoded_sql_expressions", "issue_severity": "HIGH", "issue_confidence": "LOW",
                           "filename": "C:\\Users\\dev\\proyecto\\backend\\app\\api\\x.py", "line_number": 10, "issue_text": "Possible SQL injection"}]}
    r = client.post("/api/audit-center/imports", headers=chief, data={"kind": "BANDIT"}, files={"file": ("bandit.json", json.dumps(bandit).encode(), "application/json")})
    assert r.status_code == 201 and r.json()["summary"]["items"][0]["archivo"] == "app/api/x.py"  # no machine paths
    pip_audit = {"dependencies": [{"name": "fastapi", "version": "0.162.0", "vulns": []}, {"name": "jinja2", "version": "3.0.0",
                 "vulns": [{"id": "GHSA-test", "fix_versions": ["3.1.5"], "aliases": ["CVE-2024-0000"], "description": "Prueba"}]}]}
    assert client.post("/api/audit-center/imports", headers=chief, data={"kind": "PIP_AUDIT"},
                       files={"file": ("pip.json", json.dumps(pip_audit).encode(), "application/json")}).status_code == 201
    zap = {"@version": "2.15.0", "site": [{"@name": "http://localhost:8000", "alerts": [{"pluginid": "10021", "alert": "X-Content-Type-Options", "riskcode": "1", "confidence": "2", "count": "1"}]}]}
    assert client.post("/api/audit-center/imports", headers=chief, data={"kind": "ZAP"}, files={"file": ("zap.json", json.dumps(zap).encode(), "application/json")}).status_code == 201
    assert client.post("/api/audit-center/imports", headers=chief, data={"kind": "SARIF"}, files={"file": ("x.sarif", b'{"no": "sarif"}', "application/json")}).status_code == 422
    run = wait(client, chief, start(client, chief, name="Herramientas", control_codes=["SEG-SAST-01", "SEG-DEP-02", "SEG-DAST-01"])["id"])
    assert result(run, "SEG-SAST-01")["status"] == "FALLIDO" and result(run, "SEG-SAST-01")["method"] == "IMPORTADO"
    assert result(run, "SEG-DEP-02")["status"] == "FALLIDO"
    assert result(run, "SEG-DAST-01")["status"] == "APROBADO"
    assert any(i["tipo"] == "BANDIT" for i in client.get(f"/api/audit-center/runs/{run['id']}", headers=chief).json()["tools"]["informes_importados"])


# --- Reports --------------------------------------------------------------------------------------------------------
def test_reports_and_evidence_package(client, admin, people):
    chief = people["JEFE_TI"]["headers"]
    db = SessionLocal()
    try:
        audit(db, people["JEFE_TI"]["id"], "=HYPERLINK(\"http://example.invalid\")", "PRUEBAS", "TEST", None)  # formula injection probe
        db.commit()
    finally:
        db.close()
    run = wait(client, chief, start(client, chief, name="Informe", categories=["ACCESOS", "PRIVACIDAD"],
                                    period_from=(datetime.now(timezone.utc) - timedelta(days=2)).isoformat())["id"])
    executive = client.get(f"/api/audit-center/runs/{run['id']}/report/executive", headers=chief)
    technical = client.get(f"/api/audit-center/runs/{run['id']}/report/technical", headers=chief)
    assert executive.status_code == technical.status_code == 200
    assert executive.content.startswith(b"%PDF") and technical.content.startswith(b"%PDF") and len(technical.content) > len(executive.content)
    assert executive.headers["x-content-sha256"] == hashlib.sha256(executive.content).hexdigest()
    assert client.get(f"/api/audit-center/runs/{run['id']}/report/package?redact=false", headers=chief).status_code == 403
    package = client.get(f"/api/audit-center/runs/{run['id']}/report/package", headers=chief)
    assert package.status_code == 200 and package.headers["content-type"] == "application/zip"
    archive = zipfile.ZipFile(io.BytesIO(package.content))
    names = set(archive.namelist())
    assert {"informe-ejecutivo.pdf", "informe-tecnico.pdf", "resultados.json", "hallazgos.json", "hallazgos.csv", "metadatos.json", "manifiesto.json",
            "SHA256SUMS.txt", "registros/auditoria-actividad.csv", "registros/auditoria-actividad.json", "evidencias/indice.json"} <= names
    manifest = json.loads(archive.read("manifiesto.json"))
    assert "no es una firma digital" in manifest["alcance"].lower()
    for item in manifest["archivos"]:
        assert hashlib.sha256(archive.read(item["ruta"])).hexdigest() == item["sha256"]
    everything = b"".join(archive.read(n) for n in names if not n.endswith(".pdf")).decode("utf-8", "ignore")
    assert people["JEFE_TI"]["email"] not in everything and "admin@fixit.org" not in everything  # e-mails masked by default
    assert "'=HYPERLINK" in archive.read("registros/auditoria-actividad.csv").decode("utf-8-sig")
    assert json.loads(archive.read("metadatos.json"))["auditoria"]["verificacion_sello"] == "VALIDO"
    full = client.get(f"/api/audit-center/runs/{run['id']}/report/package?redact=false", headers=admin)
    assert full.status_code == 200 and "_sin-enmascarar" in full.headers["content-disposition"]
    reports = client.get("/api/audit-center/reports", headers=chief).json()
    mine = [r for r in reports if r["run_id"] == run["id"]]
    assert {r["kind"] for r in mine} == {"EJECUTIVO", "TECNICO", "PAQUETE"}
    db = SessionLocal()
    try:
        logged = db.scalars(select(AuditLog).where(AuditLog.action == "EXPORTAR_INFORME", AuditLog.entity_id == run["id"])).all()
        assert len(logged) == len(mine) and all(r.audit_log_id for r in db.scalars(select(AuditReport).where(AuditReport.run_id == run["id"])))
    finally:
        db.close()
    pending = client.post("/api/audit-center/runs", headers=chief, json={"name": "En cola", "control_codes": ["CON-05"]}).json()
    if pending["status"] in ("PENDIENTE", "EN_CURSO"):
        assert client.get(f"/api/audit-center/runs/{pending['id']}/report/executive", headers=chief).status_code == 409
    wait(client, chief, pending["id"])


def test_compare_and_repeat(client, people):
    chief = people["JEFE_TI"]["headers"]
    first = wait(client, chief, start(client, chief, name="Comparar", control_codes=["PRI-01", "PRI-03"])["id"])
    repeated = client.post(f"/api/audit-center/runs/{first['id']}/repeat", headers=chief)
    assert repeated.status_code == 202 and repeated.json()["parent_run_id"] == first["id"]
    second = wait(client, chief, repeated.json()["id"])
    diff = client.get(f"/api/audit-center/runs/{second['id']}/compare", headers=chief).json()
    assert diff["base"]["id"] == first["id"] and {x["control"] for x in diff["controls"]} == {"PRI-01", "PRI-03"}


def test_admin_can_disable_controls_and_jefe_cannot_run_them(client, admin, people):
    assert client.patch("/api/audit-center/controls/CON-07", headers=admin, json={"enabled": False}).json()["enabled"] is False
    assert client.post("/api/audit-center/runs", headers=people["JEFE_TI"]["headers"], json={"name": "Deshabilitado", "control_codes": ["CON-07"]}).status_code == 422
    client.patch("/api/audit-center/controls/CON-07", headers=admin, json={"enabled": True})


# --- Redaction helpers -----------------------------------------------------------------------------------------------
def test_redaction_helpers():
    assert redact_text("ALTER ROLE x PASSWORD 'abc'")[0] == "ALTER ROLE x PASSWORD '[REDACTADO]'"
    assert "s3cr3t" not in redact_text("postgresql://app:s3cr3t@db.example.com:5432/x")[0]
    assert "[REDACTADO]" in redact_text("token=abcdef123456")[0]
    assert "eyJ" not in redact_text("Authorization eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl")[0]
    assert redact_text("La contraseña mínima tiene 8 caracteres")[1] is False  # prose is not redacted
    assert mask_email("juan.perez@fixit.org") == "j***z@fixit.org" and mask_ip("190.12.34.56") == "190.12.x.x"
    assert relative_source("/home/runner/work/FixIT/backend/app/api/router.py") == "app/api/router.py"
    assert "C:\\" not in safe_error(RuntimeError("fallo en C:\\Users\\admin\\secreto\\archivo.py con password=hola"))
