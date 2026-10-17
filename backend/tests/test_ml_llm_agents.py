"""AI agents: permissions, idempotency, locking, audit, business rules and LLM observability.
Runs after test_ml_llm.py (alphabetical order) and reuses its trained models when present."""
import uuid
from datetime import date, datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import func, select

from app.agents import scheduler
from app.core.config import settings
from app.core.database import SessionLocal, engine
from app.llm import provider
from app.main import app
from app.models import AgentAlert, AgentRun, AgentState, AuditLog, LLMCall, Ticket, TicketAssignment, TicketState
from app.synthetic import importer
from app.synthetic.generator import generate

ADMIN = {"email": "admin@fixit.org", "password": "FixIT!2026"}
GEMINI_KEY = "test-secret-gemini-key-agents-123"


def login(client, email, password):
    response = client.post("/api/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        admin = login(c, **ADMIN)
        if not c.get("/api/ml/status", headers=admin).json()["trained"]:
            importer.import_dataset(engine, generate(1500, seed=5, end_date=date.today() - timedelta(days=1), days=220), replace=True)
            assert c.post("/api/ml/train", headers=admin, json={}).status_code == 200
        yield c


@pytest.fixture(scope="module")
def headers(client):
    admin = login(client, **ADMIN)
    suffix = uuid.uuid4().hex[:6]
    out = {"admin": admin}
    for role in ("USUARIO", "TECNICO", "JEFE_TI"):
        email = f"ag-{role.lower()}-{suffix}@empresa.org"
        assert client.post("/api/users", headers=admin, json={"full_name": f"Agente {role}", "email": email, "password": "Secure!123", "role_code": role}).status_code == 201
        out[role] = login(client, email, "Secure!123")
    return out


def _unassigned_ticket(client, headers) -> str:
    """A real ticket created through the API, then left without technician (as if no one was available)."""
    areas = client.get("/api/catalogs/areas", headers=headers["USUARIO"]).json()
    cats = client.get("/api/catalogs/categories", headers=headers["USUARIO"]).json()
    created = client.post("/api/tickets", headers=headers["USUARIO"], json={"title": "La impresora no imprime", "description": "La impresora del área no imprime desde ayer.",
                                                                             "area_id": areas[0]["id"], "category_id": cats[0]["id"]}).json()
    with SessionLocal() as db:
        t = db.get(Ticket, created["id"])
        t.technician_id = None
        t.state_id = db.scalar(select(TicketState.id).where(TicketState.code == "NUEVO"))
        db.commit()
    return created["id"]


def test_only_managers_administer_agents_and_monitor(client, headers):
    for role in ("USUARIO", "TECNICO"):
        h = headers[role]
        assert client.get("/api/agents", headers=h).status_code == 403
        assert client.get("/api/agents/monitor", headers=h).status_code == 403
        assert client.get("/api/agents/alerts", headers=h).status_code == 403
        assert client.post("/api/agents/sla_risk/run", headers=h, json={}).status_code == 403
        assert client.patch("/api/agents/automation", headers=h, json={"enabled": False}).status_code == 403
    assert client.get("/api/agents/monitor").status_code == 401
    assert client.post("/api/agents/sla_risk/run", headers=headers["JEFE_TI"], json={"unknown": 1}).status_code == 422

    overview = client.get("/api/agents", headers=headers["JEFE_TI"]).json()
    assert [a["name"] for a in overview["agents"]] == ["triage", "sla_risk", "assignment", "diagnosis", "automation"]
    assert all(a["why"] and a["technology"] and a["evaluation"] and "runs_30d" in a["metrics"] for a in overview["agents"])
    reg = overview["regression"]["metrics"]
    assert reg["mae_hours"] > 0 and reg["rmse_hours"] >= reg["mae_hours"] and reg["r2_hours"] is not None


def test_user_gets_triage_suggestion_without_storing_text(client, headers):
    cats = client.get("/api/catalogs/categories", headers=headers["USUARIO"]).json()
    title = f"No funciona el correo {uuid.uuid4().hex[:8]}"
    out = client.post("/api/agents/triage/suggest", headers=headers["USUARIO"],
                      json={"title": title, "description": "Outlook no envía ni recibe correos desde esta mañana", "category_id": cats[0]["id"]}).json()
    assert out["priority"]["code"] in {"BAJA", "MEDIA", "ALTA", "CRITICA"} and out["category"]["name"]
    with SessionLocal() as db:
        run = db.scalar(select(AgentRun).where(AgentRun.agent == "triage", AgentRun.trigger == "USUARIO").order_by(AgentRun.started_at.desc()))
        assert run.status == "OK" and title not in str(run.params) + str(run.result) + str(run.summary)

    batch = client.post("/api/agents/triage/run", headers=headers["JEFE_TI"], json={"limit": 10}).json()
    assert batch["status"] == "OK" and batch["result"]["evaluated"] <= 10
    assert all("predicted_hours" in i for i in batch["result"]["items"])


def test_sla_agent_alerts_once_and_is_audited(client, headers):
    h = headers["JEFE_TI"]
    first = client.post("/api/agents/sla_risk/run", headers=h, json={"threshold": 0.6}).json()
    assert first["status"] == "OK", first
    assert first["result"]["new_alerts"] > 0 and first["result"]["evaluated"] > 0
    with SessionLocal() as db:
        alerts = db.scalar(select(func.count()).select_from(AgentAlert))
        assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "AGENTE_SLA_RISK", AuditLog.entity_id == first["id"])) == 1
    second = client.post("/api/agents/sla_risk/run", headers=h, json={"threshold": 0.6}).json()
    assert second["result"]["new_alerts"] == 0 and second["result"]["duplicates_skipped"] >= first["result"]["new_alerts"]
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(AgentAlert)) == alerts


def test_concurrent_runs_are_rejected_until_the_lock_expires(client, headers):
    h = headers["JEFE_TI"]
    with SessionLocal() as db:
        state = db.get(AgentState, "triage")
        state.lock_run_id, state.lock_expires_at = "otro-proceso", datetime.now(timezone.utc) + timedelta(minutes=5)
        db.commit()
    busy = client.post("/api/agents/triage/run", headers=h, json={})
    assert busy.status_code == 409 and "ejecutando" in busy.json()["detail"]
    monitor = client.get("/api/agents/monitor", headers=h).json()
    assert next(a for a in monitor["agents"] if a["name"] == "triage")["running"] is True
    with SessionLocal() as db:
        db.get(AgentState, "triage").lock_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)  # crashed holder
        db.commit()
    assert client.post("/api/agents/triage/run", headers=h, json={}).json()["status"] == "OK"
    with SessionLocal() as db:
        assert db.get(AgentState, "triage").lock_run_id is None


def test_assignment_agent_recommends_then_assigns_safely(client, headers):
    h = headers["JEFE_TI"]
    ticket_id = _unassigned_ticket(client, headers)
    with SessionLocal() as db:
        before = db.scalar(select(func.count()).select_from(TicketAssignment).where(TicketAssignment.ticket_id == ticket_id))
    rec = client.post("/api/agents/assignment/run", headers=h, json={"ticket_id": ticket_id}).json()
    assert rec["status"] == "OK" and rec["result"]["items"][0]["action"] == "recomendado"
    with SessionLocal() as db:
        assert db.get(Ticket, ticket_id).technician_id is None  # recommending never changes the ticket

    done = client.post("/api/agents/assignment/run", headers=h, json={"ticket_id": ticket_id, "mode": "ejecutar"}).json()
    assert done["result"]["assigned"] == 1, done
    with SessionLocal() as db:
        t = db.get(Ticket, ticket_id)
        assert t.technician_id and t.state.code == "ASIGNADO"
        rows = db.scalars(select(TicketAssignment).where(TicketAssignment.ticket_id == ticket_id)).all()
        assert len(rows) == before + 1 and rows[-1].assignment_type in {"AGENTE_ML", "AGENTE_REGLAS"}
        assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "ASIGNAR_AGENTE", AuditLog.entity_id == ticket_id)) == 1
    again = client.post("/api/agents/assignment/run", headers=h, json={"ticket_id": ticket_id, "mode": "ejecutar"}).json()
    assert again["result"]["assigned"] == 0 and again["result"]["items"][0]["action"] == "omitido"


@pytest.fixture
def gemini(monkeypatch):
    monkeypatch.setattr(settings, "llm_provider", "openai_compatible")
    monkeypatch.setattr(settings, "llm_api_key", SecretStr(GEMINI_KEY))
    monkeypatch.setattr(settings, "llm_model", "gemini-3.8-flash")
    monkeypatch.setattr(settings, "llm_base_url", "https://generativelanguage.googleapis.com/v1beta/openai")
    monkeypatch.setattr(provider, "_sleep", lambda s: None)
    replies = []
    monkeypatch.setattr(provider.httpx, "post", lambda url, json, headers, timeout: replies.pop(0))
    return replies


def test_diagnosis_agent_logs_llm_metadata_only(client, headers, gemini):
    h = headers["JEFE_TI"]
    ticket = client.get("/api/tickets?limit=1&state_code=EN_ATENCION", headers=h).json()[0]
    gemini.append(httpx.Response(200, json={"choices": [{"message": {"content": "Revise el cable de red."}, "finish_reason": "stop"}]}))
    out = client.post(f"/api/llm/tickets/{ticket['id']}/suggestions", headers=h).json()
    assert out["llm_used"] is True and out["answer"] == "Revise el cable de red." and out["agent_run"]["status"] == "OK"

    gemini.extend([httpx.Response(401, json={"error": {"message": f"bad key {GEMINI_KEY}"}})])
    failed = client.post(f"/api/agents/diagnosis/tickets/{ticket['id']}", headers=h).json()
    assert failed["llm_used"] is False and failed["agent_run"]["status"] == "PARCIAL"

    with SessionLocal() as db:
        calls = db.scalars(select(LLMCall).where(LLMCall.source == "agente:diagnosis").order_by(LLMCall.created_at.desc()).limit(2)).all()
        assert [c.status for c in calls] == ["ERROR", "OK"] and calls[1].model == "gemini-3.8-flash" and calls[1].run_id
        stored = " ".join(str(getattr(c, col)) for c in calls for col in ("error", "source", "model"))
        assert GEMINI_KEY not in stored and "cable de red" not in stored and ticket["title"] not in stored
        run = db.get(AgentRun, out["agent_run"]["id"])
        assert "cable de red" not in str(run.result) and run.result["similar_cases"] >= 0

    monitor = client.get("/api/agents/monitor", headers=h).json()
    assert monitor["llm"]["stats_24h"]["ok"] >= 1 and monitor["llm"]["calls"][0]["source"] == "agente:diagnosis"
    assert GEMINI_KEY not in str(monitor)


def test_technician_diagnoses_only_own_tickets(client, headers):
    other = client.get("/api/tickets?limit=1", headers=headers["JEFE_TI"]).json()[0]
    assert client.post(f"/api/agents/diagnosis/tickets/{other['id']}", headers=headers["TECNICO"]).status_code == 403
    assert client.post(f"/api/agents/diagnosis/tickets/{other['id']}", headers=headers["USUARIO"]).status_code == 403


def test_failed_run_is_sanitized_audited_and_releases_the_lock(client, headers, monkeypatch):
    from app.agents.runner import REGISTRY

    def boom(ctx):
        raise RuntimeError(f"fallo interno con clave {GEMINI_KEY}")
    monkeypatch.setattr(REGISTRY["triage"], "func", boom)
    run = client.post("/api/agents/triage/run", headers=headers["JEFE_TI"], json={}).json()
    assert run["status"] == "ERROR" and GEMINI_KEY not in run["error"] and "RuntimeError" in run["error"]
    with SessionLocal() as db:
        assert db.get(AgentState, "triage").lock_run_id is None
        assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.entity_id == run["id"])) == 1
    monitor = client.get("/api/agents/monitor", headers=headers["JEFE_TI"]).json()
    assert next(a for a in monitor["agents"] if a["name"] == "triage")["last_error"]["error"] == run["error"]


def test_automation_tasks_are_idempotent_and_schedulable(client, headers):
    h = headers["JEFE_TI"]
    automation = next(a for a in client.get("/api/agents/monitor", headers=h).json()["agents"] if a["name"] == "automation")
    assert automation["schedule_minutes"] is None and scheduler.tick() == []  # never runs on its own until configured
    body = {"tasks": ["seguimiento_atrasados", "resumen_operativo"]}
    first = client.post("/api/agents/automation/run", headers=h, json=body).json()
    assert first["status"] == "OK", first
    tasks = first["result"]["tasks"]
    assert tasks["seguimiento_atrasados"]["candidates"] > 0 and tasks["resumen_operativo"]["notified"] is True
    second = client.post("/api/agents/automation/run", headers=h, json=body).json()["result"]["tasks"]
    assert second["seguimiento_atrasados"]["reminders"] == 0 and second["resumen_operativo"]["notified"] is False

    assert client.patch("/api/agents/sla_risk", headers=h, json={"schedule_minutes": 15}).status_code == 422
    assert client.patch("/api/agents/automation", headers=h, json={"schedule_minutes": 15}).json()["schedule_minutes"] == 15
    with SessionLocal() as db:
        db.get(AgentState, "automation").last_run_at = datetime.now(timezone.utc) - timedelta(minutes=20)
        db.commit()
    runs = scheduler.tick()
    assert [r["trigger"] for r in runs] == ["PROGRAMADA"] and runs[0]["agent"] == "automation"
    assert scheduler.tick() == []  # not due again yet
    assert client.patch("/api/agents/automation", headers=h, json={"clear_schedule": True}).json()["schedule_minutes"] is None

    assert client.patch("/api/agents/automation", headers=h, json={"enabled": False}).status_code == 200
    assert client.post("/api/agents/automation/run", headers=h, json=body).status_code == 409
    assert client.patch("/api/agents/automation", headers=h, json={"enabled": True}).status_code == 200
