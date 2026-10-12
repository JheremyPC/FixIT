from datetime import date

import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.orm import Session

from app.models import Area, Category, Priority, Role, Ticket, TicketState, User
from app.services.tickets import TRANSITIONS
from app.synthetic import importer
from app.synthetic.__main__ import main as cli
from app.synthetic.generator import generate

END = date(2026, 6, 30)


def test_generator_is_reproducible():
    a = generate(300, seed=7, end_date=END, days=120)
    b = generate(300, seed=7, end_date=END, days=120)
    assert [t["id"] for t in a.tickets] == [t["id"] for t in b.tickets]
    assert a.summary() == b.summary()
    assert generate(300, seed=8, end_date=END, days=120).summary() != a.summary()


def test_generated_lifecycles_follow_business_rules():
    ds = generate(600, seed=3, end_date=END, days=150)
    anchor = ds.params["anchor"]
    assert len(ds.tickets) == 600 and len({t["number"] for t in ds.tickets}) == 600
    events = {}
    for h in ds.history:
        events.setdefault(h["ticket_id"], []).append(h)
    for t in ds.tickets:
        assert t["number"].startswith("SYN-")
        assert t["created_at"].isoformat() <= anchor and t["updated_at"].isoformat() <= anchor
        state = "NUEVO"
        for h in events[t["id"]]:
            if h["event"] == "ASIGNADO":
                state = "ASIGNADO"
            if h["event"] == "ESTADO_CAMBIADO":
                target = h["new_value"]["state"]
                assert h["old_value"]["state"] == state
                assert target in TRANSITIONS[state], f"{t['number']}: {state} -> {target}"
                state = target
        assert state == t["state"]
        if t["state"] in {"RESUELTO", "CERRADO"}:
            assert t["solution"] and t["resolved_at"] and t["technician_key"]
        if t["state"] == "CANCELADO":
            assert t["resolved_at"] is None
        if t["resolved_at"]:
            assert t["created_at"] <= t["started_at"] <= t["resolved_at"]


@pytest.mark.parametrize("url", [
    "postgresql+psycopg://u:p@aws-0-sa-east-1.pooler.supabase.com:6543/postgres",
    "postgresql+psycopg://u:p@db.abcdefgh.supabase.co:5432/postgres",
    "postgresql://u:p@dpg-xyz.oregon-postgres.render.com/fixit",
    "postgresql://u:p@10.0.0.5:5432/fixit",
])
def test_remote_targets_are_rejected(url, monkeypatch):
    monkeypatch.delenv("FIXIT_ALLOW_REMOTE_SYNTHETIC", raising=False)
    with pytest.raises(importer.UnsafeTargetError):
        importer.assert_local(url)
    with pytest.raises(importer.UnsafeTargetError):
        importer.assert_remote_confirmed(url, None)
    assert cli(["import", "--database-url", url, "--count", "10"]) == 2


def test_remote_requires_env_and_exact_host(monkeypatch):
    url = "postgresql://u:p@db.abcdefgh.supabase.co:5432/postgres"
    monkeypatch.setenv("FIXIT_ALLOW_REMOTE_SYNTHETIC", "1")
    with pytest.raises(importer.UnsafeTargetError):
        importer.assert_remote_confirmed(url, "otro-host")
    assert importer.assert_remote_confirmed(url, "db.abcdefgh.supabase.co")["local"] is False


def test_local_targets_are_accepted():
    for url in ("sqlite:///./x.db", "postgresql+psycopg://u:p@localhost:5432/fixit", "postgresql+psycopg://u:p@db:5432/fixit"):
        assert importer.assert_local(url)["local"] is True


def test_import_is_idempotent_and_purge_keeps_real_tickets(tmp_path):
    engine = create_engine(f"sqlite:///{(tmp_path / 'syn.db').as_posix()}")
    importer._ensure_base(engine)
    with Session(engine) as db:  # a real ticket that must survive every synthetic operation
        user = User(full_name="Persona Real", email="real@empresa.org", password_hash="x", role_id=db.scalar(select(Role.id).where(Role.code == "USUARIO")))
        db.add(user)
        db.flush()
        db.add(Ticket(number="FIX-REAL-0001", title="Ticket real", description="Descripción real del problema", requester_id=user.id,
                      area_id=db.scalar(select(Area.id)), category_id=db.scalar(select(Category.id)), priority_id=db.scalar(select(Priority.id)),
                      state_id=db.scalar(select(TicketState.id).where(TicketState.code == "NUEVO"))))
        db.commit()

    ds = generate(250, seed=11, end_date=END, days=100)
    result = importer.import_dataset(engine, ds)
    assert result["imported"]["tickets"] == 250
    with pytest.raises(importer.SyntheticDataExists):
        importer.import_dataset(engine, ds)
    importer.import_dataset(engine, ds, replace=True)
    status = importer.status(engine)
    assert status["tickets_synthetic"] == 250 and status["tickets_real"] == 1 and status["dataset"]["params"]["seed"] == 11
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA foreign_key_check")).fetchall() == []

    importer.purge(engine)
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(Ticket)) == 1
        assert db.scalar(select(Ticket.number)) == "FIX-REAL-0001"
        assert db.scalar(select(func.count()).select_from(User).where(importer.synthetic_user_filter())) == 0
