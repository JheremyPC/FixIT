"""DEMO_ACCESS_TEMPORARY: one-click demo accounts on the login screen (delete with the feature)."""
import pytest
from fastapi.testclient import TestClient
from app.core.config import settings
from app.main import app
from app.security.demo_access import DEMO_ACCOUNTS

ROLES = ["ADMIN", "JEFE_TI", "TECNICO", "USUARIO"]


@pytest.fixture
def demo_enabled(monkeypatch):
    monkeypatch.setattr(settings, "demo_access_enabled", True)


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_disabled_by_default_hides_endpoints():
    assert settings.demo_access_enabled is False
    with TestClient(app) as client:
        assert client.get("/api/auth/demo").status_code == 404
        for role in ROLES:
            assert client.post(f"/api/auth/demo/{role}").status_code == 404


@pytest.mark.usefixtures("demo_enabled")
def test_lists_four_roles_without_secrets():
    with TestClient(app) as client:
        body = client.get("/api/auth/demo").json()
    assert body["enabled"] is True
    assert [r["role"] for r in body["roles"]] == ROLES
    assert all(set(r) == {"role", "label", "description"} for r in body["roles"])


@pytest.mark.usefixtures("demo_enabled")
def test_each_role_gets_a_real_session_with_its_own_permissions():
    # (path, method) -> roles allowed, taken from the real require_roles() guards.
    checks = [("/api/users", {"ADMIN"}), ("/api/settings", {"ADMIN"}), ("/api/audit", {"ADMIN", "JEFE_TI"}),
              ("/api/reports/tickets.csv", {"ADMIN", "JEFE_TI"}), ("/api/ml/status", {"ADMIN", "JEFE_TI"})]
    ids = {}
    with TestClient(app) as client:
        for role in ROLES:
            response = client.post(f"/api/auth/demo/{role}")
            assert response.status_code == 200, response.text
            data = response.json()
            ids[role] = data["user"]["id"]
            assert data["user"]["role"] == role and data["user"]["email"] == DEMO_ACCOUNTS[role]["email"]
            headers = auth(data["access_token"])
            assert client.get("/api/auth/me", headers=headers).json()["role"] == role
            assert client.get("/api/dashboard", headers=headers).status_code == 200
            for path, allowed in checks:
                assert client.get(path, headers=headers).status_code == (200 if role in allowed else 403), (role, path)
            refreshed = client.post("/api/auth/refresh", json={"refresh_token": data["refresh_token"]})
            assert refreshed.status_code == 200 and refreshed.json()["user"]["role"] == role
        # Same account on every login; the demo technician never enters the automatic assignment pool.
        assert len(set(ids.values())) == 4
        assert client.post("/api/auth/demo/TECNICO").json()["user"]["id"] == ids["TECNICO"]
        admin = auth(client.post("/api/auth/demo/ADMIN").json()["access_token"])
        techs = [t for t in client.get("/api/technicians", headers=admin).json() if t["email"] == DEMO_ACCOUNTS["TECNICO"]["email"]]
        assert len(techs) == 1 and techs[0]["available"] is False


@pytest.mark.usefixtures("demo_enabled")
def test_request_cannot_choose_role_or_account():
    with TestClient(app) as client:
        assert client.post("/api/auth/demo/SUPERADMIN").status_code == 404
        assert client.post("/api/auth/demo/admin").status_code == 404
        # Extra fields are ignored: the role comes from the server-side account.
        response = client.post("/api/auth/demo/USUARIO", json={"role": "ADMIN", "email": "admin@fixit.org"})
        assert response.json()["user"]["role"] == "USUARIO"
        assert client.get("/api/users", headers=auth(response.json()["access_token"])).status_code == 403
        # Demo accounts have an unknown random password and their domain cannot be self-registered.
        assert client.post("/api/auth/login", json={"email": DEMO_ACCOUNTS["ADMIN"]["email"], "password": "FixIT!2026"}).status_code == 401
        assert client.post("/api/auth/register", json={"full_name": "Intruso", "email": "x@demo.fixit.example", "password": "Secure!123"}).status_code == 422


@pytest.mark.usefixtures("demo_enabled")
def test_modified_demo_account_is_refused():
    with TestClient(app) as client:
        admin = auth(client.post("/api/auth/demo/ADMIN").json()["access_token"])
        jefe = client.post("/api/auth/demo/JEFE_TI").json()["user"]["id"]
        assert client.patch(f"/api/users/{jefe}", headers=admin, json={"role_code": "ADMIN"}).status_code == 200
        assert client.post("/api/auth/demo/JEFE_TI").status_code == 409
        client.patch(f"/api/users/{jefe}", headers=admin, json={"role_code": "JEFE_TI"})
        assert client.post("/api/auth/demo/JEFE_TI").status_code == 200


def test_disabling_invalidates_open_demo_sessions_and_keeps_normal_login(monkeypatch):
    with TestClient(app) as client:
        monkeypatch.setattr(settings, "demo_access_enabled", True)
        session = client.post("/api/auth/demo/ADMIN").json()
        assert client.get("/api/auth/me", headers=auth(session["access_token"])).status_code == 200
        monkeypatch.setattr(settings, "demo_access_enabled", False)
        assert client.get("/api/auth/me", headers=auth(session["access_token"])).status_code == 401
        assert client.post("/api/auth/refresh", json={"refresh_token": session["refresh_token"]}).status_code == 401
        assert client.post("/api/auth/demo/ADMIN").status_code == 404
        normal = client.post("/api/auth/login", json={"email": "admin@fixit.org", "password": "FixIT!2026"})
        assert normal.status_code == 200
        assert client.get("/api/users", headers=auth(normal.json()["access_token"])).status_code == 200
