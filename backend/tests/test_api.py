import os
import uuid
os.environ["DATABASE_URL"] = "sqlite:///./test_fixit.db"
from fastapi.testclient import TestClient
from app.main import app


def test_health_and_seeded_login():
    with TestClient(app) as client:
        assert client.get("/health").json()["status"] == "ok"
        response = client.post("/api/auth/login", json={"email":"admin@fixit.org","password":"FixIT!2026"})
        assert response.status_code == 200
        assert response.json()["user"]["role"] == "ADMIN"


def test_end_to_end_ticket_lifecycle():
    suffix = uuid.uuid4().hex[:8]
    with TestClient(app) as client:
        admin = client.post("/api/auth/login", json={"email":"admin@fixit.org","password":"FixIT!2026"}).json()["access_token"]
        headers = {"Authorization": f"Bearer {admin}"}
        specialty = client.post("/api/catalogs/specialties", headers=headers, json={"name":f"Redes {suffix}"}).json()["id"]
        category = client.post("/api/catalogs/categories", headers=headers, json={"name":f"Conectividad {suffix}","specialty_id":specialty}).json()["id"]
        tech_email, user_email = f"tech-{suffix}@fixit.org", f"user-{suffix}@fixit.org"
        tech_user = client.post("/api/users", headers=headers, json={"full_name":"Técnica Prueba","email":tech_email,"password":"Secure!123","role_code":"TECNICO"}).json()["id"]
        client.post("/api/technicians", headers=headers, json={"user_id":tech_user,"specialty_ids":[specialty],"max_load":5})
        client.post("/api/users", headers=headers, json={"full_name":"Solicitante Prueba","email":user_email,"password":"Secure!123","role_code":"USUARIO"})
        user_token = client.post("/api/auth/login",json={"email":user_email,"password":"Secure!123"}).json()["access_token"]
        area = client.get("/api/catalogs/areas",headers={"Authorization":f"Bearer {user_token}"}).json()[0]["id"]
        ticket = client.post("/api/tickets",headers={"Authorization":f"Bearer {user_token}"},json={"title":"Sin conectividad de oficina","description":"El equipo no puede conectarse a la red corporativa.","area_id":area,"category_id":category}).json()
        assert ticket["assigned"] is True
        assert len(ticket["number"]) <= 20
        tech_token = client.post("/api/auth/login",json={"email":tech_email,"password":"Secure!123"}).json()["access_token"]
        tech_headers={"Authorization":f"Bearer {tech_token}"}
        assert client.post(f"/api/tickets/{ticket['id']}/accept",headers=tech_headers).status_code == 200
        assert client.post(f"/api/tickets/{ticket['id']}/transition",headers=tech_headers,json={"state":"RESUELTO","diagnosis":"Cable desconectado","solution":"Se reconectó el cable y se verificó navegación."}).status_code == 200
        assert client.post(f"/api/tickets/{ticket['id']}/rating",headers={"Authorization":f"Bearer {user_token}"},json={"score":5,"solved":True,"comment":"Atención rápida"}).status_code == 201
        final = client.get(f"/api/tickets/{ticket['id']}",headers={"Authorization":f"Bearer {user_token}"}).json()
        assert final["state"] == "RESUELTO" and final["rating"] == 5
        assert client.get("/api/reports/tickets.csv",headers=headers).status_code == 200
        assert client.get("/api/reports/tickets.xlsx",headers=headers).status_code == 200
        assert client.get("/api/reports/tickets.pdf",headers=headers).status_code == 200
