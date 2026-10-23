"""DEMO_ACCESS_TEMPORARY: demo accounts behind the "Accesos de demostración" panel of the login screen.

Disabled unless DEMO_ACCESS_ENABLED=true. To remove the feature, delete this file, app/api/demo_access.py,
app/static/demo-access.js, tests/test_demo_access.py and every line tagged DEMO_ACCESS_TEMPORARY.
"""
from app.core.config import settings

DEMO_EMAIL_DOMAIN = "demo.fixit.example"

# Fixed, server-side mapping: the client only chooses one of these keys. Each key is bound to one account
# whose role lives in the database, so a request can never pick a different role or account.
DEMO_ACCOUNTS = {
    "ADMIN": {"email": f"demo.admin@{DEMO_EMAIL_DOMAIN}", "full_name": "Demo Administrador", "label": "Administrador",
              "description": "Usuarios, catálogos, configuración, auditoría e IA."},
    "JEFE_TI": {"email": f"demo.jefe@{DEMO_EMAIL_DOMAIN}", "full_name": "Demo Jefe de TI", "label": "Jefe de TI",
                "description": "Supervisión, asignación, reportes e IA."},
    "TECNICO": {"email": f"demo.tecnico@{DEMO_EMAIL_DOMAIN}", "full_name": "Demo Técnico", "label": "Técnico",
                "description": "Atiende y resuelve los tickets asignados."},
    "USUARIO": {"email": f"demo.usuario@{DEMO_EMAIL_DOMAIN}", "full_name": "Demo Usuario", "label": "Usuario",
                "description": "Crea tickets y sigue su avance."},
}


def is_demo_email(email: str) -> bool:
    return email.lower().endswith("@" + DEMO_EMAIL_DOMAIN)


def demo_session_blocked(user) -> bool:
    """Demo sessions stop working as soon as DEMO_ACCESS_ENABLED is turned off."""
    return not settings.demo_access_enabled and is_demo_email(user.email)
