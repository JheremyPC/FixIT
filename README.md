# FixIT

Sistema Integral de Gestión de Soporte Técnico: FastAPI, PostgreSQL y una interfaz web sin dependencias de frontend.

## Inicio rápido con Docker

1. Copie `.env.example` a `.env` y reemplace `POSTGRES_PASSWORD` y `JWT_SECRET_KEY` por valores seguros.
2. Ejecute `docker compose up --build`.
3. Abra [http://localhost:8000](http://localhost:8000).
4. Inicie como `admin@fixit.org` con contraseña `FixIT!2026`, cree los demás usuarios y no use estas credenciales de inicio fuera de un entorno local.

El servicio espera a PostgreSQL, aplica la migración Alembic `0001_initial`, crea los catálogos base y la cuenta inicial solo si no existen.

## Ejecución local sin Docker

Requiere Python 3.12 y PostgreSQL. Cree un entorno virtual, instale `pip install -r requirements.txt`, configure `DATABASE_URL` en `.env`, y desde `backend` ejecute:

```powershell
alembic upgrade head
uvicorn app.main:app --reload
```

Para desarrollo muy rápido, si no existe `DATABASE_URL`, la app crea `backend/fixit.db` SQLite. PostgreSQL es la configuración objetivo para producción.

## Pruebas

Desde `backend`:

```powershell
$env:PYTHONPATH = "."
pytest -q
```

## Flujo operativo

1. FixIT carga áreas, prioridad y una categoría general al arrancar. El administrador puede añadir especialidades y categorías; luego usuarios técnicos y sus perfiles/especialidades.
2. El usuario crea un ticket. FixIT aplica el SLA de prioridad y ejecuta la asignación ponderada.
3. El técnico acepta, registra diagnóstico/solución y resuelve.
4. El usuario confirma/cierra o reabre; después califica una única vez.
5. Historial, notificaciones y auditoría se generan en cada acción relevante. Jefe de TI y administrador supervisan dashboard, auditoría y CSV.

## Seguridad y límites de esta versión

- Contraseñas con bcrypt, JWT de acceso/refresh, RBAC y verificación de propiedad por ticket.
- Validación Pydantic, errores sin detalles internos y adjuntos protegidos.
- Configure TLS, secreto de JWT, CORS institucional, rotación/invalidación de refresh tokens y almacenamiento externo de adjuntos antes de exponerlo a Internet.
- No se implementaron IA, RAG, MQTT, PLC ni ML. `AssignmentService` es el punto de extensión para inteligencia/predicción futura.
