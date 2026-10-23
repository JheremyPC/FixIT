# FixIT

Sistema Integral de Gestión de Soporte Técnico: FastAPI, PostgreSQL y una interfaz web sin dependencias de frontend, con Machine Learning predictivo y un asistente LLM.

- **Roles:** ADMIN, JEFE_TI, TECNICO y USUARIO, cada uno con su propio panel.
- **Operación:** tickets, asignación automática ponderada, comentarios, adjuntos, calificaciones, notificaciones, auditoría y reportes (CSV, Excel, PDF).
- **IA (solo ADMIN y JEFE_TI):** tiempo de resolución estimado, riesgo de incumplir SLA con explicación de factores, recomendación de técnicos, proyección de demanda, patrones por periodo/categoría/prioridad/técnico, simulador y métricas de evaluación. Ver [docs/inteligencia-artificial.md](docs/inteligencia-artificial.md).
- **Asistente LLM (todos los roles):** chat, resumen de tickets, sugerencias de diagnóstico y búsqueda contextual en el historial, respetando los permisos de cada usuario.
- **Datos sintéticos:** generador reproducible de 5.000 tickets, solo para bases locales. Ver [docs/datos-sinteticos.md](docs/datos-sinteticos.md).

## Inicio rápido con Docker (desarrollo local)

1. Copie `.env.example` a `.env` y defina `POSTGRES_PASSWORD`, `JWT_SECRET_KEY` y `FIXIT_ADMIN_PASSWORD`.
2. `docker compose up --build`
3. Abra <http://localhost:8000> e inicie sesión como `admin@fixit.org` con la contraseña de `FIXIT_ADMIN_PASSWORD`.

En Docker Compose la API usa **siempre el servicio local `db`**, aunque `.env` contenga la URL de producción (Supabase). Para apuntar a otra base defina explícitamente `COMPOSE_DATABASE_URL`.

### Datos de demostración y entrenamiento (3 comandos)

```bash
docker compose up -d --build
docker compose exec api python -m app.synthetic import --csv /srv/fixit/outputs/fixit_synthetic_tickets.csv
# Los modelos ML se entrenan al iniciar si no hay modelos guardados (Machine Learning → «Entrenar ahora» para reentrenar)
```

El importador rechaza cualquier base remota (Supabase, Render, etc.). Las cuentas de demostración son `<nombre>@sintetico.fixit.example` con la contraseña `Demo!2026` (configurable con `FIXIT_SYNTHETIC_PASSWORD`).

<!-- DEMO_ACCESS_TEMPORARY: begin -->
### Accesos de demostración (temporal)

Con `DEMO_ACCESS_ENABLED=true` el login muestra un panel para entrar con un clic como Administrador, Jefe de TI, Técnico o Usuario. El backend emite una sesión normal (JWT) para una cuenta fija por rol (`demo.*@demo.fixit.example`, contraseña aleatoria que nadie conoce), así que se aplican los permisos reales de cada rol. El técnico de demostración queda «no disponible» para que la asignación automática no le envíe tickets reales.

Está **desactivado por defecto**; al volver a `false` (o quitar la variable) y reiniciar, el panel desaparece, los endpoints `/api/auth/demo*` responden 404 y las sesiones demo abiertas dejan de ser válidas. La cuenta demo de administrador tiene permisos completos: no lo active en producción. Todo el código está marcado con `DEMO_ACCESS_TEMPORARY`.
<!-- DEMO_ACCESS_TEMPORARY: end -->

## Ejecución local sin Docker

Requiere Python 3.12 y PostgreSQL (o SQLite para pruebas rápidas). Desde la raíz:

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
cd backend
$env:DATABASE_URL = "postgresql+psycopg://fixit:clave@localhost:5432/fixit"   # o sqlite:///./fixit.db
alembic upgrade head
uvicorn app.main:app --reload
```

La configuración se lee de variables de entorno y del archivo `.env` de la raíz; las variables de entorno tienen prioridad.

## Pruebas

```powershell
cd backend
$env:PYTHONPATH = "."
..\.venv\Scripts\python -m pytest -q
```

`tests/conftest.py` crea una base SQLite temporal y una carpeta de modelos temporal; las pruebas nunca usan la base configurada en `.env` ni un proveedor LLM real.

## Producción (Render + Supabase)

- No hay cambios de tablas. La migración `0002_skip_synthetic_automation` solo modifica la función de Supabase `fixit_enqueue_automation_event()` para que una importación de demostración no genere eventos de automatización; en bases sin esa función no hace nada. Los registros sintéticos se identifican por el prefijo `SYN-` y el dominio `@sintetico.fixit.example`; nunca se cargan automáticamente en Supabase (procedimiento manual en `docs/datos-sinteticos.md`).
- Variables nuevas opcionales en Render: `LLM_PROVIDER`, `LLM_API_KEY`, `LLM_MODEL`, `ML_MODEL_DIR` (ver `.env.example`).
- Los modelos entrenados se guardan en la base de datos (tabla `ml_artifacts`, migración `0003_ml_artifacts`) y se cargan al iniciar, aunque el disco de Render sea efímero. Si cambia `JWT_SECRET_KEY`, se reentrenan automáticamente en el siguiente arranque.
- Agentes de IA y monitor del LLM: tablas de la migración `0004_agents_observability` (ver docs/inteligencia-artificial.md).
- El worker de automatización solo se inicia con PostgreSQL y si existe la tabla `automation_events` (Supabase); en bases locales se desactiva con un aviso.

## Flujo operativo

1. FixIT carga roles, áreas, prioridades y estados al arrancar. El administrador crea usuarios, técnicos y catálogos.
2. El usuario crea un ticket; FixIT aplica el SLA de la prioridad y ejecuta la asignación ponderada.
3. El técnico acepta, puede poner en espera, escalar o registrar la solución.
4. El solicitante confirma y cierra o reabre; después califica una única vez.
5. Historial, notificaciones y auditoría se generan en cada acción. Jefe de TI y administrador supervisan paneles, IA, auditoría y reportes.

## Seguridad

- Contraseñas con bcrypt, JWT de acceso/refresh (renovación automática en el cliente), RBAC y verificación de propiedad por ticket.
- Endpoints de ML exclusivos de ADMIN y JEFE_TI. La búsqueda y el asistente solo usan tickets que el usuario puede ver.
- La API key del LLM vive únicamente en el backend (`SecretStr`); nunca se envía al navegador ni se registra en logs. Las conversaciones no se guardan en la auditoría, solo el uso.
- Configure TLS, CORS institucional, rotación de refresh tokens y almacenamiento externo de adjuntos antes de exponerlo a Internet.
