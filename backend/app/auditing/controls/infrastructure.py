"""Category INFRAESTRUCTURA: what the application can observe about its own runtime, database connection, migrations,
configuration, internal services and errors. Provider panels (Render, Supabase) are not accessible: their configuration is
NO_VERIFICADO unless someone attaches evidence (INF-10). Values of environment variables are never read into results;
only whether they are defined."""
from __future__ import annotations

import os
import platform
import time
from importlib import metadata
from urllib.parse import parse_qs, urlsplit

from sqlalchemy import func, select, text

from app import __version__
from app.auditing import runtime
from app.auditing.controls.common import finding, iso, manual, period_text
from app.auditing.registry import Ctx, NotVerifiable, Outcome, control, fail, ok, warn
from app.core.config import BACKEND_DIR, settings
from app.models import AgentRun, LLMCall, TicketAttachment

C = "INFRAESTRUCTURA"
CRITERIA = ["NIST SP 800-92", "OWASP ASVS 5.0 V13 (configuración)", "ISO 19011"]


def _defined(name: str) -> bool:
    return bool((os.getenv(name) or "").strip())


@control("INF-01", C, "Estado y versión de la API", "Identificar versión de FixIT, compilación, intérprete y marcos, y medir la latencia de la "
         "API dentro del proceso.", "DINAMICO", "INFORMATIVO", CRITERIA)
def api_status(ctx: Ctx) -> Outcome:
    from app.auditing.controls.security import _requests
    t0 = time.perf_counter()
    responses = _requests([("GET", "/health", {}), ("GET", "/api/legal", {})])
    elapsed = round((time.perf_counter() - t0) * 1000, 1)
    def version(name):
        try: return metadata.version(name)
        except metadata.PackageNotFoundError: return None
    details = {"version_fixit": __version__, "compilacion": (os.getenv("RENDER_GIT_COMMIT") or "")[:12] or None, "python": platform.python_version(),
               "fastapi": version("fastapi"), "starlette": version("starlette"), "sqlalchemy": version("sqlalchemy"), "uvicorn": version("uvicorn"),
               "en_render": bool(os.getenv("RENDER")), "inicio_del_proceso": iso(runtime.STATE["started_at"]),
               "respuestas": [{"ruta": r["ruta"], "estado": r["estado"]} for r in responses], "latencia_en_proceso_ms": elapsed}
    if any(r["estado"] != 200 for r in responses):
        return fail("La API no responde correctamente a /health o /api/legal.", [finding("api:salud", "La API no responde correctamente",
                    "Rutas básicas con error.", "Indisponibilidad del servicio.", "Comprobado.", "Revise los registros del servidor.", "ALTO")], "ALTO", **details)
    return ok(f"FixIT {__version__} responde; latencia interna {elapsed} ms para 2 solicitudes.", **details)


@control("INF-02", C, "Conexión y latencia de la base de datos", "Medir la latencia de consultas triviales y obtener versión y tamaño de la base.",
         "SQL", "MEDIO", CRITERIA)
def db_latency(ctx: Ctx) -> Outcome:
    samples = []
    for _ in range(5):
        t0 = time.perf_counter()
        ctx.scalar("SELECT 1")
        samples.append((time.perf_counter() - t0) * 1000)
    median = round(sorted(samples)[2], 1)
    details = {"latencia_ms": [round(s, 1) for s in samples], "mediana_ms": median}
    if ctx.pg:
        details.update(ctx.one("SELECT current_setting('server_version') AS version, pg_database_size(current_database()) AS tamano_bytes") or {})
    if median > float(ctx.option("latencia_bd_max_ms", 250)):
        return warn(f"Latencia mediana de la base {median} ms.", [finding("bd:latencia", "Latencia alta de la base de datos", f"Mediana {median} ms.",
                    "Respuestas lentas de la aplicación.", "Medido en esta ejecución.", "Revise la región de la base frente a la del servicio y el pooler.", "BAJO")],
                    "BAJO", **details)
    return ok(f"Base de datos accesible; latencia mediana {median} ms.", **details)


@control("INF-03", C, "Migraciones de base de datos", "Comparar la versión de migración aplicada (alembic_version) con la última migración "
         "del código.", "SQL", "ALTO", CRITERIA)
def migrations(ctx: Ctx) -> Outcome:
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    heads = ScriptDirectory.from_config(cfg).get_heads()
    try:
        applied = [r[0] for r in ctx.conn.execute(text("SELECT version_num FROM alembic_version"))]
    except Exception:  # noqa: BLE001
        raise NotVerifiable("La tabla alembic_version no existe o no es legible (base creada sin Alembic).") from None
    details = {"aplicada": applied, "ultima_en_el_codigo": heads}
    if len(heads) != 1:
        return fail(f"El código tiene {len(heads)} cabezas de migración.", [finding("migraciones:cabezas", "Varias cabezas de migración", ", ".join(heads),
                    "alembic upgrade head falla.", "Cierta.", "Una las ramas con alembic merge.", "ALTO")], **details)
    if applied != heads:
        return fail(f"La base está en {applied or 'ninguna'} y el código en {heads[0]}.", [finding("migraciones:pendientes", "Migraciones pendientes o desconocidas",
                    f"Aplicada {applied}, esperada {heads}.", "Funciones que dependen del nuevo esquema fallan.", "Cierta.",
                    "Ejecute alembic upgrade head en el despliegue (lo hace el contenedor al iniciar).", "ALTO")], **details)
    return ok(f"Base de datos en la última migración ({heads[0]}).", **details)


@control("INF-04", C, "Variables de entorno requeridas", "Comprobar que las variables obligatorias y recomendadas están definidas, sin leer ni "
         "mostrar sus valores.", "ESTATICO", "MEDIO", CRITERIA)
def env_vars(ctx: Ctx) -> Outcome:
    required = {"DATABASE_URL": _defined("DATABASE_URL") or bool(settings.database_url), "JWT_SECRET_KEY": bool(settings.jwt_secret_key)}
    recommended = {"AUDIT_HMAC_KEY": bool(settings.audit_hmac_key and settings.audit_hmac_key.get_secret_value()),
                   "AUDIT_DATABASE_URL": bool(settings.audit_database_url and settings.audit_database_url.get_secret_value()),
                   "TRUSTED_PROXY_HOPS": _defined("TRUSTED_PROXY_HOPS")}
    optional = {k: _defined(k) for k in ("FIXIT_ADMIN_PASSWORD", "LLM_PROVIDER", "LLM_API_KEY", "ML_MODEL_DIR", "UPLOAD_DIR")}
    on_render = bool(os.getenv("RENDER"))
    details = {"obligatorias": required, "recomendadas": recommended, "opcionales": optional, "en_render": on_render,
               "trusted_proxy_hops": settings.trusted_proxy_hops, "nota": "Solo se informa si cada variable está definida; los valores no se leen."}
    missing = [k for k, v in required.items() if not v]
    if missing:
        return fail(f"Faltan variables obligatorias: {', '.join(missing)}.", [], "ALTO", **details)
    gaps = [k for k, v in recommended.items() if not v]
    if on_render and settings.trusted_proxy_hops == 0: gaps.append("TRUSTED_PROXY_HOPS=0 detrás del proxy de Render")
    if gaps:
        return warn(f"Variables recomendadas sin definir o mejorables: {', '.join(gaps)}.", [finding("config:variables", "Variables de entorno recomendadas sin definir",
                    ", ".join(gaps), "Sellos de auditoría dependientes de JWT_SECRET_KEY, auditoría con la conexión de la aplicación o IP del proxy en los registros.",
                    "Baja.", "Defínalas en Render (ver docs/auditoria.md y docs/seguridad.md).", "BAJO", {"faltantes": gaps})], "BAJO", **details)
    return ok("Variables obligatorias y recomendadas definidas.", **details)


@control("INF-05", C, "Configuración de producción", "Verificar motor de base de datos, documentación de la API, modo de depuración y uso de TLS "
         "declarado en la cadena de conexión.", "ESTATICO", "MEDIO", CRITERIA)
def production_config(ctx: Ctx) -> Outcome:
    from app.auditing.readonly import host_kind
    from app.main import app
    url = settings.database_url
    query = parse_qs(urlsplit(url).query) if not url.startswith("sqlite") else {}
    where = host_kind(url)
    details = {"motor": "PostgreSQL" if url.startswith("postgresql") else "SQLite" if url.startswith("sqlite") else "otro", "ubicacion": where,
               "sslmode_declarado": (query.get("sslmode") or [None])[0], "documentacion_api": settings.api_docs_enabled, "depuracion": app.debug,
               "en_render": bool(os.getenv("RENDER"))}
    problems = []
    if details["en_render"] and details["motor"] != "PostgreSQL": problems.append(("ALTO", "Producción sin PostgreSQL"))
    if settings.api_docs_enabled and details["en_render"]: problems.append(("MEDIO", "Documentación interactiva activa en producción"))
    if app.debug: problems.append(("ALTO", "Modo de depuración activo"))
    if where.startswith("PostgreSQL administrado") and details["sslmode_declarado"] not in ("require", "verify-ca", "verify-full"):
        problems.append(("BAJO", "DATABASE_URL no declara sslmode=require (ver BD-SEG-10 para el cifrado efectivo)"))
    if problems:
        severity = min((p[0] for p in problems), key=["CRITICO", "ALTO", "MEDIO", "BAJO"].index)
        return (fail if severity in ("ALTO", "CRITICO") else warn)("; ".join(p[1] for p in problems) + ".", [finding("config:produccion",
            "Configuración de producción mejorable", "; ".join(p[1] for p in problems), "Exposición de información o conexiones sin cifrado garantizado.",
            "Depende del punto.", "Corrija la configuración en Render.", severity)], severity, **details)
    return ok(f"{details['motor']} ({where}), sin depuración ni documentación interactiva expuesta.", **details)


@control("INF-06", C, "Servicios internos", "Comprobar el worker de automatización, el planificador de agentes, los modelos de Machine Learning "
         "y la configuración del asistente LLM (sin llamar al proveedor).", "ESTATICO", "MEDIO", CRITERIA)
def services(ctx: Ctx) -> Outcome:
    from app.llm.provider import provider_status
    from app.ml import store
    has_events = ctx.pg and bool(ctx.scalar("SELECT to_regclass('automation_events') IS NOT NULL"))
    meta = store.load_metadata() or {}
    llm = provider_status()
    details = {"worker_automatizacion": runtime.worker_running(), "cola_automatizacion_existe": has_events, "planificador_agentes": runtime.scheduler_running(),
               "modelos_ml": {"version": meta.get("version"), "entrenados_en": meta.get("trained_at"),
                              "estado": {k: v.get("status") for k, v in (meta.get("models") or {}).items()}},
               "llm": {"configurado": llm["configured"], "proveedor": llm["provider"], "modelo": llm["model"]},
               "nota": "No se envían solicitudes al proveedor LLM: solo se revisa su configuración y los resultados de llamadas registradas (INF-07)."}
    problems = []
    if has_events and runtime.worker_running() is False: problems.append("el worker de automatización se detuvo")
    if has_events and runtime.worker_running() is None: problems.append("el worker de automatización no se inició")
    if runtime.scheduler_running() is False: problems.append("el planificador de agentes se detuvo")
    if not meta: problems.append("los modelos de Machine Learning no están entrenados")
    if problems:
        return warn("Servicios con observaciones: " + "; ".join(problems) + ".", [finding("servicios:internos", "Servicios internos detenidos o no disponibles",
                    "; ".join(problems), "Automatizaciones, alertas o predicciones no se ejecutan.", "Comprobado en este proceso.",
                    "Revise los registros del servidor y reinicie el servicio si corresponde.", "MEDIO")], "MEDIO", **details)
    return ok("Servicios internos en ejecución y modelos ML disponibles.", **details)


@control("INF-07", C, "Errores registrados de servicios", "Medir la proporción de ejecuciones de agentes, llamadas al LLM y eventos de "
         "automatización fallidos en el periodo.", "SQL", "MEDIO", CRITERIA)
def service_errors(ctx: Ctx) -> Outcome:
    start, end = ctx.period()
    s = ctx.session
    agents = dict(s.execute(select(AgentRun.status, func.count()).where(AgentRun.started_at >= start, AgentRun.started_at < end).group_by(AgentRun.status)).all())
    llm = dict(s.execute(select(LLMCall.status, func.count()).where(LLMCall.created_at >= start, LLMCall.created_at < end).group_by(LLMCall.status)).all())
    automation = {}
    if ctx.pg and ctx.scalar("SELECT to_regclass('automation_events') IS NOT NULL"):
        automation = {r["status"]: r["n"] for r in ctx.rows("SELECT status, count(*) AS n FROM automation_events WHERE created_at >= :a AND created_at < :b GROUP BY status",
                                                              a=start, b=end)}
        automation["pendientes_de_mas_de_1h"] = ctx.scalar("SELECT count(*) FROM automation_events WHERE status = 'PENDING' AND created_at < now() - interval '1 hour'")
    def ratio(groups, bad):
        total = sum(v for k, v in groups.items() if not str(k).startswith("pendientes"))
        return round(100 * sum(groups.get(b, 0) for b in bad) / total, 1) if total else None
    rates = {"agentes_error_pct": ratio(agents, ("ERROR", "INTERRUMPIDA")), "llm_error_pct": ratio(llm, ("ERROR", "error")),
             "automatizacion_fallida_pct": ratio(automation, ("FAILED",))}
    details = {"periodo": period_text(ctx), "agentes": agents, "llm": llm, "automatizacion": automation, "tasas": rates}
    high = {k: v for k, v in rates.items() if v is not None and v > float(ctx.option("tasa_error_max", 20))}
    if high or automation.get("pendientes_de_mas_de_1h"):
        return warn("Tasas de error elevadas: " + ", ".join(f"{k} {v} %" for k, v in high.items()) +
                    (f"; {automation['pendientes_de_mas_de_1h']} eventos pendientes hace más de 1 h" if automation.get("pendientes_de_mas_de_1h") else "") + ".",
                    [finding("servicios:errores", "Errores frecuentes en servicios", "Proporción de fallos superior al umbral.",
                             "Funciones automáticas o de IA no disponibles para los usuarios.", "Medido en el periodo.", "Revise los mensajes de error en el monitor de agentes.",
                             "MEDIO", rates)], "MEDIO", **details)
    return ok("Tasas de error de agentes, LLM y automatización dentro del umbral.", **details)


@control("INF-08", C, "Proceso sin privilegios", "Verificar que el proceso de la aplicación no se ejecuta como superusuario del sistema operativo.",
         "ESTATICO", "MEDIO", ["CIS Docker Benchmark 4.1", "OWASP ASVS 5.0 V13"])
def unprivileged(ctx: Ctx) -> Outcome:
    getuid = getattr(os, "getuid", None)
    dockerfile = BACKEND_DIR.parent / "Dockerfile"
    declared = None
    if dockerfile.is_file():
        declared = next((l.split(None, 1)[1].strip() for l in dockerfile.read_text(encoding="utf-8").splitlines() if l.strip().upper().startswith("USER ")), None)
    details = {"uid": getuid() if getuid else None, "usuario_declarado_en_dockerfile": declared}
    if getuid is None:
        raise NotVerifiable("El sistema operativo de este entorno no expone el identificador de usuario del proceso.")
    if getuid() == 0:
        return fail("La aplicación se ejecuta como root.", [finding("proceso:root", "Proceso de la aplicación como root", "uid 0.",
                    "Una vulnerabilidad de ejecución de código daría control total del contenedor.", "Media.", "Use USER fixit en el Dockerfile.", "MEDIO")], **details)
    return ok(f"El proceso se ejecuta con uid {getuid()} (sin privilegios de root).", **details)


@control("INF-09", C, "Almacenamiento de adjuntos y evidencias", "Comprobar que el directorio de archivos es escribible y que cada adjunto y "
         "evidencia registrados existe en disco.", "ESTATICO", "ALTO", CRITERIA)
def storage(ctx: Ctx) -> Outcome:
    from app.auditing import evidence as ev
    from app.models import AuditEvidence
    folder = settings.upload_path
    attachments = ctx.session.execute(select(TicketAttachment.stored_name, TicketAttachment.size)).all()
    missing = [a for a in attachments if not (folder / a.stored_name).is_file()]
    evidences = ctx.session.execute(select(AuditEvidence.stored_name).where(AuditEvidence.stored_name.is_not(None))).all()
    missing_ev = [e for e in evidences if not (ev.evidence_dir() / e.stored_name).is_file()]
    details = {"escribible": os.access(folder, os.W_OK), "adjuntos_registrados": len(attachments), "adjuntos_sin_archivo": len(missing),
               "bytes_registrados": sum(a.size or 0 for a in attachments), "evidencias_registradas": len(evidences), "evidencias_sin_archivo": len(missing_ev),
               "en_render": bool(os.getenv("RENDER")),
               "nota": "En Render el disco del servicio es efímero salvo que se configure un disco persistente; no es verificable desde la aplicación."}
    if missing or missing_ev:
        return fail(f"{len(missing)} adjuntos y {len(missing_ev)} evidencias registrados no existen en disco.", [finding("almacenamiento:perdida",
                    "Archivos registrados que ya no existen", f"{len(missing)} adjuntos y {len(missing_ev)} evidencias.", "Pérdida de evidencias de tickets y de auditoría.",
                    "Cierta: ya ocurrió (típico de discos efímeros tras un redespliegue).", "Configure almacenamiento persistente (disco de Render o almacenamiento "
                    "de objetos) y restaure desde respaldo si existe.", "ALTO", {"adjuntos": len(missing), "evidencias": len(missing_ev)})], **details)
    if not details["escribible"]:
        return fail("El directorio de archivos no es escribible.", [], "ALTO", **details)
    if details["en_render"] and attachments:
        return warn("Los archivos existen, pero se guardan en el disco local del servicio de Render.", [finding("almacenamiento:efimero",
                    "Adjuntos en almacenamiento posiblemente efímero", "Los adjuntos se guardan en el disco local del contenedor.",
                    "Un redespliegue podría borrarlos.", "Alta si no hay disco persistente.", "Configure un disco persistente o almacenamiento de objetos y "
                    "adjunte la evidencia en INF-10.", "MEDIO")], "MEDIO", **details)
    return ok(f"Directorio escribible; los {len(attachments)} adjuntos y {len(evidences)} evidencias registrados existen.", **details)


@control("INF-10", C, "Configuración de Render y Supabase", "Registrar con evidencia la configuración revisada en los paneles del proveedor "
         "(región, plan, disco persistente, despliegue automático, Security Advisor de Supabase).", "MANUAL", "MEDIO", CRITERIA, evidence_days=180,
         guidance="Adjunte capturas o exportaciones de los paneles de Render (servicio, disco, variables sin valores) y de Supabase (Security Advisor, "
                  "copias de seguridad, red) con la fecha de revisión y el resultado declarado.")
def provider_panels(ctx: Ctx) -> Outcome:
    return manual(ctx)
