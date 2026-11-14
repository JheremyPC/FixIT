"""Category CONTINUIDAD: backups, restoration, recovery tests, critical dependencies and data loss risks.

Backups and restorations are managed by the providers (Supabase, Render) and cannot be observed by the application:
those controls require evidence attached by a person and are NO_VERIFICADO without it. No restoration or deletion is ever
performed by an audit."""
from __future__ import annotations

import os

from sqlalchemy import func, select

from app.auditing import runtime
from app.auditing.controls.common import finding, manual
from app.auditing.registry import Ctx, Outcome, control, fail, ok, warn
from app.core.config import settings

C = "CONTINUIDAD"
CRITERIA = ["ISO 19011", "NIST SP 800-34 (planificación de contingencias, referencia)"]


@control("CON-01", C, "Estrategia de respaldos documentada", "Verificar con evidencia la estrategia de respaldos (qué se respalda, frecuencia, "
         "retención y ubicación).", "MANUAL", "ALTO", CRITERIA, evidence_days=365,
         guidance="Adjunte el documento de estrategia de respaldos aprobado (por ejemplo, respaldos diarios de Supabase y su retención) con el resultado declarado.")
def backup_strategy(ctx: Ctx) -> Outcome:
    return manual(ctx)


@control("CON-02", C, "Evidencia de respaldo reciente", "Verificar con evidencia que existe un respaldo de la base de datos de los últimos 7 días.",
         "MANUAL", "ALTO", CRITERIA, evidence_days=7,
         guidance="Adjunte una captura de Supabase → Database → Backups que muestre la fecha del último respaldo, indicando esa fecha como fecha de evidencia.")
def recent_backup(ctx: Ctx) -> Outcome:
    return manual(ctx)


@control("CON-03", C, "Procedimiento de restauración", "Verificar con evidencia que existe un procedimiento de restauración documentado.",
         "MANUAL", "ALTO", CRITERIA, evidence_days=365, guidance="Adjunte el procedimiento de restauración (pasos, responsables, tiempos objetivo RTO/RPO).")
def restore_procedure(ctx: Ctx) -> Outcome:
    return manual(ctx)


@control("CON-04", C, "Prueba de restauración", "Verificar con evidencia una prueba de restauración realizada en los últimos 180 días en un entorno "
         "separado.", "MANUAL", "ALTO", CRITERIA, evidence_days=180,
         guidance="Adjunte el acta de la prueba de restauración (fecha, entorno de destino, tiempo empleado, verificación de datos) con su resultado.")
def restore_test(ctx: Ctx) -> Outcome:
    return manual(ctx)


@control("CON-05", C, "Dependencias críticas", "Inventariar los servicios de los que depende FixIT y su efecto si fallan.", "ESTATICO", "BAJO", CRITERIA)
def dependencies(ctx: Ctx) -> Outcome:
    from app.auditing.readonly import host_kind
    from app.llm.provider import provider_status
    llm = provider_status()
    deps = [{"servicio": host_kind(settings.database_url), "funcion": "Datos de FixIT, auditoría y modelos ML", "si_falla": "La aplicación no funciona"},
            {"servicio": "Render (alojamiento)" if os.getenv("RENDER") else "Servidor de aplicación", "funcion": "API y cliente web", "si_falla": "Servicio no disponible"},
            {"servicio": "Disco local del servicio", "funcion": "Adjuntos y evidencias de auditoría", "si_falla": "Pérdida de archivos"}]
    if llm["configured"]: deps.append({"servicio": f"Proveedor de IA ({llm['provider']})", "funcion": "Asistente y diagnóstico", "si_falla": "Funciones de IA no disponibles; el resto sigue"})
    single = [d["servicio"] for d in deps if d["si_falla"] in ("La aplicación no funciona", "Servicio no disponible")]
    return warn(f"{len(deps)} dependencias críticas; {len(single)} son puntos únicos de falla sin redundancia verificable desde la aplicación.",
                [finding("continuidad:dependencias", "Puntos únicos de falla", ", ".join(single), "Interrupción total del servicio si fallan.",
                         "Depende de los acuerdos de servicio de los proveedores (no verificables aquí).", "Documente los SLA de los proveedores y el plan de contingencia (CON-07).",
                         "BAJO")], "BAJO", dependencias=deps)


@control("CON-06", C, "Riesgos de pérdida de datos", "Identificar datos sin respaldo gestionado: archivos en disco local y registros sin copia externa.",
         "ESTATICO", "MEDIO", CRITERIA)
def data_loss(ctx: Ctx) -> Outcome:
    from app.models import AuditEvidence, MLArtifact, TicketAttachment
    s = ctx.session
    files = s.scalar(select(func.count(TicketAttachment.id))) or 0
    size = s.scalar(select(func.coalesce(func.sum(TicketAttachment.size), 0))) or 0
    evidences = s.scalar(select(func.count(AuditEvidence.id)).where(AuditEvidence.stored_name.is_not(None))) or 0
    ml = s.scalar(select(func.count(MLArtifact.name))) or 0
    risks = []
    if files or evidences:
        risks.append(f"{files} adjuntos ({size // 1024} KiB) y {evidences} evidencias se guardan en el disco del servicio, fuera de los respaldos de la base")
    details = {"adjuntos": files, "bytes_adjuntos": size, "evidencias": evidences, "modelos_ml_en_bd": ml, "riesgos": risks,
               "protegido": ["Datos de tickets, usuarios y auditoría en la base (respaldos del proveedor, ver CON-02)", "Modelos ML guardados en la base"]}
    if risks:
        return warn("; ".join(risks) + ".", [finding("continuidad:archivos_locales", "Archivos fuera de los respaldos de la base", risks[0],
                    "Pérdida de adjuntos y evidencias ante un redespliegue o falla del disco.", "Alta en discos efímeros.",
                    "Use almacenamiento persistente con respaldo (disco de Render con snapshots o almacenamiento de objetos).", "MEDIO")], "MEDIO", **details)
    return ok("No hay archivos fuera de la base de datos; los modelos ML están en la base.", **details)


@control("CON-07", C, "Plan de contingencia", "Verificar con evidencia la existencia de un plan de contingencia con responsables y comunicación.",
         "MANUAL", "MEDIO", CRITERIA, evidence_days=365, guidance="Adjunte el plan de contingencia aprobado (escenarios, responsables, contactos, comunicación).")
def contingency(ctx: Ctx) -> Outcome:
    return manual(ctx)


@control("CON-08", C, "Disponibilidad de servicios críticos", "Comprobar en esta ejecución que la base responde, el esquema está en la última "
         "migración y los procesos internos están activos.", "SQL", "ALTO", CRITERIA)
def availability(ctx: Ctx) -> Outcome:
    from app.auditing.controls.infrastructure import migrations
    db_ok = ctx.scalar("SELECT 1") == 1
    try:
        migration = migrations(ctx).status
    except Exception:  # noqa: BLE001 - reported as unknown, not as approved
        migration = "NO_VERIFICADO"
    worker = runtime.worker_running()
    details = {"base_de_datos": db_ok, "migraciones": migration, "worker_automatizacion": worker, "planificador": runtime.scheduler_running()}
    if not db_ok: return fail("La base de datos no responde.", [], "CRITICO", **details)
    if migration == "FALLIDO": return fail("El esquema no está en la última migración (INF-03).", [], "ALTO", **details)
    if worker is False: return warn("El worker de automatización se detuvo.", [], "MEDIO", **details)
    return ok("Base de datos disponible" + (", esquema actualizado" if migration == "APROBADO" else "") + " y procesos internos activos o no requeridos.", **details)
