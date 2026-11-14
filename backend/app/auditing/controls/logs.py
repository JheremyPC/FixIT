"""Category REGISTROS: the activity trail (audit_logs, HMAC seals, append-only trigger), its continuity and quality, the coverage
of security events, exports, and the integrity of the audit center's own results.

Three related but different things are distinguished: activity records (what users did), security records (logins,
denials, exports: a subset of audit_logs) and audit results (what the audit center concluded: audit_runs/audit_results).
"""
from __future__ import annotations

import inspect
import time
from datetime import timedelta

from sqlalchemy import func, select

from app.auditing.controls.common import day_range, finding, iso, manual, period_text
from app.auditing.registry import Ctx, NotVerifiable, Outcome, control, fail, not_applicable, ok, warn
from app.models import AuditLog, AuditReport, AuditResult, AuditRun, Ticket, TicketHistory
from app.services.audit import INTEGRITY, verify
from app.synthetic.catalog import SYNTHETIC_TICKET_PREFIX

C = "REGISTROS"
CRITERIA = ["OWASP Logging Cheat Sheet", "NIST SP 800-92"]
SECURITY_ACTIONS = ("LOGIN", "LOGIN_FALLIDO", "LOGIN_BLOQUEADO", "ACCESO_DENEGADO", "EXPORTAR", "EXPORTAR_INFORME", "REGISTRO", "DESACTIVAR_CUENTA_DEMO",
                    "DESCARGAR_EVIDENCIA")


@control("REG-01", C, "Verificación de sellos HMAC de la auditoría", "Recalcular el sello HMAC-SHA256 de cada registro de audit_logs y "
         "clasificarlos en VALIDO, ALTERADO, SIN_SELLO o CLAVE_DISTINTA.", "SQL", "CRITICO", CRITERIA)
def hmac_seals(ctx: Ctx) -> Outcome:
    budget = float(ctx.option("segundos_max_hmac", 300))
    started = time.monotonic()
    counts = {k: 0 for k in INTEGRITY}
    altered, partial = [], False
    total = ctx.session.scalar(select(func.count(AuditLog.id))) or 0
    for row in ctx.session.scalars(select(AuditLog).order_by(AuditLog.created_at, AuditLog.id).execution_options(yield_per=2000)):
        status = verify(row)
        counts[status] += 1
        if status == "ALTERADO" and len(altered) < 50: altered.append({"id": row.id, "fecha": iso(row.created_at), "accion": row.action, "modulo": row.module})
        if time.monotonic() - started > budget:
            partial = True
            break
    checked = sum(counts.values())
    oldest_sealed = ctx.session.scalar(select(func.min(AuditLog.created_at)).where(AuditLog.integrity_hash.is_not(None)))
    details = {"registros_totales": total, "verificados": checked, "por_estado": counts, "alterados": altered, "parcial": partial,
               "primer_registro_sellado": iso(oldest_sealed), "estados": INTEGRITY,
               "alcance": "El sello detecta cambios en un registro; no detecta registros eliminados por quien pueda desactivar el trigger."}
    if counts["ALTERADO"]:
        return fail(f"{counts['ALTERADO']} registros de auditoría no coinciden con su sello.", [finding(
            "auditoria:registros_alterados", "Registros de auditoría alterados", f"{counts['ALTERADO']} registros fueron modificados después de crearse.",
            "La evidencia de actividad no es confiable para esos registros; posible manipulación.", "Comprobado criptográficamente.",
            "Preserve una copia de la base, investigue quién tuvo acceso de escritura y compare con respaldos.", "CRITICO", {"muestra": altered})],
            "CRITICO", **details)
    if partial:
        raise NotVerifiable(f"Verificación parcial: {checked} de {total} registros en {int(budget)} s, sin alteraciones en los revisados. "
                            "Aumente segundos_max_hmac o acote el periodo.")
    findings = []
    if counts["CLAVE_DISTINTA"]:
        findings.append(finding("auditoria:clave_distinta", "Registros sellados con otra clave", f"{counts['CLAVE_DISTINTA']} registros usan otra clave de sello.",
                                "No pueden verificarse con la clave actual (rotación de JWT_SECRET_KEY o AUDIT_HMAC_KEY).", "Comprobado.",
                                "Conserve la clave anterior de forma segura para verificarlos y defina AUDIT_HMAC_KEY estable.", "MEDIO"))
    if counts["SIN_SELLO"]:
        findings.append(finding("auditoria:sin_sello", "Registros de auditoría sin sello", f"{counts['SIN_SELLO']} registros no tienen sello.",
                                "Su integridad no puede comprobarse (anteriores a la migración 0005 o insertados fuera de la aplicación).",
                                "Comprobado.", "Si son posteriores a la migración 0005, investigue su origen.", "BAJO",
                                {"primer_registro_sellado": iso(oldest_sealed)}))
    if findings: return warn(f"{counts['VALIDO']} de {checked} registros con sello válido; hay registros no verificables.", findings, **details)
    return ok(f"Los {checked} registros de auditoría tienen sello válido.", **details)


@control("REG-02", C, "Protección de solo inserción", "Verificar en PostgreSQL que los triggers que rechazan UPDATE, DELETE y TRUNCATE sobre "
         "audit_logs existen y están habilitados.", "SQL", "CRITICO", CRITERIA, requires=("postgresql",))
def append_only(ctx: Ctx) -> Outcome:
    rows = ctx.rows("""SELECT t.tgname AS trigger, t.tgenabled AS habilitado, p.proname AS funcion FROM pg_trigger t
                       JOIN pg_class c ON c.oid = t.tgrelid JOIN pg_proc p ON p.oid = t.tgfoid
                       WHERE c.oid = to_regclass('audit_logs') AND NOT t.tgisinternal""")
    by = {r["trigger"]: r for r in rows}
    expected = ("audit_logs_append_only", "audit_logs_no_truncate")
    missing = [t for t in expected if t not in by or by[t]["habilitado"] == "D"]
    details = {"triggers": rows, "limitacion": "El propietario de la tabla puede desactivar los triggers; el control lo detecta en cada ejecución."}
    if missing:
        return fail(f"Protección de solo inserción ausente o deshabilitada: {', '.join(missing)}.", [finding(
            "auditoria:solo_insercion", "audit_logs sin protección de solo inserción", f"Triggers ausentes o deshabilitados: {', '.join(missing)}.",
            "Los registros de auditoría pueden modificarse o borrarse sin dejar rastro.", "Comprobado.",
            "Vuelva a aplicar la migración 0005 (alembic upgrade head) e investigue por qué se desactivó.", "CRITICO")], "CRITICO", **details)
    return ok("Los triggers de solo inserción de audit_logs existen y están habilitados.", **details)


@control("REG-03", C, "Continuidad del registro", "Detectar días del periodo con actividad de tickets reales pero sin ningún registro de "
         "auditoría (posible interrupción) y registros con fecha futura.", "SQL", "MEDIO", CRITERIA)
def continuity(ctx: Ctx) -> Outcome:
    start, end = ctx.period()
    s = ctx.session
    audit_days = {str(d)[:10] for (d,) in s.execute(select(func.date(AuditLog.created_at)).where(AuditLog.created_at >= start, AuditLog.created_at < end).distinct())}
    activity_days = {str(d)[:10] for (d,) in s.execute(select(func.date(TicketHistory.created_at)).join(Ticket, Ticket.id == TicketHistory.ticket_id)
                     .where(TicketHistory.created_at >= start, TicketHistory.created_at < end, ~Ticket.number.like(f"{SYNTHETIC_TICKET_PREFIX}%")).distinct())}
    gaps = sorted(activity_days - audit_days)
    future = s.scalar(select(func.count(AuditLog.id)).where(AuditLog.created_at > ctx.now + timedelta(minutes=5))) or 0
    details = {"periodo": period_text(ctx), "dias_del_periodo": len(day_range(start, end)), "dias_con_auditoria": len(audit_days),
               "dias_con_actividad_real": len(activity_days), "dias_con_actividad_sin_auditoria": gaps[:60], "registros_con_fecha_futura": future,
               "criterio": "Toda acción sobre tickets reales genera también un registro de auditoría; un día con actividad y sin auditoría es "
                           "evidencia de una posible interrupción. Los tickets sintéticos (SYN-) se excluyen."}
    if future:
        return fail(f"{future} registros de auditoría tienen fecha futura.", [finding("auditoria:fecha_futura", "Registros de auditoría con fecha futura",
                    f"{future} registros.", "Indica relojes desincronizados o inserciones manipuladas.", "Comprobado.", "Revise la hora del servidor y el origen.",
                    "ALTO")], "ALTO", **details)
    if gaps:
        return warn(f"{len(gaps)} días con actividad de tickets sin registros de auditoría.", [finding("auditoria:interrupciones",
                    "Posibles interrupciones del registro de auditoría", f"Días: {', '.join(gaps[:10])}{'…' if len(gaps) > 10 else ''}.",
                    "Acciones sin trazabilidad en esos días.", "Evidencia indirecta; puede deberse a cargas de datos fuera de la aplicación.",
                    "Investigue qué ocurrió esos días (despliegues, errores, cargas directas).", "MEDIO", {"dias": gaps[:60]})], **details)
    return ok(f"Cada día con actividad de tickets reales tiene registros de auditoría ({len(audit_days)} días con auditoría).", **details)


@control("REG-04", C, "Calidad de los eventos registrados", "Detectar eventos de usuarios sin dirección IP o navegador y eventos con campos "
         "obligatorios vacíos.", "SQL", "BAJO", CRITERIA)
def event_quality(ctx: Ctx) -> Outcome:
    start, end = ctx.period()
    s = ctx.session
    base = (AuditLog.created_at >= start, AuditLog.created_at < end)
    total = s.scalar(select(func.count(AuditLog.id)).where(*base)) or 0
    by_users = s.scalar(select(func.count(AuditLog.id)).where(*base, AuditLog.user_id.is_not(None))) or 0
    no_ip = s.scalar(select(func.count(AuditLog.id)).where(*base, AuditLog.user_id.is_not(None), AuditLog.ip.is_(None),
                                                         AuditLog.module != "CENTRO_AUDITORIA", AuditLog.action.not_like("AGENTE_%"))) or 0
    no_ua = s.scalar(select(func.count(AuditLog.id)).where(*base, AuditLog.user_id.is_not(None), AuditLog.user_agent.is_(None),
                                                         AuditLog.module != "CENTRO_AUDITORIA", AuditLog.action.not_like("AGENTE_%"))) or 0
    empty = s.scalar(select(func.count(AuditLog.id)).where(*base, (AuditLog.action == "") | (AuditLog.module == "") | (AuditLog.entity == ""))) or 0
    ips = dict(s.execute(select(AuditLog.ip, func.count()).where(*base, AuditLog.action == "LOGIN").group_by(AuditLog.ip).order_by(func.count().desc()).limit(3)).all())
    single_ip = len(ips) == 1 and sum(ips.values()) > 20
    details = {"periodo": period_text(ctx), "eventos": total, "eventos_de_usuarios": by_users, "sin_ip": no_ip, "sin_navegador": no_ua, "campos_vacios": empty,
               "inicios_desde_una_sola_ip": single_ip,
               "nota": "Los eventos de procesos internos (agentes programados, motor de auditoría) no tienen IP ni navegador por diseño."}
    findings = []
    if empty: findings.append(finding("auditoria:campos_vacios", "Eventos con campos obligatorios vacíos", f"{empty} eventos.", "Eventos no interpretables.",
                                      "Comprobado.", "Revise el código que los genera.", "BAJO"))
    if by_users and (no_ip + no_ua) / by_users > 0.05:
        findings.append(finding("auditoria:sin_contexto", "Eventos de usuarios sin IP o navegador", f"{no_ip} sin IP y {no_ua} sin navegador.",
                                "Dificulta la investigación de incidentes.", "Comprobado.", "Pase el objeto request a audit() en esos puntos.", "BAJO"))
    if single_ip:
        findings.append(finding("auditoria:ip_proxy", "Todos los inicios de sesión registran la misma IP", "Probablemente es la IP del proxy de Render.",
                                "No se puede distinguir el origen real de los accesos ni usar el límite por IP.", "Alta en despliegues detrás de proxy.",
                                "Configure TRUSTED_PROXY_HOPS con el número de proxies de Render y verifíquelo.", "MEDIO"))
    if findings: return warn("La calidad de los eventos tiene observaciones.", findings, **details)
    return ok(f"{total} eventos en el periodo con campos completos e IP/navegador en los eventos de usuarios.", **details)


def _audits(fn) -> bool:
    try:
        return "audit(" in inspect.getsource(fn)
    except (OSError, TypeError):
        return False


@control("REG-05", C, "Cobertura de eventos de seguridad", "Comprobar en el código qué eventos recomendados por OWASP se registran: "
         "autenticación, autorización, cambios de privilegios, configuración, exportaciones y descargas de información sensible.",
         "ESTATICO", "MEDIO", CRITERIA)
def coverage(ctx: Ctx) -> Outcome:
    from app.api import audit as audit_api, legal, ml, router
    from app.security import auth
    events = {
        "Inicio de sesión exitoso": _audits(router.login), "Inicio de sesión fallido y bloqueo": "LOGIN_FALLIDO" in inspect.getsource(router.login),
        "Registro de cuentas": _audits(router.register), "Creación y cambio de usuarios y roles": _audits(router.create_user) and _audits(router.update_user),
        "Cambios de configuración": _audits(router.update_setting), "Aceptación de términos": _audits(legal.record_acceptance),
        "Consulta y exportación de la auditoría": _audits(audit_api.list_audit) and _audits(audit_api.export),
        "Accesos denegados en el módulo de auditoría": _audits(audit_api.auditor),
        "Accesos denegados en el resto de la API (403)": _audits(auth.require_roles),
        "Descarga de reportes de tickets (CSV, Excel, PDF)": all(_audits(f) for f in (router.tickets_report, router.tickets_xlsx, router.tickets_pdf)),
        "Descarga del dataset de Machine Learning": _audits(getattr(ml, "dataset_csv", None) or getattr(ml, "dataset", None)),
        "Descarga de adjuntos": _audits(router.download_attachment),
    }
    not_applicable_events = {"Cierre de sesión": "No hay cierre de sesión en el servidor (los tokens expiran).",
                             "Cambio y recuperación de contraseña": "FixIT no tiene esta función."}
    gaps = [k for k, v in events.items() if not v]
    details = {"eventos": events, "no_aplican": not_applicable_events}
    if gaps:
        return warn(f"{len(gaps)} tipos de evento de seguridad no se registran: {', '.join(gaps)}.", [finding(
            f"cobertura:{g}", f"Evento no registrado: {g}", f"La acción «{g}» no genera registro de auditoría.",
            "No queda evidencia de accesos o descargas de información sensible.", "Comprobado en el código desplegado.",
            "Añada una llamada a audit() con el resultado correspondiente.", "MEDIO" if "Descarga" in g or "denegados" in g else "BAJO") for g in gaps],
            **details)
    return ok("Todos los eventos de seguridad recomendados que aplican se registran.", **details)


@control("REG-06", C, "Exportaciones registradas", "Listar las exportaciones de auditoría e informes del periodo y verificar que cada informe "
         "generado tiene su registro en la auditoría.", "SQL", "MEDIO", CRITERIA)
def exports(ctx: Ctx) -> Outcome:
    start, end = ctx.period()
    s = ctx.session
    rows = s.scalars(select(AuditLog).where(AuditLog.created_at >= start, AuditLog.created_at < end,
                                            AuditLog.action.in_(("EXPORTAR", "EXPORTAR_INFORME")))).all()
    items = [{"fecha": iso(r.created_at), "accion": r.action, "modulo": r.module, "formato": (r.new_value or {}).get("formato") or (r.new_value or {}).get("tipo"),
              "registros": (r.new_value or {}).get("registros"), "usuario_id": (r.user_id or "")[:8]} for r in rows]
    reports = s.scalars(select(AuditReport).where(AuditReport.created_at >= start, AuditReport.created_at < end)).all()
    logged = {r.id for r in rows}
    unlogged = [r.id for r in reports if not r.audit_log_id or r.audit_log_id not in logged]
    details = {"periodo": period_text(ctx), "exportaciones": items[:100], "informes_generados": len(reports), "informes_sin_registro": unlogged}
    if unlogged:
        return fail(f"{len(unlogged)} informes generados sin registro en la auditoría.", [finding("auditoria:informes_sin_registro",
                    "Informes de auditoría sin registro de exportación", f"{len(unlogged)} informes.", "Salida de información sin trazabilidad.", "Comprobado.",
                    "Revise el endpoint de descarga de informes.", "ALTO", {"informes": unlogged[:20]})], "ALTO", **details)
    return ok(f"{len(rows)} exportaciones registradas en el periodo; todos los informes generados tienen registro.", **details)


@control("REG-07", C, "Conservación y centralización de registros", "Verificar con evidencia la política de conservación de registros y su "
         "copia en un almacenamiento externo o inmutable.", "MANUAL", "MEDIO", CRITERIA, evidence_days=365,
         guidance="Adjunte la política aprobada de conservación de registros (plazos) y evidencia de su copia externa (por ejemplo, exportación periódica "
                  "a un repositorio de solo escritura o logs centralizados), con el resultado declarado.")
def retention(ctx: Ctx) -> Outcome:
    out = manual(ctx)
    oldest = ctx.session.scalar(select(func.min(AuditLog.created_at)))
    out.details["registro_mas_antiguo"] = iso(oldest)
    out.details["registros"] = ctx.session.scalar(select(func.count(AuditLog.id)))
    if ctx.pg: out.details["tamano_bytes"] = ctx.scalar("SELECT pg_total_relation_size(to_regclass('audit_logs'))")
    return out


@control("REG-08", C, "Integridad de los resultados de auditorías anteriores", "Verificar el sello HMAC de los resultados de las últimas "
         "ejecuciones del Centro de Auditoría.", "SQL", "ALTO", CRITERIA)
def run_seals(ctx: Ctx) -> Outcome:
    from app.auditing.engine import verify_seal
    runs = ctx.session.scalars(select(AuditRun).where(AuditRun.results_seal.is_not(None), AuditRun.id != ctx.run.id)
                               .order_by(AuditRun.finished_at.desc()).limit(int(ctx.option("ejecuciones_a_verificar", 100)))).all()
    if not runs: return not_applicable("No hay ejecuciones anteriores finalizadas para verificar.")
    status = {}
    altered = []
    for run in runs:
        result = verify_seal(run, ctx.session.scalars(select(AuditResult).where(AuditResult.run_id == run.id)).all())
        status[result] = status.get(result, 0) + 1
        if result == "ALTERADO": altered.append(run.code)
    details = {"ejecuciones_verificadas": len(runs), "por_estado": status, "alteradas": altered}
    if altered:
        return fail(f"{len(altered)} ejecuciones tienen resultados que no coinciden con su sello.", [finding("auditoria:resultados_alterados",
                    "Resultados de auditoría alterados", f"Ejecuciones: {', '.join(altered[:10])}.", "Los informes de esas auditorías no son confiables.",
                    "Comprobado criptográficamente.", "Investigue el acceso de escritura a audit_results y vuelva a ejecutar la auditoría.", "CRITICO",
                    {"ejecuciones": altered})], "CRITICO", **details)
    if status.get("CLAVE_DISTINTA"):
        return warn(f"{status['CLAVE_DISTINTA']} ejecuciones selladas con otra clave.", [], "BAJO", **details)
    return ok(f"Los resultados de las {len(runs)} ejecuciones anteriores coinciden con su sello.", **details)


@control("REG-09", C, "Clasificación de registros del periodo", "Distinguir en el periodo los registros de actividad, los de seguridad y los "
         "generados por el Centro de Auditoría.", "SQL", "INFORMATIVO", CRITERIA)
def classification(ctx: Ctx) -> Outcome:
    start, end = ctx.period()
    rows = ctx.session.execute(select(AuditLog.module, AuditLog.action, AuditLog.outcome, func.count()).where(
        AuditLog.created_at >= start, AuditLog.created_at < end).group_by(AuditLog.module, AuditLog.action, AuditLog.outcome)).all()
    groups = {"actividad": 0, "seguridad": 0, "centro_de_auditoria": 0}
    by_outcome: dict[str, int] = {}
    for module, action, outcome, n in rows:
        key = "centro_de_auditoria" if module == "CENTRO_AUDITORIA" else "seguridad" if (action in SECURITY_ACTIONS or outcome != "EXITO" or module == "AUTH") else "actividad"
        groups[key] += n
        by_outcome[outcome] = by_outcome.get(outcome, 0) + n
    runs = ctx.session.scalar(select(func.count(AuditRun.id)).where(AuditRun.created_at >= start, AuditRun.created_at < end)) or 0
    return ok(f"{sum(groups.values())} registros en el periodo: {groups['actividad']} de actividad, {groups['seguridad']} de seguridad y "
              f"{groups['centro_de_auditoria']} del Centro de Auditoría; {runs} ejecuciones de auditoría.", periodo=period_text(ctx),
              registros=groups, por_resultado=by_outcome, ejecuciones_de_auditoria=runs,
              definiciones={"actividad": "Operación normal (tickets, catálogos, IA).", "seguridad": "Autenticación, denegaciones, fallos y exportaciones.",
                            "centro_de_auditoria": "Ejecuciones, cambios de hallazgos, evidencias e informes del Centro de Auditoría.",
                            "resultados": "Las conclusiones de auditoría se guardan aparte (audit_runs, audit_results, audit_findings)."})
