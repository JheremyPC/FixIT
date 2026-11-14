"""Category ACCESOS: accounts, roles, privileges and access activity (from users, technicians and audit_logs).

Evidence never includes passwords, tokens or full e-mail addresses: accounts appear as a masked address, their role and
the first characters of their id.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import joinedload

from app.auditing.controls.common import LIMA, aware, finding, iso, period_text, user_ref
from app.auditing.registry import Ctx, Outcome, control, fail, ok, warn
from app.models import AuditLog, Technician, User

C = "ACCESOS"
DEMO_DOMAIN = "@demo.fixit.example"
SYNTHETIC_DOMAIN = "@sintetico.fixit.example"
ADMIN_MODULES = ("USUARIOS", "CATALOGOS", "CONFIGURACION", "TECNICOS", "AGENTES", "CENTRO_AUDITORIA")
CRITERIA = ["OWASP ASVS 5.0 V8 (autorización)", "OWASP Logging Cheat Sheet", "ISO 19011 (evidencia objetiva)"]


def _users(ctx: Ctx) -> list[User]:
    return ctx.session.scalars(select(User).options(joinedload(User.role))).all()


def _logs(ctx: Ctx, *conditions):
    start, end = ctx.period()
    return select(AuditLog).where(AuditLog.created_at >= start, AuditLog.created_at < end, *conditions)


def _ref(user: User | None, user_id: str | None = None) -> str:
    return user_ref(user.id, user.email, user.role.code) if user else user_ref(user_id, None)


@control("ACC-01", C, "Inventario de cuentas", "Contar cuentas activas e inactivas por rol e identificar cuentas de demostración o sintéticas "
         "habilitadas.", "SQL", "ALTO", CRITERIA)
def accounts(ctx: Ctx) -> Outcome:
    from app.auditing.readonly import audit_url, host_kind
    users = _users(ctx)
    by_role: dict[str, dict] = {}
    for u in users:
        bucket = by_role.setdefault(u.role.code, {"activas": 0, "inactivas": 0})
        bucket["activas" if u.active else "inactivas"] += 1
    demo = [u for u in users if u.active and u.email.lower().endswith(DEMO_DOMAIN)]
    synthetic = [u for u in users if u.active and u.email.lower().endswith(SYNTHETIC_DOMAIN)]
    where = host_kind(audit_url()[0])
    details = {"total": len(users), "por_rol": by_role, "demo_activas": len(demo), "sinteticas_activas": len(synthetic), "ubicacion_base": where}
    if demo:
        return fail(f"{len(demo)} cuentas del módulo de demostración retirado siguen activas.", [finding(
            "cuentas:demo", "Cuentas de demostración activas", f"{len(demo)} cuentas {DEMO_DOMAIN} están activas.",
            "Esas cuentas tenían acceso sin contraseña en una versión anterior.", "Alta si se reactivara el mecanismo o se conocen sus credenciales.",
            "Desactívelas (la migración 0005 lo hace automáticamente).", "ALTO", {"cuentas": [_ref(u) for u in demo[:20]]})], "ALTO", **details)
    if synthetic and not where.endswith("local"):
        return fail(f"{len(synthetic)} cuentas sintéticas activas en una base remota.", [finding(
            "cuentas:sinteticas", "Cuentas sintéticas con contraseña documentada en una base remota",
            f"{len(synthetic)} cuentas {SYNTHETIC_DOMAIN} están activas; su contraseña por defecto figura en la documentación.",
            "Acceso a FixIT con roles de prueba (incluidos técnicos y supervisores).", "Alta: la contraseña es pública.",
            "Desactive las cuentas sintéticas en producción o cambie sus contraseñas.", "ALTO", {"cuentas": len(synthetic)})], "ALTO", **details)
    return ok(f"{len(users)} cuentas: " + ", ".join(f"{r} {v['activas']} activas/{v['inactivas']} inactivas" for r, v in sorted(by_role.items())) + ".", **details)


@control("ACC-02", C, "Cuentas administrativas y privilegio mínimo", "Verificar que el número de administradores es acotado y que todos se "
         "usan; un administrador inactivo es un riesgo innecesario.", "SQL", "MEDIO", CRITERIA)
def admins(ctx: Ctx) -> Outcome:
    maximum = int(ctx.option("max_admins", 3))
    days = int(ctx.option("dias_inactividad", 90))
    users = [u for u in _users(ctx) if u.active]
    admins_ = [u for u in users if u.role.code == "ADMIN"]
    chiefs = [u for u in users if u.role.code == "JEFE_TI"]
    since = ctx.now - timedelta(days=days)
    last_login = dict(ctx.session.execute(select(AuditLog.user_id, func.max(AuditLog.created_at)).where(AuditLog.action == "LOGIN")
                                          .group_by(AuditLog.user_id)).all())
    # Only accounts older than the window: a privileged account created last week is not "unused for 90 days".
    idle = [u for u in admins_ + chiefs if aware(u.created_at) < since and (not last_login.get(u.id) or aware(last_login[u.id]) < since)]
    details = {"administradores_activos": len(admins_), "jefes_ti_activos": len(chiefs), "maximo_recomendado": maximum,
               "privilegiadas_sin_inicio_de_sesion": [{"cuenta": _ref(u), "ultimo_inicio": iso(last_login.get(u.id))} for u in idle],
               "criterio": f"Máximo {maximum} administradores activos; cuentas privilegiadas usadas en los últimos {days} días."}
    if not admins_:
        return fail("No hay ningún administrador activo.", [finding("cuentas:sin_admin", "Sin administrador activo", "No hay cuentas ADMIN activas.",
                    "Nadie puede gestionar usuarios ni configuración.", "Cierta.", "Active o cree un administrador.", "ALTO")], "ALTO", **details)
    findings = []
    if len(admins_) > maximum:
        findings.append(finding("cuentas:admins", "Demasiadas cuentas administrativas", f"{len(admins_)} administradores activos (máximo {maximum}).",
                                "Cada cuenta ADMIN amplía la superficie de ataque con acceso total.", "Media.",
                                "Reduzca los administradores y asigne JEFE_TI cuando baste.", "MEDIO", {"cuentas": [_ref(u) for u in admins_]}))
    if idle:
        findings.append(finding("cuentas:privilegiadas_inactivas", "Cuentas privilegiadas sin uso reciente",
                                f"{len(idle)} cuentas ADMIN/JEFE_TI sin inicio de sesión en {days} días.", "Cuentas olvidadas son objetivo de ataques.",
                                "Media.", "Desactive las que ya no se usan.", "MEDIO", {"cuentas": details["privilegiadas_sin_inicio_de_sesion"]}))
    if findings: return warn(f"{len(admins_)} administradores y {len(chiefs)} jefes de TI activos; hay observaciones.", findings, **details)
    return ok(f"{len(admins_)} administradores y {len(chiefs)} jefes de TI activos, todos con uso reciente.", **details)


@control("ACC-03", C, "Cambios de privilegios", "Listar los cambios de rol y las cuentas privilegiadas creadas en el periodo para su revisión.",
         "SQL", "MEDIO", CRITERIA)
def privilege_changes(ctx: Ctx) -> Outcome:
    rows = ctx.session.scalars(_logs(ctx, AuditLog.module == "USUARIOS", AuditLog.action.in_(("ACTUALIZAR", "CREAR"))).order_by(AuditLog.created_at)).all()
    users = {u.id: u for u in _users(ctx)}
    changes = []
    for r in rows:
        old, new = r.old_value or {}, r.new_value or {}
        if r.action == "ACTUALIZAR" and old.get("role") != new.get("role") and new.get("role"):
            changes.append({"fecha": iso(r.created_at), "cuenta": _ref(users.get(r.entity_id), r.entity_id), "de": old.get("role"), "a": new.get("role"),
                            "por": _ref(users.get(r.user_id), r.user_id), "registro": r.id})
        elif r.action == "CREAR" and new.get("role") in ("ADMIN", "JEFE_TI"):
            changes.append({"fecha": iso(r.created_at), "cuenta": _ref(users.get(r.entity_id), r.entity_id), "de": None, "a": new.get("role"),
                            "por": _ref(users.get(r.user_id), r.user_id), "registro": r.id})
    escalations = [c for c in changes if c["a"] in ("ADMIN", "JEFE_TI")]
    details = {"periodo": period_text(ctx), "cambios": changes}
    if escalations:
        return warn(f"{len(escalations)} asignaciones de roles privilegiados en el periodo para revisar.", [finding(
            f"privilegios:{c['registro']}", f"Asignación de rol {c['a']}: {c['cuenta']}", f"El {c['fecha']} {c['por']} asignó {c['a']} (antes: {c['de'] or 'cuenta nueva'}).",
            "Un cambio no autorizado otorga control total o supervisión.", "Requiere contrastar con una solicitud aprobada.",
            "Verifique la autorización del cambio y archive la evidencia.", "MEDIO", c) for c in escalations], **details)
    return ok(f"{len(changes)} cambios de rol en el periodo; ninguno hacia roles privilegiados.", **details)


@control("ACC-04", C, "Inicios de sesión exitosos y fallidos", "Resumir los inicios de sesión del periodo y detectar cuentas con fallos "
         "repetidos o bloqueos.", "SQL", "MEDIO", ["OWASP Logging Cheat Sheet", "NIST SP 800-92"])
def logins(ctx: Ctx) -> Outcome:
    threshold = int(ctx.option("umbral_fallos", 5))
    s = ctx.session
    start, end = ctx.period()
    counts = dict(s.execute(select(AuditLog.action, func.count()).where(AuditLog.created_at >= start, AuditLog.created_at < end,
                  AuditLog.action.in_(("LOGIN", "LOGIN_FALLIDO", "LOGIN_BLOQUEADO"))).group_by(AuditLog.action)).all())
    failures = s.execute(select(AuditLog.user_id, func.count()).where(AuditLog.created_at >= start, AuditLog.created_at < end,
                         AuditLog.action == "LOGIN_FALLIDO").group_by(AuditLog.user_id).having(func.count() >= threshold)).all()
    users = {u.id: u for u in _users(ctx)}
    flagged = [{"cuenta": _ref(users.get(uid), uid), "fallos": n} for uid, n in failures]
    details = {"periodo": period_text(ctx), "exitosos": counts.get("LOGIN", 0), "fallidos": counts.get("LOGIN_FALLIDO", 0),
               "bloqueos": counts.get("LOGIN_BLOQUEADO", 0), "cuentas_con_fallos_repetidos": flagged, "umbral": threshold,
               "limitacion": "Los intentos con correos inexistentes no se registran (para no llenar la auditoría con texto arbitrario)."}
    if flagged or counts.get("LOGIN_BLOQUEADO"):
        return warn(f"{len(flagged)} cuentas con ≥{threshold} fallos y {counts.get('LOGIN_BLOQUEADO', 0)} bloqueos en el periodo.", [finding(
            "accesos:fallos_repetidos", "Intentos fallidos repetidos de inicio de sesión", f"{len(flagged)} cuentas superan {threshold} fallos en el periodo.",
            "Posibles ataques de fuerza bruta o de relleno de credenciales.", "Media; revise IPs y horarios en la auditoría.",
            "Contacte a los titulares, fuerce el cambio de contraseña si corresponde y revise TRUSTED_PROXY_HOPS para auditar la IP real.",
            "MEDIO", {"cuentas": flagged[:30]})], **details)
    return ok(f"{details['exitosos']} inicios exitosos y {details['fallidos']} fallidos; sin cuentas con fallos repetidos.", **details)


@control("ACC-05", C, "Intentos de acceso no autorizado", "Listar los accesos denegados registrados en el periodo por cuenta.", "SQL", "MEDIO",
         ["OWASP Logging Cheat Sheet (fallos de autorización)"])
def denied(ctx: Ctx) -> Outcome:
    rows = ctx.session.scalars(_logs(ctx, AuditLog.outcome == "DENEGADO", AuditLog.action != "LOGIN_BLOQUEADO")).all()
    users = {u.id: u for u in _users(ctx)}
    by_user: dict[str, dict] = {}
    for r in rows:
        item = by_user.setdefault(r.user_id or "SISTEMA", {"cuenta": _ref(users.get(r.user_id), r.user_id), "intentos": 0, "rutas": set()})
        item["intentos"] += 1
        if isinstance(r.new_value, dict) and r.new_value.get("path"): item["rutas"].add(str(r.new_value["path"])[:120])
    summary = [{**v, "rutas": sorted(v["rutas"])[:10]} for v in by_user.values()]
    details = {"periodo": period_text(ctx), "denegados": len(rows), "por_cuenta": summary,
               "alcance": "Se registran las denegaciones del módulo de auditoría y del Centro de Auditoría; otras rutas no las registran (ver REG-05)."}
    if rows:
        return warn(f"{len(rows)} accesos denegados de {len(summary)} cuentas en el periodo.", [finding(
            "accesos:denegados", "Intentos de acceso a funciones no autorizadas", f"{len(rows)} intentos denegados en el periodo.",
            "Pueden indicar exploración de permisos por una cuenta comprometida o curiosidad de usuarios.", "Requiere revisión.",
            "Revise las cuentas con más intentos y confirme con sus titulares.", "BAJO", {"por_cuenta": summary[:20]})], "BAJO", **details)
    return ok("Sin accesos denegados registrados en el periodo.", **details)


@control("ACC-06", C, "Acciones administrativas y actividad fuera de horario", "Resumir las acciones administrativas del periodo y señalar "
         "las realizadas de madrugada (00:00–05:59, hora de Lima).", "SQL", "BAJO", CRITERIA)
def admin_actions(ctx: Ctx) -> Outcome:
    from sqlalchemy import and_, or_
    rows = ctx.session.scalars(_logs(ctx, or_(AuditLog.module.in_(ADMIN_MODULES), and_(AuditLog.module == "IA", AuditLog.action == "ENTRENAR")),
                                     AuditLog.user_id.is_not(None))).all()
    users = {u.id: u for u in _users(ctx)}
    by_module: dict[str, int] = {}
    night = []
    for r in rows:
        by_module[r.module] = by_module.get(r.module, 0) + 1
        local = aware(r.created_at).astimezone(LIMA)
        if local.hour < 6:
            night.append({"fecha_lima": local.strftime("%Y-%m-%d %H:%M"), "accion": r.action, "modulo": r.module, "cuenta": _ref(users.get(r.user_id), r.user_id)})
    details = {"periodo": period_text(ctx), "acciones_por_modulo": by_module, "total": len(rows), "de_madrugada": night[:50]}
    if night:
        return warn(f"{len(rows)} acciones administrativas; {len(night)} realizadas entre las 00:00 y las 05:59 (Lima).", [finding(
            "accesos:fuera_de_horario", "Acciones administrativas fuera del horario habitual", f"{len(night)} acciones de madrugada en el periodo.",
            "Puede indicar uso indebido de una cuenta privilegiada.", "Baja; puede ser trabajo legítimo de guardia.",
            "Confirme con los responsables y documente la actividad autorizada.", "BAJO", {"muestra": night[:20]})], "BAJO", **details)
    return ok(f"{len(rows)} acciones administrativas en el periodo, ninguna de madrugada.", **details)


@control("ACC-07", C, "Cuentas potencialmente huérfanas", "Detectar cuentas activas creadas hace más de N días sin ningún inicio de sesión en "
         "ese plazo.", "SQL", "MEDIO", CRITERIA)
def orphan_accounts(ctx: Ctx) -> Outcome:
    days = int(ctx.option("dias_inactividad", 90))
    since = ctx.now - timedelta(days=days)
    last_login = dict(ctx.session.execute(select(AuditLog.user_id, func.max(AuditLog.created_at)).where(AuditLog.action == "LOGIN")
                                          .group_by(AuditLog.user_id)).all())
    candidates = [u for u in _users(ctx) if u.active and aware(u.created_at) < since and not u.email.lower().endswith(SYNTHETIC_DOMAIN)
                  and (not last_login.get(u.id) or aware(last_login[u.id]) < since)]
    by_role: dict[str, int] = {}
    for u in candidates: by_role[u.role.code] = by_role.get(u.role.code, 0) + 1
    details = {"criterio": f"Cuentas activas con más de {days} días de antigüedad y sin inicio de sesión en los últimos {days} días.",
               "cuentas": [{"cuenta": _ref(u), "creada": iso(u.created_at), "ultimo_inicio": iso(last_login.get(u.id))} for u in candidates[:50]],
               "por_rol": by_role, "excluidas": "Cuentas sintéticas (ACC-01)."}
    if candidates:
        severity = "MEDIO" if (by_role.get("ADMIN") or by_role.get("JEFE_TI") or by_role.get("TECNICO")) else "BAJO"
        return warn(f"{len(candidates)} cuentas activas sin uso en {days} días.", [finding(
            "accesos:huerfanas", "Cuentas activas sin uso", f"{len(candidates)} cuentas no inician sesión desde hace más de {days} días.",
            "Cuentas de personas que ya no trabajan en la entidad mantienen acceso.", "Media.",
            "Confirme con Recursos Humanos o los responsables de área y desactive las que no correspondan.", severity, {"por_rol": by_role})], severity, **details)
    return ok(f"Todas las cuentas activas con más de {days} días se usaron recientemente.", **details)


@control("ACC-08", C, "Coherencia entre roles y perfiles técnicos", "Verificar que cada técnico tiene rol TECNICO y que las cuentas TECNICO "
         "tienen perfil, y que no hay perfiles disponibles de cuentas inactivas.", "SQL", "BAJO", CRITERIA)
def technician_consistency(ctx: Ctx) -> Outcome:
    users = {u.id: u for u in _users(ctx)}
    techs = ctx.session.scalars(select(Technician)).all()
    tech_users = {t.user_id for t in techs}
    issues = []
    for t in techs:
        u = users.get(t.user_id)
        if u and u.role.code != "TECNICO": issues.append({"problema": "perfil técnico de una cuenta sin rol TECNICO", "cuenta": _ref(u)})
        if u and not u.active and t.available: issues.append({"problema": "perfil disponible de una cuenta inactiva (puede recibir asignaciones)", "cuenta": _ref(u)})
    for u in users.values():
        if u.active and u.role.code == "TECNICO" and u.id not in tech_users: issues.append({"problema": "cuenta TECNICO sin perfil técnico", "cuenta": _ref(u)})
    details = {"perfiles": len(techs), "inconsistencias": issues}
    if issues:
        return warn(f"{len(issues)} inconsistencias entre roles y perfiles técnicos.", [finding(
            "accesos:perfiles_tecnicos", "Inconsistencias entre roles y perfiles técnicos", f"{len(issues)} casos.",
            "Asignaciones a cuentas sin el rol correcto o a personas inactivas.", "Media.", "Corrija el rol o el perfil en Usuarios y catálogos.", "BAJO",
            {"casos": issues[:30]})], "BAJO", **details)
    return ok(f"{len(techs)} perfiles técnicos coherentes con los roles.", **details)


@control("ACC-09", C, "Acceso a recursos sensibles", "Listar consultas y exportaciones de la auditoría y descargas de informes del Centro de "
         "Auditoría, y verificar que solo las realizaron roles autorizados.", "SQL", "ALTO", ["OWASP Logging Cheat Sheet", "Ley N.º 29733"])
def sensitive_access(ctx: Ctx) -> Outcome:
    rows = ctx.session.scalars(_logs(ctx, AuditLog.module.in_(("AUDITORIA", "CENTRO_AUDITORIA")), AuditLog.outcome == "EXITO",
                                     AuditLog.action.in_(("CONSULTAR", "EXPORTAR", "EXPORTAR_INFORME", "DESCARGAR_EVIDENCIA")))).all()
    users = {u.id: u for u in _users(ctx)}
    by_user: dict[str, dict] = {}
    unauthorized = []
    for r in rows:
        u = users.get(r.user_id)
        item = by_user.setdefault(r.user_id or "SISTEMA", {"cuenta": _ref(u, r.user_id), "consultas": 0, "exportaciones": 0})
        item["exportaciones" if r.action != "CONSULTAR" else "consultas"] += 1
        if u and u.role.code not in ("ADMIN", "JEFE_TI") and r.action != "DESCARGAR_EVIDENCIA":
            unauthorized.append({"cuenta": _ref(u), "accion": r.action, "fecha": iso(r.created_at)})
    details = {"periodo": period_text(ctx), "por_cuenta": list(by_user.values()), "realizadas_por_roles_no_autorizados": unauthorized,
               "nota": "El rol considerado es el actual de la cuenta, no necesariamente el que tenía en la fecha del evento."}
    if unauthorized:
        return fail(f"{len(unauthorized)} accesos a la auditoría realizados por cuentas sin rol autorizado.", [finding(
            "accesos:auditoria_no_autorizada", "Accesos a la auditoría por roles no autorizados", f"{len(unauthorized)} eventos.",
            "Exposición de registros con datos personales.", "Cierta si el rol no cambió después.", "Revise los cambios de rol de esas cuentas (ACC-03).",
            "ALTO", {"eventos": unauthorized[:20]})], **details)
    return ok(f"{len(rows)} consultas o exportaciones de auditoría en el periodo, todas por ADMIN o JEFE_TI.", **details)


@control("ACC-10", C, "Cambios de configuración", "Listar los cambios de configuración (reglas de asignación, agentes, controles de auditoría) "
         "del periodo con su autor.", "SQL", "BAJO", CRITERIA)
def config_changes(ctx: Ctx) -> Outcome:
    rows = ctx.session.scalars(_logs(ctx, AuditLog.module.in_(("CONFIGURACION", "AGENTES", "CENTRO_AUDITORIA")),
                                     AuditLog.action.in_(("ACTUALIZAR", "CONFIGURAR", "CONFIGURAR_AGENTE", "CONFIGURAR_CONTROL")))).all()
    users = {u.id: u for u in _users(ctx)}
    changes = [{"fecha": iso(r.created_at), "modulo": r.module, "entidad": r.entity, "id": r.entity_id, "cuenta": _ref(users.get(r.user_id), r.user_id),
                "con_valor_anterior": r.old_value is not None} for r in rows]
    details = {"periodo": period_text(ctx), "cambios": changes[:100]}
    without_old = [c for c in changes if not c["con_valor_anterior"] and c["modulo"] == "CONFIGURACION"]
    if without_old:
        return warn(f"{len(changes)} cambios de configuración; {len(without_old)} sin valor anterior registrado.", [], "BAJO", **details)
    return ok(f"{len(changes)} cambios de configuración en el periodo, con autor registrado.", **details)
