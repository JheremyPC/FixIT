"""Category PRIVACIDAD: evaluation of controls related to the Peruvian personal data protection framework (Ley N.º 29733 and its
regulation), adapted to what FixIT can verify. This category never concludes legal compliance: institutional decisions
(controller identity, legal basis, retention periods, rights procedure, registration of the data bank) are marked as
pending validation unless someone attaches evidence."""
from __future__ import annotations

import re
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import joinedload

from app.auditing.controls.common import finding, manual, period_text, sample
from app.auditing.registry import Ctx, NotVerifiable, Outcome, control, fail, ok, warn
from app.legal import DOCUMENTS, PENDING
from app.models import AuditLog, TermsAcceptance, Ticket, TicketComment, User

C = "PRIVACIDAD"
LPDP = ["Ley N.º 29733 y su reglamento (referencia; no implica cumplimiento acreditado)"]
CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
SECRET_IN_TEXT = re.compile(r"(?i)\b(contrase(?:ñ|n)a|password|clave)\s*(?:es|:|=)\s*\S{4,}")


def _pending(doc: dict) -> list[str]:
    out = []
    for section in doc["sections"]:
        text = " ".join(b if isinstance(b, str) else " ".join(b.get("list", [])) for b in section["blocks"])
        if PENDING in text: out.append(section["title"])
    if PENDING in str(doc.get("effective")): out.append("Fecha de vigencia")
    return out


def _section_pending(doc_id: str, section_id: str) -> bool:
    section = next((s for s in DOCUMENTS[doc_id]["sections"] if s["id"] == section_id), None)
    return section is not None and PENDING in str(section["blocks"])


@control("PRI-01", C, "Documentos legales publicados y versionados", "Verificar que los Términos y condiciones y el Aviso de privacidad se "
         "publican en /legal con versión y fecha, y si siguen en borrador.", "ESTATICO", "MEDIO", LPDP)
def documents(ctx: Ctx) -> Outcome:
    from app.auditing.controls.security import api_routes
    from app.main import app
    routes = {getattr(r, "path", None) for r in app.routes} | {path for path, _, _ in api_routes()}
    docs = {d["id"]: {"titulo": d["title"], "version": d["version"], "actualizado": d["updated"], "vigencia": d["effective"],
                      "requiere_aceptacion": d["requires_acceptance"]} for d in DOCUMENTS.values()}
    details = {"documentos": docs, "pagina_publica": "/legal" in routes, "api_publica": "/api/legal" in routes}
    if not details["pagina_publica"] or set(docs) != {"terminos", "privacidad"}:
        return fail("Falta la página /legal o alguno de los documentos.", [], "ALTO", **details)
    drafts = [d["title"] for d in DOCUMENTS.values() if "borrador" in d["version"].lower()]
    if drafts:
        return warn(f"Documentos publicados en versión borrador: {', '.join(drafts)}.", [finding("legal:borrador", "Documentos legales en borrador",
                    "Los Términos y el Aviso de privacidad están publicados como borrador técnico.", "No acreditan por sí solos el cumplimiento de la Ley N.º 29733.",
                    "Cierta mientras sigan en borrador.", "La entidad y un especialista legal deben revisarlos, completarlos y aprobar una versión vigente.", "MEDIO")],
                    "MEDIO", **details)
    return ok("Términos y Aviso de privacidad publicados con versión vigente.", **details)


@control("PRI-02", C, "Información pendiente de validación institucional", "Identificar las secciones de los documentos legales marcadas como "
         "pendientes de validación institucional.", "ESTATICO", "MEDIO", LPDP)
def pending(ctx: Ctx) -> Outcome:
    items = {d["title"]: _pending(d) for d in DOCUMENTS.values()}
    total = sum(len(v) for v in items.values())
    details = {"secciones_pendientes": items, "marcador": PENDING,
               "nota": "FixIT no puede completar estos datos: corresponden a la entidad responsable (identidad, fundamento, plazos, contactos)."}
    if total:
        return warn(f"{total} secciones de los documentos legales tienen información pendiente de validación.", [finding("legal:pendientes",
                    "Datos institucionales pendientes en los documentos legales", f"{total} secciones con «{PENDING}».",
                    "Los titulares no conocen al responsable, el fundamento ni cómo ejercer sus derechos.", "Cierta mientras no se complete.",
                    "Complete los datos en app/legal.py tras su aprobación institucional y publique una nueva versión.", "MEDIO", {"secciones": items})],
                    "MEDIO", **details)
    return ok("Los documentos legales no tienen información pendiente de validación.", **details)


@control("PRI-03", C, "Aceptación de la versión vigente de los términos", "Medir qué cuentas activas aceptaron expresamente la versión vigente de "
         "los Términos y condiciones.", "SQL", "MEDIO", LPDP)
def acceptance(ctx: Ctx) -> Outcome:
    terms = DOCUMENTS["terminos"]
    users = ctx.session.scalars(select(User).options(joinedload(User.role)).where(User.active.is_(True))).all()
    accepted = {uid for (uid,) in ctx.session.execute(select(TermsAcceptance.user_id).where(TermsAcceptance.document == "terminos",
                                                                                            TermsAcceptance.version == terms["version"]))}
    missing = [u for u in users if u.id not in accepted]
    by_role: dict[str, int] = {}
    for u in missing: by_role[u.role.code] = by_role.get(u.role.code, 0) + 1
    versions = dict(ctx.session.execute(select(TermsAcceptance.version, func.count()).where(TermsAcceptance.document == "terminos")
                                        .group_by(TermsAcceptance.version)).all())
    details = {"version_vigente": terms["version"], "cuentas_activas": len(users), "aceptaron_vigente": len(users) - len(missing),
               "pendientes_por_rol": by_role, "aceptaciones_por_version": versions,
               "nota": "FixIT solicita la aceptación al ingresar; nunca la registra en nombre del usuario."}
    if missing:
        return warn(f"{len(missing)} de {len(users)} cuentas activas no aceptaron la versión vigente ({terms['version']}).", [finding(
            "legal:aceptacion_pendiente", "Cuentas sin aceptación de los términos vigentes", f"{len(missing)} cuentas activas.",
            "Uso de la plataforma sin constancia de conocimiento de las reglas vigentes.", "Se reduce a medida que los usuarios ingresan.",
            "Pida a los usuarios que ingresen y acepten; revise las cuentas que no se usan (ACC-07).", "BAJO", {"por_rol": by_role})], "BAJO", **details)
    return ok(f"Las {len(users)} cuentas activas aceptaron la versión vigente.", **details)


@control("PRI-04", C, "Integridad del registro de aceptaciones", "Verificar que cada aceptación tiene fecha y versión conocida, es posterior a la "
         "creación de la cuenta y quedó registrada en la auditoría.", "SQL", "MEDIO", LPDP)
def acceptance_records(ctx: Ctx) -> Outcome:
    rows = ctx.session.execute(select(TermsAcceptance.id, TermsAcceptance.user_id, TermsAcceptance.version, TermsAcceptance.accepted_at, User.created_at)
                               .join(User, User.id == TermsAcceptance.user_id)).all()
    from app.auditing.controls.common import aware
    before = [r for r in rows if aware(r.accepted_at) < aware(r.created_at) - timedelta(minutes=1)]
    logged = set()
    for uid, value in ctx.session.execute(select(AuditLog.user_id, AuditLog.new_value).where(AuditLog.action == "ACEPTAR_TERMINOS")):
        if isinstance(value, dict): logged.add((uid, str(value.get("version"))))
    unlogged = [r for r in rows if (r.user_id, str(r.version)) not in logged]
    details = {"aceptaciones": len(rows), "anteriores_a_la_cuenta": len(before), "sin_registro_de_auditoria": len(unlogged)}
    if before:
        return fail(f"{len(before)} aceptaciones con fecha anterior a la creación de la cuenta.", [finding("legal:aceptaciones_inconsistentes",
                    "Aceptaciones con fecha imposible", f"{len(before)} registros.", "La constancia de aceptación no es confiable.", "Comprobado.",
                    "Investigue su origen (inserción directa).", "MEDIO")], **details)
    if unlogged:
        return warn(f"{len(unlogged)} aceptaciones sin su evento ACEPTAR_TERMINOS en la auditoría.", [], "BAJO", **details)
    return ok(f"{len(rows)} aceptaciones coherentes y registradas en la auditoría.", **details)


@control("PRI-05", C, "Acceso a datos personales", "Verificar que las rutas que devuelven datos personales de otras personas (usuarios, técnicos, "
         "auditoría, informes, reportes) están limitadas a ADMIN y JEFE_TI.", "ESTATICO", "ALTO", LPDP + ["OWASP ASVS 5.0 V8"])
def personal_data_access(ctx: Ctx) -> Outcome:
    from app.auditing.controls.security import route_inventory
    pattern = re.compile(r"^/api/(users|technicians|reports/|ml/dataset|audit(/|$)|audit-center/(runs|reports|evidences$|imports|external-logs|assignees))")
    routes = [r for r in route_inventory() if r["metodo"] == "GET" and pattern.search(r["ruta"])]
    wide = [r for r in routes if not r["roles"] or set(r["roles"]) - {"ADMIN", "JEFE_TI"}]
    details = {"rutas_con_datos_personales": [f"{r['metodo']} {r['ruta']}: {', '.join(r['roles'] or ['cualquier usuario autenticado'])}" for r in routes]}
    if wide:
        return fail(f"{len(wide)} rutas con datos personales accesibles a otros roles.", [finding(f"privacidad:ruta:{r['ruta']}",
                    f"Datos personales accesibles a más roles: {r['ruta']}", f"Roles: {', '.join(r['roles'] or ['todos'])}.",
                    "Acceso a datos de terceros sin necesidad.", "Alta para usuarios autenticados.", "Restrinja la ruta a ADMIN/JEFE_TI.", "ALTO", r) for r in wide], **details)
    return ok(f"Las {len(routes)} rutas con datos personales de terceros están limitadas a ADMIN y JEFE_TI.", **details)


@control("PRI-06", C, "Minimización en exportaciones e informes", "Revisar qué datos personales incluyen las exportaciones y si los informes del "
         "Centro de Auditoría se redactan por defecto.", "ESTATICO", "BAJO", LPDP)
def minimization(ctx: Ctx) -> Outcome:
    from app.api.audit import COLUMNS
    from app.auditing import reports
    personal = [name for name, _ in COLUMNS if name in ("usuario_email", "usuario_nombre", "ip", "navegador")]
    details = {"exportacion_auditoria_incluye": personal, "informes_redactados_por_defecto": reports.REDACT_BY_DEFAULT,
               "dataset_ml": "Sin datos personales (identificadores de técnico y número de ticket)."}
    if not reports.REDACT_BY_DEFAULT:
        return fail("Los informes del Centro de Auditoría no se redactan por defecto.", [], "MEDIO", **details)
    return warn("La exportación de la auditoría incluye correo, nombre, IP y navegador completos (necesarios para investigar); los informes del "
                "Centro de Auditoría los enmascaran.", [finding("privacidad:exportacion_auditoria", "Exportación de auditoría con datos personales completos",
                "El CSV/JSON de la auditoría contiene correos, IP y navegador de las personas.", "Si el archivo se difunde, expone datos personales.",
                "Depende del manejo del archivo.", "Entregue la exportación solo a auditores autorizados, regístrelo y prefiera el paquete de evidencias "
                "redactado para compartir resultados.", "BAJO")], "BAJO", **details)


@control("PRI-07", C, "Conservación y eliminación de datos", "Verificar con evidencia la política aprobada de plazos de conservación y el "
         "procedimiento de eliminación o anonimización.", "MANUAL", "MEDIO", LPDP, evidence_days=365,
         guidance="Adjunte la política de conservación aprobada por la entidad (plazos por tipo de dato) y el procedimiento de eliminación o "
                  "anonimización, con el resultado declarado. Mientras no exista, el punto queda pendiente de validación.")
def retention(ctx: Ctx) -> Outcome:
    try:
        out = manual(ctx)
    except NotVerifiable as exc:
        raise NotVerifiable(f"Pendiente de validación institucional: el Aviso de privacidad no define plazos ({PENDING}) y FixIT no elimina datos "
                            f"automáticamente (solo desactiva cuentas). {exc}") from None
    out.details["eliminacion_en_la_aplicacion"] = "No existe; las cuentas solo se desactivan."
    return out


@control("PRI-08", C, "Derechos de los titulares", "Verificar con evidencia el canal y procedimiento para ejercer los derechos de acceso, "
         "rectificación, cancelación y oposición.", "MANUAL", "MEDIO", LPDP, evidence_days=365,
         guidance="Adjunte el procedimiento aprobado (canal, requisitos, plazos de respuesta) y, si existe, el registro de solicitudes atendidas.")
def rights(ctx: Ctx) -> Outcome:
    try:
        return manual(ctx)
    except NotVerifiable as exc:
        state = "pendiente de validación en el Aviso de privacidad" if _section_pending("privacidad", "derechos") else "sin evidencia"
        raise NotVerifiable(f"Procedimiento de derechos {state}. {exc}") from None


@control("PRI-09", C, "Encargados del tratamiento y transferencias", "Identificar los proveedores que tratan datos (alojamiento, base de datos, "
         "proveedor de IA) y verificar con evidencia las garantías del flujo transfronterizo.", "MANUAL", "MEDIO", LPDP, evidence_days=365,
         guidance="Adjunte los contratos o condiciones de tratamiento de datos de Render, Supabase y del proveedor de IA y, si corresponde, la "
                  "comunicación del flujo transfronterizo a la autoridad.")
def processors(ctx: Ctx) -> Outcome:
    from app.llm.provider import provider_status
    llm = provider_status()
    try:
        out = manual(ctx)
    except NotVerifiable as exc:
        if llm["configured"]:
            return warn(f"El asistente de IA está activo ({llm['provider']}): se envían fragmentos de tickets a un proveedor externo sin garantías "
                        "documentadas.", [finding("privacidad:transferencia_ia", "Transferencia de datos a un proveedor de IA sin garantías documentadas",
                        "Consultas y fragmentos de tickets se envían al proveedor configurado.", "Tratamiento por terceros, posiblemente fuera del Perú.",
                        "Cierta mientras el asistente esté habilitado.", "Documente el encargo y las garantías, o deshabilite el asistente.", "MEDIO")],
                        "MEDIO", encargados=["Render (alojamiento)", "Supabase (base de datos)", f"{llm['provider']} (IA)"], pendiente=str(exc))
        raise NotVerifiable(f"Encargados (Render, Supabase) pendientes de documentación. {exc}") from None
    out.details["proveedor_ia_activo"] = llm["configured"]
    return out


@control("PRI-10", C, "Responsable del tratamiento y banco de datos", "Verificar con evidencia la identidad del responsable y la inscripción del "
         "banco de datos personales.", "MANUAL", "MEDIO", LPDP, evidence_days=730,
         guidance="Adjunte la constancia de inscripción del banco de datos y la designación del responsable, con el resultado declarado.")
def controller(ctx: Ctx) -> Outcome:
    try:
        return manual(ctx)
    except NotVerifiable as exc:
        raise NotVerifiable(f"Pendiente de validación institucional ({'marcado en el Aviso de privacidad' if _section_pending('privacidad', 'responsable') else 'sin evidencia'}). {exc}") from None


def _luhn(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19: return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2: d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


@control("PRI-11", C, "Datos sensibles en tickets y comentarios", "Buscar en los tickets y comentarios del periodo números de tarjeta válidos "
         "(algoritmo de Luhn) y contraseñas escritas en texto; solo se informan conteos y números de ticket.", "ESTADISTICO", "MEDIO", LPDP)
def sensitive_content(ctx: Ctx) -> Outcome:
    start, end = ctx.period()
    hits: dict[str, set] = {"tarjetas": set(), "contrasenas": set()}
    rows = ctx.session.execute(select(Ticket.number, Ticket.title, Ticket.description).where(Ticket.created_at >= start, Ticket.created_at < end)
                               .execution_options(yield_per=1000))
    for number, title, description in rows:
        text = f"{title} {description}"
        if any(_luhn(m.group()) for m in CARD.finditer(text)): hits["tarjetas"].add(number)
        if SECRET_IN_TEXT.search(text): hits["contrasenas"].add(number)
    comments = ctx.session.execute(select(Ticket.number, TicketComment.body).join(Ticket, Ticket.id == TicketComment.ticket_id)
                                   .where(TicketComment.created_at >= start, TicketComment.created_at < end).execution_options(yield_per=1000))
    for number, body in comments:
        if any(_luhn(m.group()) for m in CARD.finditer(body or "")): hits["tarjetas"].add(number)
        if SECRET_IN_TEXT.search(body or ""): hits["contrasenas"].add(number)
    details = {"periodo": period_text(ctx), "tickets_con_posibles_tarjetas": sample(sorted(hits["tarjetas"]), 20),
               "tickets_con_posibles_contrasenas": sample(sorted(hits["contrasenas"]), 20),
               "nota": "El contenido se analiza en el servidor y no se incluye en el resultado; solo los números de ticket."}
    total = len(hits["tarjetas"] | hits["contrasenas"])
    if total:
        return warn(f"{total} tickets con posibles datos sensibles (tarjetas o contraseñas) en su texto.", [finding("privacidad:datos_sensibles",
                    "Datos sensibles escritos en tickets", f"{len(hits['tarjetas'])} con posibles tarjetas y {len(hits['contrasenas'])} con posibles contraseñas.",
                    "Exposición de datos financieros o credenciales a quienes ven el ticket.", "Señal por patrones; requiere revisión.",
                    "Revise los tickets, retire el dato con trazabilidad y recuerde a los usuarios no incluir datos sensibles.", "MEDIO",
                    {"tickets": sorted(hits["tarjetas"] | hits["contrasenas"])[:20]})], **details)
    return ok("No se encontraron números de tarjeta válidos ni contraseñas escritas en los tickets del periodo.", **details)
