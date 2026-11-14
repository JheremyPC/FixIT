"""Reports of an audit run: executive PDF, technical PDF and an evidence package (ZIP) with a SHA-256 manifest.

Everything is generated from the stored results (nothing is re-executed or invented). Redaction is applied by default:
e-mail addresses and IP addresses are masked and secrets removed; only an ADMIN may request an unredacted package, and
even then passwords, tokens and keys are never included (they are never stored). The manifest lets a recipient detect
later changes to the files; it is not a digital signature and does not prove authenticity by itself.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from html import escape as _html_escape

from sqlalchemy import or_, select
from sqlalchemy.orm import Session, joinedload

from app.auditing import catalog
from app.auditing.engine import controls, verify_seal
from app.auditing.evidence import path_of
from app.auditing.redaction import mask_email, mask_emails_in, mask_ip
from app.core.config import settings
from app.models import AuditControl, AuditEvidence, AuditFinding, AuditImport, AuditLog, AuditResult, AuditRun, User
from app.services.audit import iso, redact, verify
from app.services.exports import safe_row

UTC = timezone.utc
REDACT_BY_DEFAULT = True
PACKAGE_FORMAT = "fixit-paquete-auditoria 1.0"
MAX_EVIDENCE_BYTES = 50 * 1_048_576
STATUS_ORDER = ["FALLIDO", "ADVERTENCIA", "ERROR_EJECUCION", "NO_VERIFICADO", "APROBADO", "NO_APLICABLE"]


# --- Data -------------------------------------------------------------------------------------------------------------
def _mask(value, redacted: bool):
    if not redacted: return value
    if isinstance(value, dict): return {k: _mask(v, redacted) for k, v in value.items()}
    if isinstance(value, list): return [_mask(v, redacted) for v in value]
    if isinstance(value, str): return mask_emails_in(value)
    return value


def person(user: User | None, redacted: bool) -> str | None:
    if user is None: return None
    return f"{user.full_name if not redacted else user.full_name.split()[0]} · {mask_email(user.email) if redacted else user.email} ({user.role.code})"


def report_data(db: Session, run: AuditRun, redacted: bool = True) -> dict:
    registry = controls()
    catalog_rows = {c.code: c for c in db.scalars(select(AuditControl))}
    results = db.scalars(select(AuditResult).where(AuditResult.run_id == run.id)).all()
    order = {c: i for i, c in enumerate(run.control_codes)}
    results = sorted(results, key=lambda r: order.get(r.control_code, 9999))
    findings = db.scalars(select(AuditFinding).options(joinedload(AuditFinding.owner).joinedload(User.role)).where(
        AuditFinding.control_code.in_(run.control_codes),
        or_(AuditFinding.first_run_id == run.id, AuditFinding.last_run_id == run.id, AuditFinding.last_verification_run_id == run.id))
        .order_by(AuditFinding.severity, AuditFinding.code)).all()
    findings = sorted(findings, key=lambda f: (catalog.SEVERITY_ORDER.get(f.severity, 9), f.code))
    evidences = db.scalars(select(AuditEvidence).options(joinedload(AuditEvidence.uploaded_by).joinedload(User.role)).where(or_(
        AuditEvidence.control_code.in_(run.control_codes), AuditEvidence.finding_id.in_([f.id for f in findings] or [""])))
        .order_by(AuditEvidence.created_at.desc())).all()
    requester = db.get(User, run.requested_by_id) if run.requested_by_id else None

    def control_info(code):
        ctrl, row = registry.get(code), catalog_rows.get(code)
        return {"titulo": row.title if row else code, "objetivo": row.objective if row else "", "metodo": row.method if row else None,
                "criterios": (row.criteria if row else None) or [], "categoria": ctrl.category if ctrl else (row.category if row else None)}

    data = {
        "formato": PACKAGE_FORMAT, "generado_en": iso(datetime.now(UTC)), "redactado": redacted,
        "sistema": {"nombre": "FixIT", "descripcion": "Sistema Integral de Gestión de Soporte Técnico", "version": run.app_version, "compilacion": run.build},
        "auditoria": {"id": run.id, "codigo": run.code, "nombre": run.name, "tipo": run.audit_type, "estado": run.status,
                      "estado_texto": catalog.RUN_LABELS.get(run.status, run.status), "resultado": run.overall_result,
                      "resultado_texto": catalog.RESULT_LABELS.get(run.overall_result or "", "Sin resultado"),
                      "resultado_significado": catalog.RESULT_MEANING.get(run.overall_result or "", ""),
                      "responsable": person(requester, redacted), "creada": iso(run.created_at), "inicio": iso(run.started_at), "fin": iso(run.finished_at),
                      "zona_horaria": "UTC", "periodo": {"desde": iso(run.period_from), "hasta": iso(run.period_to)},
                      "categorias": [{"codigo": c, "nombre": catalog.CATEGORIES[c]["label"], "descripcion": catalog.CATEGORIES[c]["description"]}
                                     for c in run.categories if c in catalog.CATEGORIES],
                      "alcance": _mask(run.scope or {}, redacted), "controles": len(run.control_codes), "resumen": run.summary or {},
                      "herramientas": run.tools or {}, "conexion": run.connection_info or {}, "observaciones": run.observations,
                      "limitaciones": _mask(run.limitations or [], redacted), "sello_resultados": run.results_seal,
                      "verificacion_sello": verify_seal(run, results) if run.results_seal else "SIN_SELLO", "ejecucion_padre": run.parent_run_id},
        "resultados": [{"control": r.control_code, **control_info(r.control_code), "estado": r.status, "estado_texto": catalog.STATUS_LABELS.get(r.status, r.status),
                        "metodo_aplicado": r.method, "severidad": r.severity, "resumen": _mask(r.summary, redacted), "privilegios": r.privileges,
                        "inicio": iso(r.started_at), "duracion_ms": r.duration_ms, "detalles": _mask(r.details or {}, redacted), "error": r.error} for r in results],
        "hallazgos": [{"codigo": f.code, "titulo": f.title, "categoria": f.category, "control": f.control_code, "recurso": _mask(f.resource, redacted),
                       "severidad": f.severity, "estado": f.status, "estado_texto": catalog.FINDING_LABELS.get(f.status, f.status),
                       "descripcion": _mask(f.description, redacted), "impacto": f.impact, "probabilidad": f.likelihood, "recomendacion": f.recommendation,
                       "responsable": person(f.owner, redacted), "fecha_limite": f.due_date.isoformat() if f.due_date else None,
                       "detectado": iso(f.detected_at), "ultima_deteccion": iso(f.last_seen_at), "ocurrencias": f.occurrences,
                       "ultima_verificacion": f.last_verification, "evidencia": _mask(f.evidence or {}, redacted),
                       "riesgo_aceptado": {"justificacion": f.risk_justification, "revision": f.risk_review_date.isoformat() if f.risk_review_date else None}
                       if f.status == "RIESGO_ACEPTADO" else None} for f in findings],
        "evidencias": [{"id": e.id, "tipo": e.kind, "titulo": e.title, "control": e.control_code, "hallazgo_id": e.finding_id,
                        "resultado_declarado": e.declared_result, "fecha_evidencia": e.evidence_date.isoformat() if e.evidence_date else None,
                        "archivo": e.original_name, "stored_name": e.stored_name, "bytes": e.size, "sha256": e.sha256, "registrada": iso(e.created_at),
                        "registrada_por": person(e.uploaded_by, redacted), "descripcion": _mask(e.description, redacted)} for e in evidences],
        "metodologia": catalog.METHODOLOGY, "limitaciones_generales": catalog.LIMITATIONS, "estados": catalog.STATUS_MEANING,
        "metodos": catalog.METHODS, "referencias": catalog.REFERENCES,
    }
    imports = [i.get("id") for i in (run.tools or {}).get("informes_importados", [])]
    if imports:
        rows = db.scalars(select(AuditImport).where(AuditImport.id.in_(imports))).all()
        data["importaciones"] = [{"id": i.id, "tipo": i.kind, "archivo": i.source_name, "sha256": i.sha256, "importado": iso(i.imported_at),
                                  "herramienta": i.tool, "resumen": {k: v for k, v in (i.summary or {}).items() if k != "items"}} for i in rows]
    return data


# --- PDF ----------------------------------------------------------------------------------------------------------------
REPLACE = {"→": "->", "←": "<-", "≥": ">=", "≤": "<=", "·": "-", "✓": "Sí", "✗": "No", "…": "...", "‑": "-", "−": "-", "³": "3", "≈": "~"}


def _plain(value, limit: int | None = None) -> str:
    """Text the built-in PDF fonts can draw (WinAnsi): unsupported symbols are replaced, never dropped silently."""
    text = "" if value is None else str(value)
    for a, b in REPLACE.items(): text = text.replace(a, b)
    text = text.encode("cp1252", "replace").decode("cp1252")
    return text[:limit] + "..." if limit and len(text) > limit else text


def _t(value, limit: int | None = None) -> str:
    return _html_escape(_plain(value, limit), quote=False)  # &, < and > for reportlab's paragraph markup


def _styles():
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    base = getSampleStyleSheet()
    ink, muted, accent = colors.HexColor("#121826"), colors.HexColor("#667085"), colors.HexColor("#3a63d8")
    return {
        "title": ParagraphStyle("t", parent=base["Title"], fontName="Helvetica-Bold", fontSize=24, leading=29, textColor=ink, alignment=0, spaceAfter=10),
        "subtitle": ParagraphStyle("st", parent=base["Normal"], fontSize=13, leading=18, textColor=muted, spaceAfter=18),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=ink, spaceBefore=14, spaceAfter=8),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=11.5, leading=15, textColor=ink, spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("b", parent=base["Normal"], fontSize=9.5, leading=13.5, textColor=ink, spaceAfter=5),
        "small": ParagraphStyle("s", parent=base["Normal"], fontSize=8, leading=10.5, textColor=muted),
        "cell": ParagraphStyle("c", parent=base["Normal"], fontSize=8, leading=10.2, textColor=ink),
        "cellb": ParagraphStyle("cb", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=8, leading=10.2, textColor=colors.white),
        "kicker": ParagraphStyle("k", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=10, textColor=accent, spaceAfter=6),
        "colors": {"ink": ink, "muted": muted, "accent": accent, "line": colors.HexColor("#e4e7ec"), "head": colors.HexColor("#142033"),
                   "zebra": colors.HexColor("#f8f9fb")},
    }


def _table(rows: list[list], widths: list[float], st: dict, header: bool = True):
    from reportlab.lib import colors
    from reportlab.platypus import Paragraph, Table, TableStyle
    data = [[Paragraph(_t(c), st["cellb"] if header and i == 0 else st["cell"]) for c in row] for i, row in enumerate(rows)]
    table = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.3, st["colors"]["line"]), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
             ("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [colors.white, st["colors"]["zebra"]])]
    if header: style.append(("BACKGROUND", (0, 0), (-1, 0), st["colors"]["head"]))
    table.setStyle(TableStyle(style))
    return table


def _document(buffer, title: str, data: dict):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate
    audit = data["auditoria"]

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillGray(0.45)
        canvas.drawString(18 * mm, 10 * mm, _plain(f"FixIT · {title} · {audit['codigo']} · Generado {data['generado_en']} (UTC)"))
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Página {doc.page}")
        canvas.drawString(18 * mm, A4[1] - 10 * mm, "Documento de uso interno" + (" · Datos personales enmascarados" if data["redactado"] else " · CONTIENE DATOS PERSONALES"))
        canvas.restoreState()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=18 * mm, bottomMargin=18 * mm,
                            title=f"{title} {audit['codigo']}", author="FixIT Audit Engine", subject=audit["nombre"])
    return doc, footer


def _counts(data: dict) -> dict:
    by = data["auditoria"]["resumen"].get("por_estado") or {}
    return {s: by.get(s, 0) for s in catalog.STATUS_LABELS}


def _severity_counts(findings: list[dict]) -> dict:
    out = {s: 0 for s in catalog.SEVERITY_LABELS}
    for f in findings:
        if f["estado"] in catalog.OPEN_FINDING_STATUSES: out[f["severidad"]] += 1
    return out


def _cover(story, st, title: str, data: dict):
    from reportlab.platypus import PageBreak, Paragraph, Spacer
    a = data["auditoria"]
    story += [Spacer(1, 60), Paragraph("CENTRO INTEGRAL DE AUDITORÍA", st["kicker"]), Paragraph(_t(title), st["title"]),
              Paragraph(_t(f"{data['sistema']['nombre']} — {data['sistema']['descripcion']}"), st["subtitle"]),
              _table([["Auditoría", f"{a['codigo']} · {a['nombre']}"], ["Tipo", a["tipo"]], ["Estado", a["estado_texto"]],
                      ["Resultado general", a["resultado_texto"]], ["Periodo evaluado", _period(a)], ["Ejecución", f"{a['inicio']} a {a['fin']} (UTC)"],
                      ["Responsable", a["responsable"] or "Sistema"], ["Versión de FixIT", f"{data['sistema']['version']}" + (f" ({data['sistema']['compilacion']})" if data['sistema']['compilacion'] else "")],
                      ["Fecha del informe", data["generado_en"]]], [120, 340], st, header=False),
              Spacer(1, 24), Paragraph(_t("Este informe se generó automáticamente a partir de los resultados almacenados de la auditoría. Las "
                                          "referencias (OWASP ASVS 5.0, NIST SP 800-92, CIS PostgreSQL, ISO 19011, Ley N.º 29733) inspiran los controles; "
                                          "su uso no implica certificación ni cumplimiento legal pleno."), st["small"]), PageBreak()]


def _period(a: dict) -> str:
    p = a["periodo"]
    return f"{p['desde'] or 'últimos 30 días'} a {p['hasta'] or a['inicio']}" if (p["desde"] or p["hasta"]) else "Últimos 30 días hasta la ejecución"


def executive_pdf(data: dict) -> bytes:
    from reportlab.platypus import Paragraph, Spacer
    st = _styles()
    buffer = io.BytesIO()
    doc, footer = _document(buffer, "Informe ejecutivo de auditoría", data)
    story: list = []
    _cover(story, st, "Informe ejecutivo de auditoría", data)
    a, findings = data["auditoria"], data["hallazgos"]
    counts, severities = _counts(data), _severity_counts(findings)
    executed = counts["APROBADO"] + counts["FALLIDO"] + counts["ADVERTENCIA"]
    open_findings = [f for f in findings if f["estado"] in catalog.OPEN_FINDING_STATUSES]
    story += [Paragraph("1. Identificación del sistema", st["h1"]),
              Paragraph(_t(f"FixIT {data['sistema']['version']}: mesa de ayuda de soporte técnico con API FastAPI, base de datos PostgreSQL y cliente "
                           f"web. Base de datos evaluada: {a['conexion'].get('ubicacion', 'no determinada')}."), st["body"]),
              Paragraph("2. Alcance y objetivos", st["h1"]),
              Paragraph(_t(f"Se evaluaron {a['controles']} controles de {len(a['categorias'])} categorías durante el periodo {_period(a)}."), st["body"])]
    for c in a["categorias"]:
        story.append(Paragraph(_t(f"• {c['nombre']}: {c['descripcion']}"), st["body"]))
    if (a["alcance"] or {}).get("descripcion"): story.append(Paragraph(_t(f"Alcance declarado: {a['alcance']['descripcion']}"), st["body"]))
    summary_text = (f"Resultado general: {a['resultado_texto'].upper()}. {a['resultado_significado']} De {a['controles']} controles, {executed} se ejecutaron "
                    f"con resultado concluyente ({counts['APROBADO']} aprobados, {counts['FALLIDO']} fallidos y {counts['ADVERTENCIA']} con advertencias); "
                    f"{counts['NO_VERIFICADO']} no pudieron verificarse, {counts['ERROR_EJECUCION']} tuvieron error de ejecución y {counts['NO_APLICABLE']} no "
                    f"aplicaban a este entorno. Quedan {len(open_findings)} hallazgos abiertos, {severities['CRITICO']} críticos y {severities['ALTO']} altos.")
    story += [Paragraph("3. Resumen ejecutivo", st["h1"]), Paragraph(_t(summary_text), st["body"]),
              Paragraph("4. Indicadores", st["h1"]),
              _table([["Indicador", "Valor"]] + [[catalog.STATUS_LABELS[k], v] for k, v in counts.items()] +
                     [["Hallazgos abiertos", len(open_findings)]] + [[f"Hallazgos abiertos {catalog.SEVERITY_LABELS[k].lower()}s", v] for k, v in severities.items()],
                     [300, 160], st),
              Paragraph("5. Hallazgos por severidad", st["h1"])]
    if findings:
        story.append(_table([["Código", "Hallazgo", "Severidad", "Estado"]] + [[f["codigo"], f["titulo"], catalog.SEVERITY_LABELS[f["severidad"]], f["estado_texto"]]
                                                                              for f in findings[:60]], [60, 250, 65, 95], st))
        if len(findings) > 60: story.append(Paragraph(_t(f"Se muestran 60 de {len(findings)} hallazgos; la lista completa figura en el informe técnico."), st["small"]))
    else:
        story.append(Paragraph("La ejecución no produjo hallazgos.", st["body"]))
    serious = [f for f in open_findings if f["severidad"] in ("CRITICO", "ALTO")]
    story.append(Paragraph("6. Riesgos principales", st["h1"]))
    if serious:
        for f in serious[:12]:
            story.append(Paragraph(f"<b>{_t(f['codigo'] + ' · ' + f['titulo'])}</b>", st["body"]))
            story.append(Paragraph(_t(f"Impacto: {f['impacto']} Probabilidad: {f['probabilidad']}"), st["body"]))
    else:
        story.append(Paragraph("No hay hallazgos abiertos de severidad crítica o alta.", st["body"]))
    story.append(Paragraph("7. Recomendaciones", st["h1"]))
    seen = []
    for f in open_findings:
        if f["recomendacion"] not in seen: seen.append(f["recomendacion"])
    for i, rec in enumerate(seen[:15], start=1): story.append(Paragraph(_t(f"{i}. {rec}"), st["body"]))
    if not seen: story.append(Paragraph("Mantener la ejecución periódica de la auditoría y la verificación de los controles no verificados.", st["body"]))
    conclusion = {"FAVORABLE": "Los controles ejecutados no presentan incumplimientos. La conclusión se limita a lo verificado; los controles no verificados deben completarse con evidencia.",
                  "CON_OBSERVACIONES": "FixIT presenta observaciones que no comprometen de forma crítica la seguridad, pero requieren un plan de acción con responsables y plazos.",
                  "DESFAVORABLE": "Existen incumplimientos de severidad crítica o alta que requieren atención prioritaria antes de considerar el sistema en un estado aceptable.",
                  "NO_CONCLUYENTE": "La auditoría no puede emitir una conclusión: una parte relevante de los controles no pudo verificarse o tuvo errores."}
    story += [Paragraph("8. Conclusiones", st["h1"]), Paragraph(_t(conclusion.get(a["resultado"], "Auditoría sin resultado final.")), st["body"]),
              Paragraph("9. Limitaciones", st["h1"])]
    for item in data["limitaciones_generales"]: story.append(Paragraph(_t(f"• {item}"), st["body"]))
    if a["limitaciones"]:
        story.append(Paragraph(_t(f"En esta ejecución, {len(a['limitaciones'])} controles quedaron sin verificar o con error (detalle en el informe técnico)."), st["body"]))
    story += [Spacer(1, 10), Paragraph(_t(f"Sello de resultados: {a['sello_resultados'] or 'sin sello'} · verificación: {a['verificacion_sello']}."), st["small"])]
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def _flatten(value, prefix: str = "", out: list | None = None, depth: int = 0) -> list[tuple[str, str]]:
    out = [] if out is None else out
    if len(out) >= 40: return out
    if isinstance(value, dict) and depth < 2:
        for k, v in value.items():
            if str(k).startswith("_"): continue
            _flatten(v, f"{prefix}{k}." if isinstance(v, dict) and depth < 1 else f"{prefix}{k}", out, depth + 1)
    else:
        text = json.dumps(value, ensure_ascii=False, default=str) if isinstance(value, (dict, list)) else str(value)
        out.append((prefix.rstrip("."), text))
    return out


def technical_pdf(data: dict) -> bytes:
    from reportlab.platypus import KeepTogether, PageBreak, Paragraph
    st = _styles()
    buffer = io.BytesIO()
    doc, footer = _document(buffer, "Informe técnico de auditoría", data)
    story: list = []
    _cover(story, st, "Informe técnico de auditoría", data)
    a = data["auditoria"]
    story.append(Paragraph("1. Metodología", st["h1"]))
    for step in data["metodologia"]: story.append(Paragraph(_t(f"• {step}"), st["body"]))
    story.append(Paragraph("Métodos de verificación", st["h2"]))
    story.append(_table([["Método", "Descripción"]] + [[k, v] for k, v in data["metodos"].items()], [80, 390], st))
    story.append(Paragraph("Estados de las comprobaciones", st["h2"]))
    story.append(_table([["Estado", "Significado"]] + [[catalog.STATUS_LABELS[k], v] for k, v in data["estados"].items()], [95, 375], st))
    story += [Paragraph("2. Herramientas, versiones y conexión", st["h1"]),
              _table([["Elemento", "Valor"]] + [[k, json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v] for k, v in a["herramientas"].items()],
                     [130, 340], st),
              Paragraph("Privilegios de la conexión de auditoría", st["h2"]),
              Paragraph(_t(a["conexion"].get("resumen") or "No disponible."), st["body"]),
              _table([["Atributo", "Valor"]] + [[k, v] for k, v in a["conexion"].items() if k not in ("resumen",)], [130, 340], st),
              Paragraph("3. Alcance y criterios", st["h1"]),
              Paragraph(_t(f"Periodo: {_period(a)}. Categorías: {', '.join(c['nombre'] for c in a['categorias'])}. Controles: {a['controles']}. "
                           f"Opciones: {json.dumps((a['alcance'] or {}).get('options') or {}, ensure_ascii=False)}."), st["body"])]
    story.append(_table([["Referencia", "Uso"]] + [[v["name"], "Criterio de inspiración (sin certificación)"] for v in data["referencias"].values()], [320, 150], st))
    story += [PageBreak(), Paragraph("4. Controles ejecutados", st["h1"]),
              _table([["Control", "Título", "Método", "Estado", "Sev."]] + [[r["control"], r["titulo"], r["metodo_aplicado"], r["estado_texto"], r["severidad"] or ""]
                                                                          for r in data["resultados"]], [62, 228, 62, 78, 40], st),
              PageBreak(), Paragraph("5. Resultados detallados", st["h1"])]
    current = None
    for r in data["resultados"]:
        if r["categoria"] != current:
            current = r["categoria"]
            story.append(Paragraph(_t(catalog.CATEGORIES.get(current, {}).get("label", current or "")), st["h2"]))
        block = [Paragraph(_t(f"{r['control']} · {r['titulo']} — {r['estado_texto']}" + (f" ({r['severidad']})" if r["severidad"] else "")), st["body"]),
                 Paragraph(_t(f"Objetivo: {r['objetivo']}"), st["small"]),
                 Paragraph(_t(f"Resultado: {r['resumen']}"), st["body"]),
                 Paragraph(_t(f"Método: {r['metodo_aplicado']} · Privilegios: {r['privilegios'] or 'n/d'} · Duración: {r['duracion_ms']} ms"
                              + (f" · Criterios: {'; '.join(r['criterios'])}" if r["criterios"] else "")), st["small"])]
        rows = _flatten(r["detalles"])
        if rows: block.append(_table([["Evidencia", "Valor"]] + [[k, v if len(v) <= 600 else v[:600] + "..."] for k, v in rows], [130, 340], st))
        story.append(KeepTogether(block[:4]))
        story += block[4:]
    story += [PageBreak(), Paragraph("6. Hallazgos", st["h1"])]
    if not data["hallazgos"]: story.append(Paragraph("Sin hallazgos.", st["body"]))
    for f in data["hallazgos"]:
        story.append(KeepTogether([Paragraph(_t(f"{f['codigo']} · {f['titulo']}"), st["h2"]),
                                   _table([["Campo", "Valor"], ["Severidad / estado", f"{catalog.SEVERITY_LABELS[f['severidad']]} · {f['estado_texto']}"],
                                           ["Control / recurso", f"{f['control']} · {f['recurso']}"], ["Descripción", f["descripcion"]], ["Impacto", f["impacto"]],
                                           ["Probabilidad", f["probabilidad"]], ["Recomendación", f["recomendacion"]],
                                           ["Responsable / fecha límite", f"{f['responsable'] or 'Sin asignar'} · {f['fecha_limite'] or 'Sin fecha'}"],
                                           ["Detección", f"{f['detectado']} · última {f['ultima_deteccion']} · {f['ocurrencias']} ocurrencias · verificación {f['ultima_verificacion'] or 'n/d'}"]]
                                          + ([["Riesgo aceptado", f"{f['riesgo_aceptado']['justificacion']} (revisión {f['riesgo_aceptado']['revision']})"]] if f["riesgo_aceptado"] else []),
                                          [120, 350], st)]))
    story.append(Paragraph("7. Evidencias manuales y de corrección", st["h1"]))
    if data["evidencias"]:
        story.append(_table([["Título", "Tipo", "Control", "Resultado", "Fecha", "SHA-256"]] + [[e["titulo"], e["tipo"], e["control"] or "", e["resultado_declarado"] or "",
                             e["fecha_evidencia"] or e["registrada"], (e["sha256"] or "")[:16]] for e in data["evidencias"]], [150, 55, 55, 60, 70, 80], st))
    else:
        story.append(Paragraph("No hay evidencias registradas para los controles de esta auditoría.", st["body"]))
    for imp in data.get("importaciones", []):
        story.append(Paragraph(_t(f"Informe importado: {imp['tipo']} · {imp['archivo']} · {imp['importado']} · SHA-256 {imp['sha256'][:16]}…"), st["small"]))
    story += [Paragraph("8. Controles no verificados y limitaciones técnicas", st["h1"])]
    unverified = [r for r in data["resultados"] if r["estado"] in ("NO_VERIFICADO", "ERROR_EJECUCION")]
    if unverified:
        story.append(_table([["Control", "Estado", "Motivo"]] + [[r["control"], r["estado_texto"], r["resumen"]] for r in unverified], [62, 80, 328], st))
    else:
        story.append(Paragraph("Todos los controles aplicables se ejecutaron.", st["body"]))
    for item in data["limitaciones_generales"]: story.append(Paragraph(_t(f"• {item}"), st["body"]))
    story.append(Paragraph(_t(f"Sello HMAC de resultados: {a['sello_resultados'] or 'sin sello'} — verificación al generar este informe: {a['verificacion_sello']}."), st["small"]))
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


# --- Evidence package ---------------------------------------------------------------------------------------------------
LOG_COLUMNS = ["id", "fecha_utc", "usuario_id", "accion", "modulo", "entidad", "entidad_id", "resultado", "ip", "navegador", "valor_anterior", "valor_nuevo", "integridad"]


def _logs(db: Session, run: AuditRun, redacted: bool) -> tuple[list[dict], bool]:
    start, end = run.period_from, run.period_to or run.started_at or run.created_at
    query = select(AuditLog)
    if start: query = query.where(AuditLog.created_at >= start)
    if end: query = query.where(AuditLog.created_at < end)
    rows = db.scalars(query.order_by(AuditLog.created_at, AuditLog.id).limit(settings.audit_export_max_rows + 1)).all()
    truncated = len(rows) > settings.audit_export_max_rows
    out = []
    for r in rows[:settings.audit_export_max_rows]:
        out.append({"id": r.id, "fecha_utc": iso(r.created_at), "usuario_id": r.user_id, "accion": r.action, "modulo": r.module, "entidad": r.entity,
                    "entidad_id": r.entity_id, "resultado": r.outcome, "ip": mask_ip(r.ip) if redacted else r.ip,
                    "navegador": (r.user_agent or "")[:60] if redacted else r.user_agent,
                    "valor_anterior": _mask(redact(r.old_value), redacted), "valor_nuevo": _mask(redact(r.new_value), redacted), "integridad": verify(r)})
    return out, truncated


def _csv(rows: list[dict], columns: list[str]) -> bytes:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(columns)
    for r in rows:
        writer.writerow(safe_row([json.dumps(r.get(c), ensure_ascii=False) if isinstance(r.get(c), (dict, list)) else r.get(c) for c in columns]))
    return ("﻿" + out.getvalue()).encode("utf-8")


def package(db: Session, run: AuditRun, data: dict, redacted: bool) -> bytes:
    files: dict[str, bytes] = {}
    dump = lambda obj: json.dumps(obj, ensure_ascii=False, indent=2, default=str).encode("utf-8")  # noqa: E731
    files["informe-ejecutivo.pdf"] = executive_pdf(data)
    files["informe-tecnico.pdf"] = technical_pdf(data)
    files["resultados.json"] = dump(data["resultados"])
    files["hallazgos.json"] = dump(data["hallazgos"])
    files["hallazgos.csv"] = _csv([{**f, "evidencia": None} for f in data["hallazgos"]],
                                  ["codigo", "titulo", "categoria", "control", "recurso", "severidad", "estado", "responsable", "fecha_limite", "detectado",
                                   "ultima_deteccion", "ocurrencias", "ultima_verificacion", "descripcion", "impacto", "probabilidad", "recomendacion"])
    logs, truncated = _logs(db, run, redacted)
    files["registros/auditoria-actividad.json"] = dump({"periodo": data["auditoria"]["periodo"], "redactado": redacted, "truncado": truncated, "registros": logs})
    files["registros/auditoria-actividad.csv"] = _csv(logs, LOG_COLUMNS)
    included, skipped, total = [], [], 0
    for e in data["evidencias"]:
        if not e["stored_name"]: continue
        try:
            raw = path_of(e["stored_name"]).read_bytes()
        except (OSError, Exception):  # noqa: BLE001 - a missing file is reported in the index, never invented
            skipped.append({"id": e["id"], "motivo": "Archivo no encontrado en el servidor"})
            continue
        if total + len(raw) > MAX_EVIDENCE_BYTES:
            skipped.append({"id": e["id"], "motivo": "Se superó el tamaño máximo del paquete"})
            continue
        total += len(raw)
        name = f"evidencias/{e['id'][:8]}-{(e['archivo'] or 'evidencia').replace('/', '_')}"
        files[name] = raw
        included.append({"id": e["id"], "archivo": name, "sha256_registrado": e["sha256"], "coincide": hashlib.sha256(raw).hexdigest() == e["sha256"]})
    files["evidencias/indice.json"] = dump({"evidencias": [{k: v for k, v in e.items() if k != "stored_name"} for e in data["evidencias"]],
                                           "incluidas": included, "omitidas": skipped})
    if data.get("importaciones"): files["importaciones.json"] = dump(data["importaciones"])
    meta = {"formato": PACKAGE_FORMAT, "generado_en": data["generado_en"], "zona_horaria": "UTC", "sistema": data["sistema"],
            "auditoria": {k: v for k, v in data["auditoria"].items() if k not in ("limitaciones",)}, "limitaciones": data["auditoria"]["limitaciones"],
            "redaccion": ("Correos e IP enmascarados, navegador abreviado y secretos eliminados." if redacted else
                          "Paquete sin enmascarar (solicitado por un ADMIN); contraseñas, tokens y claves nunca se almacenan."),
            "registros_truncados": truncated, "metodologia": data["metodologia"], "referencias": data["referencias"]}
    files["metadatos.json"] = dump(meta)
    manifest = {"formato": PACKAGE_FORMAT, "auditoria": data["auditoria"]["codigo"], "generado_en": data["generado_en"], "algoritmo": "SHA-256",
                "archivos": [{"ruta": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} for name, raw in sorted(files.items())],
                "alcance": "El manifiesto permite detectar si un archivo del paquete se modificó después de generarlo. No es una firma digital ni "
                           "garantiza por sí solo la autenticidad: conserve el SHA-256 del ZIP en un acta o sistema independiente."}
    files["manifiesto.json"] = dump(manifest)
    files["SHA256SUMS.txt"] = "".join(f"{f['sha256']}  {f['ruta']}\n" for f in manifest["archivos"]).encode("utf-8")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, raw in files.items(): archive.writestr(name, raw)
    return buffer.getvalue()
