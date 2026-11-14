"""Category PROCESOS: FixIT operational controls over tickets, assignments, SLA, ratings and their history.

Scope: tickets created in the run period (option ``origen``: todos | reales | sinteticos; synthetic tickets have the SYN-
prefix). Statistical and Machine Learning results are risk signals for review, never proof of an irregularity. Nothing is
modified: tickets are only counted and sampled by number.
"""
from __future__ import annotations

import statistics
import threading
from datetime import timedelta

from sqlalchemy import func, select

from app.auditing.controls.common import aware, finding, pct, period_text, sample
from app.auditing.registry import Ctx, Outcome, control, fail, ok, warn
from app.models import Priority, Rating, Ticket, TicketAssignment, TicketHistory, TicketState
from app.synthetic.catalog import SYNTHETIC_TICKET_PREFIX

C = "PROCESOS"
CRITERIA = ["ISO 19011 (muestreo y evidencia objetiva)", "Reglas de negocio de FixIT (app.services.tickets.TRANSITIONS)"]
TERMINAL = ("CERRADO", "CANCELADO")
_cache: dict = {}
_cache_lock = threading.Lock()


def _origin_filter(ctx: Ctx, query):
    origin = ctx.option("origen", "todos")
    if origin == "reales": return query.where(~Ticket.number.like(f"{SYNTHETIC_TICKET_PREFIX}%"))
    if origin == "sinteticos": return query.where(Ticket.number.like(f"{SYNTHETIC_TICKET_PREFIX}%"))
    return query


def data(ctx: Ctx) -> dict:
    """Tickets of the period and their history, loaded once per run (read-only snapshot shared by the OPE controls)."""
    key = (ctx.run.id, ctx.option("origen", "todos"))
    with _cache_lock:
        if key in _cache: return _cache[key]
    start, end = ctx.period()
    q = (select(Ticket.id, Ticket.number, TicketState.code.label("state"), Priority.code.label("priority"), Priority.sla_hours, Ticket.created_at,
                Ticket.due_at, Ticket.accepted_at, Ticket.started_at, Ticket.resolved_at, Ticket.closed_at, Ticket.technician_id,
                Ticket.requester_id, Ticket.solution.is_(None).label("no_solution"))
         .join(TicketState, TicketState.id == Ticket.state_id).join(Priority, Priority.id == Ticket.priority_id)
         .where(Ticket.created_at >= start, Ticket.created_at < end))
    tickets = [dict(r._mapping) for r in ctx.session.execute(_origin_filter(ctx, q))]
    for t in tickets:
        for k in ("created_at", "due_at", "accepted_at", "started_at", "resolved_at", "closed_at"): t[k] = aware(t[k])
        t["synthetic"] = t["number"].startswith(SYNTHETIC_TICKET_PREFIX)
    ids = [t["id"] for t in tickets]
    history: dict[str, list] = {i: [] for i in ids}
    assignments: dict[str, list] = {i: [] for i in ids}
    for chunk in range(0, len(ids), 900):
        part = ids[chunk:chunk + 900]
        for h in ctx.session.execute(select(TicketHistory.ticket_id, TicketHistory.event, TicketHistory.created_at, TicketHistory.new_value)
                                     .where(TicketHistory.ticket_id.in_(part))):
            history[h.ticket_id].append({"event": h.event, "at": aware(h.created_at), "new": h.new_value or {}})
        for a in ctx.session.execute(select(TicketAssignment.ticket_id, TicketAssignment.assignment_type, TicketAssignment.reason,
                                            TicketAssignment.technician_id).where(TicketAssignment.ticket_id.in_(part))):
            assignments[a.ticket_id].append({"type": a.assignment_type, "reason": a.reason, "technician_id": a.technician_id})
    result = {"tickets": tickets, "history": history, "assignments": assignments, "start": start, "end": end}
    with _cache_lock:
        _cache.clear()
        _cache[key] = result
    return result


def _numbers(items) -> list[str]:
    return sample(t["number"] for t in items)


def _origin(items) -> dict:
    synthetic = sum(1 for t in items if t["synthetic"])
    return {"reales": len(items) - synthetic, "sinteticos": synthetic}


def _base(ctx: Ctx, d: dict) -> dict:
    return {"periodo": period_text(ctx), "origen": ctx.option("origen", "todos"), "tickets_en_alcance": len(d["tickets"]), "por_origen": _origin(d["tickets"])}


@control("OPE-01", C, "Creación y registro inicial de tickets", "Verificar que cada ticket del periodo tiene su evento de creación en el "
         "historial.", "SQL", "MEDIO", CRITERIA)
def creation(ctx: Ctx) -> Outcome:
    d = data(ctx)
    missing = [t for t in d["tickets"] if not any(h["event"] == "CREADO" for h in d["history"][t["id"]])]
    details = {**_base(ctx, d), "sin_evento_creado": len(missing), "muestra": _numbers(missing), "por_origen_sin_evento": _origin(missing)}
    if missing:
        return fail(f"{len(missing)} de {len(d['tickets'])} tickets no tienen evento de creación en su historial.", [finding(
            "procesos:sin_creacion", "Tickets sin registro de creación", f"{len(missing)} tickets carecen del evento CREADO.",
            "No puede reconstruirse el origen del ticket; posible inserción fuera de la aplicación.", "Comprobado sobre todos los tickets del periodo.",
            "Investigue cómo se crearon (importaciones, scripts) y documente el origen.", "MEDIO", details)], **details)
    return ok(f"Los {len(d['tickets'])} tickets del periodo tienen evento de creación.", **details)


@control("OPE-02", C, "Coherencia de estados y marcas de tiempo", "Detectar tickets cuyo estado no concuerda con sus fechas (cerrados sin fecha "
         "de cierre, resueltos sin solución, fechas anteriores a la creación).", "SQL", "MEDIO", CRITERIA)
def state_consistency(ctx: Ctx) -> Outcome:
    d = data(ctx)
    rules = {
        "cerrado_sin_fecha_de_cierre": lambda t: t["state"] == "CERRADO" and not t["closed_at"],
        "resuelto_o_cerrado_sin_fecha_de_resolucion": lambda t: t["state"] in ("RESUELTO", "CERRADO") and not t["resolved_at"],
        "resuelto_o_cerrado_sin_solucion": lambda t: t["state"] in ("RESUELTO", "CERRADO") and t["no_solution"],
        "en_atencion_sin_fecha_de_inicio": lambda t: t["state"] in ("EN_ATENCION", "EN_ESPERA", "RESUELTO", "CERRADO") and not t["started_at"],
        "fechas_anteriores_a_la_creacion": lambda t: any(t[k] and t[k] < t["created_at"] - timedelta(seconds=1) for k in ("accepted_at", "started_at", "resolved_at", "closed_at")),
        "cierre_anterior_a_resolucion": lambda t: t["closed_at"] and t["resolved_at"] and t["closed_at"] < t["resolved_at"],
        "asignado_sin_tecnico": lambda t: t["state"] in ("ASIGNADO", "EN_ATENCION", "EN_ESPERA") and not t["technician_id"],
    }
    found = {name: [t for t in d["tickets"] if rule(t)] for name, rule in rules.items()}
    found = {k: v for k, v in found.items() if v}
    details = {**_base(ctx, d), "inconsistencias": {k: {"tickets": len(v), "muestra": _numbers(v), "por_origen": _origin(v)} for k, v in found.items()}}
    if found:
        return fail(f"{sum(len(v) for v in found.values())} inconsistencias en {len(found)} reglas.", [finding(
            f"procesos:{name}", f"Inconsistencia de estado: {name.replace('_', ' ')}", f"{len(items)} tickets: {', '.join(_numbers(items)[:5])}…",
            "Métricas de SLA y reportes incorrectos; posible modificación directa de datos.", "Comprobado sobre todos los tickets del periodo.",
            "Revise el historial de esos tickets y corrija los datos con trazabilidad.", "MEDIO", {"muestra": _numbers(items), "por_origen": _origin(items)})
            for name, items in found.items()], **details)
    return ok(f"Estados y marcas de tiempo coherentes en los {len(d['tickets'])} tickets.", **details)


@control("OPE-03", C, "Cambios posteriores al cierre", "Detectar eventos en el historial posteriores al cierre o cancelación del ticket.",
         "SQL", "MEDIO", CRITERIA)
def after_close(ctx: Ctx) -> Outcome:
    d = data(ctx)
    hits = []
    for t in d["tickets"]:
        if t["state"] not in TERMINAL: continue
        end = t["closed_at"] or max((h["at"] for h in d["history"][t["id"]] if h["event"] == "ESTADO_CAMBIADO" and (h["new"] or {}).get("state") in TERMINAL), default=None)
        if not end: continue
        later = [h["event"] for h in d["history"][t["id"]] if h["at"] > end + timedelta(seconds=2)]
        if later: hits.append({"ticket": t["number"], "eventos": later[:5], "synthetic": t["synthetic"]})
    details = {**_base(ctx, d), "tickets_con_cambios_posteriores": len(hits), "muestra": hits[:20]}
    if hits:
        return warn(f"{len(hits)} tickets cerrados o cancelados con actividad posterior.", [finding(
            "procesos:despues_del_cierre", "Actividad en tickets después de su cierre", f"{len(hits)} tickets registran eventos tras cerrarse.",
            "Un ticket cerrado debería ser inmutable; los cambios posteriores alteran métricas o evidencias.", "Requiere revisión del caso.",
            "Verifique cada caso; si corresponde, use la reapertura en lugar de modificar tickets cerrados.", "BAJO", {"muestra": hits[:20]})], "BAJO", **details)
    return ok("Sin actividad posterior al cierre en los tickets del periodo.", **details)


@control("OPE-04", C, "Reaperturas", "Medir la tasa de reapertura y detectar tickets reabiertos repetidamente.", "SQL", "BAJO", CRITERIA)
def reopenings(ctx: Ctx) -> Outcome:
    d = data(ctx)
    counts = {t["number"]: sum(1 for h in d["history"][t["id"]] if h["event"] == "ESTADO_CAMBIADO" and (h["new"] or {}).get("state") == "REABIERTO")
              for t in d["tickets"]}
    resolved = sum(1 for t in d["tickets"] if t["resolved_at"])
    reopened = [n for n, c in counts.items() if c]
    repeated = [n for n, c in counts.items() if c >= 2]
    rate = pct(len(reopened), resolved)
    details = {**_base(ctx, d), "resueltos": resolved, "reabiertos": len(reopened), "tasa_reapertura_pct": rate, "reabiertos_2_o_mas": sample(repeated)}
    if repeated or (rate or 0) > float(ctx.option("tasa_reapertura_max", 10)):
        return warn(f"Tasa de reapertura {rate} %; {len(repeated)} tickets reabiertos dos o más veces.", [finding(
            "procesos:reaperturas", "Reaperturas frecuentes", f"Tasa {rate} % y {len(repeated)} tickets con reaperturas repetidas.",
            "Soluciones incompletas o cierres prematuros; afecta la satisfacción.", "Indicador de calidad, no de irregularidad.",
            "Analice las causas por categoría y técnico.", "BAJO", {"muestra": sample(repeated)})], "BAJO", **details)
    return ok(f"Tasa de reapertura {rate if rate is not None else 0} %; sin reaperturas repetidas.", **details)


@control("OPE-05", C, "Asignaciones y reasignaciones", "Verificar que cada ticket con técnico tiene su registro de asignación, que las "
         "asignaciones manuales tienen motivo y detectar reasignaciones excesivas.", "SQL", "MEDIO", CRITERIA)
def assignments(ctx: Ctx) -> Outcome:
    d = data(ctx)
    without = [t for t in d["tickets"] if t["technician_id"] and not d["assignments"][t["id"]]]
    excessive = [t for t in d["tickets"] if len(d["assignments"][t["id"]]) >= int(ctx.option("max_reasignaciones", 3))]
    no_reason = [t for t in d["tickets"] if any(a["type"] == "MANUAL" and not (a["reason"] or "").strip() for a in d["assignments"][t["id"]])]
    mismatch = [t for t in d["tickets"] if t["technician_id"] and d["assignments"][t["id"]] and
                t["technician_id"] not in {a["technician_id"] for a in d["assignments"][t["id"]]}]
    details = {**_base(ctx, d), "tecnico_sin_registro_de_asignacion": len(without), "reasignaciones_excesivas": len(excessive),
               "manuales_sin_motivo": len(no_reason), "tecnico_actual_sin_asignacion_registrada": len(mismatch),
               "muestras": {"sin_registro": _numbers(without), "excesivas": _numbers(excessive), "sin_correspondencia": _numbers(mismatch)}}
    findings = []
    if without or mismatch:
        items = without + mismatch
        findings.append(finding("procesos:asignacion_sin_registro", "Técnicos asignados sin registro de asignación",
                                f"{len(items)} tickets tienen un técnico que no consta en ticket_assignments.", "La asignación no es trazable.",
                                "Comprobado sobre todos los tickets del periodo.", "Investigue si se asignaron fuera de la aplicación.", "MEDIO",
                                {"muestra": _numbers(items), "por_origen": _origin(items)}))
    if excessive:
        findings.append(finding("procesos:reasignaciones", "Reasignaciones excesivas", f"{len(excessive)} tickets con 3 o más asignaciones.",
                                "Demoras y pérdida de contexto.", "Indicador operativo.", "Revise las reglas de asignación y especialidades.", "BAJO",
                                {"muestra": _numbers(excessive)}))
    if findings: return (fail if without or mismatch else warn)("Hay asignaciones sin trazabilidad o reasignaciones excesivas.", findings, **details)
    return ok("Todas las asignaciones tienen registro y no hay reasignaciones excesivas.", **details)


@control("OPE-06", C, "Cambios de prioridad y plazos", "Comparar el plazo (due_at) de cada ticket con el SLA de su prioridad actual para detectar "
         "cambios de prioridad o de plazo no registrados.", "SQL", "MEDIO", CRITERIA)
def priority_changes(ctx: Ctx) -> Outcome:
    d = data(ctx)
    tolerance = timedelta(minutes=int(ctx.option("tolerancia_plazo_min", 10)))
    recorded = {t["id"] for t in d["tickets"] if any("priority" in (h["new"] or {}) and h["event"] != "CREADO" for h in d["history"][t["id"]])}
    mismatched = [t for t in d["tickets"] if t["due_at"] and abs(t["due_at"] - (t["created_at"] + timedelta(hours=t["sla_hours"]))) > tolerance
                  and t["id"] not in recorded]
    details = {**_base(ctx, d), "plazo_distinto_al_sla_de_la_prioridad": len(mismatched), "cambios_de_prioridad_registrados": len(recorded),
               "muestra": _numbers(mismatched), "por_origen": _origin(mismatched),
               "criterio": "due_at debe ser created_at + horas SLA de la prioridad, salvo un cambio registrado en el historial."}
    if mismatched:
        return warn(f"{len(mismatched)} tickets tienen un plazo que no corresponde a su prioridad y sin cambio registrado.", [finding(
            "procesos:plazos", "Plazos o prioridades modificados sin registro", f"{len(mismatched)} tickets.",
            "Los indicadores de cumplimiento de SLA pueden estar alterados.", "Requiere revisión (incluye cambios de SLA de una prioridad).",
            "Registre los cambios de prioridad en el historial y revise los casos.", "MEDIO", {"muestra": _numbers(mismatched), "por_origen": _origin(mismatched)})],
            **details)
    return ok("Los plazos de todos los tickets corresponden al SLA de su prioridad o a un cambio registrado.", **details)


@control("OPE-07", C, "Cumplimiento de SLA", "Medir el porcentaje de tickets resueltos dentro del plazo y los abiertos vencidos, por prioridad, "
         "frente al objetivo configurado.", "SQL", "MEDIO", CRITERIA)
def sla(ctx: Ctx) -> Outcome:
    d = data(ctx)
    target = float(ctx.option("sla_objetivo", 85))
    by: dict[str, dict] = {}
    for t in d["tickets"]:
        b = by.setdefault(t["priority"], {"resueltos": 0, "a_tiempo": 0, "abiertos_vencidos": 0})
        if t["resolved_at"] and t["due_at"]:
            b["resueltos"] += 1
            b["a_tiempo"] += t["resolved_at"] <= t["due_at"]
        elif t["state"] not in TERMINAL + ("RESUELTO",) and t["due_at"] and t["due_at"] < ctx.now:
            b["abiertos_vencidos"] += 1
    for b in by.values(): b["cumplimiento_pct"] = pct(b["a_tiempo"], b["resueltos"])
    resolved = sum(b["resueltos"] for b in by.values())
    on_time = sum(b["a_tiempo"] for b in by.values())
    overall = pct(on_time, resolved)
    overdue = sum(b["abiertos_vencidos"] for b in by.values())
    details = {**_base(ctx, d), "objetivo_pct": target, "cumplimiento_pct": overall, "por_prioridad": by, "abiertos_vencidos": overdue,
               "nota": "El objetivo es configurable por ejecución; el valor institucional oficial está pendiente de definición."}
    if not resolved: return ok("No hay tickets resueltos en el periodo para medir el cumplimiento.", **details) if not overdue else \
        warn(f"Sin tickets resueltos y {overdue} abiertos vencidos.", [], "MEDIO", **details)
    if overall < target:
        return warn(f"Cumplimiento de SLA {overall} % (objetivo {target} %); {overdue} abiertos vencidos.", [finding(
            "procesos:sla", "Cumplimiento de SLA por debajo del objetivo", f"{overall} % de tickets resueltos a tiempo frente a {target} %.",
            "Incumplimiento de compromisos de servicio.", "Medido sobre los tickets del periodo.", "Revise la capacidad del equipo y la asignación por especialidad.",
            "MEDIO", {"por_prioridad": by})], **details)
    return ok(f"Cumplimiento de SLA {overall} % (objetivo {target} %); {overdue} abiertos vencidos.", **details)


def _hours(a, b):
    return (b - a).total_seconds() / 3600 if a and b else None


@control("OPE-08", C, "Tiempos de primera respuesta y resolución", "Calcular mediana y promedio de primera respuesta y de resolución por "
         "prioridad.", "ESTADISTICO", "INFORMATIVO", CRITERIA)
def times(ctx: Ctx) -> Outcome:
    d = data(ctx)
    by: dict[str, dict] = {}
    for t in d["tickets"]:
        b = by.setdefault(t["priority"], {"respuesta": [], "resolucion": []})
        first = min((x for x in (t["accepted_at"], t["started_at"]) if x), default=None)
        if first: b["respuesta"].append(_hours(t["created_at"], first))
        if t["resolved_at"]: b["resolucion"].append(_hours(t["created_at"], t["resolved_at"]))
    summary = {p: {k: {"n": len(v), "mediana_h": round(statistics.median(v), 2) if v else None, "promedio_h": round(statistics.fmean(v), 2) if v else None}
                   for k, v in b.items()} for p, b in by.items()}
    return ok(f"Tiempos calculados sobre {len(d['tickets'])} tickets del periodo.", **_base(ctx, d), por_prioridad=summary)


@control("OPE-09", C, "Calificaciones", "Verificar que las calificaciones corresponden a tickets resueltos o cerrados, que las emitió el "
         "solicitante y que el técnico calificado atendió el ticket.", "SQL", "MEDIO", CRITERIA)
def ratings(ctx: Ctx) -> Outcome:
    d = data(ctx)
    by_id = {t["id"]: t for t in d["tickets"]}
    ids, rows = list(by_id), []
    for chunk in range(0, len(ids), 900):
        rows += ctx.session.execute(select(Rating.ticket_id, Rating.user_id, Rating.technician_id, Rating.score)
                                    .where(Rating.ticket_id.in_(ids[chunk:chunk + 900]))).all()
    bad_state = [by_id[r.ticket_id] for r in rows if by_id[r.ticket_id]["state"] not in ("RESUELTO", "CERRADO")]
    other_user = [by_id[r.ticket_id] for r in rows if r.user_id != by_id[r.ticket_id]["requester_id"]]
    other_tech = [by_id[r.ticket_id] for r in rows if r.technician_id not in {a["technician_id"] for a in d["assignments"][r.ticket_id]} | {by_id[r.ticket_id]["technician_id"]}]
    scores = [r.score for r in rows]
    details = {**_base(ctx, d), "calificaciones": len(rows), "promedio": round(statistics.fmean(scores), 2) if scores else None,
               "bajas_1_2": sum(1 for s in scores if s <= 2), "en_estado_no_valido": _numbers(bad_state), "de_otro_usuario": _numbers(other_user),
               "tecnico_no_asignado": _numbers(other_tech)}
    if bad_state or other_user:
        return fail(f"{len(bad_state)} calificaciones en tickets no resueltos y {len(other_user)} emitidas por alguien distinto del solicitante.", [finding(
            "procesos:calificaciones", "Calificaciones inconsistentes", "Calificaciones que la aplicación no permite crear.",
            "Indicadores de satisfacción manipulables; posible inserción directa.", "Comprobado.", "Revise el origen de esas filas.", "MEDIO",
            {"estado_no_valido": _numbers(bad_state), "otro_usuario": _numbers(other_user)})], **details)
    if other_tech:
        return warn(f"{len(other_tech)} calificaciones de técnicos que no constan como asignados.", [], "BAJO", **details)
    return ok(f"{len(rows)} calificaciones coherentes con el estado, el solicitante y el técnico.", **details)


@control("OPE-10", C, "Trazabilidad de intervenciones", "Detectar tickets que avanzaron de estado sin eventos de asignación o de cambio de estado "
         "en su historial.", "SQL", "MEDIO", CRITERIA)
def traceability(ctx: Ctx) -> Outcome:
    d = data(ctx)
    gaps = []
    for t in d["tickets"]:
        if t["state"] == "NUEVO": continue
        events = {h["event"] for h in d["history"][t["id"]]}
        reached = {(h["new"] or {}).get("state") for h in d["history"][t["id"]] if h["event"] == "ESTADO_CAMBIADO"}
        explained = ("ASIGNADO" in events or "ASIGNADO" in reached) if t["state"] == "ASIGNADO" else t["state"] in reached
        if not explained: gaps.append(t)
    details = {**_base(ctx, d), "criterio": "El estado actual debe aparecer como destino de un evento ESTADO_CAMBIADO (o ASIGNADO).",
               "tickets_con_trazabilidad_insuficiente": len(gaps), "muestra": _numbers(gaps), "por_origen": _origin(gaps)}
    if gaps:
        return warn(f"{len(gaps)} tickets con historial insuficiente para explicar su estado actual.", [finding(
            "procesos:trazabilidad", "Tickets con trazabilidad insuficiente", f"{len(gaps)} tickets no tienen el evento que explique su estado.",
            "No puede reconstruirse quién y cuándo cambió el estado.", "Comprobado.", "Revise el origen (importaciones o cambios directos en la base).",
            "MEDIO", {"muestra": _numbers(gaps), "por_origen": _origin(gaps)})], **details)
    return ok("El historial de cada ticket explica su estado actual.", **details)


@control("OPE-11", C, "Señales de anomalía (estadística y Machine Learning)", "Detectar tiempos de resolución atípicos por prioridad, cierres "
         "inmediatos y, si el modelo está entrenado, tickets abiertos con alto riesgo estimado de incumplir el SLA.", "ESTADISTICO", "BAJO",
         ["ISO 19011 (muestreo)", "Modelos ML de FixIT (docs/inteligencia-artificial.md)"])
def anomalies(ctx: Ctx) -> Outcome:
    d = data(ctx)
    outliers, quick = [], []
    by: dict[str, list] = {}
    for t in d["tickets"]:
        h = _hours(t["created_at"], t["resolved_at"])
        if h is not None: by.setdefault(t["priority"], []).append((h, t))
        if h is not None and h < 1 / 60: quick.append(t)
    limits = {}
    for p, values in by.items():
        if len(values) < 20: continue
        q = statistics.quantiles([v for v, _ in values], n=4)
        limit = q[2] + 3 * (q[2] - q[0])
        limits[p] = round(limit, 1)
        outliers += [t for v, t in values if v > limit]
    ml = {"estado": "no ejecutado"}
    try:
        from app.ml.predictor import ModelNotTrained, score_open
        try:
            scored = score_open(ctx.session)
            high = [r for r in scored["rows"] if r.get("sla_risk", 0) >= 0.6]
            ml = {"estado": "ejecutado", "version_modelo": scored["predictor"].model_info().get("version"), "abiertos_evaluados": len(scored["rows"]),
                  "riesgo_alto": len(high), "muestra_riesgo_alto": sample(r["number"] for r in sorted(high, key=lambda r: -r["sla_risk"]))}
        except ModelNotTrained as exc:
            ml = {"estado": "modelo no entrenado", "detalle": str(exc)[:200]}
    except Exception as exc:  # noqa: BLE001 - the ML signal is optional; its failure is reported, not hidden
        ml = {"estado": "error", "detalle": type(exc).__name__}
    details = {**_base(ctx, d), "limite_atipico_horas_por_prioridad": limits, "resolucion_atipica": len(outliers), "muestra_atipica": _numbers(outliers),
               "cierres_en_menos_de_un_minuto": len(quick), "muestra_cierres_inmediatos": _numbers(quick), "machine_learning": ml,
               "interpretacion": "Señales de riesgo para revisión; no prueban una irregularidad. Atípico: más de Q3 + 3·IQR horas de resolución "
                                 "en su prioridad (mínimo 20 tickets)."}
    signals = len(outliers) + len(quick) + (ml.get("riesgo_alto") or 0)
    if signals:
        return warn(f"Señales para revisar: {len(outliers)} resoluciones atípicas, {len(quick)} cierres inmediatos, "
                    f"{ml.get('riesgo_alto', 0)} abiertos con riesgo alto según ML.", [finding(
                        "procesos:senales", "Señales de riesgo operativo para revisar", "Casos estadísticamente atípicos o con riesgo alto estimado.",
                        "Pueden indicar errores de registro, bloqueos o tickets mal gestionados.", "Señal estadística, no prueba.",
                        "Revise una muestra y documente las causas; no tome decisiones solo con esta señal.", "BAJO",
                        {"atipicos": _numbers(outliers), "inmediatos": _numbers(quick), "ml": ml})], "BAJO", **details)
    return ok("Sin señales estadísticas atípicas en el periodo.", **details)


@control("OPE-12", C, "Operaciones administrativas sobre tickets", "Medir cancelaciones y asignaciones manuales del periodo y su proporción.",
         "SQL", "BAJO", CRITERIA)
def admin_operations(ctx: Ctx) -> Outcome:
    d = data(ctx)
    cancelled = [t for t in d["tickets"] if t["state"] == "CANCELADO"]
    manual = sum(1 for t in d["tickets"] for a in d["assignments"][t["id"]] if a["type"] == "MANUAL")
    rate = pct(len(cancelled), len(d["tickets"]))
    details = {**_base(ctx, d), "cancelados": len(cancelled), "tasa_cancelacion_pct": rate, "asignaciones_manuales": manual, "muestra_cancelados": _numbers(cancelled)}
    if (rate or 0) > float(ctx.option("tasa_cancelacion_max", 10)):
        return warn(f"Tasa de cancelación {rate} % en el periodo.", [finding("procesos:cancelaciones", "Cancelaciones frecuentes",
                    f"{len(cancelled)} tickets cancelados ({rate} %).", "Solicitudes descartadas sin solución; puede ocultar incumplimientos de SLA.",
                    "Indicador operativo.", "Revise los motivos de cancelación.", "BAJO", {"muestra": _numbers(cancelled)})], "BAJO", **details)
    return ok(f"{len(cancelled)} cancelaciones ({rate if rate is not None else 0} %) y {manual} asignaciones manuales en el periodo.", **details)


def total_tickets(ctx: Ctx) -> int:
    return ctx.session.scalar(select(func.count(Ticket.id))) or 0
