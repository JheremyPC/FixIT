"use strict";
/* FixIT — Centro Integral de Auditoría (#/audit/<sección>). ADMIN y JEFE_TI ven todas las secciones; TECNICO solo los
   hallazgos y tareas asignados. Los permisos los impone el servidor (/api/audit-center); esta página solo los refleja.
   Todo lo que se muestra proviene de ejecuciones reales almacenadas: no hay valores ilustrativos. */

Object.assign(ICONS, {
  database: "M12 4c4.4 0 8 1.3 8 3s-3.6 3-8 3-8-1.3-8-3 3.6-3 8-3ZM4 7v10c0 1.7 3.6 3 8 3s8-1.3 8-3V7M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3",
  lock: "M7 11V8a5 5 0 0 1 10 0v3M6 11h12a1 1 0 0 1 1 1v7a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1v-7a1 1 0 0 1 1-1ZM12 15v2",
  flow: "M5 6h4v4H5zM15 14h4v4h-4zM9 8h3a2 2 0 0 1 2 2v4a2 2 0 0 0 2 2M7 10v4a2 2 0 0 0 2 2h6",
  server: "M5 4h14a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1ZM5 13h14a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-5a1 1 0 0 1 1-1ZM8 7.5h.01M8 16.5h.01",
  privacy: "M12 3 5 6v5.5c0 4.4 3 8.2 7 9.5 4-1.3 7-5.1 7-9.5V6ZM12 10a2 2 0 1 0 0 4 2 2 0 0 0 0-4Z",
  lifebuoy: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18ZM12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8ZM5.6 5.6l3.6 3.6M14.8 14.8l3.6 3.6M18.4 5.6l-3.6 3.6M9.2 14.8l-3.6 3.6",
  flag: "M5 21V4M5 4h11l-2 4 2 4H5",
  file: "M7 3h7l5 5v12a1 1 0 0 1-1 1H7a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1ZM14 3v5h5M9 13h6M9 17h6",
  upload: "M12 20V9M7.5 13.5 12 9l4.5 4.5M5 5h14",
  refresh: "M20 11a8 8 0 0 0-14.9-3M4 4v4h4M4 13a8 8 0 0 0 14.9 3M20 20v-4h-4",
  compare: "M8 4v16M16 4v16M4 8h4M16 16h4M4 16h4M16 8h4",
});

const AC_TABS = [
  ["panel", "Panel", "dashboard"], ["bd", "Base de datos", "database", "BASE_DATOS"], ["seguridad", "Seguridad", "lock", "SEGURIDAD"],
  ["accesos", "Usuarios y accesos", "users", "ACCESOS"], ["procesos", "Procesos", "flow", "PROCESOS"], ["registros", "Registros", "history", "REGISTROS"],
  ["infraestructura", "Infraestructura", "server", "INFRAESTRUCTURA"], ["privacidad", "Privacidad", "privacy", "PRIVACIDAD"],
  ["continuidad", "Continuidad", "lifebuoy", "CONTINUIDAD"], ["hallazgos", "Hallazgos", "flag"], ["informes", "Informes", "file"],
  ["historial", "Historial y metodología", "compare"],
];
const AC_STATUS_CLASS = { APROBADO: "ac-ok", FALLIDO: "ac-fail", ADVERTENCIA: "ac-warn", NO_APLICABLE: "ac-na", NO_VERIFICADO: "ac-unv", ERROR_EJECUCION: "ac-err" };
const AC_SEV_CLASS = { CRITICO: "ac-sev-crit", ALTO: "ac-sev-high", MEDIO: "ac-sev-med", BAJO: "ac-sev-low", INFORMATIVO: "ac-sev-info" };
const AC_RUN_CLASS = { PENDIENTE: "ac-unv", EN_CURSO: "ac-run", COMPLETADA: "ac-ok", COMPLETADA_CON_ERRORES: "ac-warn", CANCELADA: "ac-na", INTERRUMPIDA: "ac-err" };
const AC_RESULT_CLASS = { FAVORABLE: "ac-ok", CON_OBSERVACIONES: "ac-warn", DESFAVORABLE: "ac-fail", NO_CONCLUYENTE: "ac-unv" };
const AC_FINDING_CLASS = { ABIERTO: "ac-fail", EN_REVISION: "ac-warn", EN_CORRECCION: "ac-run", CORREGIDO_PENDIENTE_VERIFICACION: "ac-warn",
  CERRADO: "ac-ok", RIESGO_ACEPTADO: "ac-na", FALSO_POSITIVO: "ac-na" };
const AC_SEGMENTS = ["APROBADO", "ADVERTENCIA", "FALLIDO", "ERROR_EJECUCION", "NO_VERIFICADO", "NO_APLICABLE"];
const AC = { meta: null, poll: null, findingFilters: { q: "", category: "", severity: "", status: "", owner: "", open_only: "true", offset: 0, limit: 25 },
  runFilters: { q: "", status: "", category: "", result: "", offset: 0, limit: 20 }, logFilters: { statement_class: "", source: "", q: "", offset: 0 } };

const acLabel = (map, key) => (AC.meta?.[map] || {})[key] || key || "—";
const acPill = (cls, text, title = "") => `<span class="pill ${cls || ""}"${title ? ` title="${esc(title)}"` : ""}><span class="dot"></span>${esc(text)}</span>`;
const acStatus = (s) => acPill(AC_STATUS_CLASS[s], acLabel("statuses", s), AC.meta?.status_meaning?.[s] || "");
const acSev = (s) => s ? `<span class="ac-sev ${AC_SEV_CLASS[s] || ""}">${esc(acLabel("severities", s))}</span>` : '<span class="muted">—</span>';
const acRun = (s) => acPill(AC_RUN_CLASS[s], acLabel("run_statuses", s));
const acResult = (s) => s ? acPill(AC_RESULT_CLASS[s], acLabel("results", s), AC.meta?.result_meaning?.[s] || "") : '<span class="muted">Sin resultado</span>';
const acFinding = (s) => acPill(AC_FINDING_CLASS[s], acLabel("finding_statuses", s));
const acCat = (code) => (AC.meta?.categories || []).find((c) => c.code === code);
const acTab = (code) => (AC_TABS.find((t) => t[3] === code) || [])[0];
const acDay = (d) => d ? new Date(d).toLocaleDateString("es-PE", { day: "2-digit", month: "short", year: "numeric" }) : "—";
const acQs = (obj) => new URLSearchParams(Object.entries(obj).filter(([, v]) => v !== "" && v !== null && v !== undefined)).toString();
const acPretty = (k) => String(k).replaceAll("_", " ").replace(/^./, (c) => c.toUpperCase());
const acCanManage = () => Boolean(AC.meta?.can_manage);

function acStopPolling() { if (AC.poll) { clearTimeout(AC.poll); AC.poll = null; } }
modal.addEventListener("close", acStopPolling);

/* Structured evidence (control details) as readable rows; nested values become small tables or JSON. */
function acValue(v, depth = 0) {
  if (v === null || v === undefined || v === "") return '<span class="muted">—</span>';
  if (typeof v === "boolean") return v ? "Sí" : "No";
  if (typeof v !== "object") return esc(String(v));
  if (Array.isArray(v)) {
    if (!v.length) return '<span class="muted">Ninguno</span>';
    if (v.every((x) => x === null || typeof x !== "object")) return esc(v.slice(0, 60).join(", ")) + (v.length > 60 ? ` <span class="muted">(+${v.length - 60})</span>` : "");
    if (depth < 1 && v.every((x) => x && typeof x === "object" && !Array.isArray(x))) {
      const cols = [...new Set(v.slice(0, 50).flatMap((x) => Object.keys(x)))].slice(0, 7);
      return `<div class="table-wrap ac-mini"><table class="table-compact"><thead><tr>${cols.map((c) => `<th>${esc(acPretty(c))}</th>`).join("")}</tr></thead><tbody>
        ${v.slice(0, 50).map((x) => `<tr>${cols.map((c) => `<td class="small">${acValue(x[c], depth + 1)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>
        ${v.length > 50 ? `<span class="small muted">Se muestran 50 de ${v.length}.</span>` : ""}`;
    }
    return `<pre class="json">${esc(JSON.stringify(v, null, 2).slice(0, 4000))}</pre>`;
  }
  if (depth < 1) return acDetails(v, depth + 1);
  return `<pre class="json">${esc(JSON.stringify(v, null, 2).slice(0, 4000))}</pre>`;
}
function acDetails(obj, depth = 0) {
  const entries = Object.entries(obj || {}).filter(([k]) => !k.startsWith("_"));
  if (!entries.length) return '<span class="muted">Sin detalles.</span>';
  return `<dl class="kv ac-kv">${entries.map(([k, v]) => `<div><dt>${esc(acPretty(k))}</dt><dd>${acValue(v, depth)}</dd></div>`).join("")}</dl>`;
}

function acBar(statuses, never = 0) {
  const total = AC_SEGMENTS.reduce((s, k) => s + (statuses?.[k] || 0), 0) + never;
  if (!total) return '<div class="ac-bar"><i class="ac-seg-never" style="width:100%"></i></div>';
  const seg = (k, n) => n ? `<i class="ac-seg-${k.toLowerCase()}" style="width:${(100 * n / total).toFixed(2)}%" title="${esc(acLabel("statuses", k))}: ${n}"></i>` : "";
  return `<div class="ac-bar" role="img" aria-label="${esc(AC_SEGMENTS.map((k) => `${acLabel("statuses", k)} ${statuses?.[k] || 0}`).join(", "))}, sin ejecutar ${never}">
    ${AC_SEGMENTS.map((k) => seg(k, statuses?.[k] || 0)).join("")}${never ? `<i class="ac-seg-never" style="width:${(100 * never / total).toFixed(2)}%" title="Sin ejecutar: ${never}"></i>` : ""}</div>`;
}
const acLegend = () => `<div class="legend ac-legend">${AC_SEGMENTS.map((k) => `<span><i class="box ac-seg-${k.toLowerCase()}"></i>${esc(acLabel("statuses", k))}</span>`).join("")}<span><i class="box ac-seg-never"></i>Sin ejecutar</span></div>`;

/* ---------- Entry point ---------- */
Pages.audit = async (root, sub) => {
  acStopPolling();
  AC.meta = await api("/audit-center/meta");
  if (!acCanManage()) return acTechnician(root);
  const tab = AC_TABS.some((t) => t[0] === sub) ? sub : "panel";
  setTitle("Centro de auditoría", "Auditoría informática de FixIT: comprobaciones reales, hallazgos, evidencias e informes");
  root.innerHTML = `<nav class="tabs ac-tabs" aria-label="Secciones del Centro de auditoría">${AC_TABS.map(([k, v]) => `<button type="button" class="${k === tab ? "active" : ""}" ${k === tab ? 'aria-current="page"' : ""} data-page-link="audit" data-sub="${k}">${esc(v)}</button>`).join("")}</nav>
    <div id="ac-body" class="grid">${loadingHtml()}</div>`;
  const body = $("#ac-body");
  const entry = AC_TABS.find((t) => t[0] === tab);
  if (entry[3]) await acCategory(body, entry[3]);
  else await ({ panel: acPanel, hallazgos: acFindings, informes: acReports, historial: acHistory })[tab](body);
  Charts.mountAll(body);
};

/* ---------- Panel ---------- */
async function acPanel(body) {
  const o = await api("/audit-center/overview");
  const k = o.kpis;
  const sev = AC.meta.severities;
  body.innerHTML = `
    <section class="row-between ac-toolbar"><p class="muted small">${esc(o.basis)}</p>
      <div class="row"><button class="btn btn-secondary" data-action="ac-refresh">${icon("refresh", 15)} Actualizar</button>
        <button class="btn btn-primary" data-action="ac-new">${icon("plus", 15)} Nueva auditoría</button></div></section>
    <section class="kpis">${kpi("Auditorías ejecutadas", k.runs_executed, `${k.runs_interrupted} canceladas o interrumpidas`)}
      ${kpi("Pendientes o en curso", k.runs_pending, "En cola del motor", k.runs_pending ? "warn" : "")}
      ${kpi("Hallazgos abiertos", k.findings_open, `${k.findings_pending_verification} pendientes de verificación`, k.findings_open ? "warn" : "good")}
      ${kpi("Críticos y altos", k.findings_critical_high, "Abiertos", k.findings_critical_high ? "crit" : "good")}
      ${kpi("Hallazgos cerrados", k.findings_closed, "Con evidencia y verificación")}
      ${kpi("Controles aprobados", k.controls_approved, `de ${k.controls_enabled} habilitados`, "good")}
      ${kpi("Controles fallidos", k.controls_failed, `${k.controls_warning} con advertencias`, k.controls_failed ? "crit" : "")}
      ${kpi("No verificados", k.controls_unverified, `${k.controls_never_run} nunca ejecutados`, k.controls_unverified ? "warn" : "")}
      ${kpi("Informes generados", k.reports_generated, "PDF y paquetes ZIP")}</section>
    <section class="card"><div class="card-head"><div><h2>Estado por categoría</h2><p>Resultado de la última ejecución de cada control habilitado.</p></div></div>
      ${acLegend()}<div class="ac-cats">${AC.meta.categories.map((c) => {
        const s = o.categories[c.code] || { statuses: {}, never: 0, controls: 0 };
        const open = o.findings_by_category[c.code] || 0;
        return `<article class="ac-cat"><div class="row-between"><h3>${icon(AC_TABS.find((t) => t[3] === c.code)?.[2] || "audit", 17)} ${esc(c.label)}</h3>
          <span class="small muted num">${s.controls} controles</span></div><p>${esc(c.description)}</p>${acBar(s.statuses, s.never)}
          <div class="row-between small"><span class="muted">${s.last_run ? `Última: ${esc(fmtDate(s.last_run))}` : "Nunca ejecutada"}</span>
            <span class="${open ? "ac-open-count" : "muted"}">${open} hallazgos abiertos</span></div>
          <div class="row"><button class="btn btn-secondary btn-sm" data-page-link="audit" data-sub="${esc(c.slug)}">Ver detalle</button>
            <button class="btn btn-quiet btn-sm" data-action="ac-new" data-category="${esc(c.code)}">${icon("play", 14)} Ejecutar</button></div></article>`;
      }).join("")}</div></section>
    <section class="dash">
      <article class="card card-flush span-8"><div class="card-head"><div><h3>Ejecuciones recientes</h3><p>Seleccione una ejecución para ver su ficha completa.</p></div>
        <button class="btn btn-secondary btn-sm" data-page-link="audit" data-sub="historial">Historial ${icon("arrow", 14)}</button></div>${acRunTable(o.recent_runs)}</article>
      <article class="card span-4"><div class="card-head"><div><h3>Hallazgos abiertos por severidad</h3><p>${k.findings_open} en total</p></div></div>
        ${k.findings_open ? Charts.hbars(Object.keys(sev).map((s, i) => ({ label: sev[s], value: o.findings_by_severity[s] || 0, display: String(o.findings_by_severity[s] || 0),
          color: ["var(--crit)", "var(--serious)", "var(--warn)", "var(--c1)", "var(--faint)"][i] }))) : empty("Sin hallazgos abiertos", "Ejecute una auditoría para evaluar el sistema.", "check")}
        <div class="mt-12"><button class="btn btn-secondary btn-sm" data-page-link="audit" data-sub="hallazgos">Gestionar hallazgos ${icon("arrow", 14)}</button></div></article>
    </section>`;
}
Actions["ac-refresh"] = () => route();

function acRunTable(rows) {
  if (!rows.length) return `<div class="ac-pad">${empty("Aún no hay auditorías", "Use «Nueva auditoría» para ejecutar la primera evaluación.", "audit")}</div>`;
  return `<div class="table-wrap"><table class="table-compact ac-runs"><thead><tr><th>Código</th><th>Auditoría</th><th>Estado</th><th>Resultado</th><th>Progreso</th><th>Creada</th></tr></thead><tbody>
    ${rows.map((r) => `<tr class="clickable" data-action="ac-run" data-id="${esc(r.id)}" tabindex="0"><td><span class="ticket-no">${esc(r.code)}</span></td>
      <td><strong>${esc(r.name)}</strong><span class="sub">${esc((r.categories || []).map((c) => acCat(c)?.label || c).join(" · "))}</span></td>
      <td>${acRun(r.status)}</td><td>${acResult(r.result)}</td><td class="num small">${r.progress.done}/${r.progress.total}</td><td class="small nowrap">${fmtDate(r.created_at)}</td></tr>`).join("")}
  </tbody></table></div>`;
}

/* ---------- Category ---------- */
async function acCategory(body, code) {
  const d = await api(`/audit-center/categories/${code}`);
  const c = d.category;
  const counts = {};
  d.controls.forEach((x) => { if (x.latest) counts[x.latest.status] = (counts[x.latest.status] || 0) + 1; });
  const never = d.controls.filter((x) => !x.latest).length;
  body.innerHTML = `
    <section class="card ac-head"><div class="row-between"><div><span class="eyebrow">${esc(c.prefix)} · ${d.controls.length} controles</span><h2>${esc(c.label)}</h2>
      <p class="muted">${esc(c.description)}</p></div>
      <button class="btn btn-primary" data-action="ac-new" data-category="${esc(c.code)}">${icon("play", 15)} Ejecutar esta categoría</button></div>
      ${acBar(counts, never)}${acLegend()}</section>
    <section class="card card-flush"><div class="card-head"><div><h3>Controles</h3><p>Último resultado de cada control. Seleccione uno para ver su evidencia, criterios y privilegios utilizados.</p></div></div>
      <div class="table-wrap"><table class="table-compact ac-controls"><thead><tr><th>Control</th><th>Comprobación</th><th>Método</th><th>Resultado</th><th>Resumen</th><th>Ejecución</th></tr></thead><tbody>
      ${d.controls.map((x, i) => `<tr class="clickable${x.enabled ? "" : " ac-disabled"}" data-action="ac-control" data-index="${i}" tabindex="0"><td><span class="ticket-no">${esc(x.code)}</span></td>
        <td><strong>${esc(x.title)}</strong>${x.enabled ? "" : '<span class="sub">Deshabilitado por un administrador</span>'}</td><td class="small">${esc(x.method)}</td>
        <td>${x.latest ? acStatus(x.latest.status) + (x.latest.severity ? " " + acSev(x.latest.severity) : "") : '<span class="pill ac-never">Sin ejecutar</span>'}</td>
        <td class="small ac-summary">${esc(x.latest?.summary || (x.method === "MANUAL" ? "Requiere evidencia manual." : "—"))}</td>
        <td class="small nowrap">${x.latest ? `${esc(x.latest.run_code || "")}<span class="sub">${fmtDate(x.latest.started_at)}</span>` : "—"}</td></tr>`).join("")}
      </tbody></table></div></section>
    <section class="card card-flush"><div class="card-head"><div><h3>Hallazgos abiertos de la categoría</h3><p>${d.findings.length} hallazgos</p></div>
      <button class="btn btn-secondary btn-sm" data-action="ac-findings-of" data-category="${esc(c.code)}">Ver en Hallazgos ${icon("arrow", 14)}</button></div>${acFindingTable(d.findings)}</section>
    <div id="ac-extra" class="grid"></div>
    <section class="card card-flush"><div class="card-head"><div><h3>Ejecuciones que incluyeron esta categoría</h3></div></div>${acRunTable(d.runs)}</section>`;
  AC.category = d;
  const extra = $("#ac-extra");
  if (code === "BASE_DATOS") acDbExtra(extra, d);
  if (code === "SEGURIDAD") acToolsExtra(extra, d);
  if (code === "REGISTROS") {
    extra.innerHTML = `<section class="section-head"><div><h2>Registro de actividad (audit_logs)</h2><p>Consulta, filtros, verificación del sello HMAC por registro y exportación CSV/JSON. Las consultas y exportaciones también quedan registradas.</p></div></section><div id="ac-trail" class="grid">${loadingHtml()}</div>`;
    await renderAuditTrail($("#ac-trail"));
  }
}

Actions["ac-control"] = (el) => {
  const x = AC.category?.controls[Number(el.dataset.index)];
  if (!x) return;
  const l = x.latest;
  openModal();
  $("#modal-content").innerHTML = `<div class="modal-head"><div><span class="eyebrow">${esc(x.code)} · ${esc(x.method)}</span><h2>${esc(x.title)}</h2></div><button class="icon-btn" data-action="close-modal" aria-label="Cerrar">${icon("close", 20)}</button></div>
    <div class="modal-body">
      <div><h3 class="small-title">Objetivo</h3><p>${esc(x.objective)}</p></div>
      <dl class="kv"><div><dt>Método</dt><dd>${esc(x.method)} — ${esc(AC.meta.methods[x.method] || "")}</dd></div>
        <div><dt>Severidad base</dt><dd>${acSev(x.severity)}</dd></div><div><dt>Criterios</dt><dd>${esc((x.criteria || []).join("; ") || "—")}</dd></div>
        ${x.requires?.length ? `<div><dt>Requiere</dt><dd>${esc(x.requires.join(", "))}</dd></div>` : ""}
        ${x.evidence_days ? `<div><dt>Vigencia de la evidencia</dt><dd>${x.evidence_days} días</dd></div>` : ""}</dl>
      ${x.guidance ? banner("info", "Evidencia requerida", x.guidance) : ""}
      ${x.method === "MANUAL" ? `<div class="row"><button class="btn btn-secondary btn-sm" data-action="ac-evidence-form" data-control="${esc(x.code)}">${icon("upload", 15)} Registrar evidencia manual</button>
        ${x.last_evidence ? `<span class="small muted">Última evidencia: ${esc(x.last_evidence.title)} (${esc(x.last_evidence.evidence_date || "")}, ${esc(x.last_evidence.declared_result || "")})</span>` : ""}</div><div id="ac-evidence-slot"></div>` : ""}
      ${l ? `<div class="subpanel"><div class="row-between"><b>Último resultado · ${esc(l.run_code || "")}</b>${acStatus(l.status)}</div><p>${esc(l.summary)}</p>
        <dl class="kv"><div><dt>Fecha</dt><dd>${fmtDate(l.started_at)} <span class="muted mono">(${esc(l.started_at)})</span></dd></div><div><dt>Duración</dt><dd>${l.duration_ms} ms</dd></div>
        <div><dt>Privilegios usados</dt><dd>${esc(l.privileges || "—")}</dd></div>${l.error ? `<div><dt>Error</dt><dd>${esc(l.error)}</dd></div>` : ""}</dl>
        <h3 class="small-title">Evidencia obtenida</h3>${acDetails(l.details)}
        <div><button class="btn btn-secondary btn-sm" data-action="ac-run" data-id="${esc(l.run_id)}">Abrir la ejecución</button></div></div>`
        : banner("warn", "Sin resultados", "Este control aún no se ejecutó. Un control no ejecutado nunca se considera aprobado.")}
      ${AC.meta.is_admin ? `<label class="check"><input type="checkbox" data-action-change="ac-toggle-control" data-code="${esc(x.code)}" ${x.enabled ? "checked" : ""}> Control habilitado para nuevas auditorías</label>` : ""}
    </div>`;
};
ChangeActions["ac-toggle-control"] = async (el) => {
  try {
    await api(`/audit-center/controls/${encodeURIComponent(el.dataset.code)}`, { method: "PATCH", body: JSON.stringify({ enabled: el.checked }) });
    flash(el.checked ? "Control habilitado." : "Control deshabilitado.");
  } catch (error) { el.checked = !el.checked; flash(error.message, true); }
};

Actions["ac-evidence-form"] = (el) => {
  const slot = $("#ac-evidence-slot");
  if (!slot) return;
  const today = new Date().toISOString().slice(0, 10);
  slot.innerHTML = `<form id="ac-evidence" class="subpanel"><b>Evidencia manual para ${esc(el.dataset.control)}</b>
    <p class="small muted">Es una declaración de una persona respaldada por un archivo (PDF, PNG, JPEG, TXT, CSV o JSON). El control mostrará que su resultado proviene de evidencia manual.</p>
    <label>Título<input name="title" required minlength="5" maxlength="200" placeholder="Captura del panel de respaldos de Supabase"></label>
    <div class="form-grid"><label>Resultado que acredita<select name="declared_result" required>${["APROBADO", "ADVERTENCIA", "FALLIDO", "NO_APLICABLE"].map((s) => option(s, acLabel("statuses", s))).join("")}</select></label>
      <label>Fecha de la evidencia<input name="evidence_date" type="date" required max="${today}" value="${today}"></label></div>
    <label>Descripción<textarea name="description" maxlength="4000" placeholder="Qué muestra la evidencia, quién la obtuvo y cómo"></textarea></label>
    <label>Archivo<input name="file" type="file" required accept=".pdf,.png,.jpg,.jpeg,.txt,.csv,.json"></label>
    <div class="row"><button class="btn btn-primary btn-sm" type="submit">Registrar evidencia</button></div></form>`;
  $("#ac-evidence").onsubmit = async (e) => {
    e.preventDefault();
    const btn = e.submitter;
    const form = new FormData(e.target);
    form.set("kind", "MANUAL");
    form.set("control_code", el.dataset.control);
    busy(btn, true, "Subiendo…");
    try {
      await api("/audit-center/evidences", { method: "POST", body: form });
      flash("Evidencia registrada. Se usará en la próxima ejecución del control.");
      modal.close();
      route();
    } catch (error) { flash(error.message, true); } finally { busy(btn, false); }
  };
};

/* Database: imported logs (pgAudit / PostgreSQL / Supabase export) and their explorer. */
function acDbExtra(box, d) {
  const x = d.external_logs;
  box.innerHTML = `<section class="card"><div class="card-head"><div><h3>Actividad SQL: importar logs de PostgreSQL / pgAudit</h3>
      <p>Supabase no expone sus logs a la conexión de la aplicación: expórtelos desde el panel (Logs Explorer → Postgres) en CSV o JSON e impórtelos aquí. También se acepta un csvlog de PostgreSQL. Los parámetros de pgAudit nunca se guardan y los secretos se redactan.</p></div></div>
      <form id="ac-import-logs" class="toolbar"><input type="hidden" name="kind" value="LOGS_BD"><label class="search">Archivo (CSV o JSON, máx. ${Math.round(AC.meta.limits.import_bytes / 1048576)} MB)<input name="file" type="file" required accept=".csv,.json,.log,.txt"></label>
        <label>Nota<input name="notes" maxlength="2000" placeholder="Origen o periodo exportado"></label><button class="btn btn-primary" type="submit">${icon("upload", 15)} Importar</button></form>
      <div class="summary-grid mt-12"><div><span>Registros importados</span><strong class="num">${x.total.toLocaleString("es-PE")}</strong></div><div><span>Primer registro</span><strong>${fmtDate(x.first)}</strong></div>
        <div><span>Último registro</span><strong>${fmtDate(x.last)}</strong></div><div><span>Por clase</span><strong class="small">${esc(Object.entries(x.by_class).map(([k, v]) => `${k}: ${v}`).join(" · ") || "—")}</strong></div></div></section>
    ${acImportsTable(d.imports, "Importaciones de logs")}
    <section class="card card-flush"><div class="card-head"><div><h3>Explorador de actividad importada</h3><p>Columnas derivadas del mensaje original; abra un registro para ver los campos recibidos (redactados).</p></div></div>
      <form id="ac-log-filters" class="toolbar ac-pad-x"><label>Clase<select name="statement_class">${option("", "Todas")}${Object.keys(x.by_class).map((k) => option(k, k, AC.logFilters.statement_class === k)).join("")}</select></label>
        <label>Origen<select name="source">${option("", "Todos")}${option("PGAUDIT", "pgAudit", AC.logFilters.source === "PGAUDIT")}${option("POSTGRES", "PostgreSQL", AC.logFilters.source === "POSTGRES")}</select></label>
        <label class="search">Objeto o comando<input name="q" type="search" maxlength="100" value="${esc(AC.logFilters.q)}"></label><button class="btn btn-secondary" type="submit">Filtrar</button></form>
      <div id="ac-logs">${loadingHtml()}</div></section>`;
  acImportForm("#ac-import-logs");
  $("#ac-log-filters").onsubmit = (e) => { e.preventDefault(); Object.assign(AC.logFilters, Object.fromEntries(new FormData(e.target)), { offset: 0 }); acLoadLogs(); };
  acLoadLogs();
}
async function acLoadLogs() {
  const box = $("#ac-logs");
  if (!box) return;
  try {
    const { data, total } = await apiWithTotal(`/audit-center/external-logs?${acQs({ ...AC.logFilters, limit: 50 })}`);
    AC.logs = data;
    box.innerHTML = data.length ? `<div class="table-wrap"><table class="table-compact"><thead><tr><th>Fecha</th><th>Rol</th><th>Origen</th><th>Clase</th><th>Comando</th><th>Objeto</th><th></th></tr></thead><tbody>
      ${data.map((r, i) => `<tr><td class="small nowrap">${fmtDate(r.log_time)}</td><td class="small">${esc(r.db_user || "—")}</td><td class="small">${esc(r.source)}</td><td><span class="pill">${esc(r.class || "—")}</span></td>
        <td class="small">${esc(r.command || "—")}</td><td class="small mono">${esc(r.object || "—")}</td><td><button class="btn btn-quiet btn-sm" data-action="ac-log" data-index="${i}">Ver</button></td></tr>`).join("")}
      </tbody></table></div>${acPager(total, AC.logFilters, "ac-logs-page")}` : `<div class="ac-pad">${empty("Sin registros importados", "Importe un archivo de logs exportado del proveedor.")}</div>`;
  } catch (error) { box.innerHTML = `<div class="ac-pad">${banner("crit", "No se pudo cargar", error.message)}</div>`; }
}
Actions["ac-logs-page"] = (el) => { AC.logFilters.offset = Math.max(0, AC.logFilters.offset + Number(el.dataset.dir) * 50); acLoadLogs(); };
Actions["ac-log"] = (el) => {
  const r = AC.logs?.[Number(el.dataset.index)];
  if (!r) return;
  openModal();
  $("#modal-content").innerHTML = `<div class="modal-head"><div><span class="eyebrow">Registro importado · ${esc(r.source)}</span><h2>${esc(r.class || "")} ${esc(r.command || "")}</h2></div><button class="icon-btn" data-action="close-modal" aria-label="Cerrar">${icon("close", 20)}</button></div>
    <div class="modal-body">${r.redacted ? banner("info", "Contenido redactado", "Se reemplazaron secretos o se retiraron parámetros de la sentencia original.") : ""}
      <h3 class="small-title">Información derivada (transformada)</h3>${acDetails({ fecha_utc: r.log_time, rol: r.db_user, base: r.database, tipo: r.audit_type, clase: r.class, comando: r.command, tipo_objeto: r.object_type, objeto: r.object, sentencia: r.statement, huella_sha256: r.record_hash })}
      <h3 class="small-title">Campos recibidos (originales, saneados)</h3><pre class="json">${esc(JSON.stringify(r.original, null, 2))}</pre></div>`;
};

function acImportsTable(rows, title) {
  return `<section class="card card-flush"><div class="card-head"><div><h3>${esc(title)}</h3><p>Se conserva el nombre, tamaño y SHA-256 del archivo; un archivo idéntico no puede importarse dos veces.</p></div></div>
    ${rows?.length ? `<div class="table-wrap"><table class="table-compact"><thead><tr><th>Fecha</th><th>Tipo</th><th>Archivo</th><th>Estado</th><th>Registros</th><th>Por</th><th>SHA-256</th></tr></thead><tbody>
      ${rows.map((i) => `<tr><td class="small nowrap">${fmtDate(i.imported_at)}</td><td class="small">${esc(i.kind_label)}</td><td class="small">${esc(i.file)}</td>
        <td>${acPill(i.status === "COMPLETADA" ? "ac-ok" : i.status === "PARCIAL" ? "ac-warn" : "ac-fail", i.status)}</td>
        <td class="small num">${i.rows.imported}/${i.rows.total}${i.rows.duplicated ? ` <span class="muted">(${i.rows.duplicated} dup.)</span>` : ""}</td>
        <td class="small">${esc(i.imported_by?.name || "—")}</td><td class="small mono">${esc(i.sha256.slice(0, 12))}…</td></tr>`).join("")}</tbody></table></div>`
      : `<div class="ac-pad">${empty("Sin importaciones", "Aún no se importaron archivos.")}</div>`}</section>`;
}
function acImportForm(selector) {
  $(selector).onsubmit = async (e) => {
    e.preventDefault();
    const btn = e.submitter;
    busy(btn, true, "Importando…");
    try {
      const r = await api("/audit-center/imports", { method: "POST", body: new FormData(e.target) });
      flash(`Importación ${r.status.toLowerCase()}: ${r.rows.imported} registros${r.rows.duplicated ? `, ${r.rows.duplicated} duplicados omitidos` : ""}.`);
      route();
    } catch (error) { flash(error.message, true); } finally { busy(btn, false); }
  };
}

/* Security: imported tool reports. */
function acToolsExtra(box, d) {
  const kinds = Object.entries(AC.meta.import_kinds).filter(([k]) => k !== "LOGS_BD");
  box.innerHTML = `<section class="card"><div class="card-head"><div><h3>Informes de herramientas de seguridad</h3>
      <p>Bandit, pip-audit, OWASP ZAP y SARIF se ejecutan fuera de la aplicación (en desarrollo o en un entorno controlado; nunca escaneos activos contra producción) y se importan aquí. La interfaz no ejecuta comandos.</p></div></div>
      <form id="ac-import-tools" class="toolbar"><label>Herramienta<select name="kind" required>${kinds.map(([k, v]) => option(k, v)).join("")}</select></label>
        <label class="search">Informe JSON / SARIF<input name="file" type="file" required accept=".json,.sarif"></label>
        <label>Nota<input name="notes" maxlength="2000" placeholder="Entorno y versión analizados"></label><button class="btn btn-primary" type="submit">${icon("upload", 15)} Importar</button></form>
      <details class="mt-12"><summary class="small">Comandos de referencia</summary><pre class="json">cd backend
bandit -r app -f json -o bandit.json
pip-audit -r ../requirements.txt -f json -o pip-audit.json
docker run --rm -v "%cd%:/zap/wrk" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:8000 -J zap.json</pre></details></section>
    ${acImportsTable(d.imports, "Informes importados")}`;
  acImportForm("#ac-import-tools");
}

/* ---------- Findings ---------- */
function acFindingTable(rows) {
  if (!rows.length) return `<div class="ac-pad">${empty("Sin hallazgos", "No hay hallazgos con estos criterios.", "check")}</div>`;
  return `<div class="table-wrap"><table class="table-compact"><thead><tr><th>Código</th><th>Hallazgo</th><th>Severidad</th><th>Estado</th><th>Responsable</th><th>Límite</th><th>Verificación</th></tr></thead><tbody>
    ${rows.map((f) => `<tr class="clickable" data-action="ac-finding" data-id="${esc(f.id)}" tabindex="0"><td><span class="ticket-no">${esc(f.code)}</span></td>
      <td><strong>${esc(f.title)}</strong><span class="sub">${esc(acCat(f.category)?.label || f.category)} · ${esc(f.control)} · ${f.occurrences} detecciones</span></td>
      <td>${acSev(f.severity)}</td><td>${acFinding(f.status)}</td><td class="small">${esc(f.owner?.name || "Sin asignar")}</td>
      <td class="small nowrap${f.due_date && f.due_date < new Date().toISOString().slice(0, 10) && ["ABIERTO", "EN_REVISION", "EN_CORRECCION"].includes(f.status) ? " ac-overdue" : ""}">${esc(f.due_date || "—")}</td>
      <td class="small">${esc(f.last_verification ? f.last_verification.replaceAll("_", " ").toLowerCase() : "—")}</td></tr>`).join("")}
  </tbody></table></div>`;
}
function acPager(total, filters, action) {
  const limit = filters.limit || 50;
  if (!total) return "";
  const from = filters.offset + 1, to = Math.min(total, filters.offset + limit);
  return `<div class="pager ac-pad-x"><span class="muted small num">${from}–${to} de ${total.toLocaleString("es-PE")}</span><div class="row">
    <button class="btn btn-secondary btn-sm" data-action="${action}" data-dir="-1" ${filters.offset <= 0 ? "disabled" : ""}>${icon("left", 15)} Anterior</button>
    <button class="btn btn-secondary btn-sm" data-action="${action}" data-dir="1" ${to >= total ? "disabled" : ""}>Siguiente ${icon("right", 15)}</button></div></div>`;
}

async function acFindings(body) {
  const f = AC.findingFilters;
  const people = await api("/audit-center/assignees");
  body.innerHTML = `<section class="card"><form id="ac-finding-filters" class="toolbar" role="search" aria-label="Filtros de hallazgos">
      <label class="search">Buscar<input name="q" type="search" maxlength="100" placeholder="Código, título, recurso o control" value="${esc(f.q)}"></label>
      <label>Categoría<select name="category">${option("", "Todas")}${AC.meta.categories.map((c) => option(c.code, c.label, f.category === c.code)).join("")}</select></label>
      <label>Severidad<select name="severity">${option("", "Todas")}${Object.entries(AC.meta.severities).map(([k, v]) => option(k, v, f.severity === k)).join("")}</select></label>
      <label>Estado<select name="status">${option("", "Todos")}${Object.entries(AC.meta.finding_statuses).map(([k, v]) => option(k, v, f.status === k)).join("")}</select></label>
      <label>Responsable<select name="owner">${option("", "Todos")}${option("me", "Asignados a mí", f.owner === "me")}${option("none", "Sin asignar", f.owner === "none")}${people.map((p) => option(p.id, `${p.name} (${p.role})`, f.owner === p.id)).join("")}</select></label>
      <label>Desde<input name="date_from" type="date" value="${esc(f.date_from || "")}"></label><label>Hasta<input name="date_to" type="date" value="${esc(f.date_to || "")}"></label>
      <label class="check"><input type="checkbox" name="open_only" value="true" ${f.open_only ? "checked" : ""}> Solo abiertos</label>
      <button class="btn btn-primary" type="submit">${icon("filter", 15)} Aplicar</button></form></section>
    <section class="card card-flush" id="ac-finding-list">${loadingHtml()}</section>`;
  $("#ac-finding-filters").onsubmit = (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target));
    Object.assign(AC.findingFilters, { q: "", category: "", severity: "", status: "", owner: "", date_from: "", date_to: "", open_only: "" }, data, { offset: 0 });
    acLoadFindings();
  };
  await acLoadFindings();
}
async function acLoadFindings() {
  const box = $("#ac-finding-list");
  if (!box) return;
  const f = AC.findingFilters;
  const day = (v, plus = 0) => { const d = new Date(`${v}T00:00:00`); d.setDate(d.getDate() + plus); return d.toISOString(); };
  const params = { ...f, date_from: f.date_from ? day(f.date_from) : "", date_to: f.date_to ? day(f.date_to, 1) : "" };
  try {
    const { data, total } = await apiWithTotal(`/audit-center/findings?${acQs(params)}`);
    box.innerHTML = `<div class="card-head"><div><h3>Registro de hallazgos</h3><p>${total.toLocaleString("es-PE")} hallazgos. Los hallazgos se deduplican por control y recurso; su historial nunca se elimina.</p></div></div>
      ${acFindingTable(data)}${acPager(total, f, "ac-findings-page")}`;
  } catch (error) { box.innerHTML = `<div class="ac-pad">${banner("crit", "No se pudieron cargar los hallazgos", error.message)}</div>`; }
}
Actions["ac-findings-page"] = (el) => { AC.findingFilters.offset = Math.max(0, AC.findingFilters.offset + Number(el.dataset.dir) * AC.findingFilters.limit); acLoadFindings(); };
Actions["ac-findings-of"] = (el) => { Object.assign(AC.findingFilters, { category: el.dataset.category, offset: 0 }); go("audit", "hallazgos"); };

Actions["ac-finding"] = async (el) => {
  openModal();
  $("#modal-content").innerHTML = loadingHtml();
  try { acRenderFinding(await api(`/audit-center/findings/${el.dataset.id}`)); }
  catch (error) { $("#modal-content").innerHTML = `<div class="modal-head"><h2>No se pudo abrir el hallazgo</h2><button class="icon-btn" data-action="close-modal" aria-label="Cerrar">${icon("close", 20)}</button></div><div class="modal-body">${banner("crit", "", error.message)}</div>`; }
};

async function acRenderFinding(f) {
  const people = f.can_manage ? await api("/audit-center/assignees") : [];
  const statusLabel = AC.meta.finding_statuses;
  const transitions = f.allowed_transitions;
  $("#modal-content").innerHTML = `<div class="modal-head"><div><span class="eyebrow">${esc(f.code)} · ${esc(acCat(f.category)?.label || f.category)}</span><h2>${esc(f.title)}</h2>
      <div class="row mt-8">${acSev(f.severity)} ${acFinding(f.status)}</div></div><button class="icon-btn" data-action="close-modal" aria-label="Cerrar">${icon("close", 20)}</button></div>
    <div class="modal-body">
      <dl class="kv"><div><dt>Control</dt><dd><span class="mono">${esc(f.control)}</span> ${esc(f.control_title || "")} <span class="muted">(${esc(f.control_method || "")})</span></dd></div>
        <div><dt>Recurso afectado</dt><dd class="mono">${esc(f.resource)}</dd></div>
        <div><dt>Detección</dt><dd>${fmtDate(f.detected_at)} en ${esc(f.first_run || "—")} · última ${fmtDate(f.last_seen_at)} en ${esc(f.last_run || "—")} · ${f.occurrences} detecciones</dd></div>
        <div><dt>Última verificación</dt><dd>${esc(f.last_verification ? f.last_verification.replaceAll("_", " ").toLowerCase() : "sin verificar")}${f.last_verification_at ? ` · ${fmtDate(f.last_verification_at)} (${esc(f.last_verification_run || "")})` : ""}</dd></div>
        <div><dt>Responsable</dt><dd>${esc(f.owner?.name || "Sin asignar")}${f.owner ? ` <span class="muted">(${esc(f.owner.role)})</span>` : ""}</dd></div><div><dt>Fecha límite</dt><dd>${esc(f.due_date || "—")}</dd></div>
        ${f.risk ? `<div><dt>Riesgo aceptado</dt><dd>${esc(f.risk.justification)} <span class="muted">(revisión ${esc(f.risk.review_date || "")} · ${esc(f.risk.accepted_by?.name || "")})</span></dd></div>` : ""}</dl>
      <div class="grid grid-2"><div><h3 class="small-title">Descripción</h3><p>${esc(f.description)}</p></div><div><h3 class="small-title">Recomendación</h3><p>${esc(f.recommendation)}</p></div>
        <div><h3 class="small-title">Impacto</h3><p>${esc(f.impact)}</p></div><div><h3 class="small-title">Probabilidad / justificación del riesgo</h3><p>${esc(f.likelihood)}</p></div></div>
      ${f.evidence && Object.keys(f.evidence).length ? `<details><summary class="small-title">Evidencia de la detección</summary>${acDetails(f.evidence)}</details>` : ""}
      ${f.can_manage ? `<form id="ac-assign" class="subpanel"><b>Responsable y plazo</b><div class="form-grid"><label>Responsable<select name="owner_id">${option("", "Sin asignar")}${people.map((p) => option(p.id, `${p.name} (${p.role})`, f.owner?.id === p.id)).join("")}</select></label>
        <label>Fecha límite<input name="due_date" type="date" min="${new Date().toISOString().slice(0, 10)}" value="${esc(f.due_date || "")}"></label></div>
        <div class="row"><button class="btn btn-secondary btn-sm" type="submit">Guardar</button><button class="btn btn-quiet btn-sm" type="button" data-action="ac-verify" data-id="${esc(f.id)}">${icon("refresh", 14)} Verificar ahora (volver a ejecutar ${esc(f.control)})</button></div></form>` : ""}
      ${transitions.length ? `<form id="ac-status" class="subpanel"><b>Cambiar estado</b><p class="small muted">El cierre exige evidencia de corrección y una verificación posterior en la que el hallazgo no se reproduzca. Aceptar un riesgo exige justificación y fecha de revisión.</p>
        <label>Nuevo estado<select name="status" required>${transitions.map((t) => option(t, statusLabel[t])).join("")}</select></label>
        <label>Motivo<textarea name="note" required minlength="5" maxlength="2000"></textarea></label>
        <div class="form-grid ac-risk" hidden><label>Justificación (mín. 20 caracteres)<textarea name="justification" maxlength="4000"></textarea></label><label>Fecha de revisión<input name="review_date" type="date"></label></div>
        <div class="row"><button class="btn btn-primary btn-sm" type="submit">Aplicar cambio</button></div></form>` : ""}
      <section><div class="row-between"><h3 class="small-title">Plan de acción</h3></div>
        ${f.actions.length ? `<div class="list">${f.actions.map((a) => `<div class="list-item"><div><strong>${esc(a.description)}</strong><div class="small muted">${esc(a.owner?.name || "Sin responsable")} · límite ${esc(a.due_date || "—")}${a.note ? ` · ${esc(a.note)}` : ""}</div></div>
          <select class="ac-action-status" data-action-change="ac-action-status" data-id="${esc(a.id)}" aria-label="Estado de la tarea" ${f.can_manage || a.owner?.id === App.me.id ? "" : "disabled"}>${["PENDIENTE", "EN_CURSO", "COMPLETADA", "DESCARTADA"].map((s) => option(s, s.replace("_", " ").toLowerCase(), a.status === s)).join("")}</select></div>`).join("")}</div>`
          : '<p class="small muted">Sin tareas.</p>'}
        ${f.can_manage ? `<form id="ac-action" class="subpanel mt-8"><div class="form-grid"><label class="full">Nueva tarea<input name="description" required minlength="5" maxlength="2000"></label>
          <label>Responsable<select name="owner_id">${option("", "Sin asignar")}${people.map((p) => option(p.id, `${p.name} (${p.role})`)).join("")}</select></label>
          <label>Fecha límite<input name="due_date" type="date" min="${new Date().toISOString().slice(0, 10)}"></label></div><div class="row"><button class="btn btn-secondary btn-sm" type="submit">Agregar tarea</button></div></form>` : ""}</section>
      <section><h3 class="small-title">Evidencias de corrección</h3>
        ${f.evidences.length ? `<div class="list">${f.evidences.map((e) => `<div class="list-item"><div><strong>${esc(e.title)}</strong><div class="small muted">${esc(e.uploaded_by?.name || "")} · ${fmtDate(e.created_at)}${e.sha256 ? ` · SHA-256 <span class="mono">${esc(e.sha256.slice(0, 12))}…</span>` : ""}</div>${e.description ? `<div class="small">${esc(e.description)}</div>` : ""}</div>
          ${e.has_file ? `<button class="btn btn-secondary btn-sm" data-action="download" data-path="/audit-center/evidences/${esc(e.id)}/download" data-file="${esc(e.file || "evidencia")}">${icon("download", 14)} ${esc(e.file || "Archivo")}</button>` : ""}</div>`).join("")}</div>`
          : '<p class="small muted">Sin evidencias.</p>'}
        ${f.can_attach ? `<form id="ac-correction" class="subpanel mt-8"><label>Título<input name="title" required minlength="5" maxlength="200" placeholder="Corrección aplicada en el commit…"></label>
          <label>Descripción<textarea name="description" maxlength="4000" placeholder="Qué se corrigió y cómo verificarlo (mín. 20 caracteres si no adjunta archivo)"></textarea></label>
          <label>Archivo (opcional)<input name="file" type="file" accept=".pdf,.png,.jpg,.jpeg,.txt,.csv,.json"></label><div class="row"><button class="btn btn-secondary btn-sm" type="submit">${icon("upload", 14)} Adjuntar evidencia</button></div></form>` : ""}</section>
      <section><h3 class="small-title">Historial</h3><div class="timeline">${f.events.map((e) => `<div class="timeline-item"><span></span><div><strong>${esc(e.event.replaceAll("_", " ").toLowerCase())}</strong>
        ${e.to ? ` <span class="small muted">${esc(statusLabel[e.from] || e.from || "")} → ${esc(statusLabel[e.to] || e.to)}</span>` : ""}<div class="small muted">${fmtDate(e.created_at)} · ${esc(e.actor?.name || "Motor de auditoría")}</div>
        ${e.note ? `<div class="small">${esc(e.note)}</div>` : ""}</div></div>`).join("")}</div></section>
    </div>`;
  const refresh = async () => { acRenderFinding(await api(`/audit-center/findings/${f.id}`)); if (App.page === "audit") acLoadFindings(); };
  const submitWith = (selector, fn) => { const form = $(selector); if (form) form.onsubmit = async (e) => { e.preventDefault(); const btn = e.submitter; busy(btn, true); try { await fn(new FormData(e.target)); await refresh(); } catch (error) { flash(error.message, true); } finally { busy(btn, false); } }; };
  submitWith("#ac-assign", async (d) => {
    const payload = d.get("owner_id") ? { owner_id: d.get("owner_id") } : { clear_owner: true };
    if (d.get("due_date")) payload.due_date = d.get("due_date"); else payload.clear_due_date = true;
    await api(`/audit-center/findings/${f.id}`, { method: "PATCH", body: JSON.stringify(payload) });
    flash("Hallazgo actualizado.");
  });
  const statusForm = $("#ac-status");
  if (statusForm) {
    const toggle = () => { statusForm.querySelector(".ac-risk").hidden = !["RIESGO_ACEPTADO", "FALSO_POSITIVO"].includes(statusForm.status.value); };
    statusForm.status.addEventListener("change", toggle);
    toggle();
  }
  submitWith("#ac-status", async (d) => {
    const payload = { status: d.get("status"), note: d.get("note") };
    if (d.get("justification")) payload.justification = d.get("justification");
    if (d.get("review_date")) payload.review_date = d.get("review_date");
    await post(`/audit-center/findings/${f.id}/status`, payload);
    flash("Estado actualizado.");
  });
  submitWith("#ac-action", async (d) => {
    const payload = { description: d.get("description") };
    if (d.get("owner_id")) payload.owner_id = d.get("owner_id");
    if (d.get("due_date")) payload.due_date = d.get("due_date");
    await post(`/audit-center/findings/${f.id}/actions`, payload);
    flash("Tarea agregada.");
  });
  submitWith("#ac-correction", async (d) => {
    d.set("kind", "CORRECCION");
    d.set("finding_id", f.id);
    if (!d.get("file")?.size) d.delete("file");
    await api("/audit-center/evidences", { method: "POST", body: d });
    flash("Evidencia adjuntada.");
  });
}
ChangeActions["ac-action-status"] = async (el) => {
  try { await api(`/audit-center/actions/${el.dataset.id}`, { method: "PATCH", body: JSON.stringify({ status: el.value }) }); flash("Tarea actualizada."); }
  catch (error) { flash(error.message, true); }
};
Actions["ac-verify"] = async (el) => {
  busy(el, true, "Programando…");
  try {
    const run = await post(`/audit-center/findings/${el.dataset.id}/verify`, {});
    flash(`Verificación ${run.code} en curso.`);
    acOpenRun(run.id);
  } catch (error) { flash(error.message, true); busy(el, false); }
};

/* ---------- New audit ---------- */
Actions["ac-new"] = (el) => {
  const only = el.dataset.category;
  const today = new Date(), from = new Date(Date.now() - 30 * 86400000);
  const iso = (d) => d.toISOString().slice(0, 10);
  const o = AC.meta.options;
  openModal();
  $("#modal-content").innerHTML = `<div class="modal-head"><div><span class="eyebrow">Motor de auditoría</span><h2>Nueva auditoría</h2></div><button class="icon-btn" data-action="close-modal" aria-label="Cerrar">${icon("close", 20)}</button></div>
    <div class="modal-body"><form id="ac-new-form" class="grid">
      <label>Nombre<input name="name" required minlength="3" maxlength="150" value="${esc(only ? `Auditoría de ${acCat(only)?.label || only}` : "Auditoría integral")} · ${esc(today.toLocaleDateString("es-PE"))}"></label>
      <fieldset class="ac-fieldset"><legend>Categorías y controles</legend><p class="small muted">Por defecto se ejecutan todos los controles habilitados de cada categoría marcada. Despliegue una categoría para elegir controles concretos.</p>
        ${AC.meta.categories.map((c) => `<details class="ac-pick"><summary><label class="check"><input type="checkbox" name="categories" value="${esc(c.code)}" ${!only || only === c.code ? "checked" : ""}> ${esc(c.label)} <span class="muted small">(${c.controls})</span></label></summary>
          <div class="ac-pick-list">${AC.meta.controls.filter((x) => x.category === c.code && x.enabled).map((x) => `<label class="check small"><input type="checkbox" name="controls" value="${esc(x.code)}" data-category="${esc(c.code)}"> <span class="mono">${esc(x.code)}</span> ${esc(x.title)}</label>`).join("")}</div></details>`).join("")}</fieldset>
      <div class="form-grid"><label>Periodo desde<input name="period_from" type="date" value="${iso(from)}" max="${iso(today)}"></label><label>Periodo hasta<input name="period_to" type="date" value="${iso(today)}" max="${iso(today)}"></label></div>
      <label>Alcance y objetivos<textarea name="description" maxlength="2000" placeholder="Por ejemplo: revisión trimestral de seguridad y accesos previa a la auditoría externa"></textarea></label>
      <details><summary class="small-title">Criterios configurables</summary><div class="form-grid mt-8">
        <label>Tickets a evaluar<select name="origen">${option("todos", "Todos", o.origen === "todos")}${option("reales", "Solo reales (sin SYN-)")}${option("sinteticos", "Solo sintéticos (SYN-)")}</select></label>
        <label>Objetivo de cumplimiento SLA (%)<input name="sla_objetivo" type="number" min="50" max="100" step="1" value="${o.sla_objetivo}"></label>
        <label>Días de inactividad de cuentas<input name="dias_inactividad" type="number" min="7" max="730" value="${o.dias_inactividad}"></label>
        <label>Máximo de administradores<input name="max_admins" type="number" min="1" max="50" value="${o.max_admins}"></label>
        <label>Umbral de inicios fallidos<input name="umbral_fallos" type="number" min="1" max="100" value="${o.umbral_fallos}"></label>
        <label>Filas mínimas para exigir índice<input name="filas_minimas_indice" type="number" min="0" max="10000000" value="${o.filas_minimas_indice}"></label></div></details>
      ${banner("info", "Ejecución segura", `Todas las comprobaciones son de solo lectura y se ejecutan en segundo plano (máximo ${Math.round(AC.meta.limits.run_seconds / 60)} min). Lo que no pueda comprobarse quedará como «No verificado», nunca como aprobado.`)}
      <div class="form-foot"><span class="small muted" id="ac-new-count"></span><button class="btn btn-primary" type="submit">${icon("play", 15)} Ejecutar auditoría</button></div></form></div>`;
  const form = $("#ac-new-form");
  const count = () => {
    const picked = $$("input[name=controls]:checked", form).length;
    const cats = $$("input[name=categories]:checked", form).map((x) => x.value);
    const total = picked || AC.meta.controls.filter((x) => x.enabled && cats.includes(x.category)).length;
    $("#ac-new-count").textContent = `${total} controles${picked ? " seleccionados" : ""}`;
  };
  form.addEventListener("change", count);
  count();
  form.onsubmit = async (e) => {
    e.preventDefault();
    const btn = e.submitter;
    const d = new FormData(form);
    const day = (v, plus = 0) => { if (!v) return null; const x = new Date(`${v}T00:00:00`); x.setDate(x.getDate() + plus); return x.toISOString(); };
    const controls = d.getAll("controls");
    const payload = { name: d.get("name"), categories: controls.length ? [] : d.getAll("categories"), control_codes: controls.length ? controls : null,
      period_from: day(d.get("period_from")), period_to: d.get("period_to") ? (d.get("period_to") >= iso(today) ? new Date().toISOString() : day(d.get("period_to"), 1)) : null,
      description: d.get("description") || null,
      options: { origen: d.get("origen"), sla_objetivo: Number(d.get("sla_objetivo")), dias_inactividad: Number(d.get("dias_inactividad")), max_admins: Number(d.get("max_admins")),
        umbral_fallos: Number(d.get("umbral_fallos")), filas_minimas_indice: Number(d.get("filas_minimas_indice")) } };
    if (!payload.categories.length && !payload.control_codes) { flash("Seleccione al menos una categoría.", true); return; }
    busy(btn, true, "Programando…");
    try {
      const run = await post("/audit-center/runs", payload);
      flash(`Auditoría ${run.code} en curso.`);
      acOpenRun(run.id);
    } catch (error) { flash(error.message, true); busy(btn, false); }
  };
};

/* ---------- Run detail (with live progress) ---------- */
Actions["ac-run"] = (el) => acOpenRun(el.dataset.id);
async function acOpenRun(id) {
  acStopPolling();
  openModal();
  if (!$("#modal-content .ac-run-sheet")) $("#modal-content").innerHTML = loadingHtml();
  let r;
  try { r = await api(`/audit-center/runs/${id}`); }
  catch (error) { $("#modal-content").innerHTML = `<div class="modal-head"><h2>No se pudo abrir la auditoría</h2><button class="icon-btn" data-action="close-modal" aria-label="Cerrar">${icon("close", 20)}</button></div><div class="modal-body">${banner("crit", "", error.message)}</div>`; return; }
  if (!modal.open) return;
  const active = ["PENDIENTE", "EN_CURSO"].includes(r.status);
  const finished = !active;
  const by = r.summary?.por_estado || {};
  const groups = {};
  r.results.forEach((x) => (groups[x.category] = groups[x.category] || []).push(x));
  const pct = r.progress.total ? Math.round(100 * r.progress.done / r.progress.total) : 0;
  const conn = r.connection || {};
  $("#modal-content").innerHTML = `<div class="ac-run-sheet"><div class="modal-head"><div><span class="eyebrow">${esc(r.code)} · ${esc(r.type)}</span><h2>${esc(r.name)}</h2>
      <div class="row mt-8">${acRun(r.status)} ${acResult(r.result)}${r.seal_status ? ` <span class="pill ${r.seal_status === "VALIDO" ? "ac-ok" : "ac-fail"}" title="Sello HMAC de los resultados">Sello ${esc(r.seal_status.toLowerCase())}</span>` : ""}</div></div>
      <button class="icon-btn" data-action="close-modal" aria-label="Cerrar">${icon("close", 20)}</button></div>
    <div class="modal-body">
      ${active ? `<div class="subpanel" aria-live="polite"><div class="row-between"><b>${r.status === "PENDIENTE" ? "En cola" : "Ejecutando"}${r.progress.current ? ` · ${esc(r.progress.current)}` : ""}</b><span class="num">${r.progress.done}/${r.progress.total} · ${pct} %</span></div>
        <div class="ac-progress"><i style="width:${pct}%"></i></div><p class="small muted">Puede cerrar esta ventana: la auditoría continúa en el servidor.</p>
        <div><button class="btn btn-quiet btn-sm" data-action="ac-cancel" data-id="${esc(r.id)}" ${r.cancel_requested ? "disabled" : ""}>${r.cancel_requested ? "Cancelación solicitada" : "Cancelar"}</button></div></div>` : ""}
      ${r.status === "INTERRUMPIDA" ? banner("warn", "Ejecución interrumpida", r.error || "La ejecución no terminó; los controles pendientes quedaron como no verificados.") : ""}
      ${finished && r.summary ? `<div class="summary-grid">${AC_SEGMENTS.map((s) => `<div><span>${esc(acLabel("statuses", s))}</span><strong class="num">${by[s] || 0}</strong></div>`).join("")}<div><span>Hallazgos relacionados</span><strong class="num">${r.findings.length}</strong></div></div>
        ${banner(r.result === "FAVORABLE" ? "info" : r.result === "DESFAVORABLE" ? "crit" : "warn", acLabel("results", r.result), AC.meta.result_meaning[r.result] || "")}` : ""}
      ${finished ? `<div class="row ac-downloads"><button class="btn btn-secondary btn-sm" data-action="ac-report" data-id="${esc(r.id)}" data-kind="executive">${icon("download", 14)} Informe ejecutivo (PDF)</button>
        <button class="btn btn-secondary btn-sm" data-action="ac-report" data-id="${esc(r.id)}" data-kind="technical">${icon("download", 14)} Informe técnico (PDF)</button>
        <button class="btn btn-secondary btn-sm" data-action="ac-report" data-id="${esc(r.id)}" data-kind="package">${icon("download", 14)} Paquete de evidencias (ZIP)</button>
        <button class="btn btn-quiet btn-sm" data-action="ac-repeat" data-id="${esc(r.id)}">${icon("refresh", 14)} Repetir</button>
        <button class="btn btn-quiet btn-sm" data-action="ac-compare" data-id="${esc(r.id)}">${icon("compare", 14)} Comparar con la anterior</button></div>
        ${AC.meta.is_admin ? `<label class="check small"><input type="checkbox" id="ac-unredacted"> Generar sin enmascarar correos ni IP (solo ADMIN; queda registrado)</label>` : ""}<div id="ac-compare"></div>` : ""}
      <dl class="kv"><div><dt>Alcance</dt><dd>${esc((r.categories || []).map((c) => acCat(c)?.label || c).join(" · "))} · ${r.control_codes.length} controles${r.scope?.descripcion ? `<br>${esc(r.scope.descripcion)}` : ""}</dd></div>
        <div><dt>Periodo evaluado (UTC)</dt><dd>${esc(r.period_from || "últimos 30 días")} → ${esc(r.period_to || "fecha de ejecución")}</dd></div>
        <div><dt>Responsable</dt><dd>${esc(r.requested_by?.name || "Sistema")}${r.requested_by ? ` <span class="muted">(${esc(r.requested_by.role)})</span>` : ""}</dd></div>
        <div><dt>Ejecución</dt><dd>Creada ${fmtDate(r.created_at)} · inicio ${fmtDate(r.started_at)} · fin ${fmtDate(r.finished_at)} <span class="muted">(zona horaria de registro: UTC)</span></dd></div>
        <div><dt>Versión de FixIT</dt><dd>${esc(r.app_version)}${r.build ? ` <span class="mono">(${esc(r.build)})</span>` : ""}</dd></div>
        <div><dt>Conexión y privilegios</dt><dd>${esc(conn.resumen || "—")}${conn.origen ? `<div class="small muted">${esc(conn.origen)} · ${esc(conn.ubicacion || "")}</div>` : ""}</dd></div>
        ${r.tools ? `<div><dt>Herramientas</dt><dd class="small">${esc(Object.entries(r.tools).filter(([, v]) => typeof v !== "object").map(([k, v]) => `${k}: ${v}`).join(" · "))}</dd></div>` : ""}</dl>
      <section><h3 class="small-title">Resultados por control</h3>${Object.entries(groups).map(([cat, items]) => `<details class="ac-group" ${items.some((x) => ["FALLIDO", "ERROR_EJECUCION"].includes(x.status)) ? "open" : ""}><summary><b>${esc(acCat(cat)?.label || cat)}</b> ${acBar(items.reduce((a, x) => (a[x.status] = (a[x.status] || 0) + 1, a), {}))}</summary>
        ${items.map((x) => `<details class="ac-result"><summary><span class="ticket-no">${esc(x.control)}</span> <span class="ac-result-title">${esc(x.title)}</span> ${acStatus(x.status)} ${x.severity ? acSev(x.severity) : ""}</summary>
          <div class="ac-result-body"><p>${esc(x.summary)}</p><p class="small muted">Método ${esc(x.method)} · ${x.duration_ms} ms · ${esc(x.privileges || "")}</p>${x.error ? banner("crit", "Error de ejecución", x.error) : ""}${acDetails(x.details)}</div></details>`).join("")}</details>`).join("") || '<p class="small muted">Aún no hay resultados.</p>'}</section>
      ${r.findings.length ? `<section><h3 class="small-title">Hallazgos detectados o verificados</h3>${acFindingTable(r.findings)}</section>` : ""}
      ${r.limitations?.length ? `<details><summary class="small-title">Limitaciones de esta ejecución (${r.limitations.length})</summary><ul class="small">${r.limitations.map((l) => `<li>${esc(l)}</li>`).join("")}</ul></details>` : ""}
      ${r.reports.length ? `<section><h3 class="small-title">Informes generados</h3><div class="table-wrap"><table class="table-compact"><thead><tr><th>Fecha</th><th>Tipo</th><th>Por</th><th>SHA-256</th></tr></thead><tbody>
        ${r.reports.map((x) => `<tr><td class="small">${fmtDate(x.created_at)}</td><td class="small">${esc(x.kind)}${x.redacted ? "" : " (sin enmascarar)"}</td><td class="small">${esc(x.generated_by?.name || "")}</td><td class="small mono">${esc(x.sha256.slice(0, 16))}…</td></tr>`).join("")}</tbody></table></div></section>` : ""}
    </div></div>`;
  if (active) AC.poll = setTimeout(() => { if (modal.open) acOpenRun(id); }, 2500);
  else if (App.page === "audit" && (location.hash.endsWith("/panel") || location.hash === "#/audit")) { /* the panel refreshes on demand */ }
}
Actions["ac-cancel"] = async (el) => {
  busy(el, true, "Cancelando…");
  try { const r = await post(`/audit-center/runs/${el.dataset.id}/cancel`, {}); flash(r.status === "CANCELADA" ? "Auditoría cancelada." : "Se detendrá después del control en curso."); acOpenRun(el.dataset.id); }
  catch (error) { flash(error.message, true); busy(el, false); }
};
Actions["ac-repeat"] = async (el) => {
  busy(el, true, "Programando…");
  try { const run = await post(`/audit-center/runs/${el.dataset.id}/repeat`, {}); flash(`Repetición ${run.code} en curso.`); acOpenRun(run.id); }
  catch (error) { flash(error.message, true); busy(el, false); }
};
Actions["ac-report"] = async (el) => {
  const unredacted = $("#ac-unredacted")?.checked;
  busy(el, true, "Generando…");
  await download(`/audit-center/runs/${el.dataset.id}/report/${el.dataset.kind}${unredacted ? "?redact=false" : ""}`, `fixit-${el.dataset.kind}.${el.dataset.kind === "package" ? "zip" : "pdf"}`);
  busy(el, false);
};
Actions["ac-compare"] = async (el) => {
  const box = $("#ac-compare");
  box.innerHTML = loadingHtml("Comparando…");
  try {
    const c = await api(`/audit-center/runs/${el.dataset.id}/compare`);
    const changed = c.controls.filter((x) => x.change !== "IGUAL");
    box.innerHTML = `<div class="subpanel"><b>Comparación con ${esc(c.base.code)} (${fmtDate(c.base.created_at)})</b>
      <div class="row small">${Object.entries(c.totals).map(([k, v]) => `<span class="chip ${k === "MEJORA" ? "down" : k === "EMPEORA" ? "up" : ""}">${esc(k.toLowerCase())}: ${v}</span>`).join("")}</div>
      ${changed.length ? `<div class="table-wrap"><table class="table-compact"><thead><tr><th>Control</th><th>Antes</th><th>Ahora</th><th>Cambio</th></tr></thead><tbody>${changed.map((x) => `<tr><td><span class="mono">${esc(x.control)}</span> <span class="small">${esc(x.title)}</span></td>
        <td>${x.before ? acStatus(x.before) : "—"}</td><td>${x.after ? acStatus(x.after) : "—"}</td><td class="small">${esc(x.change.toLowerCase())}</td></tr>`).join("")}</tbody></table></div>` : '<p class="small muted">Sin cambios de estado.</p>'}</div>`;
  } catch (error) { box.innerHTML = banner("warn", "", error.message); }
};

/* ---------- Reports ---------- */
async function acReports(body) {
  const [{ data: runs }, { data: reports, total }] = await Promise.all([apiWithTotal("/audit-center/runs?limit=50"), apiWithTotal("/audit-center/reports?limit=50")]);
  const finished = runs.filter((r) => !["PENDIENTE", "EN_CURSO"].includes(r.status));
  body.innerHTML = `${banner("info", "Productos de la auditoría", "Informe ejecutivo (directivos), informe técnico (auditores) y paquete ZIP con resultados, hallazgos, registros autorizados, evidencias, metadatos y un manifiesto SHA-256. Los datos personales se enmascaran por defecto y cada descarga queda registrada. El manifiesto permite detectar alteraciones; no es una firma digital.")}
    <section class="card card-flush"><div class="card-head"><div><h3>Auditorías finalizadas</h3><p>${finished.length} disponibles</p></div></div>
      ${finished.length ? `<div class="table-wrap"><table class="table-compact"><thead><tr><th>Código</th><th>Auditoría</th><th>Resultado</th><th>Finalizada</th><th>Descargas</th></tr></thead><tbody>
      ${finished.map((r) => `<tr><td><button class="btn btn-link" data-action="ac-run" data-id="${esc(r.id)}">${esc(r.code)}</button></td><td><strong>${esc(r.name)}</strong><span class="sub">${esc(acLabel("run_statuses", r.status))}</span></td>
        <td>${acResult(r.result)}</td><td class="small nowrap">${fmtDate(r.finished_at)}</td><td><div class="row ac-dl">
        <button class="btn btn-secondary btn-sm" data-action="ac-report" data-id="${esc(r.id)}" data-kind="executive">Ejecutivo</button><button class="btn btn-secondary btn-sm" data-action="ac-report" data-id="${esc(r.id)}" data-kind="technical">Técnico</button>
        <button class="btn btn-secondary btn-sm" data-action="ac-report" data-id="${esc(r.id)}" data-kind="package">ZIP</button></div></td></tr>`).join("")}</tbody></table></div>`
        : `<div class="ac-pad">${empty("Sin auditorías finalizadas", "Los informes se generan a partir de ejecuciones finalizadas.", "file")}</div>`}</section>
    <section class="card card-flush"><div class="card-head"><div><h3>Historial de informes generados</h3><p>${total} informes · cada uno con su SHA-256 y el registro de auditoría de la descarga</p></div></div>
      ${reports.length ? `<div class="table-wrap"><table class="table-compact"><thead><tr><th>Fecha</th><th>Auditoría</th><th>Tipo</th><th>Archivo</th><th>Por</th><th>SHA-256</th></tr></thead><tbody>
      ${reports.map((x) => `<tr><td class="small nowrap">${fmtDate(x.created_at)}</td><td class="small">${esc(x.run_code || "")}</td><td class="small">${esc(x.kind)}${x.redacted ? "" : " · sin enmascarar"}</td>
        <td class="small">${esc(x.filename)} <span class="muted">(${Math.max(1, Math.round(x.size / 1024))} KiB)</span></td><td class="small">${esc(x.generated_by?.name || "")}</td><td class="small mono">${esc(x.sha256.slice(0, 16))}…</td></tr>`).join("")}</tbody></table></div>`
        : `<div class="ac-pad">${empty("Aún no se generaron informes")}</div>`}</section>`;
}

/* ---------- History and methodology ---------- */
async function acHistory(body) {
  const f = AC.runFilters;
  const m = AC.meta;
  body.innerHTML = `<section class="card"><form id="ac-run-filters" class="toolbar" role="search" aria-label="Filtros de auditorías">
      <label class="search">Buscar<input name="q" type="search" maxlength="100" placeholder="Código o nombre" value="${esc(f.q)}"></label>
      <label>Estado<select name="status">${option("", "Todos")}${Object.entries(m.run_statuses).map(([k, v]) => option(k, v, f.status === k)).join("")}</select></label>
      <label>Resultado<select name="result">${option("", "Todos")}${Object.entries(m.results).map(([k, v]) => option(k, v, f.result === k)).join("")}</select></label>
      <label>Categoría<select name="category">${option("", "Todas")}${m.categories.map((c) => option(c.code, c.label, f.category === c.code)).join("")}</select></label>
      <button class="btn btn-primary" type="submit">${icon("filter", 15)} Aplicar</button></form></section>
    <section class="card card-flush" id="ac-run-list">${loadingHtml()}</section>
    <section class="section-head"><div><h2>Metodología</h2><p>Cómo se planifica, ejecuta y documenta cada auditoría.</p></div></section>
    <section class="grid grid-2"><article class="card"><h3 class="small-title">Proceso</h3><ol class="ac-list">${m.methodology.map((x) => `<li>${esc(x)}</li>`).join("")}</ol></article>
      <article class="card"><h3 class="small-title">Limitaciones generales</h3><ul class="ac-list">${m.limitations.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></article>
      <article class="card"><h3 class="small-title">Estados de una comprobación</h3><dl class="kv">${Object.entries(m.status_meaning).map(([k, v]) => `<div><dt>${acStatus(k)}</dt><dd class="small">${esc(v)}</dd></div>`).join("")}</dl></article>
      <article class="card"><h3 class="small-title">Métodos y resultado general</h3><dl class="kv">${Object.entries(m.methods).map(([k, v]) => `<div><dt>${esc(k)}</dt><dd class="small">${esc(v)}</dd></div>`).join("")}
        ${Object.entries(m.result_meaning).map(([k, v]) => `<div><dt>${acResult(k)}</dt><dd class="small">${esc(v)}</dd></div>`).join("")}</dl></article></section>
    <section class="card"><h3 class="small-title">Referencias y criterios</h3><p class="small muted">Inspiran los controles; su uso no implica certificación ni cumplimiento legal pleno.</p>
      <ul class="ac-list">${Object.values(m.references).map((r) => `<li>${r.url ? `<a href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">${esc(r.name)}</a>` : esc(r.name)}</li>`).join("")}</ul></section>
    <section class="card card-flush"><div class="card-head"><div><h3>Catálogo de controles</h3><p>${m.controls.length} controles implementados${m.is_admin ? " · como administrador puede habilitarlos o deshabilitarlos" : ""}</p></div></div>
      <div class="table-wrap"><table class="table-compact"><thead><tr><th>Control</th><th>Categoría</th><th>Comprobación</th><th>Método</th><th>Severidad</th><th>Criterios</th>${m.is_admin ? "<th>Habilitado</th>" : ""}</tr></thead><tbody>
      ${m.controls.map((x) => `<tr><td><span class="ticket-no">${esc(x.code)}</span></td><td class="small">${esc(acCat(x.category)?.label || x.category)}</td><td><strong>${esc(x.title)}</strong><span class="sub">${esc(x.objective)}</span></td>
        <td class="small">${esc(x.method)}</td><td>${acSev(x.severity)}</td><td class="small">${esc((x.criteria || []).join("; "))}</td>
        ${m.is_admin ? `<td><input type="checkbox" aria-label="Habilitar ${esc(x.code)}" data-action-change="ac-toggle-control" data-code="${esc(x.code)}" ${x.enabled ? "checked" : ""}></td>` : ""}</tr>`).join("")}</tbody></table></div></section>`;
  $("#ac-run-filters").onsubmit = (e) => { e.preventDefault(); Object.assign(AC.runFilters, Object.fromEntries(new FormData(e.target)), { offset: 0 }); acLoadRuns(); };
  await acLoadRuns();
}
async function acLoadRuns() {
  const box = $("#ac-run-list");
  if (!box) return;
  try {
    const { data, total } = await apiWithTotal(`/audit-center/runs?${acQs(AC.runFilters)}`);
    box.innerHTML = `<div class="card-head"><div><h3>Historial de ejecuciones</h3><p>${total} ejecuciones · se conservan todas, incluidas las canceladas e interrumpidas</p></div>
      <button class="btn btn-primary btn-sm" data-action="ac-new">${icon("plus", 14)} Nueva auditoría</button></div>${acRunTable(data)}${acPager(total, AC.runFilters, "ac-runs-page")}`;
  } catch (error) { box.innerHTML = `<div class="ac-pad">${banner("crit", "No se pudo cargar el historial", error.message)}</div>`; }
}
Actions["ac-runs-page"] = (el) => { AC.runFilters.offset = Math.max(0, AC.runFilters.offset + Number(el.dataset.dir) * AC.runFilters.limit); acLoadRuns(); };

/* ---------- Technician view ---------- */
async function acTechnician(root) {
  setTitle("Mis hallazgos", "Hallazgos de auditoría y tareas de corrección asignados a ti");
  const my = await api("/audit-center/my");
  const { data } = await apiWithTotal("/audit-center/findings?limit=100");
  root.innerHTML = `${banner("info", "¿Qué puedo hacer aquí?", "Revisar los hallazgos y tareas que te asignaron, actualizar su estado y adjuntar evidencia de la corrección. El cierre lo realiza ADMIN o JEFE_TI después de verificar que el problema ya no se reproduce.")}
    <section class="kpis">${kpi("Hallazgos abiertos asignados", my.findings.length, "", my.findings.length ? "warn" : "good")}${kpi("Tareas pendientes", my.actions.length, "Pendientes o en curso", my.actions.length ? "warn" : "good")}</section>
    <section class="card card-flush"><div class="card-head"><div><h3>Tareas de corrección</h3></div></div>
      ${my.actions.length ? `<div class="list">${my.actions.map((a) => `<div class="list-item clickable" data-action="ac-finding" data-id="${esc(a.finding_id)}" role="button" tabindex="0"><div><strong>${esc(a.description)}</strong>
        <div class="small muted">${esc(a.finding_code || "")} · límite ${esc(a.due_date || "—")} · ${esc(a.status.replace("_", " ").toLowerCase())}</div></div>${icon("right", 16)}</div>`).join("")}</div>`
        : `<div class="ac-pad">${empty("Sin tareas pendientes", "", "check")}</div>`}</section>
    <section class="card card-flush"><div class="card-head"><div><h3>Hallazgos asignados o con tareas tuyas</h3></div></div>${acFindingTable(data)}</section>`;
}
