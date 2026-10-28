"use strict";
/* FixIT web client — audit trail: filters, paging, record detail and CSV/JSON export (ADMIN and JEFE_TI).
   The server enforces the permissions; this page only reflects them. Dates are picked in local time and sent
   as UTC; exported files are always in UTC. */

const auditFilters = { date_from: "", date_to: "", user_id: "", action: "", module: "", entity: "", outcome: "", q: "", offset: 0, limit: 100 };
const OUTCOME_LABEL = { EXITO: "Éxito", FALLO: "Fallo", DENEGADO: "Denegado" };
const OUTCOME_CLASS = { EXITO: "pill-ok", FALLO: "st-reabierto", DENEGADO: "st-cancelado" };
const INTEGRITY_VIEW = { VALIDO: ["Válido", "pill-ok"], ALTERADO: ["Alterado", "st-cancelado"], SIN_SELLO: ["Sin sello", ""], CLAVE_DISTINTA: ["Otra clave", "st-en-atencion"] };
let auditFacets = null;
let auditRows = [];

const outcomePill = (o) => `<span class="pill ${OUTCOME_CLASS[o] || ""}"><span class="dot"></span>${esc(OUTCOME_LABEL[o] || o)}</span>`;
function integrityPill(status) {
  const [label, cls] = INTEGRITY_VIEW[status] || [status, ""];
  return `<span class="pill ${cls}" title="${esc(auditFacets?.integrity?.[status] || "")}">${esc(label)}</span>`;
}

/* Local calendar day -> UTC instant. "Hasta" includes the whole selected day (the API bound is exclusive). */
function auditQuery(extra = {}) {
  const params = new URLSearchParams();
  const day = (value, plus = 0) => { const d = new Date(`${value}T00:00:00`); d.setDate(d.getDate() + plus); return d.toISOString(); };
  if (auditFilters.date_from) params.set("date_from", day(auditFilters.date_from));
  if (auditFilters.date_to) params.set("date_to", day(auditFilters.date_to, 1));
  for (const k of ["user_id", "action", "module", "entity", "outcome", "q"]) if (auditFilters[k]) params.set(k, auditFilters[k]);
  for (const [k, v] of Object.entries(extra)) params.set(k, v);
  return params;
}

Pages.audit = async (root) => {
  setTitle("Auditoría", "Registro de actividad para supervisión y auditorías externas");
  auditFacets = await api("/audit/facets");
  const f = auditFacets;
  const select = (name, label, values, all = "Todos") => `<label>${label}<select name="${name}"><option value="">${all}</option>${values.map(([v, l]) => option(v, l, auditFilters[name] === v)).join("")}</select></label>`;
  root.innerHTML = `
    <section class="card"><form id="audit-filters" class="toolbar audit-filters" role="search" aria-label="Filtros de auditoría">
      <label>Desde<input name="date_from" type="date" value="${esc(auditFilters.date_from)}"></label>
      <label>Hasta<input name="date_to" type="date" value="${esc(auditFilters.date_to)}"></label>
      ${select("user_id", "Usuario", [[f.system_user, "Sistema (sin usuario)"], ...f.users.map((u) => [u.id, `${u.name} · ${u.email}`])])}
      ${select("action", "Acción", f.actions.map((a) => [a, a]), "Todas")}
      ${select("module", "Módulo", f.modules.map((m) => [m, m]))}
      ${select("entity", "Entidad", f.entities.map((m) => [m, m]), "Todas")}
      ${select("outcome", "Resultado", f.outcomes.map((o) => [o, OUTCOME_LABEL[o] || o]))}
      <label class="search">Texto<input name="q" type="search" maxlength="100" placeholder="Acción, módulo, entidad o ID" value="${esc(auditFilters.q)}"></label>
      <div class="row audit-actions"><button class="btn btn-primary" type="submit">${icon("filter", 15)} Aplicar</button>
        <button class="btn btn-quiet" type="button" data-action="audit-reset">Limpiar</button></div>
    </form>
    <div class="audit-export"><p class="small muted">Las fechas se eligen en tu hora local; los archivos exportados usan UTC e incluyen los filtros aplicados, quién exportó y el estado de integridad de cada registro (máximo ${Number(f.export_max_rows).toLocaleString("es-PE")} registros).</p>
      <div class="row"><button class="btn btn-secondary btn-sm" data-action="audit-export" data-format="csv">${icon("download", 15)} Exportar CSV</button>
        <button class="btn btn-secondary btn-sm" data-action="audit-export" data-format="json">${icon("download", 15)} Exportar JSON</button></div></div></section>
    <section id="audit-results">${loadingHtml()}</section>`;
  $("#audit-filters").onsubmit = (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target));
    if (data.date_from && data.date_to && data.date_from > data.date_to) { flash("La fecha «Desde» debe ser anterior o igual a «Hasta».", true); return; }
    Object.assign(auditFilters, data, { offset: 0 });
    loadAuditResults();
  };
  await loadAuditResults();
};

async function loadAuditResults() {
  const box = $("#audit-results");
  if (!box) return;
  box.innerHTML = loadingHtml();
  try {
    const { data, total } = await apiWithTotal(`/audit?${auditQuery({ limit: auditFilters.limit, offset: auditFilters.offset })}`);
    auditRows = data;
    const from = total ? auditFilters.offset + 1 : 0, to = auditFilters.offset + data.length;
    box.innerHTML = `<div class="card card-flush"><div class="table-wrap table-scroll audit-table"><table class="table-compact">
      <thead><tr><th>Fecha</th><th>Usuario</th><th>Acción</th><th>Módulo</th><th>Entidad</th><th>Resultado</th><th>IP</th><th>Integridad</th><th><span class="sr-only">Detalle</span></th></tr></thead><tbody>
      ${data.map((a, i) => `<tr><td class="small nowrap">${fmtDate(a.created_at)}</td><td>${esc(a.user_name)}${a.user_email ? `<span class="sub">${esc(a.user_email)}</span>` : ""}</td>
        <td><strong>${esc(a.action)}</strong></td><td><span class="pill">${esc(a.module)}</span></td><td class="small">${esc(a.entity)}${a.entity_id ? `<span class="sub mono">${esc(a.entity_id)}</span>` : ""}</td>
        <td>${outcomePill(a.outcome)}</td><td class="small mono">${esc(a.ip || "—")}</td><td>${integrityPill(a.integrity)}</td>
        <td><button class="btn btn-quiet btn-sm" data-action="audit-detail" data-index="${i}">Ver</button></td></tr>`).join("") || `<tr><td colspan="9">${empty("Sin eventos", "No hay registros con estos filtros.")}</td></tr>`}
      </tbody></table></div></div>
      ${total ? `<div class="pager"><span class="muted small num">Mostrando ${from}–${to} de ${total.toLocaleString("es-PE")}</span><div class="row">
        <button class="btn btn-secondary btn-sm" data-action="audit-page" data-dir="-1" ${auditFilters.offset <= 0 ? "disabled" : ""}>${icon("left", 15)} Anterior</button>
        <button class="btn btn-secondary btn-sm" data-action="audit-page" data-dir="1" ${to >= total ? "disabled" : ""}>Siguiente ${icon("right", 15)}</button></div></div>` : ""}`;
  } catch (error) {
    box.innerHTML = banner("crit", "No se pudo cargar la auditoría", error.message);
  }
}

Actions["audit-page"] = (el) => {
  auditFilters.offset = Math.max(0, auditFilters.offset + Number(el.dataset.dir) * auditFilters.limit);
  loadAuditResults();
};
Actions["audit-reset"] = () => {
  Object.assign(auditFilters, { date_from: "", date_to: "", user_id: "", action: "", module: "", entity: "", outcome: "", q: "", offset: 0 });
  route();
};
Actions["audit-export"] = async (el) => {
  busy(el, true, "Preparando…");
  await download(`/audit/export?${auditQuery({ format: el.dataset.format })}`, `fixit-auditoria.${el.dataset.format}`);
  busy(el, false);
};
Actions["audit-detail"] = (el) => {
  const a = auditRows[Number(el.dataset.index)];
  if (!a) return;
  const json = (v) => v === null || v === undefined ? '<span class="muted">—</span>' : `<pre class="json">${esc(JSON.stringify(v, null, 2))}</pre>`;
  const row = (k, v) => `<div><dt>${esc(k)}</dt><dd>${v}</dd></div>`;
  openModal(true);
  $("#modal-content").innerHTML = `<div class="modal-head"><div><span class="eyebrow">Registro de auditoría</span><h2>${esc(a.action)}</h2></div><button class="icon-btn" data-action="close-modal" aria-label="Cerrar">${icon("close", 20)}</button></div>
    <div class="modal-body"><dl class="kv">
      ${row("Fecha (UTC)", `<span class="mono">${esc(a.created_at)}</span>`)}${row("Fecha local", esc(fmtDate(a.created_at)))}
      ${row("Usuario", `${esc(a.user_name)}${a.user_email ? ` · ${esc(a.user_email)}` : ""}${a.user_role ? ` <span class="muted">(rol actual: ${esc(ROLE_LABEL[a.user_role] || a.user_role)})</span>` : ""}`)}
      ${row("Módulo / entidad", `${esc(a.module)} · ${esc(a.entity)}${a.entity_id ? ` <span class="mono">${esc(a.entity_id)}</span>` : ""}`)}
      ${row("Resultado", outcomePill(a.outcome))}${row("IP", `<span class="mono">${esc(a.ip || "—")}</span>`)}${row("Navegador", `<span class="small">${esc(a.user_agent || "—")}</span>`)}
      ${row("Integridad", `${integrityPill(a.integrity)} <span class="small muted">${esc(auditFacets?.integrity?.[a.integrity] || "")}</span>`)}
      ${row("ID del registro", `<span class="mono">${esc(a.id)}</span>`)}
    </dl>
    <div class="grid grid-2"><div><h3 class="small-title">Valor anterior</h3>${json(a.old_value)}</div><div><h3 class="small-title">Valor nuevo</h3>${json(a.new_value)}</div></div></div>`;
};
