"use strict";
/* FixIT — Machine Learning › Agentes y monitor (ADMIN / JEFE_TI). Controls are rendered once; the
 * live area (agent status, run log, LLM activity) is refreshed from /api/agents/monitor every 4 s
 * while this tab is open and the browser tab is visible. */

const AGENT_STATUS = { OK: "pill-ok", PARCIAL: "st-en-atencion", ERROR: "st-cancelado", EN_CURSO: "st-asignado", INTERRUMPIDA: "st-cancelado" };
const TRIGGER_LABEL = { MANUAL: "Manual", PROGRAMADA: "Programada", USUARIO: "Usuario", TICKET: "Ticket" };
const EVAL_LABELS = {
  runs_30d: ["Ejecuciones (30 días)"], success_rate_30d: ["Ejecuciones correctas", "pct"], errors_30d: ["Errores (30 días)"],
  priority_macro_f1: ["F1 macro del modelo de prioridad"], priority_agreement: ["Coincidencia con la prioridad registrada", "pct"],
  category_agreement: ["Coincidencia con la categoría registrada", "pct"], precision: ["Precisión"], recall: ["Exhaustividad"], f1: ["F1"],
  roc_auc: ["AUC"], alerts_30d: ["Alertas emitidas (30 días)"], top1_match_rate: ["Coincidencia top-1 (backtest)", "pct"],
  top3_match_rate: ["Coincidencia top-3 (backtest)", "pct"], assigned_30d: ["Asignaciones ejecutadas (30 días)"],
  llm_answer_rate: ["Ejecuciones con respuesta del LLM", "pct"], avg_similar_cases: ["Casos similares por consulta"],
  reminders_30d: ["Recordatorios enviados (30 días)"],
};
const AUTOMATION_TASKS = [["alertas_sla", "Alertas SLA"], ["seguimiento_atrasados", "Seguimiento de atrasados"],
  ["seguimiento_inactivos", "Seguimiento de inactivos"], ["resumen_operativo", "Resumen operativo"]];
const POLL_MS = 4000;
const agentTitles = {};
let agentsTimer = null;

const fmtMs = (ms) => ms == null ? "—" : ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
const RUN_LABEL = { OK: "Correcta", PARCIAL: "Parcial", ERROR: "Error", EN_CURSO: "En curso…", INTERRUMPIDA: "Interrumpida" };
const runPill = (status) => `<span class="pill ${AGENT_STATUS[status] || ""}"><span class="dot"></span>${esc(RUN_LABEL[status] || status)}</span>`;
const statLine = (label, value, note = "") => `<div class="stat-line"><span>${esc(label)}${note ? ` <span class="muted small">${esc(note)}</span>` : ""}</span><strong class="num">${esc(value ?? "—")}</strong></div>`;
const crit = (message) => banner("crit", "", message);

function agentControls(a, i) {
  const params = {
    triage: `<label>Tickets<input name="limit" type="number" min="1" max="50" value="20"></label>`,
    sla_risk: `<label>Umbral de riesgo<select name="threshold">${[0.5, 0.6, 0.7, 0.8].map((v) => option(v, `${Math.round(v * 100)} %`, v === 0.6)).join("")}</select></label>`,
    assignment: `<label>Modo<select name="mode">${option("recomendar", "Solo recomendar", true)}${option("ejecutar", "Asignar (regla de negocio)")}</select></label>
      <label>Tickets<input name="limit" type="number" min="1" max="50" value="10"></label>`,
    automation: `<div class="tasks">${AUTOMATION_TASKS.map(([k, v]) => `<label class="check"><input type="checkbox" name="tasks" value="${k}" checked> ${v}</label>`).join("")}</div>`,
  }[a.name];
  const run = a.name === "diagnosis"
    ? '<p class="note">Se ejecuta por ticket desde su detalle, con «Sugerir diagnóstico».</p>'
    : `<form data-agent-run="${a.name}" aria-label="Ejecutar ${esc(a.title)}">${params}<button class="btn btn-primary btn-sm" type="submit">${icon("play", 14)} Ejecutar</button></form>`;
  const schedule = a.schedulable ? `<form data-agent-schedule="${a.name}" aria-label="Programar ${esc(a.title)}"><label>Programar cada (min)<input name="minutes" type="number" min="5" max="1440" required placeholder="p. ej. 60"></label>
      <button class="btn btn-secondary btn-sm" type="submit">Programar</button><button class="btn btn-quiet btn-sm" type="button" data-agent-unschedule="${a.name}">Quitar</button></form>` : "";
  return `<article class="agent-row"><div class="agent-id"><span class="agent-num" aria-hidden="true">${String(i + 1).padStart(2, "0")}</span>
      <div><h3>${esc(a.title)}</h3><p>${esc(a.automates)}</p><label class="check"><input type="checkbox" data-agent-enabled="${a.name}"> Habilitado</label></div></div>
    <div id="agent-live-${a.name}" class="agent-live">${loadingHtml()}</div>
    <div class="agent-controls">${run}${schedule}</div></article>`;
}

function agentLive(a) {
  const r = a.last_run;
  return `<div class="row" style="gap:6px">${a.running ? runPill("EN_CURSO") : r ? runPill(r.status) : '<span class="pill">Sin ejecuciones</span>'}
      ${a.enabled ? "" : '<span class="pill st-cancelado">Deshabilitado</span>'}${a.schedule_minutes ? `<span class="pill st-asignado">Cada ${a.schedule_minutes} min</span>` : ""}</div>
    ${r ? `<span>${esc(r.summary || r.error || "")}</span>
      <span class="muted">Última: ${fmtDate(r.started_at)} · ${fmtMs(r.duration_ms)} · ${esc(TRIGGER_LABEL[r.trigger] || r.trigger)}</span>
      ${r.status !== "EN_CURSO" ? `<div><button type="button" class="source-link" data-agent-detail="${esc(r.id)}">Ver resultado ${icon("right", 13)}</button></div>` : ""}` : '<span class="muted">Aún no se ha ejecutado.</span>'}
    ${a.last_error ? `<span class="muted" style="color:var(--crit-ink)">Último error (${fmtDate(a.last_error.at)}): ${esc(a.last_error.error)}</span>` : ""}
    <span class="muted">${a.runs_24h} ${a.runs_24h === 1 ? "ejecución" : "ejecuciones"} en 24 h</span>`;
}

function renderMonitor(m) {
  const live = $("#agents-live");
  if (!live) return;
  for (const a of m.agents) {
    const box = $(`#agent-live-${a.name}`);
    if (box) box.innerHTML = agentLive(a);
    const toggle = document.querySelector(`[data-agent-enabled="${a.name}"]`);
    if (toggle) toggle.checked = a.enabled;
  }
  const s = m.llm.stats_24h;
  const models = Object.entries(s.by_model).map(([k, v]) => `${k}: ${v}`).join(" · ") || "—";
  live.innerHTML = `
    <section class="kpis">${kpi("Llamadas LLM (24 h)", s.total, `${s.ok} correctas`)}${kpi("Errores LLM (24 h)", s.errors, s.not_configured ? `${s.not_configured} sin proveedor` : "", s.errors ? "warn" : "")}
      ${kpi("Latencia media", fmtMs(s.avg_ms), "respuestas correctas")}${kpi("Modelo alternativo", s.fallback, "respuestas con fallback")}${kpi("Alertas (24 h)", m.alerts_24h, "emitidas por agentes")}</section>
    <div class="status-line"><span class="status-dot ${m.llm.configured ? "on" : "off"}"></span>Proveedor: ${esc(m.llm.configured ? `${m.llm.provider} · ${m.llm.model}` : "no configurado")} · Modelos usados (24 h): ${esc(models)} · Actualizado ${fmtDate(m.generated_at)}</div>
    <section class="card card-flush"><div class="card-head"><div><h3>Ejecuciones de agentes</h3><p>Últimas ejecuciones manuales, programadas o disparadas por tickets.</p></div></div><div class="table-wrap"><table class="table-compact"><thead><tr><th>Fecha</th><th>Agente</th><th>Origen</th><th>Usuario</th><th>Estado</th><th>Duración</th><th>Resultado / error</th></tr></thead><tbody>
      ${m.runs.map((r) => `<tr><td class="small">${fmtDate(r.started_at)}</td><td>${esc(agentTitles[r.agent] || r.agent)}</td><td>${esc(TRIGGER_LABEL[r.trigger] || r.trigger)}</td><td>${esc(r.actor)}</td>
        <td>${runPill(r.status)}</td><td class="num">${fmtMs(r.duration_ms)}</td><td class="small">${esc(r.error || r.summary || "")}${r.status !== "EN_CURSO" ? ` <button type="button" class="source-link" data-agent-detail="${esc(r.id)}">Detalle</button>` : ""}</td></tr>`).join("")
        || `<tr><td colspan="7">${empty("Sin ejecuciones todavía", "Ejecuta un agente para ver aquí su resultado.", "agents")}</td></tr>`}</tbody></table></div></section>
    <section class="card card-flush"><div class="card-head"><div><h3>Actividad del LLM</h3><p>Solo metadatos: no se guardan claves, prompts, respuestas ni conversaciones.</p></div></div><div class="table-wrap"><table class="table-compact"><thead><tr><th>Fecha</th><th>Origen</th><th>Modelo</th><th>Estado</th><th>Duración</th><th>Error</th></tr></thead><tbody>
      ${m.llm.calls.map((c) => `<tr><td class="small">${fmtDate(c.created_at)}</td><td>${esc(c.source)}</td><td class="mono small">${esc(c.model || "—")}${c.fallback_used ? ' <span class="pill">alternativo</span>' : ""}</td>
        <td><span class="pill ${c.status === "OK" ? "pill-ok" : "st-cancelado"}"><span class="dot"></span>${esc(c.status)}</span></td><td class="num">${fmtMs(c.duration_ms)}</td><td class="small">${esc(c.error || "")}</td></tr>`).join("")
        || `<tr><td colspan="6">${empty("Sin llamadas registradas", "Las consultas al LLM de las últimas 24 h aparecerán aquí.", "assistant")}</td></tr>`}</tbody></table></div></section>`;
}

async function pollMonitor() {
  if (App.page !== "ia" || !$("#agents-live")) { clearInterval(agentsTimer); agentsTimer = null; return; }
  if (document.hidden) return;
  try { renderMonitor(await api("/agents/monitor")); } catch { /* transient: the next tick retries */ }
}

function resultView(result) {
  const cell = (v) => v === null || v === undefined ? "—" : Array.isArray(v) ? v.map((o) => o?.name || o?.number || JSON.stringify(o)).join(", ")
    : typeof v === "object" ? JSON.stringify(v) : String(v);
  const entries = Object.entries(result || {});
  const items = result?.items || [];
  const cols = items.length ? Object.keys(items[0]).filter((k) => !["ticket_id", "reason"].includes(k)) : [];
  return `${entries.filter(([, v]) => v === null || typeof v !== "object").map(([k, v]) => statLine(k, cell(v))).join("")}
    ${entries.filter(([k, v]) => k !== "items" && v && typeof v === "object" && !Array.isArray(v)).map(([k, v]) =>
      `<div class="divider"></div><b class="small">${esc(k)}</b>${Object.entries(v).map(([kk, vv]) => statLine(kk, cell(vv))).join("")}`).join("")}
    ${items.length ? `<div class="table-wrap" style="margin-top:10px"><table class="table-compact"><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>
      ${items.map((i) => `<tr>${cols.map((c) => `<td class="small">${c === "number" && i.ticket_id ? `<a href="#" data-action="open-ticket" data-id="${esc(i.ticket_id)}">${esc(cell(i[c]))}</a>` : esc(cell(i[c]))}</td>`).join("")}</tr>`).join("")}</tbody></table></div>` : ""}`;
}

async function showRun(id) {
  const box = $("#agent-result");
  if (!box) return;
  box.innerHTML = loadingHtml();
  try {
    const r = await api(`/agents/runs/${id}`);
    box.innerHTML = `<section class="card"><div class="card-head"><div><h3>${esc(agentTitles[r.agent] || r.agent)} · ${fmtDate(r.started_at)}</h3>
      <p>${esc(TRIGGER_LABEL[r.trigger] || r.trigger)} · ${esc(r.actor)} · ${fmtMs(r.duration_ms)}</p></div>${runPill(r.status)}</div>
      <p>${esc(r.summary || "")}</p>${r.error ? crit(r.error) : ""}${resultView(r.result)}</section>`;
    box.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) { box.innerHTML = crit(error.message); }
}

function regressionCard(reg) {
  const m = reg.metrics || {};
  const hours = (v) => v == null ? null : `${v} h`;
  const body = reg.status === "trained"
    ? `${statLine("MAE", hours(m.mae_hours), "error absoluto medio")}${statLine("RMSE", hours(m.rmse_hours) ?? "no calculado: reentrene", "raíz del error cuadrático medio")}
      ${statLine("R² (horas)", m.r2_hours ?? "no calculado: reentrene")}${statLine("R² (escala log)", m.r2_log)}${statLine("Mediana del error", hours(m.median_ae_hours))}
      ${statLine("MAE de referencia", hours(m.baseline_mae_hours), "mediana histórica por prioridad")}${statLine("Mejora sobre la referencia", m.improvement_vs_baseline_pct == null ? null : `${m.improvement_vs_baseline_pct} %`)}
      ${statLine("Entrenamiento / evaluación", `${reg.n_train} / ${reg.n_test}`, "tickets, partición temporal 80/20")}
      <p class="small muted">Las horas estimadas se muestran en Riesgo SLA, Simulador, el detalle de cada ticket («Predicción ML») y en los resultados de los agentes de triage y riesgo SLA.</p>`
    : `<p class="muted">${esc(reg.message || "El modelo de regresión aún no está entrenado.")}</p>`;
  return `<section class="card"><div class="card-head"><div><h3>Regresión: tiempo estimado de resolución</h3><p>${esc(reg.algorithm || "")}${reg.version ? ` · versión ${esc(reg.version)}` : ""}</p></div></div>${body}</section>`;
}

function justification(agents) {
  const value = (k, v) => v === null || v === undefined ? "sin datos" : EVAL_LABELS[k]?.[1] === "pct" ? pct(v, 1) : v;
  return `<section class="stack" style="gap:14px"><div class="section-head"><div><h2>Justificación de los agentes</h2>
      <p>Por qué existe cada agente, qué problema resuelve, qué tecnología usa, qué tarea automatiza y cómo se evalúa. Las cifras provienen de los modelos entrenados y del registro de ejecuciones.</p></div></div>
    <div class="justify-grid">${agents.map((a, i) => `<article class="justify"><h4><span class="mono muted">${String(i + 1).padStart(2, "0")}</span> ${esc(a.title)}</h4>
      <dl><div><dt>Por qué</dt><dd>${esc(a.why)}</dd></div><div><dt>Problema</dt><dd>${esc(a.problem)}</dd></div><div><dt>Tecnología</dt><dd>${esc(a.technology)}</dd></div>
      <div><dt>Automatiza</dt><dd>${esc(a.automates)}</dd></div><div><dt>Evaluación</dt><dd>${esc(a.evaluation)}</dd></div><div><dt>Acceso</dt><dd>${esc(a.roles)}</dd></div></dl>
      <div class="divider"></div><div>${Object.entries(a.metrics || {}).map(([k, v]) => statLine(EVAL_LABELS[k]?.[0] || k, value(k, v))).join("")}</div></article>`).join("")}</div></section>`;
}

async function agentRequest(box, path, body, method = "POST") {
  try { return await api(path, { method, body: JSON.stringify(body) }); }
  catch (error) { flash(error.message, true); return null; }
  finally { pollMonitor(); }
}

AiTabs.agentes = async (box) => {
  const o = await api("/agents");
  o.agents.forEach((a) => { agentTitles[a.name] = a.title; });
  box.innerHTML = `<div class="section-head" style="margin-top:0"><div><h2>Agentes</h2><p>${o.agents.length} agentes. Activa o desactiva cada uno, ejecútalo bajo demanda o prográmalo; el estado se actualiza cada ${POLL_MS / 1000} s.</p></div></div>
    <section class="agent-list">${o.agents.map(agentControls).join("")}</section>
    <div id="agent-result"></div>
    <div class="section-head"><div><h2>Monitor</h2><p>Actividad de las últimas 24 horas.</p></div></div>
    <div id="agents-live" class="grid">${loadingHtml()}</div>
    ${regressionCard(o.regression)}${justification(o.agents)}`;

  box.querySelectorAll("[data-agent-run]").forEach((form) => { form.onsubmit = async (e) => {
    e.preventDefault();
    const name = form.dataset.agentRun;
    const fd = new FormData(form);
    const body = {};
    if (fd.get("limit")) body.limit = Number(fd.get("limit"));
    if (fd.get("threshold")) body.threshold = Number(fd.get("threshold"));
    if (fd.get("mode")) body.mode = fd.get("mode");
    if (name === "automation") body.tasks = fd.getAll("tasks");
    if (body.mode === "ejecutar" && !confirm("Se asignarán técnicos a los tickets sin asignar con la regla de negocio de FixIT. ¿Continuar?")) return;
    busy(e.submitter, true, "Ejecutando…");
    const r = await agentRequest(box, `/agents/${name}/run`, body);
    busy(e.submitter, false);
    if (r) { flash(`${agentTitles[name]}: ${r.status === "ERROR" ? r.error : r.summary}`, r.status === "ERROR"); showRun(r.id); }
  }; });
  box.querySelectorAll("[data-agent-schedule]").forEach((form) => { form.onsubmit = async (e) => {
    e.preventDefault();
    if (await agentRequest(box, `/agents/${form.dataset.agentSchedule}`, { schedule_minutes: Number(form.minutes.value) }, "PATCH")) flash("Programación guardada.");
  }; });
  box.querySelectorAll("[data-agent-unschedule]").forEach((btn) => { btn.onclick = async () => {
    if (await agentRequest(box, `/agents/${btn.dataset.agentUnschedule}`, { clear_schedule: true }, "PATCH")) flash("Programación eliminada.");
  }; });
  box.querySelectorAll("[data-agent-enabled]").forEach((input) => { input.onchange = async () => {
    if (!await agentRequest(box, `/agents/${input.dataset.agentEnabled}`, { enabled: input.checked }, "PATCH")) input.checked = !input.checked;
  }; });
  box.addEventListener("click", (e) => {
    const detail = e.target.closest("[data-agent-detail]");
    if (detail) showRun(detail.dataset.agentDetail);
  });

  clearInterval(agentsTimer);
  await pollMonitor();
  agentsTimer = setInterval(pollMonitor, POLL_MS);
};
