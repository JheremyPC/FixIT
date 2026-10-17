"use strict";
/* FixIT — Machine Learning (ADMIN / JEFE_TI). Every number shown here comes from
 * the backend models (/api/ml/*); nothing is computed or invented in the browser. */

const AI_TABS = [
  ["resumen", "Resumen y entrenamiento"], ["riesgo", "Riesgo SLA"], ["tecnicos", "Técnicos"], ["demanda", "Demanda"],
  ["patrones", "Patrones"], ["simulador", "Simulador"], ["metricas", "Métricas"],
];
const aiFilters = { area_id: "", category_id: "", priority: "", technician_id: "", source: "all" };
const patternFilters = { period: "month", days: "365", area_id: "", category_id: "", priority: "", technician_id: "", source: "all" };
let mlStatusCache = null;

function notTrainedBanner(message) {
  return banner("warn", "Modelo no disponible", message, `<div><button class="btn btn-primary btn-sm" data-page-link="ia" data-sub="resumen">Ir a entrenamiento</button></div>`);
}

async function aiCall(box, fn) {
  try { return await fn(); }
  catch (error) {
    box.innerHTML = error.status === 409 ? notTrainedBanner(error.message) : banner("crit", "", error.message);
    return null;
  }
}

/* #/ia/<tab> renders the ML tabs; #/ia/agentes is the agents page (own nav entry, no ML tabs). */
Pages.ia = async (root, sub) => {
  if (sub === "agentes") {
    setTitle("Agentes y monitor", "Cinco agentes de IA: ejecución, programación, actividad del LLM y evaluación");
    root.innerHTML = `<div id="ai-body" class="grid">${loadingHtml()}</div>`;
  } else {
    const tab = AI_TABS.some(([k]) => k === sub) ? sub : "resumen";
    sub = tab;
    setTitle("Machine Learning", "Modelos predictivos de tiempos, riesgo de SLA, técnicos y demanda");
    root.innerHTML = `<nav class="tabs" aria-label="Secciones de Machine Learning">${AI_TABS.map(([k, v]) => `<button type="button" class="${k === tab ? "active" : ""}" ${k === tab ? 'aria-current="page"' : ""} data-page-link="ia" data-sub="${k}">${esc(v)}</button>`).join("")}</nav>
      <div id="ai-body" class="grid">${loadingHtml()}</div>`;
  }
  const body = $("#ai-body");
  await AiTabs[sub](body);
  Charts.mountAll(body);
};

async function mlStatus(force = false) {
  if (!mlStatusCache || force) mlStatusCache = await api("/ml/status");
  return mlStatusCache;
}

function filterBar(id, cats, techs, values, extra = "") {
  return `<form id="${id}" class="card toolbar" aria-label="Filtros">
    ${extra}
    <label>Área<select name="area_id">${option("", "Todas")}${cats.areas.map((a) => option(a.id, a.name, values.area_id === a.id)).join("")}</select></label>
    <label>Categoría<select name="category_id">${option("", "Todas")}${cats.categories.map((c) => option(c.id, c.name, values.category_id === c.id)).join("")}</select></label>
    <label>Prioridad<select name="priority">${option("", "Todas")}${cats.priorities.map((p) => option(p.code, p.name, values.priority === p.code)).join("")}</select></label>
    <label>Técnico<select name="technician_id">${option("", "Todos")}${techs.map((t) => option(t.id, t.name, values.technician_id === t.id)).join("")}</select></label>
    <label>Datos<select name="source">${option("all", "Todos", values.source === "all")}${option("real", "Sin prefijo SYN-", values.source === "real")}${option("synthetic", "Prefijo SYN-", values.source === "synthetic")}</select></label>
    <button class="btn btn-primary" type="submit">Actualizar</button></form>`;
}

const qs = (obj) => new URLSearchParams(Object.entries(obj).filter(([, v]) => v !== "" && v !== null && v !== undefined)).toString();

const AiTabs = {
  /* ----- Overview & training ----- */
  async resumen(box) {
    const s = await mlStatus(true);
    const meta = s.metadata;
    const ds = s.dataset;
    const modelCard = (key, title, what) => {
      const m = meta?.models?.[key];
      const ok = m?.status === "trained";
      return `<article class="model"><div class="row-between"><h3>${esc(title)}</h3>${m ? `<span class="pill ${ok ? "pill-ok" : "st-en-espera"}"><span class="dot"></span>${ok ? "Entrenado" : "Datos insuficientes"}</span>` : '<span class="pill">Sin entrenar</span>'}</div>
        <p class="muted small">${esc(what)}</p>${ok ? `<span class="headline">${esc(m.headline || "")}</span><span class="small muted">${esc(m.algorithm || "")}</span>` : m ? `<span class="small">${esc(m.message || "")}</span>` : ""}</article>`;
    };
    box.innerHTML = `
      <section class="kpis">${kpi("Tickets", ds.tickets_total.toLocaleString("es-PE"))}
        ${kpi("Procesados en el último entrenamiento", meta ? meta.data.tickets_used.toLocaleString("es-PE") : "—", meta ? `${meta.data.resolved.toLocaleString("es-PE")} resueltos` : "Sin entrenamiento")}
        ${kpi("Último entrenamiento", meta ? fmtDate(meta.trained_at) : "Nunca", meta ? `Versión ${meta.version}` : "")}</section>
      <section class="card"><div class="train-panel"><div><h2 style="font-size:16px">Entrenar modelos</h2><p class="muted small mt-8" style="max-width:72ch">Reentrena todos los modelos con los tickets actuales. Evaluación temporal: el 80 % más antiguo entrena y el 20 % más reciente evalúa.</p></div>
        <form id="train-form"><label class="check"><input type="checkbox" name="include_synthetic" ${meta?.include_synthetic === false ? "" : "checked"}> Incluir tickets con prefijo SYN-</label>
          <button class="btn btn-primary" type="submit" ${s.training_in_progress ? "disabled" : ""}>${icon("play", 15)} ${s.training_in_progress ? "Entrenamiento en curso…" : "Entrenar ahora"}</button></form></div>
        <div id="train-result"></div></section>
      <div class="section-head"><div><h2>Modelos</h2><p>Estado y métrica principal de cada modelo en el último entrenamiento.</p></div>
        <button class="btn btn-secondary btn-sm" data-page-link="ia" data-sub="metricas">Ver métricas detalladas ${icon("arrow", 14)}</button></div>
      <section class="model-grid">
        ${modelCard("resolution", "Tiempo de resolución", "Estima cuántas horas tardará un ticket en resolverse.")}
        ${modelCard("sla_risk", "Riesgo de incumplir SLA", "Probabilidad de que el ticket se resuelva fuera de plazo.")}
        ${modelCard("recommendation", "Recomendación de técnicos", "Ordena técnicos por riesgo y tiempo estimados, especialidad y carga.")}
        ${modelCard("forecast", "Proyección de demanda", "Pronostica el volumen diario de tickets de las próximas 4 semanas.")}
        ${modelCard("priority", "Prioridad sugerida", "Sugiere prioridad a partir del texto, área y categoría.")}
      </section>
      ${s.history?.length ? `<section class="card card-flush"><div class="card-head"><h3>Historial de entrenamientos</h3></div><div class="table-wrap"><table class="table-compact"><thead><tr><th>Versión</th><th>Fecha</th><th>Por</th><th>Tickets</th><th>Resolución</th><th>Riesgo SLA</th></tr></thead><tbody>
        ${s.history.map((h) => `<tr><td class="mono">${esc(h.version)}</td><td class="small">${fmtDate(h.trained_at)}</td><td>${esc(h.trained_by || "—")}</td>
          <td class="num">${(h.tickets || 0).toLocaleString("es-PE")}</td><td class="small">${esc(h.models?.resolution?.headline || h.models?.resolution?.status || "—")}</td><td class="small">${esc(h.models?.sla_risk?.headline || h.models?.sla_risk?.status || "—")}</td></tr>`).join("")}</tbody></table></div></section>` : ""}
      ${ds.tickets_total < 200 ? `<div class="banner banner-info"><span class="ico">${icon("info")}</span><div><b>¿Pocos datos?</b>En un entorno local puedes cargar el conjunto de 5.000 tickets con <span class="mono">python -m app.synthetic import</span> (ver docs/datos-sinteticos.md). Nunca se importa en bases remotas.</div></div>` : ""}`;
    $("#train-form").onsubmit = async (e) => {
      e.preventDefault();
      const btn = e.submitter;
      const out = $("#train-result");
      busy(btn, true, "Entrenando… (puede tardar unos segundos)");
      out.innerHTML = "";
      out.classList.remove("mt-12");
      try {
        const meta2 = await post("/ml/train", { include_synthetic: e.target.include_synthetic.checked });
        const trained = Object.values(meta2.models).filter((m) => m.status === "trained").length;
        flash(`Entrenamiento ${meta2.version} completado: ${trained} de ${Object.keys(meta2.models).length} modelos entrenados.`);
        mlStatusCache = null;
        route();
      } catch (error) {
        out.classList.add("mt-12");
        out.innerHTML = banner("crit", "El entrenamiento falló", error.message);
        busy(btn, false);
      }
    };
  },

  /* ----- Risk ----- */
  async riesgo(box) {
    const [cats, techs] = await Promise.all([loadCatalogs(), api("/technicians")]);
    box.innerHTML = `${filterBar("risk-filters", cats, techs, aiFilters)}<div id="risk-body" class="grid">${loadingHtml("Calculando predicciones…")}</div>`;
    $("#risk-filters").onsubmit = (e) => { e.preventDefault(); Object.assign(aiFilters, Object.fromEntries(new FormData(e.target))); loadRisk(); };
    await loadRisk();
  },

  /* ----- Technicians ----- */
  async tecnicos(box) {
    box.innerHTML = loadingHtml("Calculando recomendaciones…");
    const r = await aiCall(box, () => api("/ml/recommendations?limit=30"));
    if (!r) return;
    const maxLoad = Math.max(...r.workload.map((w) => w.max_load), 1);
    box.innerHTML = `
      <section class="grid grid-2">
        <article class="card"><div class="card-head"><div><h3>Carga actual por técnico</h3><p>Tickets abiertos frente a su capacidad máxima</p></div></div>
          ${Charts.hbars(r.workload.map((w) => ({ label: w.name + (w.available ? "" : " (no disponible)"), value: w.open, max: maxLoad, display: `${w.open}/${w.max_load}`,
            color: w.open >= w.max_load ? "var(--crit)" : w.open / w.max_load >= 0.75 ? "var(--warn)" : "var(--c1)",
            tip: `${w.name}\nAbiertos: ${w.open} de ${w.max_load}\nHistórico: ${w.historical_hours} h promedio\nFuera de SLA: ${pct(w.historical_breach_rate)}` })), { max: maxLoad })}</article>
        <article class="card"><div class="card-head"><div><h3>Desempeño histórico</h3><p>Tiempo medio de resolución (horas) usado por el modelo</p></div></div>
          ${Charts.hbars([...r.workload].sort((a, b) => a.historical_hours - b.historical_hours).map((w) => ({ label: w.name, value: w.historical_hours, display: `${w.historical_hours} h`,
            tip: `${w.name}\nPromedio: ${w.historical_hours} h\nFuera de SLA: ${pct(w.historical_breach_rate)}` })))}</article>
      </section>
      <section class="card card-flush"><div class="card-head"><div><h3>Recomendaciones para la cola abierta</h3><p>Primero los tickets sin técnico, reabiertos o escalados. «Asignar» registra la asignación con el motivo del modelo.</p></div></div>
        ${r.items.length ? `<div class="table-wrap"><table><thead><tr><th>Ticket</th><th>Estado</th><th>Actual</th><th>Mejor opción</th><th>Alternativas</th><th></th></tr></thead><tbody>
        ${r.items.map((it) => {
          const best = it.options[0];
          return `<tr><td><button class="btn btn-link ticket-no" data-action="open-ticket" data-id="${esc(it.id)}">${esc(it.number)}</button><span class="sub">${esc(it.title)} · ${esc(it.category)}</span></td>
            <td>${statePill(it.state)} ${prioBadge(it.priority)}</td>
            <td>${it.current ? `${esc(it.current.name)}<span class="sub">riesgo ${pct(it.current.sla_risk)} · ${fmtHours(it.current.predicted_hours)}</span>` : '<span class="muted">Sin asignar</span>'}</td>
            <td>${best ? `<strong>${esc(best.name)}</strong>${it.better_option ? ' <span class="pill pill-ok">mejora</span>' : ""}<span class="sub">riesgo ${pct(best.sla_risk)} · ${fmtHours(best.predicted_hours)} · carga ${best.open_tickets}/${best.max_load}</span>` : '<span class="muted">Sin candidatos disponibles</span>'}</td>
            <td class="small">${it.options.slice(1).map((o) => `${esc(o.name)} (${pct(o.sla_risk)})`).join("<br>") || "—"}</td>
            <td>${best && (!it.current || best.technician_id !== it.current.technician_id) ? `<button class="btn btn-primary btn-sm" data-action="ml-assign" data-id="${esc(it.id)}" data-tech="${esc(best.technician_id)}" data-reason="${esc(`Recomendación ML (${r.model.version}): ${best.reason}`)}">Asignar</button>` : '<span class="muted small">Ya asignado al mejor</span>'}</td></tr>`;
        }).join("")}</tbody></table></div>` : `<div style="padding:0 20px 20px">${empty("No hay tickets abiertos", "Cuando existan tickets abiertos verás aquí las recomendaciones.", "check")}</div>`}</section>`;
  },

  /* ----- Demand ----- */
  async demanda(box) {
    box.innerHTML = loadingHtml();
    const f = await aiCall(box, () => api("/ml/forecast"));
    if (!f) return;
    const hist = f.history_daily.slice(-90);
    const labels = [...hist.map((h) => h.date), ...f.forecast_daily.map((d) => d.date)];
    const histVals = [...hist.map((h) => h.value), ...f.forecast_daily.map(() => null)];
    const fcVals = [...hist.map((_, i) => (i === hist.length - 1 ? hist[i].value : null)), ...f.forecast_daily.map((d) => d.value)];
    const band = { low: [...hist.map(() => null), ...f.forecast_daily.map((d) => d.low)], high: [...hist.map(() => null), ...f.forecast_daily.map((d) => d.high)], color: "var(--c2)" };
    const m = f.metrics;
    const dayLabel = (d) => `${d.slice(8, 10)}/${d.slice(5, 7)}`;
    box.innerHTML = `
      <section class="kpis">${kpi("Proyección 4 semanas", Math.round(f.forecast_total).toLocaleString("es-PE"), "Tickets esperados")}${kpi("Promedio diario proyectado", (f.forecast_total / f.forecast_daily.length).toFixed(1))}
        ${kpi("MAE (evaluación)", `${m.mae} /día`, `Base estacional ${m.baseline_mae}`)}${kpi("sMAPE", `${m.smape_pct} %`)}${kpi("Mejora vs. base", m.improvement_vs_baseline_pct !== null ? `${m.improvement_vs_baseline_pct} %` : "—", "Menor error es mejor")}</section>
      <section class="card"><div class="card-head"><div><h3>Volumen diario: histórico y proyección</h3><p>Últimos 90 días con datos y próximos ${f.forecast_daily.length} días (banda: intervalo aproximado del 80 %). Datos hasta ${fmtDay(f.data_until + "T12:00:00")}.</p></div></div>
        ${Charts.legend([{ name: "Histórico", color: "var(--c1)" }, { name: "Proyección", color: "var(--c2)", dashed: true }, { name: "Intervalo 80 %", color: "var(--c2)", box: true }])}
        ${Charts.line({ labels, series: [{ name: "Histórico", color: "var(--c1)", values: histVals }, { name: "Proyección", color: "var(--c2)", values: fcVals, dashed: true }], band, marker: hist.length - 1, markerLabel: "último dato", height: 280, xLabel: dayLabel, format: (v) => Charts.fmtNum(v, 1), label: "Histórico y proyección de tickets" })}
        ${Charts.dataTable(["Fecha", "Proyección", "Mínimo", "Máximo"], f.forecast_daily.map((d) => [d.date, d.value, d.low, d.high]), "Ver proyección en tabla")}</section>
      <section class="grid grid-2">
        <article class="card"><div class="card-head"><div><h3>Evaluación fuera de muestra</h3><p>Últimos ${m.holdout_days} días que el modelo no vio: real vs. predicho vs. base estacional</p></div></div>
          ${Charts.legend([{ name: "Real", color: "var(--c1)" }, { name: "Modelo", color: "var(--c2)" }, { name: "Base estacional", color: "var(--c3)", dashed: true }])}
          ${Charts.line({ labels: f.holdout.map((h) => h.date), series: [{ name: "Real", color: "var(--c1)", values: f.holdout.map((h) => h.actual) }, { name: "Modelo", color: "var(--c2)", values: f.holdout.map((h) => h.predicted) }, { name: "Base estacional", color: "var(--c3)", values: f.holdout.map((h) => h.baseline), dashed: true }], height: 240, xLabel: dayLabel, label: "Evaluación del pronóstico" })}
          <p class="small muted">Total real ${m.holdout_total_actual} vs. predicho ${m.holdout_total_predicted}. RMSE ${m.rmse}. ${esc(f.algorithm)}.</p></article>
        <article class="card"><div class="card-head"><div><h3>Tickets por semana</h3><p>Últimas semanas registradas</p></div></div>
          ${Charts.columns({ items: f.history_weekly.slice(-26).map((w) => ({ label: w.week, value: w.value, tip: `Semana del ${fmtDay(w.week + "T12:00:00")}\n${w.value} tickets` })), xLabel: dayLabel, height: 240, label: "Tickets por semana" })}</article>
      </section>
      <section class="card"><div class="card-head"><div><h3>Proyección por categoría</h3><p>Reparto del total proyectado según la participación de cada categoría en los últimos 90 días (derivado, no es un modelo por categoría).</p></div></div>
        ${Charts.hbars(f.by_category.map((c) => ({ label: c.category, value: c.projected, display: `${Math.round(c.projected)} (${pct(c.share)})` })))}</section>`;
  },

  /* ----- Patterns ----- */
  async patrones(box) {
    const [cats, techs] = await Promise.all([loadCatalogs(), api("/technicians")]);
    const extra = `<label>Agrupar por<select name="period">${option("week", "Semana", patternFilters.period === "week")}${option("month", "Mes", patternFilters.period === "month")}${option("day", "Día", patternFilters.period === "day")}</select></label>
      <label>Periodo<select name="days">${[["30", "30 días"], ["90", "90 días"], ["180", "6 meses"], ["365", "12 meses"], ["730", "24 meses"], ["0", "Todo"]].map(([v, l]) => option(v, l, patternFilters.days === v)).join("")}</select></label>`;
    box.innerHTML = `${filterBar("pattern-filters", cats, techs, patternFilters, extra)}<div id="pattern-body" class="grid">${loadingHtml()}</div>`;
    $("#pattern-filters").onsubmit = (e) => { e.preventDefault(); Object.assign(patternFilters, Object.fromEntries(new FormData(e.target))); loadPatterns(); };
    await loadPatterns();
  },

  /* ----- Simulator ----- */
  async simulador(box) {
    const cats = await loadCatalogs();
    box.innerHTML = `<section class="grid grid-2">
      <article class="card"><div class="card-head"><div><h3>Simular un ticket nuevo</h3><p>Obtén prioridad sugerida, tiempo y riesgo estimados y los mejores técnicos antes de registrarlo.</p></div></div>
        <form id="sim-form"><label>Título<input name="title" required minlength="5" maxlength="180" value="La computadora no enciende"></label>
          <label>Descripción<textarea name="description" required minlength="10" maxlength="8000">Al presionar el botón no hay luces ni sonido. Es urgente porque detiene la operación del área.</textarea></label>
          <div class="form-grid"><label>Área<select name="area_id">${cats.areas.map((a) => option(a.id, a.name)).join("")}</select></label>
            <label>Categoría<select name="category_id">${cats.categories.map((c) => option(c.id, c.name, c.name === "Falla de hardware")).join("")}</select></label>
            <label class="full">Prioridad<select name="priority_id">${option("", "Usar la sugerida por el modelo")}${cats.priorities.map((p) => option(p.id, `${p.name} (SLA ${p.sla_hours} h)`)).join("")}</select></label></div>
          <div><button class="btn btn-primary" type="submit">${icon("play", 15)} Calcular predicción</button></div></form></article>
      <article class="card" id="sim-result">${empty("Sin simulación", "Completa el formulario y pulsa «Calcular predicción».", "model")}</article></section>`;
    $("#sim-form").onsubmit = async (e) => {
      e.preventDefault();
      const out = $("#sim-result");
      const data = Object.fromEntries(new FormData(e.target));
      if (!data.priority_id) delete data.priority_id;
      out.innerHTML = loadingHtml("Consultando modelos…");
      const r = await aiCall(out, () => post("/ml/predict", data));
      if (!r) return;
      const probs = r.priority_suggestion?.probabilities || {};
      out.innerHTML = `<div class="stack">
        <div class="card-head"><div><h3>Resultado</h3><p>Modelo ${esc(r.model.version)}</p></div></div>
        ${r.priority_suggestion ? `<div><b class="small">Prioridad sugerida por el texto: ${esc(PRIORITY_LABEL[r.priority_suggestion.code] || r.priority_suggestion.code)}</b>
          ${Charts.hbars(["BAJA", "MEDIA", "ALTA", "CRITICA"].filter((k) => probs[k] !== undefined).map((k) => ({ label: PRIORITY_LABEL[k], value: probs[k], max: 1, display: pct(probs[k]), color: PRIORITY_COLOR[k] })), { max: 1 })}</div>` : '<p class="muted small">El modelo de prioridad no está entrenado.</p>'}
        <div class="summary-grid"><div><span>Prioridad usada</span><strong>${esc(PRIORITY_LABEL[r.priority_used] || r.priority_used)} · SLA ${r.sla_hours} h</strong></div>
          <div><span>Sin técnico asignado</span><strong>${fmtHours(r.without_technician.predicted_hours)}</strong>${riskBadge(r.without_technician.sla_risk)}</div></div>
        <div><b class="small">Técnicos recomendados</b>${r.recommendations.length ? `<div class="table-wrap"><table class="table-compact"><thead><tr><th>#</th><th>Técnico</th><th>Riesgo SLA</th><th>Tiempo</th><th>Carga</th></tr></thead><tbody>
          ${r.recommendations.map((t, i) => `<tr><td>${i + 1}</td><td>${esc(t.name)}${t.at_capacity ? ' <span class="pill st-cancelado">sin capacidad</span>' : ""}</td><td>${riskBadge(t.sla_risk)}</td><td class="num">${fmtHours(t.predicted_hours)}</td><td class="num">${t.open_tickets}/${t.max_load}</td></tr>`).join("")}</tbody></table></div>` : '<p class="muted">No hay técnicos disponibles compatibles.</p>'}</div>
        <div><b class="small">Factores relevantes (sin técnico)</b><div>${factorChips(r.factors)}</div></div></div>`;
    };
  },

  /* ----- Metrics ----- */
  async metricas(box) {
    const s = await mlStatus(true);
    const meta = s.metadata;
    if (!meta) { box.innerHTML = notTrainedBanner("Aún no se ha entrenado ningún modelo."); return; }
    const M = meta.models;
    const stat = (label, value, note = "") => `<div class="stat-line"><span>${esc(label)}${note ? ` <span class="muted small">${esc(note)}</span>` : ""}</span><strong class="num">${esc(value)}</strong></div>`;
    const importance = (m) => m?.importance?.length ? Charts.hbars(m.importance.filter((i) => i.importance > 0).slice(0, 8).map((i) => ({ label: i.label, value: i.importance, display: i.importance.toFixed(3) }))) : "";
    const notTrained = (m) => `<p class="muted">${esc(m?.message || "No entrenado.")}</p>`;
    const res = M.resolution, sla = M.sla_risk, pri = M.priority, fc = M.forecast, rec = M.recommendation;
    box.innerHTML = `
      <section class="card"><div class="card-head"><div><h3>Entrenamiento ${esc(meta.version)}</h3><p>${fmtDate(meta.trained_at)} · ${esc(meta.trained_by || "—")} · ${meta.duration_seconds}s · scikit-learn ${esc(meta.libraries["scikit-learn"])}</p></div>
        <button class="btn btn-secondary btn-sm" data-action="download" data-path="/ml/dataset.csv" data-file="fixit-ml-dataset.csv">Descargar dataset</button></div>
        <p class="small">${esc(meta.split.rule)} Datos: ${meta.data.tickets_used.toLocaleString("es-PE")} tickets (${meta.data.real.toLocaleString("es-PE")} sin prefijo, ${meta.data.synthetic.toLocaleString("es-PE")} con prefijo SYN-) del ${fmtDay(meta.data.first_created)} al ${fmtDay(meta.data.last_created)}.
          Las variables se calculan con la información disponible al crear cada ticket (sin estado, fechas de resolución, diagnóstico, solución ni calificación). La procedencia del conjunto de datos se documenta en docs/datos-sinteticos.md.</p></section>
      <section class="grid grid-2">
        <article class="card"><div class="card-head"><div><h3>Tiempo de resolución</h3><p>${esc(res?.algorithm || "")}</p></div></div>
          ${res?.status === "trained" ? `${stat("MAE", `${res.metrics.mae_hours} h`, "error absoluto medio")}${stat("Mediana del error", `${res.metrics.median_ae_hours} h`)}
            ${stat("MAE de referencia", `${res.metrics.baseline_mae_hours} h`, res.metrics.baseline)}${stat("Mejora", `${res.metrics.improvement_vs_baseline_pct} %`)}
            ${res.metrics.rmse_hours != null ? stat("RMSE", `${res.metrics.rmse_hours} h`, "raíz del error cuadrático medio") : ""}${res.metrics.r2_hours != null ? stat("R² (horas)", res.metrics.r2_hours) : ""}
            ${stat("R² (escala log)", res.metrics.r2_log)}${stat("Predicciones con error ≤ 50 %", pct(res.metrics.within_50pct))}${stat("Entrenamiento / evaluación", `${res.n_train} / ${res.n_test}`)}
            <div class="divider"></div><b class="small">Predicho vs. real (evaluación, escala logarítmica)</b>
            ${Charts.legend(["BAJA", "MEDIA", "ALTA", "CRITICA"].map((k, i) => ({ name: PRIORITY_LABEL[k], color: Charts.color(i), box: true })))}
            ${Charts.scatter({ points: res.scatter.map((p) => ({ x: p.actual, y: p.predicted, group: p.priority, tip: `Real ${fmtHours(p.actual)}\nPredicho ${fmtHours(p.predicted)}\nPrioridad ${PRIORITY_LABEL[p.priority] || p.priority}` })), groups: ["BAJA", "MEDIA", "ALTA", "CRITICA"].map((k, i) => ({ key: k, color: Charts.color(i) })), xTitle: "Horas reales", yTitle: "Horas predichas", height: 300, label: "Predicho frente a real" })}
            ${Charts.dataTable(["Prioridad", "Casos", "MAE (h)", "Mediana real (h)"], res.metrics.per_priority.map((p) => [PRIORITY_LABEL[p.priority] || p.priority, p.n, p.mae_hours, p.median_actual_hours]), "Error por prioridad")}
            <div class="divider"></div><b class="small">Importancia por permutación</b>${importance(res)}` : notTrained(res)}</article>
        <article class="card"><div class="card-head"><div><h3>Riesgo de incumplimiento SLA</h3><p>${esc(sla?.algorithm || "")}</p></div></div>
          ${sla?.status === "trained" ? `${stat("Precisión", sla.metrics.precision, `referencia ${sla.metrics.baseline_precision}`)}${stat("Recall (sensibilidad)", sla.metrics.recall, `referencia ${sla.metrics.baseline_recall}`)}
            ${stat("F1", sla.metrics.f1, `referencia ${sla.metrics.baseline_f1}`)}${stat("ROC AUC", sla.metrics.roc_auc)}${stat("Exactitud", sla.metrics.accuracy)}
            ${stat("Tasa real de incumplimiento (evaluación)", pct(sla.metrics.positive_rate_test, 1))}${stat("Umbral", sla.metrics.threshold)}
            <p class="small muted">Referencia: ${esc(sla.metrics.baseline)}.</p>
            <div class="divider"></div><b class="small">Matriz de confusión (evaluación)</b>
            ${Charts.heat(["Real: cumple", "Real: incumple"], ["Predicho: cumple", "Predicho: incumple"], [[sla.metrics.confusion.tn, sla.metrics.confusion.fp], [sla.metrics.confusion.fn, sla.metrics.confusion.tp]])}
            <b class="small">Calibración: probabilidad predicha vs. tasa observada</b>
            ${Charts.dataTable(["Rango", "Casos", "Predicho", "Observado"], sla.calibration.map((c) => [c.bucket, c.n, pct(c.predicted), pct(c.observed)]), "Ver calibración")}
            <div class="divider"></div><b class="small">Importancia por permutación (AUC)</b>${importance(sla)}` : notTrained(sla)}</article>
      </section>
      <section class="grid grid-3">
        <article class="card"><div class="card-head"><div><h3>Prioridad sugerida</h3><p>${esc(pri?.algorithm || "")}</p></div></div>
          ${pri?.status === "trained" ? `${stat("Exactitud", pri.metrics.accuracy, `referencia ${pri.metrics.baseline_accuracy}`)}${stat("F1 macro", pri.metrics.macro_f1, `referencia ${pri.metrics.baseline_macro_f1}`)}
            ${stat("Precisión macro", pri.metrics.macro_precision)}${stat("Recall macro", pri.metrics.macro_recall)}
            ${Charts.dataTable(["Prioridad", "Precisión", "Recall", "F1", "Casos"], pri.metrics.per_class.map((c) => [PRIORITY_LABEL[c.priority] || c.priority, c.precision, c.recall, c.f1, c.n]), "Métricas por clase")}
            <p class="small muted">Referencia: ${esc(pri.metrics.baseline)}.</p>` : notTrained(pri)}</article>
        <article class="card"><div class="card-head"><div><h3>Pronóstico de demanda</h3><p>${esc(fc?.algorithm || "")}</p></div></div>
          ${fc?.status === "trained" ? `${stat("MAE", `${fc.metrics.mae} tickets/día`)}${stat("RMSE", fc.metrics.rmse)}${stat("sMAPE", `${fc.metrics.smape_pct} %`)}${stat("MAPE", fc.metrics.mape_pct !== null ? `${fc.metrics.mape_pct} %` : "—")}
            ${stat("MAE base estacional", fc.metrics.baseline_mae)}${stat("Mejora vs. base", `${fc.metrics.improvement_vs_baseline_pct} %`)}${stat("Días de evaluación", fc.metrics.holdout_days)}` : notTrained(fc)}</article>
        <article class="card"><div class="card-head"><div><h3>Recomendación de técnicos</h3><p>Backtest observacional</p></div></div>
          ${rec?.status === "trained" ? `${stat("Tickets evaluados", rec.metrics.n)}${stat("Candidatos promedio", rec.metrics.avg_candidates)}${stat("Coincidencia top-1", pct(rec.metrics.top1_match_rate))}${stat("Coincidencia top-3", pct(rec.metrics.top3_match_rate))}
            ${stat("Horas reales si se asignó al recomendado", rec.metrics.avg_hours_when_top1_assigned)}${stat("Horas reales en el resto", rec.metrics.avg_hours_otherwise)}
            ${stat("Incumplimiento si se asignó al recomendado", pct(rec.metrics.breach_rate_when_top1_assigned))}${stat("Incumplimiento en el resto", pct(rec.metrics.breach_rate_otherwise))}
            <p class="small muted">${esc(rec.note)}</p>` : notTrained(rec)}</article>
      </section>`;
  },
};

async function loadRisk() {
  const body = $("#risk-body");
  body.innerHTML = loadingHtml("Calculando predicciones…");
  const r = await aiCall(body, () => api(`/ml/predictions?${qs({ ...aiFilters, source: aiFilters.source === "all" ? "" : aiFilters.source, limit: 100 })}`));
  if (!r) return;
  const s = r.summary;
  body.innerHTML = `
    <section class="kpis">${kpi("Tickets abiertos analizados", s.open)}${kpi("Riesgo alto", s.high_risk, "Probabilidad ≥ 60 %", s.high_risk ? "crit" : "good")}
      ${kpi("Riesgo medio", s.medium_risk ?? 0, "30 – 60 %", s.medium_risk ? "warn" : "")}${kpi("Incumplimientos esperados", s.expected_breaches, "Suma de probabilidades")}
      ${kpi("Ya vencidos", s.overdue, "Hecho, no predicción", s.overdue ? "crit" : "")}${kpi("Tiempo medio estimado", fmtHours(s.avg_predicted_hours))}</section>
    <section class="card card-flush"><div class="card-head"><div><h3>Tickets con mayor riesgo de incumplir el SLA</h3><p>Predicción del modelo ${esc(r.model.version)} con la información disponible al crear cada ticket. Los factores indican cuánto cambia el riesgo frente a un caso típico.</p></div></div>
      ${r.tickets.length ? `<div class="table-wrap"><table><thead><tr><th>Ticket</th><th>Riesgo SLA</th><th>Tiempo estimado</th><th>Factores principales</th><th>Técnico recomendado</th></tr></thead><tbody>
      ${r.tickets.map((t) => `<tr class="clickable" data-action="open-ticket" data-id="${esc(t.id)}" tabindex="0">
        <td><span class="ticket-no">${esc(t.number)}</span><span class="sub">${esc(t.title)}</span><span class="sub">${esc(t.category)} · ${PRIORITY_LABEL[t.priority] || esc(t.priority)} · ${esc(STATE_LABEL[t.state] || t.state)} · ${esc(t.technician || "sin técnico")}</span></td>
        <td>${riskBadge(t.sla_risk)}<div class="meter" style="margin-top:6px"><i style="width:${(t.sla_risk * 100).toFixed(0)}%;background:${t.sla_risk >= 0.6 ? "var(--crit)" : t.sla_risk >= 0.3 ? "var(--warn)" : "var(--good)"}"></i></div>
          ${t.overdue ? '<span class="sub" style="color:var(--crit-ink)">Plazo SLA ya vencido</span>' : `<span class="sub">Vence ${fmtDate(t.due_at)}</span>`}</td>
        <td class="num">${fmtHours(t.predicted_hours)}<span class="sub">Transcurrido ${fmtHours(t.elapsed_hours)} · restante ${fmtHours(t.predicted_remaining_hours)}</span></td>
        <td style="max-width:340px">${factorChips(t.factors)}</td>
        <td>${t.recommended ? `${esc(t.recommended.name)}<span class="sub">riesgo ${pct(t.recommended.sla_risk)} · ${fmtHours(t.recommended.predicted_hours)}</span>` : '<span class="muted">—</span>'}</td></tr>`).join("")}
      </tbody></table></div>` : `<div style="padding:0 20px 20px">${empty("No hay tickets abiertos con estos filtros", "Ajusta los filtros para ver otras predicciones.", "search")}</div>`}</section>`;
}

async function loadPatterns() {
  const body = $("#pattern-body");
  body.innerHTML = loadingHtml();
  let d;
  try { d = await api(`/ml/insights?${qs({ ...patternFilters, source: patternFilters.source === "all" ? "" : patternFilters.source })}`); }
  catch (error) { body.innerHTML = banner("crit", "No se pudieron calcular los patrones", error.message); return; }
  const t = d.totals;
  const periodLabel = (p) => d.period === "month" ? p : `${p.slice(8, 10)}/${p.slice(5, 7)}`;
  const withBreach = d.by_period.filter((p) => p.breach_rate !== null);
  body.innerHTML = `
    <section class="kpis">${kpi("Tickets en el periodo", t.tickets.toLocaleString("es-PE"))}${kpi("Abiertos", t.open)}${kpi("Resolución media", fmtHours(t.avg_resolution_hours))}${kpi("Incumplimiento SLA", pct(t.breach_rate, 1), "", t.breach_rate > 0.25 ? "crit" : "")}</section>
    <section class="grid grid-2">
      <article class="card"><div class="card-head"><div><h3>Tickets creados por ${d.period === "month" ? "mes" : d.period === "week" ? "semana" : "día"}</h3></div></div>
        ${Charts.columns({ items: d.by_period.map((p) => ({ label: p.period, value: p.count, tip: `${p.period}\n${p.count} tickets\nResolución media ${fmtHours(p.avg_resolution_hours)}\nFuera de SLA ${pct(p.breach_rate)}` })), xLabel: periodLabel, height: 240, label: "Tickets por periodo" })}
        ${Charts.dataTable(["Periodo", "Tickets", "Resueltos", "Resolución media (h)", "Fuera de SLA"], d.by_period.map((p) => [p.period, p.count, p.resolved, p.avg_resolution_hours ?? "—", pct(p.breach_rate)]))}</article>
      <article class="card"><div class="card-head"><div><h3>Incumplimiento de SLA por periodo</h3><p>Porcentaje de tickets con resultado conocido que superaron su plazo</p></div></div>
        ${withBreach.length ? Charts.line({ labels: withBreach.map((p) => p.period), series: [{ name: "Fuera de SLA", color: "var(--c8)", values: withBreach.map((p) => +(p.breach_rate * 100).toFixed(1)) }], xLabel: periodLabel, height: 240, format: (v) => `${Charts.fmtNum(v, 1)} %`, label: "Incumplimiento por periodo" }) : empty("Sin datos")}</article>
    </section>
    <section class="grid grid-2">
      <article class="card"><div class="card-head"><div><h3>Categorías</h3><p>Volumen (barra) · tiempo medio y % fuera de SLA en el detalle</p></div></div>
        ${Charts.hbars(d.by_category.map((c) => ({ label: c.name, value: c.count, display: c.count.toLocaleString("es-PE"), tip: `${c.name}\n${c.count} tickets\nResolución media ${fmtHours(c.avg_resolution_hours)}\nFuera de SLA ${pct(c.breach_rate)}` })))}
        ${Charts.dataTable(["Categoría", "Tickets", "Resolución media (h)", "Fuera de SLA"], d.by_category.map((c) => [c.name, c.count, c.avg_resolution_hours ?? "—", pct(c.breach_rate)]))}</article>
      <article class="card"><div class="card-head"><div><h3>Categorías con más incumplimiento</h3><p>% de tickets fuera de SLA</p></div></div>
        ${Charts.hbars([...d.by_category].filter((c) => c.breach_rate !== null).sort((a, b) => b.breach_rate - a.breach_rate).map((c) => ({ label: c.name, value: c.breach_rate, max: 1, display: pct(c.breach_rate), color: "var(--c8)" })), { max: Math.max(0.01, ...d.by_category.map((c) => c.breach_rate || 0)) })}</article>
    </section>
    <section class="grid grid-2">
      <article class="card"><div class="card-head"><div><h3>Prioridades</h3></div></div>
        <div class="table-wrap"><table class="table-compact"><thead><tr><th>Prioridad</th><th>Tickets</th><th>Abiertos</th><th>Resolución media</th><th>Fuera de SLA</th></tr></thead><tbody>
        ${d.by_priority.map((p) => `<tr><td>${prioBadge(p.name)}</td><td class="num">${p.count.toLocaleString("es-PE")}</td><td class="num">${p.open}</td><td class="num">${fmtHours(p.avg_resolution_hours)}</td><td class="num">${pct(p.breach_rate, 1)}</td></tr>`).join("")}</tbody></table></div></article>
      <article class="card"><div class="card-head"><div><h3>Categoría × prioridad</h3><p>Número de tickets</p></div></div>
        ${Charts.heat(d.category_priority.categories, d.category_priority.priorities.map((p) => PRIORITY_LABEL[p] || p), d.category_priority.values)}</article>
    </section>
    <section class="card"><div class="card-head"><div><h3>¿Cuándo llegan los tickets?</h3><p>Día de la semana × hora de creación (UTC)</p></div></div>
      ${Charts.heat(d.weekday_hour.weekdays, [...Array(24).keys()].map((h) => String(h).padStart(2, "0")), d.weekday_hour.values, { hideValues: true })}</section>
    <section class="card"><div class="card-head"><div><h3>Técnicos</h3><p>Desempeño en el periodo filtrado</p></div></div>
      ${d.by_technician.length ? `<div class="table-wrap"><table class="table-compact"><thead><tr><th>Técnico</th><th>Asignados</th><th>Resueltos</th><th>Abiertos</th><th>Resolución media</th><th>Fuera de SLA</th><th>Calificación</th></tr></thead><tbody>
      ${d.by_technician.map((x) => `<tr><td>${esc(x.name)}</td><td class="num">${x.count}</td><td class="num">${x.resolved}</td><td class="num">${x.open}</td><td class="num">${fmtHours(x.avg_resolution_hours)}</td><td class="num">${pct(x.breach_rate, 1)}</td><td class="num">${x.rating ?? "—"}</td></tr>`).join("")}</tbody></table></div>` : empty("Sin técnicos en el periodo")}</section>`;
  Charts.mountAll(body);
}

Actions["ml-assign"] = async (el) => {
  busy(el, true, "Asignando");
  try {
    await post(`/tickets/${el.dataset.id}/assign`, { technician_id: el.dataset.tech, reason: el.dataset.reason.slice(0, 1000) });
    flash("Asignación registrada según la recomendación del modelo.");
    route();
  } catch (error) { flash(error.message, true); busy(el, false); }
};
