"use strict";
/* FixIT web client — core, navigation and operational pages. AI pages live in ai.js. */

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => [...root.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const ROLE_LABEL = { ADMIN: "Administrador", JEFE_TI: "Jefe de TI", TECNICO: "Técnico", USUARIO: "Solicitante" };
const STATE_LABEL = { NUEVO: "Nuevo", ASIGNADO: "Asignado", EN_ATENCION: "En atención", EN_ESPERA: "En espera", RESUELTO: "Resuelto",
  CERRADO: "Cerrado", REABIERTO: "Reabierto", CANCELADO: "Cancelado", ESCALADO: "Escalado" };
const PRIORITY_LABEL = { BAJA: "Baja", MEDIA: "Media", ALTA: "Alta", CRITICA: "Crítica" };
const PRIORITY_COLOR = { BAJA: "var(--seq-2)", MEDIA: "var(--seq-3)", ALTA: "var(--seq-4)", CRITICA: "var(--seq-5)" };
const OPEN_STATES = ["NUEVO", "ASIGNADO", "EN_ATENCION", "EN_ESPERA", "REABIERTO", "ESCALADO"];
const isSupervisor = () => ["ADMIN", "JEFE_TI"].includes(App.me?.role);

const App = { me: null, catalogs: {}, page: null };
const Pages = {};
const Actions = {};
const modal = $("#modal");

/* ---------- Session & API ---------- */
const Session = {
  token: () => localStorage.getItem("fixitToken"),
  refreshToken: () => localStorage.getItem("fixitRefresh"),
  save(result) {
    localStorage.setItem("fixitToken", result.access_token);
    if (result.refresh_token) localStorage.setItem("fixitRefresh", result.refresh_token);
  },
  clear() {
    localStorage.removeItem("fixitToken");
    localStorage.removeItem("fixitRefresh");
    App.me = null;
  },
};

class ApiError extends Error {
  constructor(message, status, data) { super(message); this.status = status; this.data = data; }
}

async function tryRefresh() {
  const refresh = Session.refreshToken();
  if (!refresh) return false;
  try {
    const res = await fetch("/api/auth/refresh", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ refresh_token: refresh }) });
    if (!res.ok) return false;
    Session.save(await res.json());
    return true;
  } catch { return false; }
}

async function request(path, opt = {}, retry = true) {
  const options = { ...opt, headers: new Headers(opt.headers || {}) };
  const token = Session.token();
  if (token) options.headers.set("Authorization", `Bearer ${token}`);
  if (options.body && !(options.body instanceof FormData) && !options.headers.has("Content-Type")) options.headers.set("Content-Type", "application/json");
  let res;
  try {
    res = await fetch(`/api${path}`, options);
  } catch {
    throw new ApiError("No se pudo conectar con el servidor. Revisa tu conexión.", 0);
  }
  if (res.status === 401 && retry && path !== "/auth/login" && await tryRefresh()) return request(path, opt, false);
  if (!res.ok) {
    let data = null;
    try { data = await res.json(); } catch { /* not JSON */ }
    let message = data?.detail || `Error ${res.status}`;
    if (res.status === 422 && Array.isArray(data?.errors)) message = "Revisa los datos: " + data.errors.map((e) => e.msg).slice(0, 3).join("; ");
    if (res.status === 401) {
      Session.clear();
      showLogin();
      message = "Tu sesión expiró. Vuelve a iniciar sesión.";
    }
    if (typeof message !== "string") message = JSON.stringify(message);
    throw new ApiError(message, res.status, data);
  }
  return res;
}

async function api(path, opt = {}) {
  const res = await request(path, opt);
  const type = res.headers.get("content-type") || "";
  return type.includes("application/json") ? res.json() : res;
}

async function apiWithTotal(path) {
  const res = await request(path);
  return { data: await res.json(), total: Number(res.headers.get("X-Total-Count") || 0) };
}

const post = (path, body) => api(path, { method: "POST", body: JSON.stringify(body ?? {}) });

async function download(path, filename) {
  try {
    const res = await request(path);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const link = Object.assign(document.createElement("a"), { href: url, download: filename });
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    flash(`Descarga lista: ${filename}`);
  } catch (error) {
    flash(error.message, true);
  }
}

/* ---------- UI helpers ---------- */
function flash(message, error = false) {
  const zone = $("#flash");
  const item = document.createElement("div");
  item.className = `flash${error ? " error" : ""}`;
  item.setAttribute("role", error ? "alert" : "status");
  item.textContent = message;
  zone.appendChild(item);
  setTimeout(() => item.remove(), error ? 7000 : 4000);
}

function setTitle(title, note = "") {
  $("#page-title").textContent = title;
  $("#page-note").textContent = note;
  document.title = `${title} · FixIT`;
}

const fmtDate = (d) => d ? new Date(d).toLocaleString("es-PE", { dateStyle: "medium", timeStyle: "short" }) : "—";
const fmtDay = (d) => d ? new Date(d).toLocaleDateString("es-PE", { day: "2-digit", month: "short" }) : "—";
function fmtHours(h) {
  if (h === null || h === undefined) return "—";
  if (h < 1) return `${Math.round(h * 60)} min`;
  if (h < 48) return `${h.toFixed(h < 10 ? 1 : 0)} h`;
  return `${(h / 24).toFixed(1)} días`;
}
const pct = (v, d = 0) => (v === null || v === undefined) ? "—" : `${(v * 100).toFixed(d)} %`;

function statePill(code) {
  return `<span class="pill st-${esc(String(code).toLowerCase().replaceAll("_", "-"))}"><span class="dot"></span>${esc(STATE_LABEL[code] || code)}</span>`;
}
function prioBadge(code) {
  return `<span class="prio"><i style="background:${PRIORITY_COLOR[code] || "var(--faint)"}"></i>${esc(PRIORITY_LABEL[code] || code || "—")}</span>`;
}
const synBadge = (flag) => flag ? '<span class="pill" title="Registro del conjunto de datos (prefijo SYN-)">Datos</span>' : "";
function riskBadge(p) {
  const level = p >= 0.6 ? "alto" : p >= 0.3 ? "medio" : "bajo";
  const icon = { alto: "▲", medio: "●", bajo: "▼" }[level];
  return `<span class="risk risk-${level}" title="Probabilidad estimada de incumplir el SLA"><span aria-hidden="true">${icon}</span>${pct(p)} · ${level}</span>`;
}
function slaLeft(ticket) {
  if (!ticket.due_at || !OPEN_STATES.includes(ticket.state)) return "";
  const hours = (new Date(ticket.due_at) - Date.now()) / 3600000;
  return hours < 0 ? `<span class="risk risk-alto">Vencido hace ${fmtHours(-hours)}</span>`
    : `<span class="risk ${hours < 4 ? "risk-medio" : "risk-bajo"}">Vence en ${fmtHours(hours)}</span>`;
}
const empty = (title, text = "") => `<div class="empty"><strong>${esc(title)}</strong>${text ? `<span>${esc(text)}</span>` : ""}</div>`;
const loadingHtml = (text = "Cargando…") => `<div class="loading"><span class="spinner"></span>${esc(text)}</div>`;
const option = (value, label, selected = false) => `<option value="${esc(value)}"${selected ? " selected" : ""}>${esc(label)}</option>`;

function busy(button, on, text) {
  if (!button) return;
  if (on) {
    button.dataset.label = button.innerHTML;
    button.disabled = true;
    button.innerHTML = `<span class="spinner"></span> ${esc(text || "Procesando…")}`;
  } else {
    button.disabled = false;
    if (button.dataset.label) button.innerHTML = button.dataset.label;
  }
}

async function loadCatalogs(force = false) {
  if (!force && App.catalogs.areas) return App.catalogs;
  const [areas, categories, priorities, specialties] = await Promise.all(["areas", "categories", "priorities", "specialties"].map((k) => api(`/catalogs/${k}`)));
  App.catalogs = { areas, categories, priorities, specialties };
  return App.catalogs;
}

/* ---------- Navigation ---------- */
function navItems() {
  const role = App.me.role;
  const groups = [{ title: "Operación", items: [["dashboard", "Panel", "▦"], ["tickets", role === "TECNICO" ? "Mis tickets" : role === "USUARIO" ? "Mis solicitudes" : "Tickets", "▤"]] }];
  if (role === "USUARIO") groups[0].items.push(["newticket", "Nueva solicitud", "＋"]);
  groups[0].items.push(["assistant", "Asistente", "✦"], ["notifications", "Notificaciones", "◉"]);
  if (isSupervisor()) groups.push({ title: "Inteligencia artificial", items: [["ia", "Centro de IA", "◈"]] });
  const manage = [];
  if (role === "ADMIN") manage.push(["admin", "Usuarios y catálogos", "⚙"], ["settings", "Reglas de asignación", "⚖"]);
  if (isSupervisor()) manage.push(["audit", "Auditoría", "◷"], ["reports", "Reportes", "⇩"]);
  if (manage.length) groups.push({ title: "Gestión", items: manage });
  return groups;
}

function renderNav() {
  $("#nav").innerHTML = navItems().map((g) => `<div class="nav-group">${esc(g.title)}</div>` +
    g.items.map(([id, name, icon]) => `<button type="button" data-page="${id}"><span class="nav-icon" aria-hidden="true">${icon}</span><span>${esc(name)}</span></button>`).join("")).join("");
  $("#identity").innerHTML = `<b>${esc(App.me.full_name)}</b><small>${esc(ROLE_LABEL[App.me.role] || App.me.role)}</small>`;
}

function allowedPages() {
  return new Set(navItems().flatMap((g) => g.items.map((i) => i[0])));
}

function go(page, sub = "") {
  const target = `#/${page}${sub ? "/" + sub : ""}`;
  if (location.hash === target) route();
  else location.hash = target;
}

async function route() {
  if (!App.me) return;
  const [, page = "dashboard", sub = ""] = location.hash.split("/");
  const allowed = allowedPages();
  const name = allowed.has(page) && Pages[page] ? page : "dashboard";
  App.page = name;
  $$("#nav button").forEach((b) => b.classList.toggle("active", b.dataset.page === name));
  $("#app").classList.remove("menu-open");
  const content = $("#content");
  content.innerHTML = loadingHtml();
  try {
    await Pages[name](content, sub);
    Charts.mountAll(content);
  } catch (error) {
    console.error(error);
    content.innerHTML = `<div class="banner banner-crit"><span class="ico">⚠</span><div><b>No se pudo cargar esta sección</b>${esc(error.message)}</div></div>`;
  }
}

function showLogin() {
  $("#login").hidden = false;
  $("#app").hidden = true;
}

async function startSession() {
  App.me = await api("/auth/me");
  $("#login").hidden = true;
  $("#app").hidden = false;
  renderNav();
  refreshUnread();
  if (!location.hash || location.hash === "#") location.hash = "#/dashboard";
  else route();
}

async function refreshUnread() {
  try {
    const rows = await api("/notifications");
    const count = rows.filter((n) => !n.read).length;
    const badge = $("#unread");
    badge.hidden = !count;
    badge.textContent = count > 99 ? "99+" : String(count);
  } catch { /* non critical */ }
}

/* ---------- Dashboard ---------- */
function kpi(label, value, note = "", tone = "") {
  return `<article class="kpi ${tone ? "tone-" + tone : ""}"><span>${esc(label)}</span><strong class="num">${esc(value)}</strong>${note ? `<small>${esc(note)}</small>` : ""}</article>`;
}

Pages.dashboard = async (root) => {
  const role = App.me.role;
  const d = await api("/dashboard");
  const c = d.counts || {};
  const openTotal = OPEN_STATES.reduce((s, k) => s + (c[k] || 0), 0);
  if (role === "USUARIO") {
    setTitle(`Hola, ${App.me.full_name.split(" ")[0]}`, "Aquí puedes ver el estado de tus solicitudes");
    const { data: mine } = await apiWithTotal("/tickets?limit=6");
    root.innerHTML = `
      <section class="hero"><div><h2>¿Tienes un problema con tu equipo o sistema?</h2><p>Cuéntanos qué pasa y te asignaremos un técnico especializado. Podrás seguir el avance desde aquí.</p></div>
        <button class="btn" data-page-link="newticket">＋ Nueva solicitud</button></section>
      <section class="kpis">${kpi("Solicitudes abiertas", openTotal, "En proceso")}${kpi("Esperando tu confirmación", c.RESUELTO || 0, "Revisa la solución", c.RESUELTO ? "warn" : "")}
        ${kpi("Cerradas", c.CERRADO || 0, "Solucionadas")}${kpi("Satisfacción del servicio", d.satisfaction ? `${d.satisfaction}/5` : "—", "Promedio de todos los usuarios")}</section>
      <section class="card"><div class="card-head"><div><h2>Mis solicitudes recientes</h2><p>Toca una solicitud para ver el detalle, comentar o calificar.</p></div>
        <button class="btn btn-secondary btn-sm" data-page-link="tickets">Ver todas</button></div>${ticketList(mine)}</section>`;
    return;
  }
  if (role === "TECNICO") {
    setTitle("Mi panel", "Tu cola de trabajo y desempeño");
    const { data: queue } = await apiWithTotal("/tickets?limit=200");
    const pending = queue.filter((t) => OPEN_STATES.includes(t.state)).sort((a, b) => new Date(a.due_at) - new Date(b.due_at));
    const perf = d.technician_performance?.[0];
    root.innerHTML = `
      <section class="kpis">${kpi("Por aceptar", c.ASIGNADO || 0, "Asignados a ti", c.ASIGNADO ? "warn" : "")}${kpi("En atención", c.EN_ATENCION || 0)}
        ${kpi("En espera", c.EN_ESPERA || 0)}${kpi("Vencidos", d.overdue, "Fuera de SLA", d.overdue ? "crit" : "good")}
        ${kpi("Resueltos", (c.RESUELTO || 0) + (c.CERRADO || 0))}${kpi("Resolución media", fmtHours(d.avg_resolution_hours))}</section>
      <section class="card"><div class="card-head"><div><h2>Mi cola por vencimiento</h2><p>Los tickets más urgentes aparecen primero.</p></div></div>
        ${pending.length ? ticketTable(pending.slice(0, 15), { showSla: true }) : empty("No tienes tickets pendientes", "¡Buen trabajo!")}</section>
      ${perf ? `<section class="card"><div class="card-head"><h2>Mi desempeño</h2></div><div class="kpis">${kpi("Asignados", perf.assigned)}${kpi("Resueltos", perf.resolved)}${kpi("Calificación", perf.rating ? `${perf.rating}/5` : "—")}</div></section>` : ""}`;
    return;
  }
  setTitle("Panel de control", "Visión general de la operación de soporte");
  const trendDays = Object.entries(d.trend || {});
  const monthly = Object.entries(d.trend_monthly || {});
  const total = d.total || 1;
  root.innerHTML = `
    <section class="kpis">${kpi("Tickets totales", d.total.toLocaleString("es-PE"))}${kpi("Abiertos", openTotal.toLocaleString("es-PE"), "Nuevos, asignados o en curso")}
      ${kpi("Vencidos", d.overdue, "Abiertos fuera de SLA", d.overdue ? "crit" : "good")}${kpi("Alta / crítica", d.critical.toLocaleString("es-PE"), "Prioridad elevada")}
      ${kpi("Primera atención", fmtHours(d.avg_attention_hours), "Promedio")}${kpi("Resolución", fmtHours(d.avg_resolution_hours), "Promedio")}
      ${kpi("Satisfacción", d.satisfaction ? `${d.satisfaction}/5` : "—", "Calificación media")}</section>
    <section class="grid grid-2">
      <article class="card"><div class="card-head"><div><h3>Tickets creados · últimos 30 días</h3><p>Volumen diario</p></div></div>
        ${Charts.columns({ items: trendDays.map(([k, v]) => ({ label: k, value: v, tip: `${fmtDay(k + "T12:00:00")}\n${v} tickets` })), xLabel: (k) => k.slice(8) + "/" + k.slice(5, 7), height: 220, label: "Tickets por día" })}
        ${Charts.dataTable(["Día", "Tickets"], trendDays)}</article>
      <article class="card"><div class="card-head"><div><h3>Tendencia mensual · 12 meses</h3><p>Tickets creados por mes (el mes en curso está incompleto)</p></div></div>
        ${Charts.line({ labels: monthly.map(([k]) => k), series: [{ name: "Tickets", color: "var(--c1)", values: monthly.map(([, v]) => v) }], height: 220, format: (v) => Charts.fmtNum(v), label: "Tickets por mes" })}
        ${Charts.dataTable(["Mes", "Tickets"], monthly)}</article>
    </section>
    <section class="grid grid-3">
      <article class="card"><div class="card-head"><h3>Por estado</h3></div>${Charts.hbars(Object.entries(d.by_state || {}).map(([k, v]) => ({ label: STATE_LABEL[k] || k, value: v, display: v.toLocaleString("es-PE"), tip: `${STATE_LABEL[k] || k}\n${v} (${pct(v / total, 1)})` })))}</article>
      <article class="card"><div class="card-head"><h3>Por prioridad</h3></div>${Charts.hbars(["BAJA", "MEDIA", "ALTA", "CRITICA"].filter((k) => d.by_priority?.[k] !== undefined).map((k) => ({ label: PRIORITY_LABEL[k], value: d.by_priority[k], color: PRIORITY_COLOR[k], display: d.by_priority[k].toLocaleString("es-PE") })))}</article>
      <article class="card"><div class="card-head"><h3>Por área</h3></div>${Charts.hbars(Object.entries(d.by_area || {}).filter(([, v]) => v).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ label: k, value: v, display: v.toLocaleString("es-PE") })))}</article>
    </section>
    <section class="grid grid-2">
      <article class="card"><div class="card-head"><h3>Por categoría</h3></div>${Charts.hbars(Object.entries(d.by_category || {}).filter(([, v]) => v).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([k, v]) => ({ label: k, value: v, display: v.toLocaleString("es-PE") })))}</article>
      <article class="card"><div class="card-head"><div><h3>Rendimiento de técnicos</h3><p>Tickets asignados, resueltos y calificación</p></div></div>
        ${(d.technician_performance || []).length ? `<div class="table-wrap"><table class="table-compact"><thead><tr><th>Técnico</th><th>Asignados</th><th>Resueltos</th><th>Calificación</th></tr></thead><tbody>
        ${d.technician_performance.sort((a, b) => b.assigned - a.assigned).map((p) => `<tr><td>${esc(p.name)}</td><td class="num">${p.assigned}</td><td class="num">${p.resolved}</td><td class="num">${p.rating ? p.rating + "/5" : "—"}</td></tr>`).join("")}</tbody></table></div>` : empty("Sin técnicos registrados")}
      </article>
    </section>
    <section class="banner banner-info"><span class="ico">◈</span><div><b>Centro de Inteligencia Artificial</b>Predicciones de tiempos, riesgo de SLA, recomendaciones de técnicos y proyección de demanda.
      <div style="margin-top:8px"><button class="btn btn-primary btn-sm" data-page-link="ia">Abrir Centro de IA</button></div></div></section>`;
};

function ticketList(rows) {
  if (!rows.length) return empty("Aún no tienes solicitudes", "Cuando registres una solicitud aparecerá aquí.");
  return `<div class="list">${rows.map((t) => `<div class="list-item clickable" data-action="open-ticket" data-id="${esc(t.id)}" role="button" tabindex="0">
    <div><strong>${esc(t.title)}</strong><div class="small muted">${esc(t.number)} · ${fmtDate(t.created_at)} · ${esc(t.technician?.name || "Buscando técnico")}</div></div>
    <div class="row">${statePill(t.state)}</div></div>`).join("")}</div>`;
}

function ticketTable(rows, opts = {}) {
  if (!rows.length) return empty("No hay tickets con estos filtros");
  return `<div class="table-wrap"><table><thead><tr><th>Ticket</th><th>Solicitud</th><th>Estado</th><th>Prioridad</th>${opts.showSla ? "<th>SLA</th>" : ""}<th>Técnico</th><th>Creado</th></tr></thead><tbody>
    ${rows.map((t) => `<tr class="clickable" data-action="open-ticket" data-id="${esc(t.id)}" tabindex="0"><td><strong class="mono">${esc(t.number)}</strong></td>
      <td><strong>${esc(t.title)}</strong><span class="sub">${esc(t.category?.name || "")} · ${esc(t.area?.name || "")}</span></td><td>${statePill(t.state)}</td><td>${prioBadge(t.priority?.code)}</td>
      ${opts.showSla ? `<td>${slaLeft(t)}</td>` : ""}<td>${esc(t.technician?.name || "Sin asignar")}</td><td class="small">${fmtDate(t.created_at)}</td></tr>`).join("")}
  </tbody></table></div>`;
}

/* ---------- Tickets ---------- */
const ticketFilters = { q: "", state_code: "", priority_code: "", category_id: "", source: "all", offset: 0, limit: 25 };

Pages.tickets = async (root) => {
  const role = App.me.role;
  setTitle(role === "TECNICO" ? "Mis tickets" : role === "USUARIO" ? "Mis solicitudes" : "Tickets", "Busca, filtra y abre cualquier ticket para gestionarlo");
  const cats = await loadCatalogs();
  root.innerHTML = `
    <section class="card"><form id="ticket-filters" class="toolbar">
      <label class="search">Buscar<input name="q" placeholder="Número o título" value="${esc(ticketFilters.q)}"></label>
      <label>Estado<select name="state_code"><option value="">Todos</option>${Object.entries(STATE_LABEL).map(([k, v]) => option(k, v, ticketFilters.state_code === k)).join("")}</select></label>
      <label>Prioridad<select name="priority_code"><option value="">Todas</option>${cats.priorities.map((p) => option(p.code, p.name, ticketFilters.priority_code === p.code)).join("")}</select></label>
      <label>Categoría<select name="category_id"><option value="">Todas</option>${cats.categories.map((c) => option(c.id, c.name, ticketFilters.category_id === c.id)).join("")}</select></label>
      ${isSupervisor() ? `<label>Datos<select name="source">${option("all", "Todos", ticketFilters.source === "all")}${option("real", "Sin prefijo SYN-", ticketFilters.source === "real")}${option("synthetic", "Prefijo SYN-", ticketFilters.source === "synthetic")}</select></label>` : ""}
      <button class="btn btn-primary" type="submit">Aplicar</button>
      ${role === "USUARIO" ? '<button class="btn btn-secondary" type="button" data-page-link="newticket">＋ Nueva solicitud</button>' : ""}
    </form></section>
    <section id="ticket-results">${loadingHtml()}</section>`;
  $("#ticket-filters").onsubmit = (e) => {
    e.preventDefault();
    Object.assign(ticketFilters, Object.fromEntries(new FormData(e.target)), { offset: 0 });
    loadTicketResults();
  };
  await loadTicketResults();
};

async function loadTicketResults() {
  const box = $("#ticket-results");
  if (!box) return;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(ticketFilters)) if (v !== "" && v !== null && !(k === "source" && v === "all")) params.set(k, v);
  box.innerHTML = loadingHtml();
  try {
    const { data, total } = await apiWithTotal(`/tickets?${params}`);
    const from = total ? ticketFilters.offset + 1 : 0, to = ticketFilters.offset + data.length;
    box.innerHTML = `${ticketTable(data, { showSla: App.me.role !== "USUARIO" })}
      <div class="pager"><span class="muted small">${from}–${to} de ${total.toLocaleString("es-PE")}</span>
        <button class="btn btn-secondary btn-sm" data-action="ticket-page" data-dir="-1" ${ticketFilters.offset <= 0 ? "disabled" : ""}>← Anterior</button>
        <button class="btn btn-secondary btn-sm" data-action="ticket-page" data-dir="1" ${to >= total ? "disabled" : ""}>Siguiente →</button></div>`;
  } catch (error) {
    box.innerHTML = `<div class="banner banner-crit"><span class="ico">⚠</span><div>${esc(error.message)}</div></div>`;
  }
}

Actions["ticket-page"] = (el) => {
  ticketFilters.offset = Math.max(0, ticketFilters.offset + Number(el.dataset.dir) * ticketFilters.limit);
  loadTicketResults();
};

Pages.newticket = async (root) => {
  setTitle("Nueva solicitud", "Describe el problema con tus palabras; nosotros nos encargamos del resto");
  const cats = await loadCatalogs();
  root.innerHTML = `
    <section class="card" style="max-width:860px"><div class="card-head"><div><span class="eyebrow">Paso único</span><h2>¿Qué está pasando?</h2>
      <p>Cuanto más claro sea el detalle, más rápido podremos ayudarte.</p></div></div>
      <form id="ticket-form">
        <label>Resumen del problema<input name="title" required minlength="5" maxlength="180" placeholder="Ej.: La impresora del piso 2 no imprime"></label>
        <label>Detalle<textarea name="description" required minlength="10" maxlength="8000" placeholder="¿Qué intentabas hacer? ¿Qué mensaje aparece? ¿Desde cuándo ocurre? ¿Afecta a más personas?"></textarea>
          <span class="hint">No incluyas contraseñas.</span></label>
        <div class="form-grid">
          <label>Tu área<select name="area_id" required>${cats.areas.filter((a) => a.active).map((a) => option(a.id, a.name, a.id === App.me.area_id)).join("")}</select></label>
          <label>Tipo de problema<select name="category_id" required>${cats.categories.filter((c) => c.active).map((c) => option(c.id, c.name)).join("")}</select></label>
          <label class="full">¿Qué tan urgente es?<select name="priority_id">${option("", "No estoy seguro (la definirá el sistema)")}${cats.priorities.map((p) => option(p.id, `${p.name} — atención en máximo ${p.sla_hours} h`)).join("")}</select>
            <span class="hint">Crítica: el trabajo está detenido para varias personas. Baja: es una molestia menor.</span></label>
        </div>
        <div class="row-between"><span class="muted small">Recibirás notificaciones cuando cambie el estado.</span><button class="btn btn-primary" type="submit">Enviar solicitud</button></div>
      </form></section>`;
  $("#ticket-form").onsubmit = async (e) => {
    e.preventDefault();
    const btn = e.submitter;
    const data = Object.fromEntries(new FormData(e.target));
    if (!data.priority_id) delete data.priority_id;
    busy(btn, true, "Enviando…");
    try {
      const result = await post("/tickets", data);
      flash(`Solicitud ${result.number} registrada${result.assigned ? " y asignada a un técnico." : ". Un supervisor la asignará pronto."}`);
      go("tickets");
    } catch (error) {
      flash(error.message, true);
    } finally { busy(btn, false); }
  };
};

/* ---------- Ticket detail ---------- */
async function openTicket(id) {
  modal.showModal();
  $("#modal-content").innerHTML = loadingHtml("Cargando ticket…");
  try {
    const t = await api(`/tickets/${id}`);
    renderTicket(t);
  } catch (error) {
    $("#modal-content").innerHTML = `<div class="modal-head"><h2>No se pudo abrir el ticket</h2><button class="icon-btn" data-action="close-modal" aria-label="Cerrar">✕</button></div><div class="modal-body">${esc(error.message)}</div>`;
  }
}
Actions["open-ticket"] = (el) => openTicket(el.dataset.id);
Actions["close-modal"] = () => modal.close();

function ticketActions(t) {
  const role = App.me.role;
  const isReq = t.requester?.id === App.me.id;
  const isTech = t.technician && t.technician.id === App.me.technician_id;
  const b = [];
  const btn = (action, label, cls = "btn-secondary", extra = "") => `<button class="btn ${cls}" data-action="${action}" data-id="${esc(t.id)}" ${extra}>${label}</button>`;
  if (role === "TECNICO" && isTech) {
    if (t.state === "ASIGNADO") b.push(btn("ticket-accept", "Aceptar e iniciar", "btn-primary"));
    if (t.state === "EN_ATENCION") b.push(btn("ticket-resolve-form", "Registrar solución", "btn-good"), btn("ticket-transition", "Poner en espera", "btn-secondary", 'data-state="EN_ESPERA"'), btn("ticket-transition", "Escalar", "btn-secondary", 'data-state="ESCALADO"'));
    if (["EN_ESPERA", "REABIERTO", "ESCALADO"].includes(t.state)) b.push(btn("ticket-transition", "Retomar atención", "btn-primary", 'data-state="EN_ATENCION"'));
  }
  if ((isReq || isSupervisor()) && t.state === "RESUELTO") b.push(btn("ticket-transition", "Confirmar y cerrar", "btn-good", 'data-state="CERRADO"'), btn("ticket-transition", "No se resolvió: reabrir", "btn-secondary", 'data-state="REABIERTO"'));
  if (isReq && role === "USUARIO" && ["RESUELTO", "CERRADO"].includes(t.state) && !t.rating) b.push(btn("ticket-rate-form", "Calificar atención", "btn-primary"));
  if (isSupervisor() && !["CERRADO", "CANCELADO", "RESUELTO"].includes(t.state)) b.push(btn("ticket-assign-form", t.technician ? "Reasignar" : "Asignar técnico", "btn-primary"));
  if (isSupervisor() && ["NUEVO", "ASIGNADO", "EN_ESPERA", "REABIERTO", "ESCALADO"].includes(t.state)) b.push(btn("ticket-cancel", "Cancelar ticket", "btn-danger"));
  return b.join("");
}

function renderTicket(t) {
  const canSuggest = ["ADMIN", "JEFE_TI", "TECNICO"].includes(App.me.role);
  $("#modal-content").innerHTML = `
    <div class="modal-head"><div><span class="eyebrow">Ticket ${esc(t.number)}</span><h2>${esc(t.title)}</h2>
      <div class="row" style="margin-top:6px">${statePill(t.state)} ${prioBadge(t.priority?.code)} ${synBadge(t.synthetic)} ${slaLeft(t)}</div></div>
      <button class="icon-btn" data-action="close-modal" aria-label="Cerrar">✕</button></div>
    <div class="modal-body">
      <div class="summary-grid">
        <div><span>Solicitante</span><strong>${esc(t.requester?.full_name)}</strong></div>
        <div><span>Técnico</span><strong>${esc(t.technician?.name || "Sin asignar")}</strong></div>
        <div><span>Categoría</span><strong>${esc(t.category?.name)}</strong></div>
        <div><span>Área</span><strong>${esc(t.area?.name)}</strong></div>
        <div><span>Creado</span><strong>${fmtDate(t.created_at)}</strong></div>
        <div><span>Vence (SLA)</span><strong>${fmtDate(t.due_at)}</strong></div>
        ${t.resolved_at ? `<div><span>Resuelto</span><strong>${fmtDate(t.resolved_at)}</strong></div>` : ""}
        ${t.rating ? `<div><span>Calificación</span><strong>${"★".repeat(t.rating)}${"☆".repeat(5 - t.rating)}</strong></div>` : ""}
      </div>
      <div><div class="section-title">Descripción</div><div class="description">${esc(t.description)}</div></div>
      ${(t.diagnosis || t.solution) ? `<div class="grid grid-2"><div class="subpanel"><b>Diagnóstico</b><span>${esc(t.diagnosis || "Pendiente")}</span></div><div class="subpanel"><b>Solución</b><span>${esc(t.solution || "Pendiente")}</span></div></div>` : ""}
      <div class="actions">${ticketActions(t)}</div>
      <div id="ticket-panel"></div>
      <div class="subpanel"><div class="row-between"><div class="section-title">✦ Ayuda de IA</div><span class="muted small">Las respuestas del asistente requieren un proveedor LLM configurado</span></div>
        <div class="actions"><button class="btn btn-secondary btn-sm" data-action="ai-summary" data-id="${esc(t.id)}">Resumir ticket</button>
          ${canSuggest ? `<button class="btn btn-secondary btn-sm" data-action="ai-suggest" data-id="${esc(t.id)}">Sugerir diagnóstico</button>` : ""}
          ${isSupervisor() ? `<button class="btn btn-secondary btn-sm" data-action="ml-ticket" data-id="${esc(t.id)}">Predicción ML</button>` : ""}</div>
        <div id="ai-output"></div></div>
      <div><div class="section-title">Comentarios <span class="pill">${(t.comments || []).length}</span></div>
        <div class="stack" style="margin-top:8px">${(t.comments || []).map((c) => `<div class="comment ${c.internal ? "internal" : ""}"><div class="row-between"><strong>${esc(c.author)}</strong><span class="small muted">${fmtDate(c.created_at)}${c.internal ? " · nota interna" : ""}</span></div><div>${esc(c.body)}</div></div>`).join("") || '<p class="muted">Sin comentarios todavía.</p>'}</div>
        ${["CERRADO", "CANCELADO"].includes(t.state) ? "" : `<form id="comment-form" class="stack" style="margin-top:10px"><textarea name="body" required maxlength="5000" placeholder="Escribe una actualización o pregunta"></textarea>
          <div class="row-between">${["ADMIN", "JEFE_TI", "TECNICO"].includes(App.me.role) ? '<label class="check"><input type="checkbox" name="internal"> Nota interna (no la ve el solicitante)</label>' : "<span></span>"}<button class="btn btn-primary btn-sm" type="submit">Comentar</button></div></form>`}</div>
      <div><div class="section-title">Adjuntos <span class="pill">${(t.attachments || []).length}</span></div>
        <div class="row" style="margin-top:8px">${(t.attachments || []).map((a) => `<button class="source-link" data-action="download-attachment" data-id="${esc(a.id)}" data-name="${esc(a.name)}">⇩ ${esc(a.name)}</button>`).join("") || '<span class="muted">Sin adjuntos.</span>'}</div>
        ${["CERRADO", "CANCELADO"].includes(t.state) ? "" : `<form id="attachment-form" class="row" style="margin-top:10px"><input type="file" name="file" accept="image/png,image/jpeg,application/pdf,text/plain" required style="flex:1"><button class="btn btn-secondary btn-sm" type="submit">Subir evidencia</button></form>`}</div>
      <div><div class="section-title">Historial</div><div class="timeline" style="margin-top:8px">${(t.history || []).map((h) => `<div class="timeline-item"><div><strong>${esc(h.detail)}</strong><div class="small muted">${esc(h.actor)} · ${fmtDate(h.created_at)}</div></div></div>`).join("") || '<p class="muted">Sin eventos.</p>'}</div></div>
    </div>`;
  const commentForm = $("#comment-form");
  if (commentForm) commentForm.onsubmit = async (e) => {
    e.preventDefault();
    const form = new FormData(e.target);
    try {
      await post(`/tickets/${t.id}/comments`, { body: form.get("body"), internal: form.get("internal") === "on" });
      flash("Comentario agregado.");
      openTicket(t.id);
    } catch (error) { flash(error.message, true); }
  };
  const attachmentForm = $("#attachment-form");
  if (attachmentForm) attachmentForm.onsubmit = async (e) => {
    e.preventDefault();
    try {
      await api(`/tickets/${t.id}/attachments`, { method: "POST", body: new FormData(e.target) });
      flash("Archivo adjuntado.");
      openTicket(t.id);
    } catch (error) { flash(error.message, true); }
  };
}

async function afterTicketChange(id, message) {
  flash(message);
  await openTicket(id);
  refreshUnread();
  if (App.page === "tickets") loadTicketResults();
}

Actions["download-attachment"] = (el) => download(`/attachments/${el.dataset.id}`, el.dataset.name);
Actions["ticket-accept"] = async (el) => {
  busy(el, true);
  try { await post(`/tickets/${el.dataset.id}/accept`); await afterTicketChange(el.dataset.id, "Ticket aceptado. ¡A trabajar!"); }
  catch (error) { flash(error.message, true); busy(el, false); }
};
Actions["ticket-transition"] = async (el) => {
  busy(el, true);
  try { await post(`/tickets/${el.dataset.id}/transition`, { state: el.dataset.state }); await afterTicketChange(el.dataset.id, `Estado actualizado: ${STATE_LABEL[el.dataset.state]}.`); }
  catch (error) { flash(error.message, true); busy(el, false); }
};
Actions["ticket-cancel"] = (el) => {
  $("#ticket-panel").innerHTML = `<div class="subpanel"><b>¿Cancelar este ticket?</b><span class="muted">El ticket quedará cerrado como cancelado y no podrá reabrirse.</span>
    <div class="actions"><button class="btn btn-danger btn-sm" data-action="ticket-transition" data-state="CANCELADO" data-id="${esc(el.dataset.id)}">Sí, cancelar</button>
    <button class="btn btn-secondary btn-sm" data-action="clear-panel">No</button></div></div>`;
};
Actions["clear-panel"] = () => { $("#ticket-panel").innerHTML = ""; };
Actions["ticket-resolve-form"] = (el) => {
  const id = el.dataset.id;
  $("#ticket-panel").innerHTML = `<form id="resolve-form" class="subpanel"><b>Registrar solución</b>
    <label>Diagnóstico (causa del problema)<textarea name="diagnosis" maxlength="6000"></textarea></label>
    <label>Solución aplicada<textarea name="solution" required maxlength="6000"></textarea></label>
    <div class="actions"><button class="btn btn-good btn-sm" type="submit">Marcar como resuelto</button><button class="btn btn-secondary btn-sm" type="button" data-action="clear-panel">Cancelar</button></div></form>`;
  $("#resolve-form").onsubmit = async (e) => {
    e.preventDefault();
    try { await post(`/tickets/${id}/transition`, { ...Object.fromEntries(new FormData(e.target)), state: "RESUELTO" }); await afterTicketChange(id, "Ticket resuelto. El solicitante confirmará la solución."); }
    catch (error) { flash(error.message, true); }
  };
};
Actions["ticket-rate-form"] = (el) => {
  const id = el.dataset.id;
  $("#ticket-panel").innerHTML = `<form id="rating-form" class="subpanel"><b>¿Cómo te atendimos?</b>
    <label>Puntuación<select name="score">${[5, 4, 3, 2, 1].map((s) => option(s, `${"★".repeat(s)} ${["", "Muy mala", "Mala", "Regular", "Buena", "Excelente"][s]}`)).join("")}</select></label>
    <label>¿Se solucionó tu problema?<select name="solved">${option("true", "Sí")}${option("false", "No")}</select></label>
    <label>Comentario (opcional)<textarea name="comment" maxlength="2000"></textarea></label>
    <div class="actions"><button class="btn btn-primary btn-sm" type="submit">Enviar calificación</button></div></form>`;
  $("#rating-form").onsubmit = async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target));
    try { await post(`/tickets/${id}/rating`, { score: Number(data.score), solved: data.solved === "true", comment: data.comment || null }); await afterTicketChange(id, "¡Gracias por tu calificación!"); }
    catch (error) { flash(error.message, true); }
  };
};
Actions["ticket-assign-form"] = async (el) => {
  const id = el.dataset.id;
  const techs = await api("/technicians");
  $("#ticket-panel").innerHTML = `<form id="assign-form" class="subpanel"><b>Asignar técnico</b>
    <label>Técnico<select name="technician_id">${option("", "Automático (reglas de asignación)")}${techs.filter((x) => x.available).map((x) => option(x.id, `${x.name} · ${(x.specialties || []).join(", ") || "General"}`)).join("")}</select></label>
    <label>Motivo (opcional)<input name="reason" maxlength="1000"></label>
    <div id="assign-ml" class="small"></div>
    <div class="actions"><button class="btn btn-primary btn-sm" type="submit">Guardar asignación</button>
      <button class="btn btn-secondary btn-sm" type="button" data-action="assign-ml" data-id="${esc(id)}">Ver recomendación ML</button>
      <button class="btn btn-secondary btn-sm" type="button" data-action="clear-panel">Cancelar</button></div></form>`;
  $("#assign-form").onsubmit = async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target));
    if (!data.technician_id) delete data.technician_id;
    if (!data.reason) delete data.reason;
    try { await post(`/tickets/${id}/assign`, data); await afterTicketChange(id, "Asignación registrada."); }
    catch (error) { flash(error.message, true); }
  };
};
Actions["assign-ml"] = async (el) => {
  const box = $("#assign-ml");
  box.innerHTML = loadingHtml("Consultando modelo…");
  try {
    const p = await api(`/ml/tickets/${el.dataset.id}`);
    if (!p.recommendations?.length) { box.innerHTML = '<p class="muted">El modelo no encontró técnicos disponibles compatibles.</p>'; return; }
    box.innerHTML = `<div class="stack">${p.recommendations.map((r, i) => `<div class="row-between"><span><b>${i + 1}. ${esc(r.name)}</b> — ${esc(r.reason)}</span>
      <button type="button" class="btn btn-secondary btn-sm" data-action="pick-tech" data-tech="${esc(r.technician_id)}" data-reason="${esc(`Recomendación ML (${p.model.version}): riesgo SLA ${pct(r.sla_risk)}, tiempo estimado ${r.predicted_hours} h`)}">Elegir</button></div>`).join("")}
      </div>`;
  } catch (error) {
    box.innerHTML = `<p class="muted">${esc(error.message)}</p>`;
  }
};
Actions["pick-tech"] = (el) => {
  const form = $("#assign-form");
  form.technician_id.value = el.dataset.tech;
  form.reason.value = el.dataset.reason;
  flash("Técnico seleccionado. Pulsa «Guardar asignación» para confirmar.");
};

function renderAiResult(box, result) {
  const sources = (result.sources || []).map((s) => `<button class="source-link" data-action="open-ticket" data-id="${esc(s.id)}" title="${esc(s.solution || "")}">${esc(s.number)} · ${esc(s.title)}</button>`).join("");
  box.innerHTML = `<div class="stack" style="margin-top:8px">
    ${result.llm_used ? `<div class="ai-answer">${esc(result.answer)}</div><span class="small muted">Generado por ${esc(result.provider)} · ${esc(result.model)}. Verifica la información antes de actuar.</span>`
      : `<div class="banner ${result.error ? "banner-crit" : "banner-warn"}"><span class="ico">ⓘ</span><div><b>${result.error ? "El LLM no respondió" : "LLM no configurado"}</b>${esc(result.notice)}</div></div>`}
    ${result.notice && result.llm_used ? `<span class="small muted">${esc(result.notice)}</span>` : ""}
    ${sources ? `<div><span class="small muted">Tickets similares encontrados en el historial (búsqueda local):</span><div class="row" style="margin-top:6px">${sources}</div></div>` : ""}</div>`;
}

Actions["ai-summary"] = async (el) => {
  const box = $("#ai-output");
  busy(el, true, "Resumiendo…");
  try { renderAiResult(box, await post(`/llm/tickets/${el.dataset.id}/summary`)); }
  catch (error) { box.innerHTML = `<p class="muted">${esc(error.message)}</p>`; }
  finally { busy(el, false); }
};
Actions["ai-suggest"] = async (el) => {
  const box = $("#ai-output");
  busy(el, true, "Analizando…");
  try { renderAiResult(box, await post(`/llm/tickets/${el.dataset.id}/suggestions`)); }
  catch (error) { box.innerHTML = `<p class="muted">${esc(error.message)}</p>`; }
  finally { busy(el, false); }
};
Actions["ml-ticket"] = async (el) => {
  const box = $("#ai-output");
  busy(el, true, "Calculando…");
  try {
    const p = await api(`/ml/tickets/${el.dataset.id}`);
    box.innerHTML = `<div class="stack" style="margin-top:8px">
      <div class="summary-grid"><div><span>Riesgo de incumplir SLA</span>${riskBadge(p.sla_risk)}</div><div><span>Tiempo total estimado</span><strong>${fmtHours(p.predicted_hours)}</strong></div>
        <div><span>Resolución estimada</span><strong>${fmtDate(p.predicted_resolution_at)}</strong></div>
        ${p.actual ? `<div><span>Resultado real</span><strong>${fmtHours(p.actual.hours)} · ${p.actual.sla_breached ? "incumplió SLA" : "cumplió SLA"}</strong></div>` : ""}</div>
      ${p.actual?.in_training_data ? '<span class="small muted">Este ticket formó parte de los datos de entrenamiento: la comparación con el resultado real no es una validación.</span>' : ""}
      <div><b class="small">Factores que más influyen</b><div>${factorChips(p.factors)}</div></div>
      ${p.recommendations?.length ? `<div><b class="small">Técnicos recomendados</b><ol class="small">${p.recommendations.map((r) => `<li>${esc(r.name)} — ${esc(r.reason)}</li>`).join("")}</ol></div>` : ""}
      <span class="small muted">Modelo ${esc(p.model.version)}</span></div>`;
  } catch (error) {
    box.innerHTML = `<div class="banner banner-warn"><span class="ico">ⓘ</span><div>${esc(error.message)}</div></div>`;
  } finally { busy(el, false); }
};

function factorChips(factors) {
  if (!factors?.length) return '<span class="muted small">Ningún factor se aparta de forma relevante del caso típico.</span>';
  return factors.map((f) => `<span class="chip ${f.direction === "aumenta" ? "up" : "down"}" title="${f.direction === "aumenta" ? "Aumenta" : "Reduce"} el riesgo en ${Math.abs(f.impact * 100).toFixed(0)} puntos">${f.direction === "aumenta" ? "▲" : "▼"} ${esc(f.label)}</span>`).join("");
}

/* ---------- Notifications ---------- */
Pages.notifications = async (root) => {
  setTitle("Notificaciones", "Novedades de tus tickets");
  const rows = await api("/notifications");
  const unread = rows.filter((n) => !n.read);
  root.innerHTML = `<section class="card"><div class="card-head"><div><h2>Centro de actividad</h2><p>${unread.length} sin leer</p></div>
      ${unread.length ? '<button class="btn btn-secondary btn-sm" data-action="read-all">Marcar todas como leídas</button>' : ""}</div>
    <div class="list">${rows.map((n) => `<div class="list-item ${n.read ? "" : "unread"}"><div><strong>${esc(n.title)}</strong><div>${esc(n.body)}</div><div class="small muted">${fmtDate(n.created_at)}</div></div>
      <div class="row">${n.ticket_id ? `<button class="btn btn-secondary btn-sm" data-action="open-ticket" data-id="${esc(n.ticket_id)}">Ver ticket</button>` : ""}
      ${n.read ? "" : `<button class="btn btn-link" data-action="read-one" data-id="${esc(n.id)}">Marcar leída</button>`}</div></div>`).join("") || empty("No tienes notificaciones")}</div></section>`;
};
Actions["read-one"] = async (el) => {
  try { await api(`/notifications/${el.dataset.id}/read`, { method: "PATCH" }); refreshUnread(); route(); } catch (error) { flash(error.message, true); }
};
Actions["read-all"] = async (el) => {
  busy(el, true);
  try {
    const rows = (await api("/notifications")).filter((n) => !n.read);
    for (let i = 0; i < rows.length; i += 10) await Promise.all(rows.slice(i, i + 10).map((n) => api(`/notifications/${n.id}/read`, { method: "PATCH" })));
    flash("Notificaciones marcadas como leídas.");
    refreshUnread();
    route();
  } catch (error) { flash(error.message, true); busy(el, false); }
};

/* ---------- Assistant (shared with the AI hub) ---------- */
const CHAT_PROMPTS = {
  USUARIO: ["Mi computadora está muy lenta, ¿qué puedo revisar?", "¿Cómo va mi última solicitud?", "No puedo conectarme a la VPN"],
  TECNICO: ["Impresora con cola de impresión bloqueada", "¿Qué tickets tengo vencidos?", "Soluciones previas para error de ERP al facturar"],
  SUPERVISOR: ["¿Cuántos tickets críticos abiertos hay?", "Resume la situación de la cola actual", "Problemas más frecuentes con la VPN y cómo se resolvieron"],
};

function chatKey() { return `fixitChat:${App.me.id}`; }
function chatHistory() {
  try { return JSON.parse(sessionStorage.getItem(chatKey()) || "[]"); } catch { return []; }
}
function saveChat(items) {
  try { sessionStorage.setItem(chatKey(), JSON.stringify(items.slice(-40))); } catch { /* storage unavailable */ }
}

async function renderAssistant(root) {
  const status = await api("/llm/status").catch(() => ({ configured: false, message: "No se pudo consultar el estado del asistente." }));
  const prompts = CHAT_PROMPTS[isSupervisor() ? "SUPERVISOR" : App.me.role];
  root.innerHTML = `
    ${status.configured ? `<div class="banner banner-info"><span class="ico">✦</span><div><b>Asistente conectado</b>Proveedor ${esc(status.provider)} · modelo ${esc(status.model)}. Usa el historial de tickets que puedes ver como contexto.</div></div>`
      : `<div class="banner banner-warn"><span class="ico">ⓘ</span><div><b>El asistente LLM no está configurado</b>${esc(status.message || "")} Mientras tanto, la búsqueda en el historial funciona con normalidad y no se simulan respuestas.</div></div>`}
    <section class="grid grid-2" style="grid-template-columns:minmax(0,2fr) minmax(0,1fr)">
      <article class="card chat"><div class="chat-log" id="chat-log"></div>
        <form id="chat-form" class="chat-form"><textarea name="message" required minlength="2" maxlength="2000" placeholder="Escribe tu consulta sobre soporte técnico…"></textarea>
          <div class="stack"><button class="btn btn-primary" type="submit">Enviar</button><button class="btn btn-secondary btn-sm" type="button" data-action="chat-clear">Limpiar</button></div></form></article>
      <aside class="stack">
        <div class="card"><div class="card-head"><h3>Prueba con</h3></div><div class="suggestions">${prompts.map((p) => `<button type="button" data-action="chat-prompt" data-text="${esc(p)}">${esc(p)}</button>`).join("")}</div></div>
        <div class="card"><div class="card-head"><div><h3>Buscar en el historial</h3><p>Búsqueda local por similitud (no usa LLM).</p></div></div>
          <form id="kb-search" class="row"><input name="q" required minlength="2" placeholder="Ej.: VPN no conecta" style="flex:1"><button class="btn btn-secondary" type="submit">Buscar</button></form>
          <div id="kb-results" class="stack" style="margin-top:10px"></div></div>
      </aside>
    </section>`;
  const log = $("#chat-log");
  const draw = () => {
    const items = chatHistory();
    log.innerHTML = items.length ? items.map((m) => {
      const sources = (m.sources || []).map((s) => `<button class="source-link" data-action="open-ticket" data-id="${esc(s.id)}">${esc(s.number)}</button>`).join("");
      return `<div class="msg ${m.kind}">${esc(m.text)}${sources ? `<div class="sources"><span class="small muted">Tickets relacionados:</span>${sources}</div>` : ""}</div>`;
    }).join("") : `<div class="empty"><strong>¿En qué puedo ayudarte?</strong><span>Pregunta sobre problemas técnicos, el estado de tus tickets o soluciones anteriores.</span></div>`;
    log.scrollTop = log.scrollHeight;
  };
  draw();
  const form = $("#chat-form");
  form.message.addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); form.requestSubmit(); } });
  form.onsubmit = async (e) => {
    e.preventDefault();
    const message = form.message.value.trim();
    if (message.length < 2) return;
    const items = chatHistory();
    const history = items.filter((m) => m.kind === "user" || m.kind === "bot").slice(-10).map((m) => ({ role: m.kind === "user" ? "user" : "assistant", content: m.text.slice(0, 6000) }));
    items.push({ kind: "user", text: message });
    saveChat(items);
    draw();
    form.message.value = "";
    const btn = form.querySelector("button[type=submit]");
    busy(btn, true, "Pensando…");
    try {
      const result = await post("/llm/chat", { message, history: history.filter((h, i) => !(i === 0 && h.role === "assistant")) });
      const next = chatHistory();
      if (result.llm_used) next.push({ kind: "bot", text: result.answer, sources: result.sources });
      else next.push({ kind: "notice", text: result.notice, sources: result.sources });
      saveChat(next);
    } catch (error) {
      const next = chatHistory();
      next.push({ kind: "notice", text: `Error: ${error.message}` });
      saveChat(next);
    } finally {
      busy(btn, false);
      draw();
    }
  };
  $("#kb-search").onsubmit = async (e) => {
    e.preventDefault();
    const box = $("#kb-results");
    box.innerHTML = loadingHtml("Buscando…");
    try {
      const r = await api(`/llm/search?q=${encodeURIComponent(e.target.q.value)}`);
      box.innerHTML = r.results.length ? r.results.map((s) => `<div class="list-item clickable" data-action="open-ticket" data-id="${esc(s.id)}" role="button" tabindex="0"><div>
        <strong>${esc(s.number)} · ${esc(s.title)}</strong><div class="small muted">${esc(s.category)} · ${esc(STATE_LABEL[s.state] || s.state)}</div>
        ${s.solution ? `<div class="small">Solución: ${esc(s.solution)}</div>` : ""}</div></div>`).join("") : empty("Sin coincidencias");
    } catch (error) { box.innerHTML = `<p class="muted">${esc(error.message)}</p>`; }
  };
}
Actions["chat-prompt"] = (el) => { const f = $("#chat-form"); f.message.value = el.dataset.text; f.requestSubmit(); };
Actions["chat-clear"] = () => { saveChat([]); route(); };

Pages.assistant = async (root) => {
  setTitle("Asistente de soporte", "Consultas en lenguaje natural y búsqueda en el historial de tickets");
  await renderAssistant(root);
};

/* ---------- Administration ---------- */
Pages.admin = async (root) => {
  setTitle("Usuarios y catálogos", "Gestiona cuentas, técnicos, áreas y categorías");
  const cats = await loadCatalogs(true);
  const [users, techs] = await Promise.all([api("/users"), api("/technicians")]);
  const specIdByName = Object.fromEntries(cats.specialties.map((s) => [s.name, s.id]));
  const candidates = users.filter((u) => u.role === "TECNICO" && !techs.some((t) => t.user_id === u.id));
  const roleSelect = (u) => `<select data-action-change="user-role" data-id="${esc(u.id)}" aria-label="Rol de ${esc(u.full_name)}" ${u.id === App.me.id ? "disabled" : ""}>${Object.entries(ROLE_LABEL).map(([k, v]) => option(k, v, u.role === k)).join("")}</select>`;
  root.innerHTML = `
    <section class="kpis">${kpi("Usuarios", users.length)}${kpi("Activos", users.filter((u) => u.active).length)}${kpi("Técnicos", techs.length)}${kpi("Disponibles", techs.filter((t) => t.available).length)}</section>
    <section class="grid grid-2">
      <article class="card"><div class="card-head"><h3>Crear usuario</h3></div><form id="user-form" class="form-grid">
        <label>Nombre completo<input name="full_name" required minlength="2"></label><label>Correo<input name="email" type="email" required></label>
        <label>Contraseña inicial<input name="password" type="password" required minlength="8"></label>
        <label>Rol<select name="role_code">${Object.entries(ROLE_LABEL).map(([k, v]) => option(k, v, k === "USUARIO")).join("")}</select></label>
        <label class="full">Área<select name="area_id">${option("", "Sin área")}${cats.areas.map((a) => option(a.id, a.name)).join("")}</select></label>
        <div class="full"><button class="btn btn-primary" type="submit">Crear usuario</button></div></form></article>
      <article class="card"><div class="card-head"><h3>Agregar al catálogo</h3></div><form id="catalog-form" class="form-grid">
        <label>Tipo<select name="kind">${option("areas", "Área")}${option("categories", "Categoría")}${option("specialties", "Especialidad")}</select></label>
        <label>Nombre<input name="name" required minlength="2" maxlength="100"></label>
        <label class="full">Descripción<input name="description" maxlength="1000"></label>
        <label class="full">Especialidad requerida (solo categorías)<select name="specialty_id">${option("", "Ninguna")}${cats.specialties.map((s) => option(s.id, s.name)).join("")}</select></label>
        <div class="full"><button class="btn btn-primary" type="submit">Guardar</button></div></form></article>
    </section>
    <section class="card"><div class="card-head"><div><h3>Técnicos</h3><p>Disponibilidad, carga máxima y especialidades usadas por la asignación automática y por el recomendador ML.</p></div></div>
      ${candidates.length ? `<form id="tech-form" class="toolbar" style="margin-bottom:14px"><label>Nuevo perfil técnico<select name="user_id">${candidates.map((u) => option(u.id, u.full_name)).join("")}</select></label>
        <label>Carga máxima<input name="max_load" type="number" min="1" max="100" value="8"></label>
        <label>Especialidades<select name="specialty_ids" multiple size="3">${cats.specialties.map((s) => option(s.id, s.name)).join("")}</select></label>
        <button class="btn btn-primary" type="submit">Crear perfil</button></form>` : '<p class="muted small" style="margin-bottom:10px">Para crear un perfil técnico, primero crea un usuario con rol Técnico.</p>'}
      <div class="table-wrap"><table class="table-compact"><thead><tr><th>Técnico</th><th>Especialidades</th><th>Carga máx.</th><th>Disponible</th><th></th></tr></thead><tbody>
      ${techs.map((t) => `<tr data-tech-row="${esc(t.id)}" data-user="${esc(t.user_id)}"><td><strong>${esc(t.name)}</strong><span class="sub">${esc(t.email)}</span></td>
        <td><select name="specialty_ids" multiple size="3" aria-label="Especialidades">${cats.specialties.map((s) => option(s.id, s.name, (t.specialties || []).map((n) => specIdByName[n]).includes(s.id))).join("")}</select></td>
        <td><input name="max_load" type="number" min="1" max="100" value="${t.max_load}" style="width:80px"></td>
        <td><label class="check"><input type="checkbox" name="available" ${t.available ? "checked" : ""}> Sí</label></td>
        <td><button class="btn btn-secondary btn-sm" data-action="save-tech" data-id="${esc(t.id)}">Guardar</button></td></tr>`).join("") || `<tr><td colspan="5">${empty("Sin técnicos")}</td></tr>`}
      </tbody></table></div></section>
    <section class="card"><div class="card-head"><h3>Usuarios</h3><input id="user-filter" placeholder="Filtrar por nombre o correo" style="max-width:280px"></div>
      <div class="table-wrap"><table class="table-compact"><thead><tr><th>Usuario</th><th>Rol</th><th>Estado</th><th></th></tr></thead><tbody id="user-rows">
      ${users.map((u) => `<tr data-filter="${esc((u.full_name + " " + u.email).toLowerCase())}"><td><strong>${esc(u.full_name)}</strong><span class="sub">${esc(u.email)}</span></td>
        <td>${roleSelect(u)}</td><td>${u.active ? '<span class="pill pill-real">Activo</span>' : '<span class="pill st-cancelado">Inactivo</span>'}</td>
        <td>${u.id === App.me.id ? '<span class="muted small">Tu cuenta</span>' : `<button class="btn btn-secondary btn-sm" data-action="toggle-user" data-id="${esc(u.id)}" data-active="${u.active}">${u.active ? "Desactivar" : "Activar"}</button>`}</td></tr>`).join("")}
      </tbody></table></div></section>`;

  $("#user-filter").oninput = (e) => { const q = e.target.value.toLowerCase(); $$("#user-rows tr").forEach((r) => { r.hidden = !r.dataset.filter.includes(q); }); };
  $("#user-form").onsubmit = async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target));
    if (!data.area_id) delete data.area_id;
    try { await post("/users", data); flash("Usuario creado."); route(); } catch (error) { flash(error.message, true); }
  };
  $("#catalog-form").onsubmit = async (e) => {
    e.preventDefault();
    const data = Object.fromEntries(new FormData(e.target));
    const kind = data.kind;
    delete data.kind;
    if (kind !== "categories" || !data.specialty_id) delete data.specialty_id;
    if (!data.description) delete data.description;
    try { await post(`/catalogs/${kind}`, data); flash("Elemento agregado al catálogo."); App.catalogs = {}; route(); } catch (error) { flash(error.message, true); }
  };
  const techForm = $("#tech-form");
  if (techForm) techForm.onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try { await post("/technicians", { user_id: f.get("user_id"), max_load: Number(f.get("max_load")), available: true, specialty_ids: f.getAll("specialty_ids") }); flash("Perfil técnico creado."); route(); }
    catch (error) { flash(error.message, true); }
  };
};
Actions["save-tech"] = async (el) => {
  const row = el.closest("tr");
  const payload = { user_id: row.dataset.user, max_load: Number(row.querySelector("[name=max_load]").value), available: row.querySelector("[name=available]").checked,
    specialty_ids: [...row.querySelector("[name=specialty_ids]").selectedOptions].map((o) => o.value) };
  busy(el, true, "Guardando");
  try { await api(`/technicians/${el.dataset.id}`, { method: "PATCH", body: JSON.stringify(payload) }); flash("Técnico actualizado."); } catch (error) { flash(error.message, true); }
  finally { busy(el, false); }
};
Actions["toggle-user"] = async (el) => {
  const active = el.dataset.active !== "true";
  try { await api(`/users/${el.dataset.id}`, { method: "PATCH", body: JSON.stringify({ active }) }); flash(active ? "Usuario activado." : "Usuario desactivado."); route(); }
  catch (error) { flash(error.message, true); }
};
const ChangeActions = {
  "user-role": async (el) => {
    try { await api(`/users/${el.dataset.id}`, { method: "PATCH", body: JSON.stringify({ role_code: el.value }) }); flash(`Rol actualizado a ${ROLE_LABEL[el.value]}.`); }
    catch (error) { flash(error.message, true); route(); }
  },
};

/* ---------- Assignment rules ---------- */
const WEIGHT_TEXT = {
  "assignment.rating": ["Calificación de los usuarios", "Favorece a técnicos mejor valorados."],
  "assignment.sla": ["Cumplimiento de SLA", "Favorece a quienes resuelven a tiempo."],
  "assignment.speed": ["Rapidez", "Favorece tiempos de resolución cortos."],
  "assignment.specialty": ["Especialidad", "Peso de tener la especialidad requerida."],
  "assignment.resolved": ["Experiencia", "Favorece a técnicos con más tickets resueltos."],
  "assignment.reopened": ["Penalización por reaperturas", "Resta puntos por tickets reabiertos."],
  "assignment.load_penalty": ["Penalización por carga", "Resta puntos según los tickets abiertos del técnico."],
};
Pages.settings = async (root) => {
  setTitle("Reglas de asignación", "Pesos del algoritmo que elige técnico automáticamente al crear un ticket");
  const rows = await api("/settings");
  const weights = rows.filter((s) => WEIGHT_TEXT[s.key]);
  root.innerHTML = `<div class="banner banner-info"><span class="ico">ⓘ</span><div><b>¿Cómo funciona?</b>Cada técnico disponible y compatible recibe un puntaje ponderado. Valores entre 0 y 1; un valor mayor da más importancia al criterio.
      Estas reglas son deterministas e independientes del recomendador de Machine Learning del Centro de IA.</div></div>
    <form id="settings-form" class="card stack">${weights.map((s) => `<div class="row-between"><div><strong>${esc(WEIGHT_TEXT[s.key][0])}</strong><div class="small muted">${esc(WEIGHT_TEXT[s.key][1])} <span class="mono">${esc(s.key)}</span></div></div>
      <input name="${esc(s.key)}" type="number" min="0" max="1" step="0.01" value="${esc(s.value)}" style="max-width:120px" required></div>`).join('<div class="divider"></div>')}
      <div><button class="btn btn-primary" type="submit">Guardar cambios</button></div></form>`;
  $("#settings-form").onsubmit = async (e) => {
    e.preventDefault();
    const btn = e.submitter;
    busy(btn, true, "Guardando…");
    try {
      for (const [key, value] of new FormData(e.target)) await api(`/settings/${key}`, { method: "PUT", body: JSON.stringify({ value: String(value), description: WEIGHT_TEXT[key]?.[0] }) });
      flash("Reglas actualizadas.");
    } catch (error) { flash(error.message, true); } finally { busy(btn, false); }
  };
};

/* ---------- Audit & reports ---------- */
Pages.audit = async (root) => {
  setTitle("Auditoría", "Últimas 500 operaciones registradas");
  const rows = await api("/audit");
  root.innerHTML = `<section class="card"><div class="card-head"><div><h3>Registro de actividad</h3><p>${rows.length} eventos</p></div><input id="audit-filter" placeholder="Filtrar por acción, módulo o usuario" style="max-width:300px"></div>
    <div class="table-wrap"><table class="table-compact"><thead><tr><th>Fecha</th><th>Usuario</th><th>Acción</th><th>Módulo</th><th>Entidad</th><th>IP</th></tr></thead><tbody id="audit-rows">
    ${rows.map((a) => `<tr data-filter="${esc(`${a.action} ${a.module} ${a.user} ${a.entity}`.toLowerCase())}"><td class="small">${fmtDate(a.created_at)}</td><td>${esc(a.user)}</td><td><strong>${esc(a.action)}</strong></td><td>${esc(a.module)}</td><td class="small">${esc(a.entity)}</td><td class="small mono">${esc(a.ip || "—")}</td></tr>`).join("") || `<tr><td colspan="6">${empty("Sin eventos")}</td></tr>`}
    </tbody></table></div></section>`;
  $("#audit-filter").oninput = (e) => { const q = e.target.value.toLowerCase(); $$("#audit-rows tr").forEach((r) => { r.hidden = !(r.dataset.filter || "").includes(q); }); };
};

Pages.reports = async (root) => {
  setTitle("Reportes", "Exporta la información para análisis o presentaciones");
  const card = (icon, title, text, path, file) => `<article class="card stack"><span class="eyebrow">${icon}</span><h3>${esc(title)}</h3><p class="muted">${esc(text)}</p>
    <div><button class="btn btn-primary" data-action="download" data-path="${esc(path)}" data-file="${esc(file)}">Descargar</button></div></article>`;
  root.innerHTML = `<section class="grid grid-auto">
    ${card("CSV", "Tickets (CSV)", "Datos tabulares para filtrar y analizar.", "/reports/tickets.csv", "fixit-tickets.csv")}
    ${card("Excel", "Tickets (Excel)", "Hoja de cálculo con formato.", "/reports/tickets.xlsx", "fixit-tickets.xlsx")}
    ${card("PDF", "Tickets (PDF)", "Listado listo para compartir.", "/reports/tickets.pdf", "fixit-tickets.pdf")}
    ${card("ML", "Dataset de Machine Learning", "Variables sin fuga de información y objetivos (horas de resolución, incumplimiento SLA). Incluye la columna de origen del registro.", "/ml/dataset.csv", "fixit-ml-dataset.csv")}
  </section>`;
};
Actions.download = (el) => download(el.dataset.path, el.dataset.file);

/* ---------- Global events ---------- */
document.addEventListener("click", (e) => {
  const pageLink = e.target.closest("[data-page-link]");
  if (pageLink) { e.preventDefault(); go(pageLink.dataset.pageLink, pageLink.dataset.sub || ""); return; }
  const navBtn = e.target.closest("#nav [data-page]");
  if (navBtn) { go(navBtn.dataset.page); return; }
  const el = e.target.closest("[data-action]");
  if (el && Actions[el.dataset.action]) {
    if (el.tagName === "A") e.preventDefault();
    Actions[el.dataset.action](el, e);
  }
});
document.addEventListener("keydown", (e) => {
  if ((e.key === "Enter" || e.key === " ") && e.target.matches("[data-action][tabindex]")) { e.preventDefault(); e.target.click(); }
});
document.addEventListener("change", (e) => {
  const el = e.target.closest("[data-action-change]");
  if (el && ChangeActions[el.dataset.actionChange]) ChangeActions[el.dataset.actionChange](el, e);
});
Actions["toggle-menu"] = () => $("#app").classList.toggle("menu-open");
window.addEventListener("hashchange", route);
modal.addEventListener("click", (e) => { if (e.target === modal) modal.close(); });

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.submitter || $("#login-form button");
  const error = $("#login-error");
  error.hidden = true;
  const email = $("#email").value.trim(), password = $("#password").value;
  if (!email || password.length < 8) { error.textContent = "Ingresa tu correo y una contraseña de al menos 8 caracteres."; error.hidden = false; return; }
  busy(btn, true, "Entrando…");
  try {
    const res = await fetch("/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, password }) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(res.status === 401 ? "Correo o contraseña incorrectos." : (typeof data.detail === "string" ? data.detail : "No fue posible iniciar sesión."));
    Session.save(data);
    $("#password").value = "";
    await startSession();
    flash(`Bienvenido/a, ${App.me.full_name}`);
  } catch (err) {
    error.textContent = err.message;
    error.hidden = false;
  } finally { busy(btn, false); }
});

$("#logout").onclick = () => {
  Session.clear();
  $("#content").innerHTML = "";
  location.hash = "";
  showLogin();
};
$("#notify").onclick = () => go("notifications");
$("#show-register").onclick = async () => {
  modal.showModal();
  $("#modal-content").innerHTML = `<div class="modal-head"><div><span class="eyebrow">Solicitante</span><h2>Crear cuenta</h2></div><button class="icon-btn" data-action="close-modal" aria-label="Cerrar">✕</button></div>
    <div class="modal-body"><form id="register-form"><label>Nombre completo<input name="full_name" required minlength="2"></label>
      <label>Correo institucional<input name="email" type="email" required></label><label>Contraseña<input name="password" type="password" minlength="8" required><span class="hint">Mínimo 8 caracteres.</span></label>
      <button class="btn btn-primary" type="submit">Crear cuenta</button></form></div>`;
  $("#register-form").onsubmit = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch("/api/auth/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(Object.fromEntries(new FormData(e.target))) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Revisa los datos ingresados.");
      modal.close();
      flash("Cuenta creada. Ya puedes iniciar sesión.");
    } catch (err) { flash(err.message, true); }
  };
};

(async function boot() {
  if (!Session.token()) { showLogin(); return; }
  try { await startSession(); } catch { Session.clear(); showLogin(); }
})();
