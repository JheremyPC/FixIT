const $ = (s) => document.querySelector(s);

const esc = (s) =>
  String(s ?? "").replace(/[&<>"]/g, (c) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;"
  }[c]));

let me = null;
let catalogs = {};

const modal = $("#modal");

function getToken() {
  return localStorage.getItem("fixitToken");
}

function getRefreshToken() {
  return localStorage.getItem("fixitRefresh");
}

function clearSession() {
  localStorage.removeItem("fixitToken");
  localStorage.removeItem("fixitRefresh");
  me = null;
}

function showLogin() {
  const login = $("#login");
  const app = $("#app");

  if (login) login.hidden = false;
  if (app) app.hidden = true;
}

function showApp() {
  const login = $("#login");
  const app = $("#app");

  if (login) login.hidden = true;
  if (app) app.hidden = false;
}

function setIdentity() {
  const identity = $("#identity");

  if (!identity || !me) return;

  identity.innerHTML =
    `<b>${esc(me.full_name)}</b><small>${esc(me.role)}</small>`;
}

async function api(path, opt = {}) {
  const options = { ...opt };
  const headers = new Headers(options.headers || {});
  const token = getToken();

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  if (
    options.body &&
    !(options.body instanceof FormData) &&
    !headers.has("Content-Type")
  ) {
    headers.set("Content-Type", "application/json");
  }

  options.headers = headers;

  const response = await fetch(`/api${path}`, options);

  const contentType = response.headers.get("content-type") || "";
  let data = null;

  if (contentType.includes("application/json")) {
    try {
      data = await response.json();
    } catch {
      data = null;
    }
  } else {
    data = response;
  }

  if (!response.ok) {
    const error = new Error(
      data?.detail || `Error HTTP ${response.status}`
    );

    error.status = response.status;
    error.data = data;

    throw error;
  }

  return data;
}

function flash(msg, error = false) {
  const container = $("#flash");

  if (!container) return;

  container.innerHTML =
    `<div class="flash ${error ? "error" : ""}">${esc(msg)}</div>`;

  setTimeout(() => {
    container.innerHTML = "";
  }, 4500);
}

function title(t, n = "") {
  const pageTitle = $("#page-title");
  const pageNote = $("#page-note");

  if (pageTitle) pageTitle.textContent = t;
  if (pageNote) pageNote.textContent = n;
}

function fmt(d) {
  return d
    ? new Date(d).toLocaleString("es-PE", {
        dateStyle: "short",
        timeStyle: "short"
      })
    : "—";
}

function state(s) {
  const key = String(s ?? "").replaceAll("_", " ");
  const cls = String(s ?? "").toLowerCase().replaceAll("_", "-");
  return `<span class="status-pill status-${esc(cls)}"><span class="status-dot"></span>${esc(key)}</span>`;
}

function nav() {
  if (!me) return;
  const role = me.role;
  const items = [
    ["dashboard", "Panel", "▦"],
    ["tickets", "Tickets", "◫"]
  ];
  if (role === "USUARIO") items.push(["newticket", "Nueva solicitud", "＋"]);
  items.push(["notifications", "Notificaciones", "◉"]);
  if (role === "ADMIN") {
    items.push(["admin", "Administración", "⚙"], ["settings", "Asignación", "◌"]);
  }
  if (["ADMIN", "JEFE_TI"].includes(role)) {
    items.push(["audit", "Auditoría", "◷"], ["reports", "Reportes", "⇩"]);
  }
  const navEl = $("#nav");
  if (!navEl) return;
  navEl.innerHTML = items.map(([id, name, icon]) =>
    `<button type="button" data-page="${id}" aria-label="${esc(name)}"><span class="nav-icon">${icon}</span><span>${esc(name)}</span></button>`
  ).join("");
  navEl.onclick = (e) => {
    const button = e.target.closest("[data-page]");
    if (!button) return;
    go(button.dataset.page);
  };
}

async function init() {
  const token = getToken();

  if (!token) {
    showLogin();
    return;
  }

  try {
    me = await api("/auth/me");

    if (!me?.id) {
      throw new Error("La sesión no es válida.");
    }

    showApp();
    setIdentity();
    nav();

    try {
      await noticeCount();
    } catch (e) {
      console.warn("No se pudo cargar el contador:", e);
    }

    try {
      await dashboard();
    } catch (e) {
      console.error("Error al cargar dashboard:", e);
      flash(
        "Sesión iniciada, pero no se pudo cargar el panel.",
        true
      );
    }
  } catch (error) {
    console.warn("No se pudo restaurar la sesión:", error);
    clearSession();
    showLogin();
  }
}

function logout() {
  clearSession();
  showLogin();

  const content = $("#content");
  const identity = $("#identity");

  if (content) content.innerHTML = "";
  if (identity) identity.innerHTML = "";

  flash("Sesión cerrada.");
}

async function noticeCount() {
  if (!me) return;

  const n = await api("/notifications");

  const unread = $("#unread");

  if (!unread) return;

  unread.textContent = Array.isArray(n)
    ? (n.filter((x) => !x.read).length || "")
    : "";
}

async function go(page) {
  if (!me) {
    showLogin();
    return;
  }

  document
    .querySelectorAll("#nav button")
    .forEach((button) => {
      button.classList.toggle(
        "active",
        button.dataset.page === page
      );
    });

  const pages = {
    dashboard,
    tickets,
    newticket,
    notifications,
    admin,
    settings,
    audit,
    reports
  };

  try {
    await (pages[page] || dashboard)();
  } catch (error) {
    console.error(`Error en página ${page}:`, error);

    if (error.status === 401) {
      clearSession();
      showLogin();
      flash("La sesión ha expirado.", true);
      return;
    }

    flash(
      error.message || "No se pudo cargar la sección.",
      true
    );
  }
}

function bars(values, total) {
  if (!values || typeof values !== "object") return '<p class="muted">Sin datos.</p>';
  const entries = Object.entries(values);
  if (!entries.length) return '<p class="muted">Sin datos.</p>';
  const denominator = Number(total) || entries.reduce((sum, [, value]) => sum + (Number(value) || 0), 0) || 1;
  return `<div class="bar-list">${entries.map(([name, value]) => {
    const numeric = Number(value) || 0;
    const width = Math.max(0, Math.min(100, numeric / denominator * 100));
    return `<div class="bar-row"><div class="bar-label"><span>${esc(name)}</span><strong>${numeric}</strong></div><div class="bar"><i style="width:${width}%"></i></div></div>`;
  }).join("")}</div>`;
}

async function dashboard() {
  title("Panel de control", "Resumen operativo en tiempo real");
  const d = await api("/dashboard");
  const c = d?.counts || {};
  const performance = Array.isArray(d?.technician_performance) ? d.technician_performance : [];
  const content = $("#content");
  if (!content) throw new Error("No se encontró el contenedor del dashboard.");
  const cards = [
    ["Tickets totales", d?.total ?? 0, "Total registrado", "total"],
    ["Nuevos", c.NUEVO ?? 0, "Pendientes de atención", "new"],
    ["En atención", c.EN_ATENCION ?? 0, "Trabajo activo", "active"],
    ["Resueltos", (c.RESUELTO ?? 0) + (c.CERRADO ?? 0), "Solucionados", "done"],
    ["Críticos", d?.critical ?? 0, "Alta prioridad", "critical"],
    ["Vencidos", d?.overdue ?? 0, "Fuera de SLA", "overdue"],
    ["Resolución", `${d?.avg_resolution_hours ?? 0}h`, "Promedio", "time"],
    ["Satisfacción", `${d?.satisfaction || "—"}/5`, "Valoración media", "rating"]
  ];
  content.innerHTML = `
    <section class="kpi-grid">
      ${cards.map(([label, value, note, kind]) => `<article class="kpi-card kpi-${kind}"><div class="kpi-top"><span>${esc(label)}</span><span class="kpi-mark"></span></div><strong>${esc(value)}</strong><small>${esc(note)}</small></article>`).join("")}
    </section>
    <section class="dashboard-grid">
      <article class="panel dashboard-panel"><div class="panel-head"><div><span class="eyebrow">Distribución</span><h2>Tickets por categoría</h2></div><span class="panel-icon">▤</span></div>${bars(d?.by_category, d?.total)}</article>
      <article class="panel dashboard-panel"><div class="panel-head"><div><span class="eyebrow">Prioridad</span><h2>Criticidad</h2></div><span class="panel-icon">◈</span></div>${bars(d?.by_priority, d?.total)}</article>
      <article class="panel dashboard-panel"><div class="panel-head"><div><span class="eyebrow">Operación</span><h2>Por área y estado</h2></div><span class="panel-icon">◎</span></div>${bars(d?.by_area, d?.total)}<div class="section-divider"></div>${bars(d?.by_state, d?.total)}</article>
      <article class="panel dashboard-panel"><div class="panel-head"><div><span class="eyebrow">Equipo</span><h2>${me.role === "TECNICO" ? "Mi desempeño" : "Rendimiento de técnicos"}</h2></div><span class="panel-icon">◌</span></div>${performance.length ? `<div class="performance-list">${performance.map(x => `<div class="performance-row"><div><strong>${esc(x?.name)}</strong><small>${x?.assigned ?? 0} asignados · ${x?.resolved ?? 0} resueltos</small></div><span class="rating-badge">${esc(x?.rating ?? "—")}/5</span></div>`).join("")}</div>` : '<p class="empty-state">Aún no hay datos de rendimiento.</p>'}</article>
    </section>
    <article class="panel trend-panel"><div class="panel-head"><div><span class="eyebrow">Tendencia</span><h2>Evolución temporal</h2></div><span class="panel-icon">⌁</span></div>${bars(d?.trend, d?.total)}</article>
  `;
}

async function tickets() {
  title(me.role === "TECNICO" ? "Mis tickets asignados" : "Tickets", "Seguimiento y atención");
  const rows = await api("/tickets");
  $("#content").innerHTML = `
    <section class="page-toolbar"><div><span class="eyebrow">Gestión operativa</span><h2 class="section-title">${me.role === "TECNICO" ? "Mis tickets asignados" : "Tickets"}</h2></div><div class="toolbar-actions"><label class="search-box"><span>⌕</span><input id="filter" placeholder="Buscar ticket o título"></label>${me.role === "USUARIO" ? `<button type="button" class="primary-action" onclick="go('newticket')">＋ Nueva solicitud</button>` : ""}</div></section>
    <div class="table-card table-wrap"><table><thead><tr><th>Ticket</th><th>Solicitud</th><th>Estado</th><th>Prioridad</th><th>Técnico</th><th>Actualización</th></tr></thead><tbody id="ticket-rows">${Array.isArray(rows) && rows.length ? rows.map(ticketRow).join("") : `<tr><td colspan="6"><div class="empty-state table-empty"><strong>No hay tickets</strong><span>Cuando se registre una solicitud aparecerá aquí.</span></div></td></tr>`}</tbody></table></div>
  `;
  const filter = $("#filter");
  if (filter) filter.oninput = e => { const q = e.target.value.toLowerCase(); document.querySelectorAll(".ticket-row").forEach(row => { row.hidden = !row.textContent.toLowerCase().includes(q); }); };
}

function ticketRow(t) {
  const priorityName = t?.priority?.name || "—";
  return `<tr class="ticket-row" data-ticket-id="${esc(t?.id)}" tabindex="0" role="button"><td><strong class="ticket-number">${esc(t?.number)}</strong></td><td><div class="ticket-title-cell"><strong>${esc(t?.title)}</strong><small>${fmt(t?.created_at)}</small></div></td><td>${state(t?.state)}</td><td><span class="priority-dot" style="background:${esc(t?.priority?.color || "#94a3b8")}"></span>${esc(priorityName)}</td><td>${esc(t?.technician?.name || "Sin asignar")}</td><td class="updated-cell">${fmt(t?.updated_at)}</td></tr>`;
}

async function loadCatalogs() {
  const keys = [
    "areas",
    "categories",
    "priorities",
    "specialties"
  ];

  await Promise.all(
    keys.map(async (key) => {
      catalogs[key] =
        await api("/catalogs/" + key);
    })
  );
}

async function newticket() {
  title("Nueva solicitud", "Registra el problema y el sistema buscará un técnico compatible");
  await loadCatalogs();
  $("#content").innerHTML = `<section class="form-shell"><div class="form-hero"><div><span class="eyebrow">Nueva incidencia</span><h2>Crear solicitud de soporte</h2><p>Completa la información para que FixIT pueda clasificar y asignar correctamente tu solicitud.</p></div><span class="hero-icon">＋</span></div><div class="panel form-panel"><form id="ticket-form"><div class="form-grid"><label>Título<input name="title" placeholder="Ej. No tengo acceso a la impresora" required minlength="5"></label><label>Área<select name="area_id">${(catalogs.areas || []).filter(x => x.active).map(opt).join("")}</select></label><label class="full">Descripción<textarea name="description" placeholder="Describe el problema, impacto y desde cuándo ocurre." required minlength="10"></textarea></label><label>Categoría<select name="category_id">${(catalogs.categories || []).filter(x => x.active).map(opt).join("")}</select></label><label>Prioridad<select name="priority_id"><option value="">Sugerida por el sistema</option>${(catalogs.priorities || []).map(x => `<option value="${esc(x.id)}">${esc(x.name)} · SLA ${esc(x.sla_hours)}h</option>`).join("")}</select></label></div><div class="form-footer"><small>La prioridad puede ajustarse según el impacto conocido.</small><button type="submit" class="primary-action">Crear ticket y buscar técnico</button></div></form></div></section>`;
  $("#ticket-form").onsubmit = async e => { e.preventDefault(); const data = Object.fromEntries(new FormData(e.target)); if (!data.priority_id) delete data.priority_id; try { const result = await api("/tickets", { method: "POST", body: JSON.stringify(data) }); flash(`Ticket ${result.number} creado${result.assigned ? " y asignado automáticamente." : ". Un supervisor deberá asignarlo."}`); await go("tickets"); } catch (error) { flash(error.message, true); } };
}

function opt(x) {
  return `
    <option value="${x.id}">
      ${esc(x.name)}
    </option>
  `;
}

async function openTicket(id) {
  const t = await api("/tickets/" + id);
  const isRequester = t?.requester?.id === me.id;
  const isCurrentTech = !!t?.technician && t.technician.id === me.technician_id;
  let controls = "";
  if (me.role === "TECNICO" && isCurrentTech) {
    if (t.state === "ASIGNADO") controls += `<button type="button" class="primary-action" onclick="acceptTicket('${esc(id)}')">Aceptar e iniciar</button>`;
    if (["EN_ATENCION", "EN_ESPERA"].includes(t.state)) controls += `<button type="button" class="ghost" onclick="transitionTicket('${esc(id)}','EN_ESPERA')">Poner en espera</button><button type="button" class="primary-action" onclick="resolveTicket('${esc(id)}')">Resolver ticket</button>`;
  }
  if (isRequester && t.state === "RESUELTO") controls += `<button type="button" class="primary-action" onclick="transitionTicket('${esc(id)}','CERRADO')">Confirmar y cerrar</button><button type="button" class="danger" onclick="transitionTicket('${esc(id)}','REABIERTO')">Reabrir</button>`;
  if (isRequester && ["RESUELTO", "CERRADO"].includes(t.state) && !t.rating) controls += `<button type="button" class="ghost" onclick="rateTicket('${esc(id)}')">Calificar atención</button>`;
  if (["ADMIN", "JEFE_TI"].includes(me.role)) controls += `<button type="button" class="ghost" onclick="assignTicket('${esc(id)}')">Asignar / reasignar</button>`;
  modal.showModal();
  $("#modal-content").innerHTML = `<div class="modal-head"><div><span class="eyebrow">Detalle del ticket</span><h2>${esc(t.number)} · ${esc(t.title)}</h2></div><button class="modal-close close" type="button" onclick="modal.close()">×</button></div><div class="ticket-summary"><div><span>Estado</span>${state(t.state)}</div><div><span>Prioridad</span><strong>${esc(t.priority?.name || "—")}</strong></div><div><span>Técnico</span><strong>${esc(t.technician?.name || "Sin asignar")}</strong></div></div><div class="modal-description">${esc(t.description)}</div><div class="detail-grid"><div class="detail-card"><span class="eyebrow">Atención técnica</span><h3>Seguimiento</h3><p><b>Diagnóstico</b><br>${esc(t.diagnosis || "Pendiente")}</p><p><b>Solución</b><br>${esc(t.solution || "Pendiente")}</p></div><div class="detail-card"><span class="eyebrow">Fechas</span><h3>Cronología</h3><p>Creado: ${fmt(t.created_at)}</p><p>Vence: ${fmt(t.due_at)}</p><p>Resuelto: ${fmt(t.resolved_at)}</p></div></div><div class="actions modal-actions">${controls}</div><div class="modal-section"><div class="section-heading"><h3>Comentarios</h3><span>${(t.comments || []).length}</span></div><div class="comment-list">${(t.comments || []).map(c => `<div class="comment-item"><div class="comment-meta"><strong>${esc(c.author)}</strong><small>${fmt(c.created_at)}${c.internal ? " · interno" : ""}</small></div><div>${esc(c.body)}</div></div>`).join("") || '<div class="empty-state"><strong>Sin comentarios</strong><span>Aún no hay actualizaciones.</span></div>'}</div><form id="comment-form" class="inline-form"><textarea name="body" placeholder="Escriba una actualización" required></textarea>${["ADMIN", "JEFE_TI", "TECNICO"].includes(me.role) ? `<label class="check-label"><input type="checkbox" name="internal"> Nota interna</label>` : ""}<button type="submit" class="primary-action">Agregar comentario</button></form></div><div class="modal-section"><div class="section-heading"><h3>Historial</h3><span>${(t.history || []).length}</span></div><div class="timeline">${(t.history || []).map(h => `<div class="timeline-item"><span class="timeline-dot"></span><div><strong>${esc(h.event)}</strong><p>${esc(h.detail)}</p><small>${esc(h.actor)} · ${fmt(h.created_at)}</small></div></div>`).join("") || '<div class="empty-state"><strong>Sin historial</strong></div>'}</div></div><div class="modal-section"><div class="section-heading"><h3>Adjuntos</h3><span>${(t.attachments || []).length}</span></div>${(t.attachments || []).map(a => `<a class="attachment-item" href="/api/attachments/${esc(a.id)}" target="_blank" rel="noopener noreferrer">↗ ${esc(a.name)}</a>`).join("") || '<p class="muted">No hay archivos adjuntos.</p>'}<form id="attachment-form" class="attachment-form"><input name="file" type="file" accept="image/png,image/jpeg,application/pdf,text/plain" required><button type="submit" class="ghost">Adjuntar evidencia</button></form></div>`;
  $("#comment-form").onsubmit = e => sendComment(e, id);
  $("#attachment-form").onsubmit = e => sendAttachment(e, id);
}

async function sendComment(e, id) {
  e.preventDefault();

  const form = new FormData(e.target);

  try {
    await api("/tickets/" + id + "/comments", {
      method: "POST",
      body: JSON.stringify({
        body: form.get("body"),
        internal: form.get("internal") === "on"
      })
    });

    await openTicket(id);
    await noticeCount();
  } catch (error) {
    flash(error.message, true);
  }
}

async function sendAttachment(e, id) {
  e.preventDefault();

  try {
    await api("/tickets/" + id + "/attachments", {
      method: "POST",
      body: new FormData(e.target)
    });

    await openTicket(id);
  } catch (error) {
    flash(error.message, true);
  }
}

async function acceptTicket(id) {
  try {
    await api("/tickets/" + id + "/accept", {
      method: "POST"
    });

    flash("Ticket aceptado e iniciado.");
    await openTicket(id);
  } catch (error) {
    flash(error.message, true);
  }
}

async function transitionTicket(id, target) {
  try {
    await api("/tickets/" + id + "/transition", {
      method: "POST",
      body: JSON.stringify({
        state: target
      })
    });

    flash("Estado actualizado.");
    await openTicket(id);
  } catch (error) {
    flash(error.message, true);
  }
}

async function resolveTicket(id) {
  $("#modal-content").insertAdjacentHTML("afterbegin", `<div class="action-overlay-panel"><div class="panel-head"><div><span class="eyebrow">Cierre técnico</span><h3>Registrar solución</h3></div></div><form id="resolve-form"><label>Diagnóstico<textarea name="diagnosis" placeholder="Qué originó el problema"></textarea></label><label>Solución aplicada<textarea name="solution" placeholder="Qué se hizo para resolverlo" required></textarea></label><button type="submit" class="primary-action">Marcar como resuelto</button></form></div>`);
  $("#resolve-form").onsubmit = async e => { e.preventDefault(); const data = Object.fromEntries(new FormData(e.target)); try { await api("/tickets/" + id + "/transition", { method: "POST", body: JSON.stringify({ ...data, state: "RESUELTO" }) }); flash("Ticket resuelto."); await openTicket(id); } catch (error) { flash(error.message, true); } };
}

async function assignTicket(id) {
  const technicians = await api("/technicians");
  $("#modal-content").insertAdjacentHTML("afterbegin", `<div class="action-overlay-panel"><div class="panel-head"><div><span class="eyebrow">Asignación</span><h3>Seleccionar técnico</h3></div></div><form id="assign-form"><label>Técnico<select name="technician_id"><option value="">Seleccionar automáticamente</option>${(technicians || []).filter(t => t.available).map(t => `<option value="${esc(t.id)}">${esc(t.name)} · ${esc((t.specialties || []).join(", ") || "General")}</option>`).join("")}</select></label><label>Motivo<textarea name="reason" placeholder="Opcional"></textarea></label><button type="submit" class="primary-action">Registrar asignación</button></form></div>`);
  $("#assign-form").onsubmit = async e => { e.preventDefault(); const data = Object.fromEntries(new FormData(e.target)); if (!data.technician_id) delete data.technician_id; try { await api("/tickets/" + id + "/assign", { method: "POST", body: JSON.stringify(data) }); flash("Asignación registrada."); await openTicket(id); } catch (error) { flash(error.message, true); } };
}

async function rateTicket(id) {
  $("#modal-content").insertAdjacentHTML("afterbegin", `<div class="action-overlay-panel"><div class="panel-head"><div><span class="eyebrow">Satisfacción</span><h3>Calificar atención</h3></div></div><form id="rating-form"><label>Puntuación<select name="score"><option value="5">5 — Excelente</option><option value="4">4 — Buena</option><option value="3">3 — Regular</option><option value="2">2 — Deficiente</option><option value="1">1 — Muy deficiente</option></select></label><label>¿Se solucionó el problema?<select name="solved"><option value="true">Sí</option><option value="false">No</option></select></label><label>Comentario<textarea name="comment" placeholder="Cuéntanos cómo fue la atención"></textarea></label><button type="submit" class="primary-action">Enviar calificación</button></form></div>`);
  $("#rating-form").onsubmit = async e => { e.preventDefault(); const data = Object.fromEntries(new FormData(e.target)); data.score = Number(data.score); data.solved = data.solved === "true"; try { await api("/tickets/" + id + "/rating", { method: "POST", body: JSON.stringify(data) }); flash("Gracias por calificar la atención."); await openTicket(id); } catch (error) { flash(error.message, true); } };
}

async function notifications() {
  title("Notificaciones", "Eventos relevantes de sus tickets");
  const rows = await api("/notifications");
  $("#content").innerHTML = `<section class="page-toolbar"><div><span class="eyebrow">Centro de actividad</span><h2 class="section-title">Notificaciones</h2></div></section><div class="notification-list">${(rows || []).map(n => `<article class="notification-card ${n.read ? "read" : "unread"}"><div class="notification-mark">${n.read ? "✓" : "•"}</div><div class="notification-body"><div class="notification-top"><strong>${esc(n.title)}</strong>${!n.read ? '<span class="new-badge">Nueva</span>' : ''}</div><p>${esc(n.body)}</p><small>${fmt(n.created_at)}</small>${!n.read ? `<button type="button" class="ghost notification-action" onclick="markRead('${esc(n.id)}')">Marcar como leída</button>` : ''}</div></article>`).join("") || '<div class="empty-state large-empty"><strong>No tienes notificaciones</strong><span>Te mostraremos aquí los eventos importantes.</span></div>'}</div>`;
}

async function markRead(id) {
  try {
    await api("/notifications/" + id + "/read", {
      method: "PATCH"
    });

    await noticeCount();
    await notifications();
  } catch (error) {
    flash(error.message, true);
  }
}

async function admin() {
  title("Administración", "Usuarios, técnicos y catálogos");
  await loadCatalogs();
  const [users, technicians] = await Promise.all([api("/users"), api("/technicians")]);
  const userCount = (users || []).length;
  const techCount = (technicians || []).length;
  const activeCount = (users || []).filter(u => u.active).length;
  $("#content").innerHTML = `<section class="admin-overview"><article class="summary-card"><span>Usuarios</span><strong>${userCount}</strong><small>Total registrado</small></article><article class="summary-card"><span>Técnicos</span><strong>${techCount}</strong><small>Perfiles operativos</small></article><article class="summary-card"><span>Activos</span><strong>${activeCount}</strong><small>Usuarios habilitados</small></article></section><div class="admin-grid"><article class="panel admin-form-card"><div class="panel-head"><div><span class="eyebrow">Acceso</span><h2>Crear usuario</h2></div></div><form id="user-form"><label>Nombre<input name="full_name" required></label><label>Correo<input type="email" name="email" required></label><label>Contraseña<input type="password" name="password" minlength="8" required></label><label>Rol<select name="role_code"><option value="USUARIO">USUARIO</option><option value="TECNICO">TECNICO</option><option value="JEFE_TI">JEFE_TI</option><option value="ADMIN">ADMIN</option></select></label><button type="submit" class="primary-action">Crear usuario</button></form></article><article class="panel admin-form-card"><div class="panel-head"><div><span class="eyebrow">Catálogos</span><h2>Agregar elemento</h2></div></div><form id="catalog-form"><label>Tipo<select name="kind"><option value="areas">Área</option><option value="categories">Categoría</option><option value="specialties">Especialidad</option></select></label><label>Nombre<input name="name" required></label><label>Descripción<textarea name="description"></textarea></label><label>Especialidad de categoría<select name="specialty_id"><option value="">No requerida</option>${(catalogs.specialties || []).map(opt).join("")}</select></label><button type="submit" class="primary-action">Guardar elemento</button></form></article></div><article class="panel admin-form-card technician-card"><div class="panel-head"><div><span class="eyebrow">Equipo</span><h2>Crear perfil técnico</h2></div></div><form id="tech-form" class="form-grid"><label>Usuario técnico<select name="user_id">${(users || []).filter(u => u.role === "TECNICO" && !(technicians || []).some(t => t.user_id === u.id)).map(u => `<option value="${esc(u.id)}">${esc(u.full_name)}</option>`).join("")}</select></label><label>Carga máxima<input type="number" name="max_load" value="8" min="1"></label><label class="full">Especialidades<select name="specialty_ids" multiple size="4">${(catalogs.specialties || []).map(opt).join("")}</select></label><div class="full"><button type="submit" class="primary-action">Crear perfil técnico</button></div></form></article><div class="table-card table-wrap"><table><thead><tr><th>Usuario</th><th>Correo</th><th>Rol</th><th>Estado</th></tr></thead><tbody>${(users || []).map(u => `<tr><td><strong>${esc(u.full_name)}</strong></td><td>${esc(u.email)}</td><td><span class="role-badge">${esc(u.role)}</span></td><td><span class="state-active ${u.active ? "on" : "off"}">${u.active ? "Activo" : "Inactivo"}</span></td></tr>`).join("")}</tbody></table></div>`;
  $("#user-form").onsubmit = e => createUser(e);
  $("#catalog-form").onsubmit = e => createCatalog(e);
  $("#tech-form").onsubmit = e => createTech(e);
}

async function createUser(e) {
  e.preventDefault();

  try {
    await api("/users", {
      method: "POST",
      body: JSON.stringify(
        Object.fromEntries(
          new FormData(e.target)
        )
      )
    });

    flash("Usuario creado.");
    await admin();
  } catch (error) {
    flash(error.message, true);
  }
}

async function createCatalog(e) {
  e.preventDefault();

  const data =
    Object.fromEntries(
      new FormData(e.target)
    );

  const kind = data.kind;

  delete data.kind;

  if (
    kind !== "categories" ||
    !data.specialty_id
  ) {
    delete data.specialty_id;
  }

  try {
    await api("/catalogs/" + kind, {
      method: "POST",
      body: JSON.stringify(data)
    });

    await loadCatalogs();

    flash("Catálogo creado.");
    await admin();
  } catch (error) {
    flash(error.message, true);
  }
}

async function createTech(e) {
  e.preventDefault();

  const form = new FormData(e.target);

  const data = {
    user_id: form.get("user_id"),
    max_load: Number(form.get("max_load")),
    available: true,
    specialty_ids: form.getAll("specialty_ids")
  };

  try {
    await api("/technicians", {
      method: "POST",
      body: JSON.stringify(data)
    });

    flash("Técnico creado.");
    await admin();
  } catch (error) {
    flash(error.message, true);
  }
}

async function settings() {
  title("Configuración de asignación", "Ajusta cómo FixIT prioriza la selección automática");
  const settingsData = await api("/settings");
  $("#content").innerHTML = `<section class="settings-shell"><div class="panel settings-intro"><span class="eyebrow">Reglas del motor</span><h2>Pesos de asignación</h2><p>Estos valores se guardan en la base de datos y se aplican al cálculo automático del técnico.</p></div><div class="settings-list">${(settingsData || []).map(s => `<article class="panel setting-card"><div class="setting-info"><strong>${esc(s.key)}</strong><small>${esc(s.description || "Sin descripción")}</small></div><input aria-label="${esc(s.key)}" name="${esc(s.key)}" value="${esc(s.value)}" form="settings-form" pattern="0(\\.\\d+)?|1(\\.0+)?" required></article>`).join("")}</div><form id="settings-form" class="settings-save"><button type="submit" class="primary-action">Guardar configuración</button></form></section>`;
  $("#settings-form").onsubmit = async e => { e.preventDefault(); const form = new FormData(e.target); try { for (const [key, value] of form) await api("/settings/" + key, { method: "PUT", body: JSON.stringify({ value }) }); flash("Configuración actualizada."); } catch (error) { flash(error.message, true); } };
}

async function audit() {
  title("Auditoría", "Registro de operaciones relevantes");
  const rows = await api("/audit");
  $("#content").innerHTML = `<section class="page-toolbar"><div><span class="eyebrow">Trazabilidad</span><h2 class="section-title">Actividad del sistema</h2></div><span class="count-badge">${(rows || []).length} registros</span></section><div class="audit-list">${(rows || []).map(a => `<article class="audit-item"><div class="audit-icon">◷</div><div class="audit-main"><div><strong>${esc(a.action)}</strong><span class="audit-module">${esc(a.module)}</span></div><p>${esc(a.entity)} · ${esc(a.user)}</p></div><time>${fmt(a.created_at)}</time></article>`).join("") || '<div class="empty-state large-empty"><strong>No hay movimientos</strong><span>La actividad del sistema aparecerá aquí.</span></div>'}</div>`;
}

async function reports() {
  title("Reportes", "Exportación institucional");
  $("#content").innerHTML = `<section class="reports-shell"><div class="report-hero"><div><span class="eyebrow">Centro de reportes</span><h2>Exporta la información de FixIT</h2><p>Genera el reporte de tickets en el formato que necesites para análisis o presentación.</p></div><span class="hero-icon">⇩</span></div><div class="report-cards"><article class="panel report-card"><span class="report-icon">CSV</span><div><strong>CSV</strong><p>Datos tabulares para análisis y filtros.</p></div><button type="button" data-format="csv" class="primary-action">Descargar</button></article><article class="panel report-card"><span class="report-icon">XLS</span><div><strong>Excel</strong><p>Ideal para revisión y trabajo en hojas de cálculo.</p></div><button type="button" data-format="xlsx" class="primary-action">Descargar</button></article><article class="panel report-card"><span class="report-icon">PDF</span><div><strong>PDF</strong><p>Versión lista para compartir o presentar.</p></div><button type="button" data-format="pdf" class="primary-action">Descargar</button></article></div></section>`;
  document.querySelectorAll("[data-format]").forEach(button => button.onclick = () => downloadReport(button.dataset.format));
}

async function downloadReport(format) {
  const token = getToken();

  if (!token) {
    showLogin();
    return;
  }

  try {
    const response =
      await fetch(
        "/api/reports/tickets." + format,
        {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      );

    if (response.status === 401) {
      clearSession();
      showLogin();
      flash(
        "La sesión ha expirado.",
        true
      );
      return;
    }

    if (!response.ok) {
      throw new Error(
        "No se pudo generar el reporte"
      );
    }

    const blob = await response.blob();
    const url =
      URL.createObjectURL(blob);

    const link =
      document.createElement("a");

    link.href = url;
    link.download =
      "fixit-tickets." + format;

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);

  } catch (error) {
    flash(error.message, true);
  }
}

function bindEvents() {
  const loginForm = $("#login-form");
  const logoutButton = $("#logout");
  const notifyButton = $("#notify");
  const showRegisterButton = $("#show-register");

  if (!loginForm) {
    console.error(
      "FixIT: #login-form no existe."
    );
    return;
  }

  loginForm.addEventListener(
    "submit",
    async (e) => {
      e.preventDefault();

      const submitButton =
        loginForm.querySelector(
          'button[type="submit"], button:not([type])'
        );

      if (submitButton) {
        submitButton.disabled = true;
      }

      const email =
        $("#email")?.value.trim() || "";

      const password =
        $("#password")?.value || "";

      if (!email || !password) {
        flash(
          "Ingrese correo y contraseña.",
          true
        );

        if (submitButton) {
          submitButton.disabled = false;
        }

        return;
      }

      try {
        console.log(
          "FixIT: intentando iniciar sesión..."
        );

        const result =
          await api("/auth/login", {
            method: "POST",
            body: JSON.stringify({
              email,
              password
            })
          });

        console.log(
          "FixIT: login API correcto."
        );

        if (!result?.access_token) {
          throw new Error(
            "El servidor no devolvió un access token."
          );
        }

        // Guardar el token antes de cualquier petición protegida.
        localStorage.setItem(
          "fixitToken",
          result.access_token
        );

        if (result.refresh_token) {
          localStorage.setItem(
            "fixitRefresh",
            result.refresh_token
          );
        } else {
          localStorage.removeItem(
            "fixitRefresh"
          );
        }

        // Verificar identidad con el nuevo token.
        me = await api("/auth/me");

        console.log(
          "FixIT: sesión verificada.",
          me
        );

        if (!me?.id) {
          throw new Error(
            "El servidor no devolvió información de usuario válida."
          );
        }

        // MUY IMPORTANTE:
        // Mostrar la aplicación ANTES de cargar el dashboard.
        // Así, si dashboard falla, el usuario permanece autenticado.
        showApp();
        setIdentity();
        nav();

        flash(
          `Bienvenido, ${me.full_name}`
        );

        // Las cargas posteriores no invalidan la sesión.
        try {
          await noticeCount();
        } catch (error) {
          console.warn(
            "No se pudo cargar notificaciones:",
            error
          );
        }

        try {
          await dashboard();
        } catch (error) {
          console.error(
            "Error al cargar dashboard:",
            error
          );

          flash(
            "Sesión iniciada. El dashboard tuvo un problema al cargar.",
            true
          );
        }

      } catch (error) {
        console.error(
          "FixIT: error durante login:",
          error
        );

        clearSession();
        showLogin();

        if (error.status === 401) {
          flash(
            "Correo o contraseña incorrectos.",
            true
          );
        } else {
          flash(
            error.message ||
              "No fue posible iniciar sesión.",
            true
          );
        }

      } finally {
        if (submitButton) {
          submitButton.disabled = false;
        }
      }
    }
  );

  if (logoutButton) {
    logoutButton.onclick = logout;
  }

  if (notifyButton) {
    notifyButton.onclick = () =>
      go("notifications");
  }

  if (showRegisterButton) {
    showRegisterButton.onclick = () => {
      modal.showModal();

      $("#modal-content").innerHTML = `
        <h2>Crear cuenta de solicitante</h2>

        <form id="register-form">

          <label>
            Nombre completo

            <input
              name="full_name"
              required
            >
          </label>

          <label>
            Correo institucional

            <input
              name="email"
              type="email"
              required
            >
          </label>

          <label>
            Contraseña

            <input
              name="password"
              type="password"
              minlength="8"
              required
            >
          </label>

          <button type="submit">
            Crear cuenta
          </button>

        </form>
      `;

      $("#register-form").onsubmit =
        async (e) => {
          e.preventDefault();

          try {
            await api("/auth/register", {
              method: "POST",
              body: JSON.stringify(
                Object.fromEntries(
                  new FormData(e.target)
                )
              )
            });

            modal.close();

            flash(
              "Cuenta creada. Ya puede iniciar sesión."
            );
          } catch (error) {
            flash(
              error.message,
              true
            );
          }
        };
    }
  }

  const content = $("#content");

  if (content) {
    content.addEventListener("click", (e) => {
      const row =
        e.target.closest(".ticket-row");

      if (!row) return;

      const id =
        row.dataset.ticketId;

      if (id) {
        openTicket(id);
      }
    });
  }
}

function startApp() {
  // La aplicación siempre comienza mostrando una vista válida.
  showLogin();

  bindEvents();

  init();
}

if (document.readyState === "loading") {
  document.addEventListener(
    "DOMContentLoaded",
    startApp
  );
} else {
  startApp();
}
