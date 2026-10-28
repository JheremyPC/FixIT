"use strict";
/* FixIT web client — Terms of use and privacy notice. Served by GET /api/legal (content: backend app/legal.py).
   Used in two places: the public page /legal (legal.html, no session needed) and the in-app page #/legal, which
   also shows the user's acceptance and lets them accept the current terms. Nothing is ever accepted on the
   user's behalf, and the privacy notice is information, not consent. */

const LegalView = (() => {
  const escape = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmt = (d) => d ? new Date(d).toLocaleString("es-PE", { dateStyle: "long", timeStyle: "short" }) : "—";
  const fmtDay = (d) => d ? new Date(`${d}T12:00:00`).toLocaleDateString("es-PE", { dateStyle: "long" }) : "—";
  let cache = null;

  async function load() {
    if (cache) return cache;
    const res = await fetch("/api/legal");
    if (!res.ok) throw new Error("No se pudieron cargar los documentos.");
    cache = await res.json();
    return cache;
  }

  /* Escaped text where every pending marker is highlighted. */
  function text(value, marker) {
    return escape(value).split(escape(marker)).join(`<mark class="pending">${escape(marker)}</mark>`);
  }

  function documentHtml(doc, data) {
    const m = data.pending_marker;
    const blocks = (section) => section.blocks.map((b) => typeof b === "string" ? `<p>${text(b, m)}</p>`
      : `<ul>${b.list.map((li) => `<li>${text(li, m)}</li>`).join("")}</ul>`).join("");
    const note = data.review_note;
    return `<article class="card legal-doc" aria-labelledby="legal-${escape(doc.id)}">
      <header class="legal-head"><span class="eyebrow">Versión ${escape(doc.version)} · Actualizado el ${escape(fmtDay(doc.updated))}</span>
        <h2 id="legal-${escape(doc.id)}">${escape(doc.title)}</h2><p>${escape(doc.summary)}</p>
        <dl class="legal-meta"><div><dt>Vigencia</dt><dd>${text(doc.effective, m)}</dd></div><div><dt>Versión</dt><dd>${escape(doc.version)}</dd></div>
          <div><dt>Aceptación</dt><dd>${doc.requires_acceptance ? "Requiere aceptación expresa" : "Informativo, no requiere aceptación"}</dd></div></dl></header>
      <div class="banner banner-warn legal-note"><div><b>${escape(note.title)}</b>${escape(note.text)}
        <details><summary>Aspectos que debe validar la entidad</summary><ul>${note.checklist.map((x) => `<li>${escape(x)}</li>`).join("")}</ul></details></div></div>
      <nav class="legal-toc" aria-label="Contenido"><b>Contenido</b><ol>${doc.sections.map((s) => `<li><button type="button" class="btn-link" data-legal-jump="${escape(doc.id)}-${escape(s.id)}">${escape(s.title.replace(/^\d+\.\s*/, ""))}</button></li>`).join("")}</ol></nav>
      ${doc.sections.map((s) => `<section class="legal-section" id="${escape(doc.id)}-${escape(s.id)}"><h3>${escape(s.title)}</h3>${blocks(s)}</section>`).join("")}
      <div id="legal-accept-${escape(doc.id)}"></div>
    </article>`;
  }

  function tabsHtml(docs, active, inApp) {
    return `<nav class="tabs" aria-label="Documentos">${docs.map((d) => `<button type="button" class="${d.id === active ? "active" : ""}" ${d.id === active ? 'aria-current="page"' : ""}
      ${inApp ? `data-page-link="legal" data-sub="${escape(d.id)}"` : `data-legal-tab="${escape(d.id)}"`}>${escape(d.title)}</button>`).join("")}</nav>`;
  }

  async function render(root, active, inApp) {
    const data = await load();
    const doc = data.documents.find((d) => d.id === active) || data.documents[0];
    root.innerHTML = `<div class="legal">${tabsHtml(data.documents, doc.id, inApp)}${documentHtml(doc, data)}</div>`;
    return doc;
  }

  document.addEventListener("click", (e) => {
    const jump = e.target.closest("[data-legal-jump]");
    if (jump) document.getElementById(jump.dataset.legalJump)?.scrollIntoView({ behavior: "smooth", block: "start" });
  });

  return { load, render, escape, fmt };
})();

/* ---------- In-app page (#/legal/terminos, #/legal/privacidad) ---------- */
if (typeof Pages !== "undefined") {
  Pages.legal = async (root, sub) => {
    setTitle("Términos y privacidad", "Reglas de uso de FixIT y tratamiento de tus datos personales");
    const doc = await LegalView.render(root, sub || "terminos", true);
    if (doc.requires_acceptance) await renderAcceptance(doc);
  };

  async function renderAcceptance(doc) {
    const box = $(`#legal-accept-${doc.id}`);
    if (!box) return;
    const state = await api("/legal/acceptances");
    const mine = state.accepted.filter((a) => a.document === doc.id);
    const current = mine.find((a) => a.version === doc.version);
    const history = mine.length ? `<p class="small muted">Historial de aceptaciones: ${mine.map((a) => `versión ${esc(a.version)} el ${esc(LegalView.fmt(a.accepted_at))}`).join(" · ")}.</p>` : "";
    box.innerHTML = `<div class="legal-accept">${current
      ? `${banner("info", "Aceptaste esta versión", `Versión ${current.version}, el ${LegalView.fmt(current.accepted_at)}. La aceptación quedó registrada con fecha, hora y dirección IP.`)}${history}`
      : `<form id="terms-accept" class="stack"><label class="check consent"><input type="checkbox" name="ok" required> <span>He leído y acepto los Términos y condiciones, versión ${esc(doc.version)}.</span></label>
          <div class="row"><button class="btn btn-primary" type="submit">Aceptar términos</button><span class="small muted">Se registrará tu usuario, la versión y la fecha de aceptación.</span></div></form>${history}`}</div>`;
    const form = $("#terms-accept");
    if (form) form.onsubmit = async (e) => {
      e.preventDefault();
      busy(e.submitter, true, "Registrando…");
      try {
        await post("/legal/acceptances", { document: doc.id, version: doc.version });
        $("#legal-notice")?.setAttribute("hidden", "");
        flash("Aceptación registrada.");
        await renderAcceptance(doc);
      } catch (error) { flash(error.message, true); busy(e.submitter, false); }
    };
  }

  /* Non-blocking reminder after login when the current terms version has not been accepted yet. */
  var checkPendingTerms = async () => {
    const box = $("#legal-notice");
    if (!box) return;
    try {
      const state = await api("/legal/acceptances");
      box.hidden = !state.pending.length;
      if (state.pending.length) box.innerHTML = banner("info", "Términos y condiciones actualizados",
        `Revisa y acepta la versión ${state.pending[0].version} de los Términos y condiciones.`,
        `<div class="row"><button class="btn btn-secondary btn-sm" data-page-link="legal" data-sub="terminos">Revisar ahora</button>
          <button class="btn btn-quiet btn-sm" data-action="dismiss-legal-notice">Más tarde</button></div>`);
    } catch { box.hidden = true; }
  };
  Actions["dismiss-legal-notice"] = () => { $("#legal-notice").hidden = true; };
}

/* ---------- Public page /legal (#terminos, #privacidad) ---------- */
if (document.body.dataset.page === "legal") {
  const root = document.getElementById("legal-root");
  const show = async () => {
    const id = (location.hash || "#terminos").slice(1);
    try {
      const doc = await LegalView.render(root, id, false);
      document.title = `${doc.title} · FixIT`;
    } catch (error) {
      root.innerHTML = `<div class="banner banner-crit"><div><b>No se pudo cargar el documento</b>${LegalView.escape(error.message)}</div></div>`;
    }
  };
  document.addEventListener("click", (e) => {
    const tab = e.target.closest("[data-legal-tab]");
    if (tab) location.hash = tab.dataset.legalTab;
  });
  window.addEventListener("hashchange", show);
  show();
}
