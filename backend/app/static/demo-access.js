"use strict";
/* DEMO_ACCESS_TEMPORARY: "Accesos de demostración" panel of the login screen.
   Shown only when the backend reports DEMO_ACCESS_ENABLED=true. It holds no credentials: the server
   issues a regular session for its own demo account of the chosen role. Delete this file to remove it. */

(async function demoAccess() {
  const box = $("#demo-access");
  let data;
  try {
    const res = await fetch("/api/auth/demo");
    if (!res.ok) return;
    data = await res.json();
  } catch { return; }
  if (!data.enabled || !data.roles?.length) return;

  box.innerHTML = `<h3 id="demo-access-title">Accesos de demostración</h3>
    <p>Entra con una cuenta de prueba de cada rol, sin correo ni contraseña.</p>
    <ul class="demo-roles">${data.roles.map((r) => `<li class="demo-role">
      <div><strong>${esc(r.label)}<code>${esc(r.role)}</code></strong><span>${esc(r.description)}</span></div>
      <button type="button" class="btn btn-secondary btn-sm" data-demo-role="${esc(r.role)}">Ingresar como ${esc(r.label)}</button>
    </li>`).join("")}</ul>
    <div id="demo-error" class="form-error" role="alert" hidden></div>
    ${banner("warn", "Modo de prueba:", "estos accesos permiten explorar el sistema con fines demostrativos. No utilizar en producción.")}`;
  box.hidden = false;

  box.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-demo-role]");
    if (!btn) return;
    const error = $("#demo-error");
    error.hidden = true;
    const buttons = $$("[data-demo-role]", box);
    buttons.forEach((b) => { b.disabled = true; });
    busy(btn, true, "Entrando…");
    try {
      const res = await fetch(`/api/auth/demo/${encodeURIComponent(btn.dataset.demoRole)}`, { method: "POST" });
      const result = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(typeof result.detail === "string" ? result.detail : "No fue posible iniciar la sesión de demostración.");
      Session.save(result);
      await startSession();
      flash(`Sesión de demostración: ${data.roles.find((r) => r.role === App.me.role)?.label || App.me.role}`);
    } catch (err) {
      error.textContent = err.message;
      error.hidden = false;
    } finally {
      busy(btn, false);
      buttons.forEach((b) => { b.disabled = false; });
    }
  });
})();
