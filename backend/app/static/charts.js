/* FixIT charts: small dependency-free SVG charts rendered at the container's real width.
 * Usage: insert the HTML returned by Charts.line/columns/scatter, then call Charts.mountAll(). */
const Charts = (() => {
  const specs = new Map();
  let seq = 0;
  const escT = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const color = (i) => `var(--c${(i % 8) + 1})`;
  const fmtNum = (v, d = 0) => (v === null || v === undefined || Number.isNaN(v)) ? "—" : Number(v).toLocaleString("es-PE", { maximumFractionDigits: d, minimumFractionDigits: 0 });

  function niceMax(max) {
    if (!(max > 0)) return 1;
    const exp = Math.pow(10, Math.floor(Math.log10(max)));
    const f = max / exp;
    return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10) * exp;
  }

  function place(type, spec) {
    const id = `ch${++seq}`;
    specs.set(id, { type, spec });
    const h = spec.height || 220;
    return `<div class="chart" data-chart="${id}" style="min-height:${h}px" role="img" aria-label="${escT(spec.label || "Gráfico")}"></div>`;
  }

  function mountAll(root = document) {
    for (const id of [...specs.keys()]) if (!document.querySelector(`[data-chart="${id}"]`)) specs.delete(id);
    root.querySelectorAll("[data-chart]").forEach(render);
  }

  function render(el) {
    const entry = specs.get(el.dataset.chart);
    if (!entry) return;
    const width = Math.max(260, Math.floor(el.clientWidth || el.parentElement?.clientWidth || 600));
    el.innerHTML = renderers[entry.type](entry.spec, width, el.dataset.chart);
    if (entry.type === "line") bindLine(el, entry.spec, width);
  }

  let resizeTimer;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => document.querySelectorAll("[data-chart]").forEach(render), 150);
  });

  function yAxis(max, min, t, innerH, l, w, format) {
    let out = '<g class="grid">';
    for (let k = 0; k <= 4; k++) {
      const v = min + (max - min) * k / 4;
      const y = t + innerH - innerH * k / 4;
      out += `<line x1="${l}" x2="${w - 8}" y1="${y}" y2="${y}"/><text x="${l - 6}" y="${y + 4}" text-anchor="end">${escT(format(v))}</text>`;
    }
    return out + "</g>";
  }

  const renderers = {
    line(spec, w) {
      const h = spec.height || 240, l = 46, r = 12, t = 12, b = 30;
      const innerW = w - l - r, innerH = h - t - b;
      const n = spec.labels.length;
      const all = spec.series.flatMap((s) => s.values).concat(spec.band ? spec.band.high : []).filter((v) => v !== null && v !== undefined);
      const max = niceMax(Math.max(...all, 0) * 1.05);
      const min = 0;
      const fmt = spec.format || ((v) => fmtNum(v, 1));
      const x = (i) => l + (n <= 1 ? innerW / 2 : (i * innerW) / (n - 1));
      const y = (v) => t + innerH - ((v - min) / (max - min)) * innerH;
      let svg = `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}">` + yAxis(max, min, t, innerH, l, w, (v) => fmtNum(v, max < 5 ? 1 : 0));
      const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(innerW / 90))));
      for (let i = 0; i < n; i += every) svg += `<text x="${x(i)}" y="${h - 10}" text-anchor="middle">${escT(spec.xLabel ? spec.xLabel(spec.labels[i]) : spec.labels[i])}</text>`;
      svg += `<line class="axis" x1="${l}" x2="${w - r}" y1="${t + innerH}" y2="${t + innerH}"/>`;
      if (spec.band) {
        const pts = [];
        spec.band.high.forEach((v, i) => { if (v !== null) pts.push(`${x(i)},${y(v)}`); });
        for (let i = spec.band.low.length - 1; i >= 0; i--) if (spec.band.low[i] !== null) pts.push(`${x(i)},${y(spec.band.low[i])}`);
        if (pts.length) svg += `<polygon points="${pts.join(" ")}" fill="${spec.band.color || "var(--c1)"}" opacity="0.14"/>`;
      }
      if (spec.marker !== undefined && spec.marker !== null) {
        svg += `<line x1="${x(spec.marker)}" x2="${x(spec.marker)}" y1="${t}" y2="${t + innerH}" stroke="var(--faint)" stroke-dasharray="4 4"/>`;
        if (spec.markerLabel) svg += `<text x="${x(spec.marker) + 4}" y="${t + 10}">${escT(spec.markerLabel)}</text>`;
      }
      spec.series.forEach((s) => {
        let d = "", pen = false;
        s.values.forEach((v, i) => {
          if (v === null || v === undefined) { pen = false; return; }
          d += `${pen ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`;
          pen = true;
        });
        svg += `<path d="${d}" fill="none" stroke="${s.color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"${s.dashed ? ' stroke-dasharray="5 4"' : ""}/>`;
      });
      svg += `<line class="crosshair" x1="0" x2="0" y1="${t}" y2="${t + innerH}" visibility="hidden"/>`;
      svg += `<g class="dots"></g><rect class="hit" x="${l}" y="${t}" width="${innerW}" height="${innerH}"/>`;
      return svg + "</svg>";
    },

    columns(spec, w) {
      const h = spec.height || 220, l = 40, r = 8, t = 10, b = 30;
      const items = spec.items;
      const innerW = w - l - r, innerH = h - t - b;
      const max = niceMax(Math.max(...items.map((i) => i.value || 0), 0) * 1.05);
      const slot = innerW / Math.max(1, items.length);
      const gap = Math.min(6, Math.max(2, slot * 0.2));
      const bw = Math.max(2, slot - gap);
      let svg = `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}">` + yAxis(max, 0, t, innerH, l, w, (v) => fmtNum(v, max < 5 ? 1 : 0));
      const every = Math.max(1, Math.ceil(items.length / Math.max(2, Math.floor(innerW / 70))));
      items.forEach((it, i) => {
        const bh = ((it.value || 0) / max) * innerH;
        const x0 = l + i * slot + gap / 2, y0 = t + innerH - bh;
        const rad = Math.min(4, bw / 2, bh);
        const fill = it.color || spec.color || "var(--c1)";
        if (bh > 0) svg += `<path d="M${x0},${t + innerH}V${y0 + rad}Q${x0},${y0} ${x0 + rad},${y0}H${x0 + bw - rad}Q${x0 + bw},${y0} ${x0 + bw},${y0 + rad}V${t + innerH}Z" fill="${fill}"/>`;
        svg += `<rect x="${l + i * slot}" y="${t}" width="${slot}" height="${innerH}" fill="transparent" data-tip="${escT(it.tip || `${it.label}\n${fmtNum(it.value, 2)}`)}"/>`;
        if (i % every === 0) svg += `<text x="${x0 + bw / 2}" y="${h - 10}" text-anchor="middle">${escT(spec.xLabel ? spec.xLabel(it.label) : it.label)}</text>`;
      });
      svg += `<line class="axis" x1="${l}" x2="${w - r}" y1="${t + innerH}" y2="${t + innerH}"/>`;
      return svg + "</svg>";
    },

    scatter(spec, w) {
      const h = spec.height || 300, l = 50, r = 12, t = 12, b = 40;
      const innerW = w - l - r, innerH = h - t - b;
      const pts = spec.points.filter((p) => p.x > 0 && p.y > 0);
      const maxV = Math.max(...pts.map((p) => Math.max(p.x, p.y)), 1);
      const lo = Math.log10(0.5), hi = Math.log10(niceMax(maxV));
      const sx = (v) => l + ((Math.log10(v) - lo) / (hi - lo)) * innerW;
      const sy = (v) => t + innerH - ((Math.log10(v) - lo) / (hi - lo)) * innerH;
      let svg = `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}"><g class="grid">`;
      for (let v = 1; v <= Math.pow(10, hi); v *= 10) {
        svg += `<line x1="${l}" x2="${w - r}" y1="${sy(v)}" y2="${sy(v)}"/><line x1="${sx(v)}" x2="${sx(v)}" y1="${t}" y2="${t + innerH}"/>`;
        svg += `<text x="${l - 6}" y="${sy(v) + 4}" text-anchor="end">${v} h</text><text x="${sx(v)}" y="${t + innerH + 16}" text-anchor="middle">${v} h</text>`;
      }
      svg += `</g><line x1="${sx(0.5)}" y1="${sy(0.5)}" x2="${sx(Math.pow(10, hi))}" y2="${sy(Math.pow(10, hi))}" stroke="var(--faint)" stroke-dasharray="4 4"/>`;
      const groups = Object.fromEntries((spec.groups || []).map((g) => [g.key, g.color]));
      pts.forEach((p) => {
        svg += `<circle cx="${sx(p.x).toFixed(1)}" cy="${sy(p.y).toFixed(1)}" r="4" fill="${groups[p.group] || "var(--c1)"}" fill-opacity="0.75" stroke="var(--surface)" stroke-width="1.5" data-tip="${escT(p.tip || "")}"/>`;
      });
      svg += `<text x="${l + innerW / 2}" y="${h - 4}" text-anchor="middle">${escT(spec.xTitle || "")}</text>`;
      svg += `<text x="12" y="${t + innerH / 2}" text-anchor="middle" transform="rotate(-90 12 ${t + innerH / 2})">${escT(spec.yTitle || "")}</text>`;
      return svg + "</svg>";
    },
  };

  function bindLine(el, spec, w) {
    const svg = el.querySelector("svg");
    const hit = svg.querySelector(".hit");
    const cross = svg.querySelector(".crosshair");
    const dots = svg.querySelector(".dots");
    const h = spec.height || 240, l = 46, r = 12, t = 12, b = 30;
    const innerW = w - l - r, innerH = h - t - b, n = spec.labels.length;
    const all = spec.series.flatMap((s) => s.values).concat(spec.band ? spec.band.high : []).filter((v) => v !== null && v !== undefined);
    const max = niceMax(Math.max(...all, 0) * 1.05);
    const fmt = spec.format || ((v) => fmtNum(v, 1));
    const move = (evt) => {
      const rect = svg.getBoundingClientRect();
      const px = ((evt.clientX - rect.left) / rect.width) * w;
      const i = Math.max(0, Math.min(n - 1, Math.round(((px - l) / innerW) * (n - 1))));
      const cx = l + (n <= 1 ? innerW / 2 : (i * innerW) / (n - 1));
      cross.setAttribute("x1", cx); cross.setAttribute("x2", cx); cross.setAttribute("visibility", "visible");
      let marks = "";
      const lines = [spec.tooltipLabel ? spec.tooltipLabel(spec.labels[i]) : spec.labels[i]];
      spec.series.forEach((s) => {
        const v = s.values[i];
        if (v === null || v === undefined) return;
        marks += `<circle cx="${cx}" cy="${t + innerH - (v / max) * innerH}" r="4.5" fill="${s.color}" stroke="var(--surface)" stroke-width="2"/>`;
        lines.push(`${s.name}: ${fmt(v)}`);
      });
      if (spec.band && spec.band.low[i] !== null && spec.band.low[i] !== undefined) lines.push(`Intervalo 80 %: ${fmt(spec.band.low[i])} – ${fmt(spec.band.high[i])}`);
      dots.innerHTML = marks;
      Tooltip.show(lines, evt.clientX, evt.clientY);
    };
    hit.addEventListener("mousemove", move);
    hit.addEventListener("touchstart", (e) => move(e.touches[0]), { passive: true });
    hit.addEventListener("mouseleave", () => { cross.setAttribute("visibility", "hidden"); dots.innerHTML = ""; Tooltip.hide(); });
  }

  function hbars(items, opts = {}) {
    if (!items.length) return '<p class="muted">Sin datos para mostrar.</p>';
    const max = opts.max || Math.max(...items.map((i) => i.value || 0), 1);
    return `<div class="hbars">${items.map((it, idx) => {
      const pct = Math.max(0, Math.min(100, ((it.value || 0) / max) * 100));
      const fill = it.color || opts.color || "var(--c1)";
      return `<div class="hbar" data-tip="${escT(it.tip || `${it.label}\n${it.display ?? fmtNum(it.value, 2)}`)}"><span class="lbl" title="${escT(it.label)}">${escT(it.label)}</span>` +
        `<span class="track"><i style="width:${pct}%;background:${fill}"></i></span><span class="val">${escT(it.display ?? fmtNum(it.value, 1))}</span></div>`;
    }).join("")}</div>`;
  }

  function heat(rows, cols, values, opts = {}) {
    const flat = values.flat();
    const max = Math.max(...flat, 1);
    const ramp = ["var(--surface-3)", "var(--seq-1)", "var(--seq-2)", "var(--seq-3)", "var(--seq-4)", "var(--seq-5)"];
    const head = `<tr><th></th>${cols.map((c) => `<th>${escT(c)}</th>`).join("")}</tr>`;
    const body = rows.map((r, i) => `<tr><th class="rowh">${escT(r)}</th>${values[i].map((v, j) => {
      const step = v <= 0 ? 0 : Math.min(5, 1 + Math.floor((v / max) * 4.999));
      const ink = step >= 4 ? "#fff" : "var(--ink-2)";
      return `<td style="background:${ramp[step]};color:${ink}" data-tip="${escT(`${r} · ${cols[j]}\n${opts.format ? opts.format(v) : fmtNum(v)}`)}">${opts.hideValues ? "" : escT(opts.format ? opts.format(v) : fmtNum(v))}</td>`;
    }).join("")}</tr>`).join("");
    return `<div class="table-wrap" style="border:0"><table class="heat">${head}${body}</table></div>`;
  }

  function legend(items) {
    return `<div class="legend">${items.map((i) => `<span><i class="${i.box ? "box" : ""}" style="background:${i.color}${i.dashed ? ";background:repeating-linear-gradient(90deg," + i.color + " 0 5px,transparent 5px 8px)" : ""}"></i>${escT(i.name)}</span>`).join("")}</div>`;
  }

  function dataTable(headers, rows, summary = "Ver datos en tabla") {
    return `<details class="data-table"><summary>${escT(summary)}</summary><div class="table-wrap"><table class="table-compact"><thead><tr>${headers.map((h) => `<th>${escT(h)}</th>`).join("")}</tr></thead>` +
      `<tbody>${rows.map((r) => `<tr>${r.map((c) => `<td class="num">${escT(c)}</td>`).join("")}</tr>`).join("")}</tbody></table></div></details>`;
  }

  return {
    color, fmtNum, mountAll, hbars, heat, legend, dataTable,
    line: (spec) => place("line", spec),
    columns: (spec) => place("columns", spec),
    scatter: (spec) => place("scatter", spec),
  };
})();

/* Shared tooltip for any element with data-tip (plain text; first line in bold). */
const Tooltip = (() => {
  const el = () => document.getElementById("tooltip");
  function show(lines, x, y) {
    const tip = el();
    if (!tip) return;
    tip.replaceChildren(...lines.map((line, i) => {
      const node = document.createElement(i === 0 ? "b" : "div");
      node.textContent = line;
      return node;
    }));
    tip.hidden = false;
    const pad = 14, rect = tip.getBoundingClientRect();
    let left = x + pad, top = y + pad;
    if (left + rect.width > window.innerWidth - 8) left = x - rect.width - pad;
    if (top + rect.height > window.innerHeight - 8) top = y - rect.height - pad;
    tip.style.left = `${Math.max(8, left)}px`;
    tip.style.top = `${Math.max(8, top)}px`;
  }
  function hide() { const tip = el(); if (tip) tip.hidden = true; }
  document.addEventListener("mousemove", (e) => {
    const target = e.target.closest?.("[data-tip]");
    if (target) show(target.dataset.tip.split("\n"), e.clientX, e.clientY);
    else if (!e.target.closest?.(".hit")) hide();
  });
  document.addEventListener("scroll", hide, true);
  return { show, hide };
})();
