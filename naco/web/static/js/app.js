// NACo admin client — one ES module, no framework, no build step.
// Pages are server-rendered shells; this file talks to /api/v1 and loads
// the page module named by <body data-page>.

const meta = (name) => document.querySelector(`meta[name="${name}"]`)?.content ?? "";
export const me = { username: meta("naco-user"), role: meta("naco-role"), tz: meta("naco-tz") || undefined };
const RANK = { VIEWER: 0, OPERATOR: 1, SUPERUSER: 2 };
export const can = (role) => (RANK[me.role] ?? -1) >= RANK[role];
const reducedMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

// ── DOM ────────────────────────────────────────────────────────────────────
export function h(spec, props, ...children) {
  const [tag, ...parts] = spec.split(/(?=[.#])/);
  const el = document.createElement(tag || "div");
  for (const p of parts) p[0] === "." ? el.classList.add(p.slice(1)) : (el.id = p.slice(1));
  if (props && (typeof props !== "object" || props instanceof Node || Array.isArray(props))) {
    children.unshift(props);
    props = null;
  }
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (k === "class") el.className += (el.className ? " " : "") + v;
    else if (k === "dataset") Object.assign(el.dataset, v);
    else if (k in el && typeof v !== "string") el[k] = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

export function icon(name, cls = "") {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", `icon ${cls}`.trim());
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", `/static/icons.svg#${name}`);
  svg.append(use);
  return svg;
}

export const clear = (el) => { while (el.firstChild) el.firstChild.remove(); return el; };

// ── API ────────────────────────────────────────────────────────────────────
export class ApiError extends Error {
  constructor(message, status, detail) { super(message); this.status = status; this.detail = detail; }
}

export async function api(method, path, body) {
  const headers = { Accept: "application/json" };
  let payload;
  if (body instanceof FormData) payload = body;
  else if (body !== undefined) { headers["Content-Type"] = "application/json"; payload = JSON.stringify(body); }
  if (method !== "GET") headers["X-CSRF-Token"] = meta("naco-csrf");
  let response;
  try {
    response = await fetch(`/api/v1${path}`, { method, headers, body: payload, credentials: "same-origin" });
  } catch {
    throw new ApiError("NACo is unreachable — check your connection", 0, {});
  }
  if (response.status === 401 && path !== "/auth/login") {
    location.href = `/login?next=${encodeURIComponent(location.pathname)}`;
    throw new ApiError("signed out", 401, {});
  }
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const err = data.error || { message: response.statusText };
    if (err.code === "setup_required") location.href = "/setup";
    throw new ApiError(err.message || "request failed", response.status, err);
  }
  return data;
}

export const get = (path) => api("GET", path);
export const post = (path, body = {}) => api("POST", path, body);
export const patch = (path, body) => api("PATCH", path, body);
export const del = (path) => api("DELETE", path);

// ── toasts ─────────────────────────────────────────────────────────────────
export function toast(message, kind = "ok") {
  const names = { ok: "check-circle-fill", bad: "x-circle-fill", info: "info-circle-fill" };
  const el = h(`div.toast-n.${kind}`, { role: kind === "bad" ? "alert" : "status" }, icon(names[kind] || names.info),
    h("div", message));
  document.getElementById("toasts")?.append(el);
  setTimeout(() => { el.classList.add("out"); el.addEventListener("animationend", () => el.remove()); },
    kind === "bad" ? 6500 : 3500);
}

export const fail = (err) => toast(err?.message || String(err), "bad");

// ── dialogs ────────────────────────────────────────────────────────────────
export function sheet({ title, body, wide = false, foot }) {
  const closeBtn = h("button.icon-btn", { type: "button", "aria-label": "Close" }, icon("x-lg"));
  const dialog = h(`dialog.sheet${wide ? ".wide" : ""}`, h("div.sheet-head", h("h2", title), closeBtn),
    h("div.sheet-body", body), foot ? h("div.sheet-foot", foot) : null);
  document.body.append(dialog);
  const close = () => {
    if (reducedMotion()) { dialog.close(); dialog.remove(); return; }
    dialog.classList.add("closing");
    dialog.addEventListener("animationend", () => { dialog.close(); dialog.remove(); }, { once: true });
  };
  closeBtn.addEventListener("click", close);
  dialog.addEventListener("cancel", (e) => { e.preventDefault(); close(); });
  dialog.showModal();
  return { dialog, close };
}

export function confirm(message, { title = "Are you sure?", label = "Confirm", danger = true } = {}) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (value) => { if (!done) { done = true; resolve(value); } };
    const ok = h(`button.btn.${danger ? "btn-danger" : "btn-accent"}`, { type: "button" }, label);
    const cancel = h("button.btn.btn-ghost", { type: "button" }, "Cancel");
    const s = sheet({ title, body: h("p.mb-0", message), foot: [cancel, ok] });
    ok.addEventListener("click", () => { finish(true); s.close(); });
    cancel.addEventListener("click", () => { finish(false); s.close(); });
    s.dialog.addEventListener("close", () => finish(false));
    ok.focus();
  });
}

// fields: [{name, label, type, options, required, help, placeholder, full, min, max, value}]
// types: text, password, email, number, select, switch, textarea, custom ({render() -> {el, get}})
export function formSheet({ title, fields, values = {}, submit, label = "Save", wide = false, intro }) {
  return new Promise((resolve) => {
    const getters = {};
    const grid = h("div.form-grid");
    for (const f of fields) {
      const id = `f-${f.name}-${Math.random().toString(36).slice(2, 7)}`;
      const value = values[f.name] ?? f.value ?? "";
      let input;
      if (f.type === "select") {
        input = h("select.form-select", { id, name: f.name, required: f.required },
          (f.options || []).map(([v, text]) => h("option", { value: v, selected: String(v) === String(value) }, text)));
        getters[f.name] = () => (input.value === "" && f.nullable ? null : f.numeric ? Number(input.value) : input.value);
      } else if (f.type === "switch") {
        input = h("input.form-check-input", { id, type: "checkbox", role: "switch", checked: Boolean(value) });
        getters[f.name] = () => input.checked;
      } else if (f.type === "textarea") {
        input = h("textarea.form-control", { id, name: f.name, rows: f.rows || 3, placeholder: f.placeholder || "" }, value);
        getters[f.name] = () => input.value;
      } else if (f.type === "custom") {
        const c = f.render(value);
        input = c.el;
        getters[f.name] = c.get;
      } else {
        input = h("input.form-control", {
          id, name: f.name, type: f.type || "text", value: value ?? "", required: f.required, placeholder: f.placeholder || "",
          autocomplete: f.autocomplete || "off", min: f.min, max: f.max, class: f.mono ? "mono" : undefined,
        });
        getters[f.name] = () => {
          const v = input.value.trim();
          if (f.type === "number") return v === "" ? (f.nullable ? null : undefined) : Number(v);
          if (v === "" && f.nullable) return null;
          return f.type === "password" ? input.value : v;
        };
      }
      const wrap = f.type === "switch"
        ? h("div.form-check.form-switch.mt-2", input, h("label.form-check-label", { for: id }, f.label))
        : f.type === "custom" ? h("div", input) : h("div", h("label.form-label", { for: id }, f.label), input);
      if (f.help) wrap.append(h("div.form-text", f.help));
      if (f.full || f.type === "textarea" || f.type === "custom") wrap.classList.add("full");
      grid.append(wrap);
    }
    const error = h("p.text-danger.small.mt-3.mb-0.hidden", { role: "alert" });
    const formEl = h("form", { novalidate: true }, intro ? h("p.muted", intro) : null, grid, error);
    const save = h("button.btn.btn-accent", { type: "submit" }, label);
    const cancel = h("button.btn.btn-ghost", { type: "button" }, "Cancel");
    save.setAttribute("form", formEl.id = `form-${Math.random().toString(36).slice(2, 8)}`);
    const s = sheet({ title, body: formEl, wide, foot: [cancel, save] });
    let settled = false;
    const finish = (v) => { if (!settled) { settled = true; resolve(v); } };
    cancel.addEventListener("click", () => { finish(null); s.close(); });
    s.dialog.addEventListener("close", () => finish(null));
    formEl.addEventListener("submit", async (e) => {
      e.preventDefault();
      const out = {};
      for (const [k, g] of Object.entries(getters)) { const v = g(); if (v !== undefined) out[k] = v; }
      save.disabled = true;
      try {
        const result = submit ? await submit(out) : out;
        finish(result ?? true);
        s.close();
      } catch (err) {
        error.textContent = err.message;
        error.classList.remove("hidden");
        formEl.classList.remove("shake"); void formEl.offsetWidth; formEl.classList.add("shake");
      } finally { save.disabled = false; }
    });
    setTimeout(() => formEl.querySelector("input:not([type=checkbox]),select,textarea")?.focus(), 50);
  });
}

export function showSecret(title, secret, note) {
  const copy = h("button.btn.btn-ghost.btn-sm", { type: "button" }, icon("copy"), " Copy");
  copy.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(secret); toast("Copied to clipboard"); } catch { toast("Copy failed — select and copy manually", "bad"); }
  });
  const done = h("button.btn.btn-accent", { type: "button" }, "Done");
  const s = sheet({ title, body: [note ? h("p.muted", note) : null, h("div.secret-box", h("span.flex-grow-1", secret), copy)],
    foot: [done] });
  done.addEventListener("click", s.close);
}

// ── formatting ─────────────────────────────────────────────────────────────
const dtf = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short", timeZone: me.tz });
const tf = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", timeZone: me.tz });
const hf = new Intl.DateTimeFormat(undefined, { hour: "2-digit", timeZone: me.tz });
const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
export const fmt = {
  dt: (v) => (v ? dtf.format(new Date(v)) : "—"),
  time: (v) => (v ? tf.format(new Date(v)) : "—"),
  hour: (v) => hf.format(new Date(v)),
  rel(v) {
    if (!v) return "never";
    const s = (new Date(v) - Date.now()) / 1000;
    for (const [unit, n] of [["day", 86400], ["hour", 3600], ["minute", 60]]) if (Math.abs(s) >= n) return rtf.format(Math.round(s / n), unit);
    return rtf.format(Math.round(s), "second");
  },
  bytes(n) {
    if (!n) return "0 B";
    const u = ["B", "KB", "MB", "GB", "TB"]; const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
    return `${(n / 1024 ** i).toFixed(i ? 1 : 0)} ${u[i]}`;
  },
  duration(s) {
    if (!s) return "—";
    const d = Math.floor(s / 86400), hh = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    return d ? `${d}d ${hh}h` : hh ? `${hh}h ${m}m` : `${m}m`;
  },
};

export const pill = (text, kind = "") => h(`span.pill${kind ? `.${kind}` : ""}`, h("span.dot"), text);
export const resultPill = (r) => pill(r === "ACCEPT" || r === "PASS" ? "Accepted" : r === "REJECT" || r === "FAIL" ? "Rejected" : r,
  r === "ACCEPT" || r === "PASS" ? "ok" : r === "REJECT" || r === "FAIL" ? "bad" : "");

// ── animated numbers ───────────────────────────────────────────────────────
export function countUp(el, to) {
  const from = Number(el.dataset.value || 0);
  el.dataset.value = to;
  if (reducedMotion() || from === to) { el.textContent = to.toLocaleString(); return; }
  const start = performance.now(), dur = 650;
  const step = (now) => {
    const t = Math.min(1, (now - start) / dur), e = 1 - (1 - t) ** 3;
    el.textContent = Math.round(from + (to - from) * e).toLocaleString();
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

// ── charts ─────────────────────────────────────────────────────────────────
const SVG = "http://www.w3.org/2000/svg";
const s = (tag, attrs) => { const el = document.createElementNS(SVG, tag); for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v); return el; };

export function barChart(svg, buckets) {
  while (svg.firstChild) svg.firstChild.remove();
  const W = 720, H = 220, pad = { l: 34, r: 8, t: 10, b: 24 };
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  const max = Math.max(4, ...buckets.map((b) => b.accept + b.reject));
  const step = (W - pad.l - pad.r) / buckets.length, bw = Math.max(4, step * 0.62);
  const y = (v) => H - pad.b - (v / max) * (H - pad.t - pad.b);
  for (const frac of [0, 0.5, 1]) {
    const yy = y(max * frac);
    svg.append(s("line", { x1: pad.l, x2: W - pad.r, y1: yy, y2: yy, class: "grid-line" }));
    svg.append(Object.assign(s("text", { x: pad.l - 6, y: yy + 3, "text-anchor": "end", class: "axis" }), { textContent: Math.round(max * frac) }));
  }
  buckets.forEach((b, i) => {
    const x = pad.l + i * step + (step - bw) / 2;
    const okH = y(0) - y(b.accept), badH = y(0) - y(b.reject);
    const group = s("g", {});
    const title = s("title", {}); title.textContent = `${fmt.hour(b.hour)}: ${b.accept} accepted, ${b.reject} rejected`;
    group.append(title);
    if (b.accept) group.append(s("rect", { x, y: y(b.accept), width: bw, height: okH, rx: 3, class: "bar bar-ok" }));
    if (b.reject) group.append(s("rect", { x, y: y(b.accept) - badH, width: bw, height: badH, rx: 3, class: "bar bar-bad" }));
    group.querySelectorAll(".bar").forEach((r) => (r.style.animationDelay = `${i * 18}ms`));
    svg.append(group);
    if (i % 4 === 0) svg.append(Object.assign(s("text", { x: x + bw / 2, y: H - 6, "text-anchor": "middle", class: "axis" }), { textContent: fmt.hour(b.hour) }));
  });
}

// ── live events (SSE) ──────────────────────────────────────────────────────
const listeners = {};
let source;
export function live(type, handler) {
  (listeners[type] ||= []).push(handler);
  if (source) { source.addEventListener(type, dispatch); return; }
  const dot = document.getElementById("live");
  source = new EventSource("/api/v1/events");
  source.onopen = () => dot?.classList.add("on");
  source.onerror = () => dot?.classList.remove("on");
  for (const t of Object.keys(listeners)) source.addEventListener(t, dispatch);
}
function dispatch(e) {
  let data = {};
  try { data = JSON.parse(e.data); } catch { return; }
  for (const fn of listeners[e.type] || []) fn(data);
}

// ── table view ─────────────────────────────────────────────────────────────
// columns: [{label, render(row) -> Node|string, class}]
export class TableView {
  constructor({ columns, load, empty = {}, search = true, filters = [], actions, rowClass, perPage = 25 }) {
    Object.assign(this, { columns, loadPage: load, empty, search, filters, actions, rowClass, perPage });
    this.page = 1; this.q = ""; this.total = 0; this.timer = null;
  }

  mount(container, extra = []) {
    const toolbar = h("div.toolbar");
    if (this.search) {
      const input = h("input.form-control", { type: "search", placeholder: "Search…", "aria-label": "Search" });
      input.addEventListener("input", () => { clearTimeout(this.timer); this.timer = setTimeout(() => { this.q = input.value.trim(); this.page = 1; this.load(); }, 220); });
      toolbar.append(h("div.search", icon("search"), input));
    }
    for (const f of this.filters) toolbar.append(f);
    toolbar.append(h("span.spacer"), ...extra);
    this.tbody = h("tbody");
    this.pager = h("div.pager");
    const thead = h("thead", h("tr", this.columns.map((c) => h("th", { class: c.class }, c.label)), this.actions ? h("th") : null));
    this.panel = h("div.panel.reveal", h("div.table-wrap", h("table.table.table-hover", thead, this.tbody)), this.pager);
    container.append(toolbar, this.panel);
    return this.load();
  }

  skeleton() {
    clear(this.tbody);
    for (let i = 0; i < 5; i++) {
      this.tbody.append(h("tr.skeleton-row", this.columns.map(() => h("td", h("div.skeleton"))), this.actions ? h("td") : null));
    }
  }

  async load() {
    if (!this.tbody.children.length) this.skeleton();
    try {
      const res = await this.loadPage({ page: this.page, perPage: this.perPage, q: this.q });
      const rows = Array.isArray(res) ? res : res.items;
      this.total = Array.isArray(res) ? res.length : res.total;
      this.render(rows);
    } catch (err) { fail(err); }
  }

  row(item, animate = true) {
    const tr = h("tr", { class: this.rowClass?.(item) },
      this.columns.map((c) => h("td", { class: c.class }, c.render(item))),
      this.actions ? h("td", h("div.row-actions", this.actions(item))) : null);
    if (animate && !reducedMotion()) tr.classList.add("enter");
    return tr;
  }

  render(rows) {
    clear(this.tbody);
    if (!rows.length) {
      const e = this.empty;
      this.tbody.append(h("tr", h("td", { colSpan: this.columns.length + 1 },
        h("div.empty", icon(e.icon || "search"), h("h3", this.q ? "No matches" : e.title || "Nothing here yet"),
          h("p", this.q ? "Try another search." : e.text || ""), this.q ? null : e.action || null))));
    }
    rows.forEach((item, i) => { const tr = this.row(item); tr.style.animationDelay = `${Math.min(i, 12) * 22}ms`; this.tbody.append(tr); });
    clear(this.pager);
    const pages = Math.max(1, Math.ceil(this.total / this.perPage));
    if (this.total > this.perPage || this.page > 1) {
      const prev = h("button.btn.btn-ghost.btn-sm", { type: "button", disabled: this.page <= 1 }, icon("chevron-left"));
      const next = h("button.btn.btn-ghost.btn-sm", { type: "button", disabled: this.page >= pages }, icon("chevron-right"));
      prev.addEventListener("click", () => { this.page--; this.load(); });
      next.addEventListener("click", () => { this.page++; this.load(); });
      this.pager.append(h("span", `${this.total.toLocaleString()} total · page ${this.page} of ${pages}`), prev, next);
    } else {
      this.pager.append(h("span", `${this.total.toLocaleString()} ${this.total === 1 ? "item" : "items"}`));
    }
  }

  prepend(item) {
    this.tbody.querySelector(".empty")?.closest("tr")?.remove();
    const tr = this.row(item);
    tr.classList.add("flash");
    this.tbody.prepend(tr);
    while (this.tbody.children.length > this.perPage) this.tbody.lastElementChild.remove();
    this.total++;
  }
}

// ── command palette ────────────────────────────────────────────────────────
function palette() {
  if (document.querySelector("dialog.palette")) return;
  const items = [...document.querySelectorAll(".sidebar a.nav-item")].map((a) => ({ label: a.textContent.trim(), href: a.getAttribute("href"), kind: "Page" }));
  const input = h("input.form-control", { type: "text", placeholder: "Jump to a page, user or MAC address…", "aria-label": "Search", autocomplete: "off" });
  const list = h("ul", { role: "listbox" });
  const dialog = h("dialog.palette", input, list);
  document.body.append(dialog);
  let current = [], sel = 0, seq = 0;
  const draw = () => {
    clear(list);
    current.forEach((it, i) => list.append(h("li", h(`a${i === sel ? ".sel" : ""}`, { href: it.href }, icon(it.icon || "chevron-right"), it.label, h("small", it.kind)))));
  };
  const search = async () => {
    const q = input.value.trim().toLowerCase(), mine = ++seq;
    current = items.filter((i) => i.label.toLowerCase().includes(q));
    sel = 0; draw();
    if (q.length < 2) return;
    try {
      const [users, devices] = await Promise.all([get(`/users?q=${encodeURIComponent(q)}&per_page=5`), get(`/devices?q=${encodeURIComponent(q)}&per_page=5`)]);
      if (mine !== seq) return;
      current = current.concat(users.items.map((u) => ({ label: u.username, href: `/users?q=${encodeURIComponent(u.username)}`, kind: "User", icon: "people" })),
        devices.items.map((d) => ({ label: `${d.mac_address} ${d.vendor || ""}`.trim(), href: `/devices?q=${d.mac_address}`, kind: "Device", icon: "pc-display" })));
      draw();
    } catch { /* palette search is best-effort */ }
  };
  input.addEventListener("input", search);
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { sel = Math.min(current.length - 1, sel + 1); draw(); e.preventDefault(); }
    if (e.key === "ArrowUp") { sel = Math.max(0, sel - 1); draw(); e.preventDefault(); }
    if (e.key === "Enter" && current[sel]) location.href = current[sel].href;
    if (e.key === "Escape") { e.preventDefault(); dialog.close(); }
  });
  dialog.addEventListener("close", () => dialog.remove());
  dialog.addEventListener("click", (e) => { if (e.target === dialog) dialog.close(); });
  dialog.showModal();
  search();
}

// ── shell ──────────────────────────────────────────────────────────────────
function shell() {
  document.addEventListener("click", async (e) => {
    for (const menu of document.querySelectorAll("details.account-menu[open]")) if (!menu.contains(e.target)) menu.open = false;
    const action = e.target.closest("[data-action]")?.dataset.action;
    if (action === "theme") {
      const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
      document.documentElement.dataset.theme = next;
      document.documentElement.dataset.bsTheme = next;
      try { localStorage.setItem("naco-theme", next); } catch { /* ignore */ }
    } else if (action === "menu") document.body.classList.toggle("nav-open");
    else if (action === "palette") palette();
    else if (action === "logout") {
      try { await post("/auth/logout"); } catch { /* signed out either way */ }
      location.href = "/login";
    }
  });
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); palette(); }
    if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName)) { e.preventDefault(); palette(); }
  });
  const badge = document.getElementById("pending-count");
  if (badge) {
    get("/devices?status=PENDING&per_page=1").then((r) => {
      if (r.total) { badge.textContent = r.total > 99 ? "99+" : r.total; badge.classList.remove("hidden"); }
    }).catch(() => {});
  }
}

// ── boot ───────────────────────────────────────────────────────────────────
const pageName = document.body.dataset.page;
if (pageName && !["login", "setup"].includes(pageName)) shell();
if (pageName) {
  const root = document.getElementById("page");
  import(`/static/js/pages/${pageName}.js`)
    .then((m) => m.default(root))
    .catch((err) => { console.error(err); toast(err?.message || "This page failed to load — try reloading", "bad"); })
    .finally(() => root?.setAttribute("aria-busy", "false"));
}
