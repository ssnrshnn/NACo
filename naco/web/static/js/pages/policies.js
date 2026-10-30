import { api, can, clear, fail, get, h, icon, pill, toast } from "/static/js/app.js";
import { btn, formSheet, primary, remove } from "/static/js/ui.js";

export const TYPES = {
  always: { label: "Always", ops: [] },
  username: { label: "Username", ops: [["equals", "is"], ["not_equals", "is not"], ["in", "is one of"], ["matches", "matches"]] },
  group: { label: "Group", ops: [["in", "is one of"], ["not_in", "is not one of"]] },
  auth_method: { label: "Method", ops: [["in", "is one of"]], choices: ["EAP-TLS", "EAP-TTLS", "PEAP", "PAP", "MAB"] },
  device_status: { label: "Device status", ops: [["in", "is one of"]], choices: ["approved", "pending", "guest"] },
  device_type: { label: "Device type", ops: [["in", "is one of"], ["not_in", "is not one of"]] },
  mac: { label: "MAC address", ops: [["equals", "is"], ["in", "is one of"], ["matches", "matches"]] },
  vendor: { label: "Vendor", ops: [["in", "is one of"], ["matches", "matches"]] },
  nas: { label: "NAS", ops: [["in", "is one of"], ["not_in", "is not one of"]] },
  ssid: { label: "SSID", ops: [["in", "is one of"], ["not_in", "is not one of"], ["matches", "matches"]] },
  time: { label: "Time", ops: [["between", "between"]] },
};
const DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
const LIST_OPS = new Set(["in", "not_in"]);

export function describe(c) {
  const t = TYPES[c.type];
  if (!t) return c.type;
  if (c.type === "always") return "always";
  if (c.type === "time") return `${c.start}–${c.end}${c.days && c.days.length < 7 ? ` (${c.days.join(", ")})` : ""}`;
  const op = Object.fromEntries(t.ops)[c.op] || c.op;
  const v = Array.isArray(c.value) ? c.value.join(", ") : c.value;
  return `${t.label.toLowerCase()} ${op} ${v}`;
}

function conditionRow(initial, suggestions, onRemove) {
  const type = h("select.form-select", Object.entries(TYPES).map(([k, t]) => h("option", { value: k, selected: k === initial.type }, t.label)));
  const op = h("select.form-select");
  const valueBox = h("div");
  let getValue = () => ({});

  const drawValue = (c = {}) => {
    clear(valueBox);
    const t = type.value, o = op.value, spec = TYPES[t];
    if (t === "always") { getValue = () => ({}); return; }
    if (t === "time") {
      const start = h("input.form-control", { type: "time", value: c.start || "08:00" });
      const end = h("input.form-control", { type: "time", value: c.end || "18:00" });
      const days = DAYS.map((d) => {
        const box = h("input.btn-check", { type: "checkbox", id: `d-${d}-${Math.random().toString(36).slice(2, 6)}`, checked: (c.days || DAYS).includes(d) });
        return [box, h("label.btn.btn-sm.btn-ghost", { for: box.id }, d)];
      });
      valueBox.append(h("div.d-flex.gap-2.mb-2", start, end), h("div.btn-group.flex-wrap", days.flat()));
      getValue = () => ({ start: start.value, end: end.value, days: days.filter(([b]) => b.checked).map(([b]) => b.id.split("-")[1]) });
      return;
    }
    if (spec.choices) {
      const chosen = new Set(Array.isArray(c.value) ? c.value : []);
      const boxes = spec.choices.map((ch) => {
        const box = h("input.btn-check", { type: "checkbox", id: `c-${ch}-${Math.random().toString(36).slice(2, 6)}`, checked: chosen.has(ch) });
        return [box, h("label.btn.btn-sm.btn-ghost", { for: box.id }, ch)];
      });
      valueBox.append(h("div.btn-group.flex-wrap", boxes.flat()));
      getValue = () => ({ value: boxes.filter(([b]) => b.checked).map(([b]) => b.id.split("-").slice(1, -1).join("-")) });
      return;
    }
    const listId = suggestions[t] ? `dl-${t}` : undefined;
    const input = h("input.form-control", {
      value: Array.isArray(c.value) ? c.value.join(", ") : c.value || "", list: listId,
      placeholder: LIST_OPS.has(o) ? "comma, separated, values" : o === "matches" ? "glob, e.g. lab-*" : "value",
      class: t === "mac" ? "mono" : undefined,
    });
    valueBox.append(input);
    getValue = () => {
      const raw = input.value;
      return { value: LIST_OPS.has(o) ? raw.split(",").map((x) => x.trim()).filter(Boolean) : raw.trim() };
    };
  };

  const drawOps = (c = {}) => {
    clear(op);
    const ops = TYPES[type.value].ops;
    op.disabled = !ops.length;
    for (const [k, label] of ops) op.append(h("option", { value: k, selected: k === c.op }, label));
    drawValue(c);
  };

  type.addEventListener("change", () => drawOps());
  op.addEventListener("change", () => drawValue({ value: getValue().value }));
  drawOps(initial);
  const rm = btn("x-lg", "Remove condition", () => { row.remove(); onRemove?.(); }, "btn-danger-ghost");
  const row = h("div.cond", type, op, valueBox, rm);
  row.read = () => {
    const t = type.value;
    if (t === "always") return { type: t };
    if (t === "time") return { type: t, op: "between", ...getValue() };
    return { type: t, op: op.value, ...getValue() };
  };
  return row;
}

function conditionsField(suggestions) {
  return {
    name: "conditions", label: "Conditions", type: "custom",
    render(value) {
      const list = h("div.cond-list");
      const hint = h("p.small.muted.mb-2", "All conditions must match. No conditions = matches every request.");
      const add = h("button.btn.btn-ghost.btn-sm.mt-2", { type: "button" }, icon("plus-lg"), " Add condition");
      add.addEventListener("click", () => list.append(conditionRow({ type: "group", op: "in" }, suggestions)));
      for (const c of value || []) list.append(conditionRow(c, suggestions));
      const datalists = Object.entries(suggestions).map(([t, values]) => h("datalist", { id: `dl-${t}` }, values.map((v) => h("option", { value: v }))));
      return { el: h("div", h("label.form-label", "Conditions"), hint, list, add, datalists),
        get: () => [...list.children].map((r) => r.read()) };
    },
  };
}

function attributesField() {
  return {
    name: "reply_attributes", label: "Extra RADIUS attributes", type: "custom",
    render(value) {
      const rows = h("div.d-grid.gap-2");
      const addRow = (k = "", v = "") => {
        const name = h("input.form-control.mono", { value: k, placeholder: "Aruba-User-Role, Filter-Id, Cisco-AVPair…" });
        const val = h("input.form-control.mono", { value: v, placeholder: "value" });
        const r = h("div.d-flex.gap-2", name, val, btn("x-lg", "Remove", () => r.remove(), "btn-danger-ghost"));
        r.read = () => [name.value.trim(), val.value];
        rows.append(r);
      };
      for (const [k, v] of Object.entries(value || {})) for (const one of [v].flat()) addRow(k, String(one));
      const add = h("button.btn.btn-ghost.btn-sm", { type: "button" }, icon("plus-lg"), " Add attribute");
      add.addEventListener("click", () => addRow());
      return {
        el: h("div", h("label.form-label", "Extra RADIUS attributes"), h("p.small.muted.mb-2", "Sent with the accept, e.g. a role or ACL name. VLAN is set above."), rows, add),
        get() {
          const out = {};
          for (const r of rows.children) {
            const [k, v] = r.read();
            if (!k) continue;
            const value = /^\d+$/.test(v) ? Number(v) : v;
            out[k] = k in out ? [out[k]].flat().concat(value) : value;
          }
          return out;
        },
      };
    },
  };
}

export default async function (root) {
  const [groups, nas] = await Promise.all([get("/groups"), get("/nas")]);
  const suggestions = { group: groups.map((g) => g.name), nas: nas.map((n) => n.name), auth_method: [], device_status: [] };
  const editable = can("SUPERUSER");
  let policies = [];

  const fields = [
    { name: "name", label: "Name", required: true },
    { name: "action", label: "Decision", type: "select", options: [["PERMIT", "Permit"], ["DENY", "Deny"]] },
    { name: "description", label: "Description", full: true },
    { name: "vlan", label: "VLAN (optional)", type: "number", min: 1, max: 4094, nullable: true, help: "Leave empty to keep the port's own VLAN." },
    { name: "enabled", label: "Enabled", type: "switch", value: true },
    conditionsField(suggestions),
    attributesField(),
  ];

  const tbody = h("tbody");
  const panel = h("div.panel.reveal", h("div.table-wrap", h("table.table.table-hover",
    h("thead", h("tr", h("th", "#"), h("th", "Policy"), h("th", "When"), h("th", "Then"), h("th", "On"), h("th"))), tbody)));

  async function load() {
    try { policies = await get("/policies"); draw(); } catch (err) { fail(err); }
  }

  async function move(index, delta) {
    const ids = policies.map((p) => p.id);
    const j = index + delta;
    if (j < 0 || j >= ids.length) return;
    [ids[index], ids[j]] = [ids[j], ids[index]];
    try { policies = await api("POST", "/policies/reorder", { ids }); draw(j); } catch (err) { fail(err); }
  }

  function draw(flash) {
    clear(tbody);
    if (!policies.length) {
      tbody.append(h("tr", h("td", { colSpan: 6 }, h("div.empty", icon("shield-check"), h("h3", "No policies — everything is denied"),
        h("p", "NACo is default-deny. Add a policy to let users or devices in, e.g. “group is staff → permit, VLAN 10”."),
        editable ? primary("Add your first policy", add) : null))));
      return;
    }
    policies.forEach((p, i) => {
      const toggle = h("input.form-check-input", { type: "checkbox", role: "switch", checked: p.enabled, disabled: !editable, "aria-label": "Enabled" });
      toggle.addEventListener("change", async () => {
        try { await api("PATCH", `/policies/${p.id}`, { enabled: toggle.checked }); p.enabled = toggle.checked; toast(`${p.name} ${toggle.checked ? "enabled" : "disabled"}`); }
        catch (err) { toggle.checked = !toggle.checked; fail(err); }
      });
      const then = p.action === "PERMIT"
        ? [pill(p.vlan ? `Permit · VLAN ${p.vlan}` : "Permit", "ok"), ...Object.keys(p.reply_attributes).map((k) => h("span.chip", k))]
        : pill("Deny", "bad");
      const tr = h(`tr${p.enabled ? "" : ".opacity-50"}`,
        h("td.text-nowrap", editable ? [btn("arrow-up", "Move up", () => move(i, -1)), btn("arrow-down", "Move down", () => move(i, 1))] : h("span.muted", i + 1)),
        h("td", h("b", p.name), p.description ? h("div.small.muted", p.description) : null),
        h("td", p.conditions.length ? p.conditions.map((c) => h("span.chip", describe(c))) : h("span.chip", "every request")),
        h("td", then),
        h("td", h("div.form-check.form-switch.m-0", toggle)),
        h("td", editable ? h("div.row-actions", btn("pencil", "Edit", () => edit(p)),
          btn("trash3", "Delete", () => remove(`policy ${p.name}`, `/policies/${p.id}`, load), "btn-danger-ghost")) : null));
      if (i === flash) tr.classList.add("flash"); else tr.classList.add("enter");
      tr.style.animationDelay = `${Math.min(i, 12) * 25}ms`;
      tbody.append(tr);
    });
  }

  async function edit(p) {
    const done = await formSheet({ title: `Edit ${p.name}`, wide: true, fields, values: { ...p, vlan: p.vlan ?? "" },
      submit: (v) => api("PATCH", `/policies/${p.id}`, v) });
    if (done) { toast(`Saved ${p.name} — affected sessions are re-checked`); load(); }
  }
  async function add() {
    const priority = policies.length ? Math.max(...policies.map((p) => p.priority)) + 10 : 10;
    const done = await formSheet({ title: "New policy", wide: true, fields, label: "Create",
      values: { action: "PERMIT", enabled: true, conditions: [{ type: "group", op: "in", value: [] }] },
      submit: (v) => api("POST", "/policies", { ...v, priority }) });
    if (done) { toast(`Created ${done.name}`); load(); }
  }

  root.append(h("div.toolbar", h("span.muted.small", "First match wins · nothing matched → denied"), h("span.spacer"),
    h("a.btn.btn-ghost", { href: "/simulator" }, icon("signpost-split"), " Simulate"), editable ? primary("Add policy", add) : null), panel);
  await load();
}
