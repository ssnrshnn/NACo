import { TableView, api, can, h, icon, pill, toast, get } from "/static/js/app.js";
import { btn, formSheet, primary, remove } from "/static/js/ui.js";

function rulesField() {
  return {
    name: "rules", label: "Rules", type: "custom",
    render(value) {
      const list = h("div.d-grid.gap-2");
      const addRule = (r = { action: "PERMIT", pattern: "" }) => {
        const action = h("select.form-select", [["PERMIT", "Permit"], ["DENY", "Deny"]].map(([v, l]) => h("option", { value: v, selected: v === r.action }, l)));
        const pattern = h("input.form-control.mono", { value: r.pattern, placeholder: "show *" });
        const row = h("div.rule", h("span.drag", icon("grip-vertical")), action, pattern, h("div.d-flex",
          btn("arrow-up", "Up", () => row.previousElementSibling && list.insertBefore(row, row.previousElementSibling)),
          btn("arrow-down", "Down", () => row.nextElementSibling && list.insertBefore(row.nextElementSibling, row)),
          btn("x-lg", "Remove", () => row.remove(), "btn-danger-ghost")));
        row.read = () => ({ action: action.value, pattern: pattern.value.trim() });
        list.append(row);
      };
      (value || []).forEach(addRule);
      const add = h("button.btn.btn-ghost.btn-sm", { type: "button" }, icon("plus-lg"), " Add rule");
      add.addEventListener("click", () => addRule());
      return {
        el: h("div", h("label.form-label", "Rules"), h("p.small.muted.mb-2", "Matched against the full command line, top to bottom; * matches anything. The first match decides."), list, add),
        get: () => [...list.children].map((r) => r.read()).filter((r) => r.pattern),
      };
    },
  };
}

export default async function (root) {
  const su = can("SUPERUSER");
  const fields = [
    { name: "name", label: "Name", required: true },
    { name: "default_action", label: "When no rule matches", type: "select", options: [["DENY", "Deny the command"], ["PERMIT", "Permit the command"]] },
    { name: "description", label: "Description", full: true },
    rulesField(),
  ];
  const table = new TableView({
    search: false,
    columns: [
      { label: "Command set", render: (c) => [h("b", c.name), c.description ? h("div.small.muted", c.description) : null] },
      { label: "Rules", render: (c) => c.rules.slice(0, 4).map((r) => h("span.chip.mono", `${r.action === "PERMIT" ? "✓" : "✗"} ${r.pattern}`)).concat(c.rules.length > 4 ? h("span.small.muted", ` +${c.rules.length - 4}`) : []) },
      { label: "Otherwise", render: (c) => pill(c.default_action === "DENY" ? "Deny" : "Permit", c.default_action === "DENY" ? "bad" : "ok") },
      { label: "Used by", render: (c) => `${c.groups} group${c.groups === 1 ? "" : "s"}` },
    ],
    load: () => get("/command-sets"),
    empty: { icon: "list-check", title: "No command sets", text: "Without one, a device admin may run every command their privilege level allows." },
    actions: su ? (c) => [btn("pencil", "Edit", () => edit(c)),
      btn("trash3", "Delete", () => remove(`command set ${c.name}`, `/command-sets/${c.id}`, () => table.load()), "btn-danger-ghost")] : null,
  });
  async function edit(c) {
    const done = await formSheet({ title: `Edit ${c.name}`, wide: true, fields, values: c, submit: (v) => api("PATCH", `/command-sets/${c.id}`, v) });
    if (done) { toast(`Saved ${c.name}`); table.load(); }
  }
  async function add() {
    const done = await formSheet({ title: "New command set", wide: true, fields, label: "Create",
      values: { default_action: "DENY", rules: [{ action: "PERMIT", pattern: "show *" }] }, submit: (v) => api("POST", "/command-sets", v) });
    if (done) { toast(`Created ${done.name}`); table.load(); }
  }
  await table.mount(root, su ? [primary("Add command set", add)] : []);
}
