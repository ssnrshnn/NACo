import { TableView, api, can, fail, fmt, get, h, pill, showSecret, toast } from "/static/js/app.js";
import { btn, formSheet, primary, remove, secretField } from "/static/js/ui.js";

export default async function (root) {
  const su = can("SUPERUSER");
  const fields = (editing) => [
    { name: "name", label: "Name", required: true, placeholder: "core-sw01" },
    { name: "ip_address", label: "IP address", required: true, mono: true },
    { ...secretField("Key", editing ? "Leave empty to keep the current key." : "The TACACS+ key configured on the device."), name: "key" },
    { name: "description", label: "Description" },
    { name: "enabled", label: "Enabled", type: "switch", value: true },
  ];
  const table = new TableView({
    search: false,
    columns: [
      { label: "Name", render: (t) => [h("b", t.name), t.description ? h("div.small.muted", t.description) : null] },
      { label: "Address", render: (t) => h("span.mono", t.ip_address) },
      { label: "Status", render: (t) => pill(t.enabled ? "Enabled" : "Disabled", t.enabled ? "ok" : "bad") },
      { label: "Added", render: (t) => h("span.muted", fmt.dt(t.created_at)) },
    ],
    load: () => get("/tacacs-clients"),
    empty: { icon: "terminal", title: "No TACACS+ clients", text: "Add switches and routers whose administrators should sign in with NACo accounts." },
    actions: su ? (t) => [
      btn("eye", "Show key", async () => { try { showSecret(`${t.name} key`, (await get(`/tacacs-clients/${t.id}/key`)).key, "Viewing a key is recorded in the audit log."); } catch (err) { fail(err); } }),
      btn("pencil", "Edit", () => edit(t)),
      btn("trash3", "Delete", () => remove(`TACACS+ client ${t.name}`, `/tacacs-clients/${t.id}`, () => table.load()), "btn-danger-ghost"),
    ] : null,
  });
  async function edit(t) {
    const done = await formSheet({ title: `Edit ${t.name}`, fields: fields(t), values: t, submit: (v) => api("PATCH", `/tacacs-clients/${t.id}`, v) });
    if (done) { toast(`Saved ${t.name}`); table.load(); }
  }
  async function add() {
    const done = await formSheet({ title: "Add TACACS+ client", fields: fields(null), label: "Add", submit: (v) => api("POST", "/tacacs-clients", v) });
    if (done) { toast(`Added ${done.name}`); table.load(); }
  }
  await table.mount(root, su ? [primary("Add client", add)] : []);
}
