import { TableView, api, can, fail, fmt, get, h, pill, showSecret, toast } from "/static/js/app.js";
import { btn, csvExport, csvImport, formSheet, primary, remove, secretField } from "/static/js/ui.js";

export default async function (root) {
  const su = can("SUPERUSER");
  const vendors = await get("/nas/vendors");
  const vendorName = Object.fromEntries(vendors.map((v) => [v.key, v.label.split(" (")[0].split(" — ")[0]]));
  const fields = (editing) => [
    { name: "name", label: "Name", required: true, placeholder: "core-sw01" },
    { name: "ip_address", label: "IP address or network", required: true, mono: true, placeholder: "10.0.0.1 or 10.0.20.0/24",
      help: "A network covers devices that each send RADIUS themselves — access points, cloud-managed switches. One address always wins over a network." },
    secretField("Shared secret", editing ? "Leave empty to keep the current secret." : "Configure the same secret on the switch or controller."),
    { name: "vendor", label: "Device type", type: "select", options: vendors.map((v) => [v.key, v.label]),
      help: "Decides what a disconnect request (CoA) carries — vendors accept different attributes. See docs/network-devices.md." },
    { name: "coa_port", label: "CoA port", type: "number", min: 1, max: 65535, nullable: true,
      placeholder: editing ? "" : "the device type's default (3799; Meraki 1700)" },
    { name: "description", label: "Description" },
    { name: "require_message_authenticator", label: "Require Message-Authenticator (recommended)", type: "switch", value: true },
    { name: "enabled", label: "Enabled", type: "switch", value: true },
  ];
  const table = new TableView({
    search: false,
    columns: [
      { label: "Name", render: (n) => [h("b", n.name), n.description ? h("div.small.muted", n.description) : null] },
      { label: "Address", render: (n) => h("span.mono", n.ip_address) },
      { label: "Type", render: (n) => h("span.small", vendorName[n.vendor] || n.vendor) },
      { label: "CoA", render: (n) => h("span.mono", n.coa_port) },
      { label: "Security", render: (n) => n.require_message_authenticator ? pill("Message-Authenticator", "ok") : pill("Legacy NAS", "warn") },
      { label: "Status", render: (n) => pill(n.enabled ? "Enabled" : "Disabled", n.enabled ? "ok" : "bad") },
      { label: "Added", render: (n) => h("span.muted", fmt.dt(n.created_at)) },
    ],
    load: () => get("/nas"),
    empty: { icon: "router", title: "No RADIUS clients yet", text: "Add every switch, AP or controller that should ask NACo who may connect." },
    actions: su ? (n) => [
      btn("eye", "Show secret", async () => { try { showSecret(`${n.name} shared secret`, (await get(`/nas/${n.id}/secret`)).secret, "Viewing a secret is recorded in the audit log."); } catch (err) { fail(err); } }),
      btn("pencil", "Edit", () => edit(n)),
      btn("trash3", "Delete", () => remove(`RADIUS client ${n.name}`, `/nas/${n.id}`, () => table.load()), "btn-danger-ghost"),
    ] : null,
  });
  async function edit(n) {
    const done = await formSheet({ title: `Edit ${n.name}`, fields: fields(n), values: n, submit: (v) => api("PATCH", `/nas/${n.id}`, v) });
    if (done) { toast(`Saved ${n.name}`); table.load(); }
  }
  async function add() {
    const done = await formSheet({ title: "Add RADIUS client", fields: fields(null), label: "Add", submit: (v) => api("POST", "/nas", v) });
    if (done) { toast(`Added ${done.name} — now configure the same secret on the device`); table.load(); }
  }
  const extra = [csvExport("nas")];
  if (su) extra.push(csvImport("nas", "name,ip_address,secret,vendor,description,coa_port,enabled", () => table.load()), primary("Add client", add));
  await table.mount(root, extra);
}
