import { TableView, api, can, get, h, pill, toast } from "/static/js/app.js";
import { btn, formSheet, primary, remove } from "/static/js/ui.js";

export default async function (root) {
  const sets = await get("/command-sets");
  const setOptions = [["", "— none: all commands at this privilege —"], ...sets.map((s) => [s.id, s.name])];
  const setName = Object.fromEntries(sets.map((s) => [s.id, s.name]));

  const fields = [
    { name: "name", label: "Name", required: true },
    { name: "description", label: "Description" },
    { name: "device_admin_privilege", label: "Device-admin privilege (TACACS+)", type: "select", nullable: true, numeric: true,
      options: [["", "None — no switch logins"], ...Array.from({ length: 15 }, (_, i) => [i + 1, `Level ${i + 1}${i === 14 ? " (full)" : ""}`])],
      help: "Members may log in to network devices up to this privilege level." },
    { name: "command_set_id", label: "Command set", type: "select", options: setOptions, nullable: true, numeric: true },
    { name: "device_admin_attributes", label: "TACACS+ attributes for other vendors", type: "textarea", rows: 3,
      placeholder: "junos-exec: local-user-name=super-user\nfortigate: admin_prof=super_admin",
      help: "One 'service: attribute=value' per line, for devices that ask for another service than Cisco's shell (Juniper, Fortinet, Dell OS10 …). A service with no line is refused." },
  ];
  const lines = (text) => (text || "").split("\n").map((l) => l.trim()).filter(Boolean);
  const services = (g) => [...new Set((g.device_admin_attributes || []).map((l) => l.split(":")[0]))];

  const table = new TableView({
    search: false,
    columns: [
      { label: "Group", render: (g) => [h("b", g.name), g.description ? h("div.small.muted", g.description) : null] },
      { label: "Members", render: (g) => g.members.toLocaleString() },
      { label: "Device administration", render: (g) => g.device_admin_privilege
        ? [pill(`Privilege ${g.device_admin_privilege}`, "accent"), " ", g.command_set_id ? h("span.chip", setName[g.command_set_id]) : h("span.small.muted", "all commands"),
          ...services(g).map((s) => [" ", h("span.chip.mono", s)])]
        : h("span.faint", "—") },
    ],
    load: () => get("/groups"),
    empty: { icon: "people-fill", title: "No groups yet", text: "Groups are what policies match on — e.g. staff, contractors, network admins." },
    actions: can("SUPERUSER") ? (g) => [
      btn("pencil", "Edit", () => edit(g)),
      btn("trash3", "Delete", () => remove(`group ${g.name}`, `/groups/${g.id}`, () => table.load()), "btn-danger-ghost"),
    ] : null,
  });

  async function edit(g) {
    const done = await formSheet({ title: `Edit ${g.name}`, fields,
      values: { ...g, device_admin_privilege: g.device_admin_privilege ?? "", command_set_id: g.command_set_id ?? "",
                device_admin_attributes: (g.device_admin_attributes || []).join("\n") },
      submit: (v) => api("PATCH", `/groups/${g.id}`, { ...v, device_admin_attributes: lines(v.device_admin_attributes) }) });
    if (done) { toast(`Saved ${g.name}`); table.load(); }
  }
  async function add() {
    const done = await formSheet({ title: "Add group", fields, label: "Create",
      submit: (v) => api("POST", "/groups", { ...v, device_admin_attributes: lines(v.device_admin_attributes) }) });
    if (done) { toast(`Created ${done.name}`); table.load(); }
  }
  await table.mount(root, can("SUPERUSER") ? [primary("Add group", add)] : []);
}
