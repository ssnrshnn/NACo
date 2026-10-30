import { TableView, api, can, fail, fmt, get, h, pill, toast } from "/static/js/app.js";
import { btn, csvExport, csvImport, formSheet, primary, remove } from "/static/js/ui.js";

export default async function (root) {
  const groups = await get("/groups");
  const groupOptions = [["", "— no group —"], ...groups.map((g) => [g.id, g.device_admin_privilege ? `${g.name} (device admin)` : g.name])];
  const params = new URLSearchParams(location.search);

  const fields = (editing) => [
    ...(editing ? [] : [{ name: "username", label: "Username", required: true, autocomplete: "off" }]),
    { name: "full_name", label: "Full name" },
    { name: "email", label: "Email", type: "email" },
    { name: "group_id", label: "Group", type: "select", options: groupOptions, nullable: true, numeric: true },
    ...(editing?.source === "LDAP" ? [] : [{ name: "password", label: editing ? "New password" : "Password", type: "password",
      help: editing ? "Leave empty to keep the current password." : "At least 8 characters.", autocomplete: "new-password" }]),
    { name: "enabled", label: "Enabled", type: "switch", value: true },
  ];

  const table = new TableView({
    columns: [
      { label: "User", render: (u) => [h("b", u.username), u.full_name ? h("div.small.muted", u.full_name) : null] },
      { label: "Group", render: (u) => u.group_name ? h("span.chip", u.group_name) : h("span.faint", "—") },
      { label: "Source", render: (u) => pill(u.source === "LDAP" ? "Directory" : "Local", u.source === "LDAP" ? "accent" : "") },
      { label: "Status", render: (u) => pill(u.enabled ? "Enabled" : "Disabled", u.enabled ? "ok" : "bad") },
      { label: "Last sign-in", render: (u) => h("span.muted", { title: fmt.dt(u.last_login_at) }, fmt.rel(u.last_login_at)) },
    ],
    load: ({ page, perPage, q }) => get(`/users?page=${page}&per_page=${perPage}&q=${encodeURIComponent(q)}`),
    empty: { icon: "people", title: "No users yet", text: "Add users here, import a CSV, or connect LDAP / Active Directory." },
    actions: can("OPERATOR") ? (u) => [
      btn("pencil", "Edit", () => edit(u)),
      btn("trash3", "Delete", () => remove(`user ${u.username}`, `/users/${u.id}`, () => table.load()), "btn-danger-ghost"),
    ] : null,
  });

  async function edit(u) {
    const done = await formSheet({
      title: `Edit ${u.username}`, fields: fields(u), values: { ...u, group_id: u.group_id ?? "" },
      submit: (v) => { if (!v.password) delete v.password; return api("PATCH", `/users/${u.id}`, v); },
    });
    if (done) { toast(`Saved ${u.username}`); table.load(); }
  }

  async function add() {
    const done = await formSheet({ title: "Add user", fields: fields(null), label: "Create", submit: (v) => api("POST", "/users", v) });
    if (done) { toast(`Created ${done.username}`); table.load(); }
  }

  const extra = [csvExport("users")];
  if (can("OPERATOR")) extra.push(csvImport("users", "username,password,email,full_name,group,enabled", () => table.load()), primary("Add user", add));
  await table.mount(root, extra);
  if (params.get("q")) { root.querySelector(".search input").value = params.get("q"); table.q = params.get("q"); table.load().catch(fail); }
}
