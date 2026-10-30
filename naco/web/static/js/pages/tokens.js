import { TableView, api, confirm, fail, fmt, get, h, pill, showSecret, toast } from "/static/js/app.js";
import { btn, formSheet, primary } from "/static/js/ui.js";

export default async function (root) {
  const table = new TableView({
    search: false,
    columns: [
      { label: "Token", render: (t) => [h("b", t.name), h("div.small.mono.muted", `${t.prefix}…`)] },
      { label: "Role", render: (t) => pill(t.role.toLowerCase(), t.role === "SUPERUSER" ? "accent" : "") },
      { label: "Created", render: (t) => [fmt.dt(t.created_at), h("div.small.muted", `by ${t.created_by}`)] },
      { label: "Expires", render: (t) => t.expires_at ? fmt.rel(t.expires_at) : h("span.muted", "never") },
      { label: "Last used", render: (t) => h("span.muted", fmt.rel(t.last_used_at)) },
      { label: "Status", render: (t) => t.revoked_at ? pill("Revoked", "bad") : t.expires_at && new Date(t.expires_at) < new Date() ? pill("Expired") : pill("Active", "ok") },
    ],
    load: () => get("/tokens"),
    empty: { icon: "key", title: "No API tokens", text: "Create one for scripts, CI or monitoring — never share an admin password." },
    actions: (t) => t.revoked_at ? [] : [btn("x-lg", "Revoke", async () => {
      if (!(await confirm(`Revoke ${t.name}? Anything using it stops working immediately.`, { label: "Revoke" }))) return;
      try { await api("DELETE", `/tokens/${t.id}`); toast("Token revoked"); table.load(); } catch (err) { fail(err); }
    }, "btn-danger-ghost")],
  });
  async function add() {
    const r = await formSheet({ title: "Create API token", label: "Create", fields: [
      { name: "name", label: "Name", required: true, placeholder: "ci-deploy", full: true },
      { name: "role", label: "Role", type: "select", options: [["VIEWER", "Viewer"], ["OPERATOR", "Operator"], ["SUPERUSER", "Superuser"]] },
      { name: "expires_days", label: "Expires after (days)", type: "number", min: 1, max: 3650, value: 90 },
    ], values: { role: "VIEWER" }, submit: (v) => api("POST", "/tokens", v) });
    if (r) { showSecret(`Token ${r.token.name}`, r.secret, "Copy it now — it is never shown again. Use it as: Authorization: Bearer <token>. The API is described at /api/v1/openapi.json."); table.load(); }
  }
  await table.mount(root, [primary("Create token", add)]);
}
