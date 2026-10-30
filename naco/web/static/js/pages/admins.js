import { TableView, api, confirm, fail, fmt, get, h, me, pill, showSecret, toast } from "/static/js/app.js";
import { btn, formSheet, primary, remove } from "/static/js/ui.js";

const ROLES = [["VIEWER", "Viewer — read only"], ["OPERATOR", "Operator — users, devices, guests, sessions"], ["SUPERUSER", "Superuser — everything"]];

export default async function (root) {
  const table = new TableView({
    search: false,
    columns: [
      { label: "Administrator", render: (a) => [h("b", a.username), a.username === me.username ? h("span.small.muted", " (you)") : null] },
      { label: "Role", render: (a) => pill(a.role.toLowerCase(), a.role === "SUPERUSER" ? "accent" : "") },
      { label: "Two-factor", render: (a) => a.totp_enabled ? pill("On", "ok") : pill("Off", "warn") },
      { label: "Status", render: (a) => a.must_change_password ? pill("Invited", "warn") : pill(a.enabled ? "Enabled" : "Disabled", a.enabled ? "ok" : "bad") },
      { label: "Last sign-in", render: (a) => h("span.muted", fmt.rel(a.last_login_at)) },
    ],
    load: () => get("/admins"),
    actions: (a) => a.username === me.username ? [] : [
      btn("pencil", "Role & status", () => edit(a)),
      btn("key", "Reset password", async () => {
        if (!(await confirm(`Give ${a.username} a new temporary password? Their sessions end.`, { label: "Reset", danger: false }))) return;
        try { const r = await api("POST", `/admins/${a.id}/reset-password`); showSecret(`Temporary password for ${a.username}`, r.temporary_password, "Share it securely; they must change it at first sign-in."); table.load(); } catch (err) { fail(err); }
      }),
      a.totp_enabled ? btn("shield-lock", "Reset two-factor", async () => {
        if (!(await confirm(`Remove ${a.username}'s two-factor authentication? They enroll again at next sign-in.`, { label: "Reset" }))) return;
        try { await api("POST", `/admins/${a.id}/reset-totp`); toast("Two-factor reset"); table.load(); } catch (err) { fail(err); }
      }) : null,
      btn("trash3", "Delete", () => remove(`administrator ${a.username}`, `/admins/${a.id}`, () => table.load()), "btn-danger-ghost"),
    ],
  });
  async function edit(a) {
    const done = await formSheet({ title: a.username, fields: [{ name: "role", label: "Role", type: "select", options: ROLES, full: true },
      { name: "enabled", label: "Enabled", type: "switch" }], values: a, submit: (v) => api("PATCH", `/admins/${a.id}`, v) });
    if (done) { toast(`Saved ${a.username}`); table.load(); }
  }
  async function add() {
    const r = await formSheet({ title: "Invite administrator", label: "Create",
      fields: [{ name: "username", label: "Username", required: true, full: true }, { name: "role", label: "Role", type: "select", options: ROLES, full: true }],
      values: { role: "OPERATOR" }, submit: (v) => api("POST", "/admins", v) });
    if (r) { showSecret(`Temporary password for ${r.admin.username}`, r.temporary_password, "Share it securely. They choose their own password and set up two-factor at first sign-in."); table.load(); }
  }
  await table.mount(root, [primary("Invite administrator", add)]);
}
