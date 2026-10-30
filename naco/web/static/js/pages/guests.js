import { TableView, api, can, confirm, fail, fmt, get, h, pill, toast } from "/static/js/app.js";
import { btn, formSheet, primary, segmented } from "/static/js/ui.js";

export default async function (root) {
  let active = "true";
  const table = new TableView({
    search: false,
    columns: [
      { label: "Device", render: (g) => h("span.mono", g.mac_address) },
      { label: "Guest", render: (g) => [g.full_name || h("span.faint", "anonymous"), g.email ? h("div.small.muted", g.email) : null] },
      { label: "Registered", render: (g) => [fmt.dt(g.created_at), h("div.small.muted", g.created_by === "portal" ? "via portal" : `by ${g.created_by}`)] },
      { label: "Expires", render: (g) => g.revoked_at ? h("span.muted", "revoked") : h("span", { title: fmt.dt(g.expires_at) }, fmt.rel(g.expires_at)) },
      { label: "Status", render: (g) => pill(g.active ? "Active" : g.revoked_at ? "Revoked" : "Expired", g.active ? "ok" : "") },
    ],
    load: ({ page, perPage }) => get(`/guests?page=${page}&per_page=${perPage}${active ? `&active=${active}` : ""}`),
    empty: { icon: "person-badge", title: "No guests", text: "Guests register on the portal, or an operator can add a device here." },
    actions: can("OPERATOR") ? (g) => g.active ? [btn("x-lg", "Revoke", async () => {
      if (!(await confirm(`Revoke guest access for ${g.mac_address}? The device is disconnected.`, { label: "Revoke" }))) return;
      try { await api("DELETE", `/guests/${g.id}`); toast("Guest access revoked"); table.load(); } catch (err) { fail(err); }
    }, "btn-danger-ghost")] : [] : null,
    filters: [segmented([["true", "Active"], ["", "All"], ["false", "Ended"]], active, (v) => { active = v; table.page = 1; table.load(); })],
  });
  async function add() {
    const done = await formSheet({
      title: "Add guest device", label: "Grant access",
      fields: [
        { name: "mac_address", label: "MAC address", required: true, mono: true },
        { name: "hours", label: "Hours", type: "number", min: 1, max: 720, value: 8 },
        { name: "full_name", label: "Name" }, { name: "email", label: "Email", type: "email" },
      ],
      submit: (v) => api("POST", "/guests", v),
    });
    if (done) { toast(`Guest access granted to ${done.mac_address}`); table.load(); }
  }
  await table.mount(root, can("OPERATOR") ? [primary("Add guest", add)] : []);
}
