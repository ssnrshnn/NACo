import { TableView, api, clear, confirm, fail, fmt, get, h, me, pill, toast } from "/static/js/app.js";
import { btn, formSheet } from "/static/js/ui.js";

export default async function (root) {
  const info = await get("/auth/me");
  const totp = h("div");
  const drawTotp = (enabled) => {
    clear(totp);
    totp.append(h("p", "Two-factor authentication ", enabled ? pill("on", "ok") : pill("off", "warn")));
    if (enabled) {
      const off = h("button.btn.btn-ghost", { type: "button" }, "Turn off…");
      off.addEventListener("click", async () => {
        const done = await formSheet({ title: "Turn off two-factor", label: "Turn off", intro: "You will have to enroll again before using the panel if your organisation requires it.",
          fields: [{ name: "password", label: "Password", type: "password", full: true }, { name: "code", label: "Current code", full: true, mono: true }],
          submit: (v) => api("POST", "/auth/totp/disable", v) });
        if (done) location.href = "/setup";
      });
      totp.append(off);
    } else totp.append(h("a.btn.btn-accent", { href: "/setup" }, "Set up"));
  };
  drawTotp(info.totp_enabled);

  const change = h("button.btn.btn-ghost", { type: "button" }, "Change password…");
  change.addEventListener("click", async () => {
    const done = await formSheet({ title: "Change password", label: "Change", fields: [
      { name: "current_password", label: "Current password", type: "password", full: true, autocomplete: "current-password" },
      { name: "new_password", label: "New password (12+ characters)", type: "password", full: true, autocomplete: "new-password" },
    ], submit: (v) => api("POST", "/auth/password", v) });
    if (done) toast("Password changed — your other sessions were signed out");
  });

  const sessions = new TableView({
    search: false,
    columns: [
      { label: "Signed in", render: (s) => [fmt.dt(s.created_at), s.current ? h("span.small.text-success", " · this browser") : null] },
      { label: "Last active", render: (s) => fmt.rel(s.last_seen_at) },
      { label: "From", render: (s) => [h("span.mono", s.ip || "—"), h("div.small.muted.text-truncate", { title: s.user_agent }, s.user_agent)] },
    ],
    load: () => get("/auth/sessions"),
    actions: (s) => s.current ? [] : [btn("box-arrow-right", "Sign out this session", async () => {
      if (!(await confirm("Sign out that session?", { label: "Sign out", danger: false }))) return;
      try { await api("DELETE", `/auth/sessions/${s.id}`); toast("Session ended"); sessions.load(); } catch (err) { fail(err); }
    })],
  });
  const sessionBox = h("div");
  root.append(h("div.grid.cols-2.mb-3",
    h("section.panel.reveal", h("div.panel-head", h("h2", me.username), h("span.spacer"), pill(info.role.toLowerCase(), "accent")),
      h("div.panel-body", h("p.muted", "Your password is never shown or stored in readable form."), change)),
    h("section.panel.reveal", h("div.panel-head", h("h2", "Two-factor authentication")), h("div.panel-body", totp))),
    h("h2.h6.mt-4.mb-2", "Active sessions"), sessionBox);
  await sessions.mount(sessionBox);
}
