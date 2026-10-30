import { fmt, get, h, pill } from "/static/js/app.js";

export default async function (root) {
  const s = await get("/system");
  const radius = { active: pill("Receiving requests", "ok"), idle: pill("Idle for 10+ minutes", "warn"), never: pill("No requests yet", "warn") }[s.radius];
  const row = (k, v) => h("div.d-flex.justify-content-between.py-2.border-bottom", h("span.muted", k), h("span", v));
  const settings = Object.entries(s.settings).map(([k, v]) => row(k.replaceAll("_", " "),
    typeof v === "boolean" ? pill(v ? "on" : "off", v ? "ok" : "") : v === null ? h("span.faint", "—") :
      typeof v === "object" ? h("span.mono.small", Array.isArray(v) ? v.join(", ") || "—" : Object.entries(v).map(([a, b]) => `${a}: ${b}`).join(" · ")) : h("span.mono", String(v))));
  root.append(h("div.grid.cols-2",
    h("section.panel.reveal", h("div.panel-head", h("h2", "Status")), h("div.panel-body",
      row("Version", h("span.mono", s.version)), row("Running since", `${fmt.dt(s.started_at)} (${fmt.duration(s.uptime_seconds)})`),
      row("Time zone", s.timezone), row("Database", fmt.bytes(s.database_bytes)),
      row("FreeRADIUS", radius), row("Last RADIUS request", fmt.rel(s.radius_last_request)))),
    h("section.panel.reveal", h("div.panel-head", h("h2", "Configuration"), h("span.spacer"), h("span.small.muted", "read-only · config.yaml")),
      h("div.panel-body", settings))));
}
