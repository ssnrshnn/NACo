import { TableView, fmt, get, h, live } from "/static/js/app.js";

const fmtChange = ([k, v]) => Array.isArray(v) && v.length === 2 ? `${k}: ${JSON.stringify(v[0])} → ${JSON.stringify(v[1])}` : `${k}: ${JSON.stringify(v)}`;

export default async function (root) {
  const table = new TableView({
    columns: [
      { label: "Time", render: (a) => h("span.muted.text-nowrap", fmt.dt(a.timestamp)) },
      { label: "Who", render: (a) => [h("b", a.actor), h("div.small.muted", [a.actor_type.toLowerCase(), a.ip].filter(Boolean).join(" · "))] },
      { label: "Action", render: (a) => h("span.chip.mono", a.action) },
      { label: "Target", render: (a) => a.target_name || a.target_id || h("span.faint", "—") },
      { label: "Changes", render: (a) => {
        const entries = Object.entries(a.changes || {});
        if (!entries.length) return h("span.faint", "—");
        return h("details", h("summary.small", `${entries.length} field${entries.length === 1 ? "" : "s"}`),
          h("ul.small.mono.mb-0.ps-3", entries.map((e) => h("li", fmtChange(e)))));
      } },
    ],
    load: ({ page, perPage, q }) => get(`/audit?page=${page}&per_page=${perPage}&q=${encodeURIComponent(q)}`),
    empty: { icon: "clock-history", title: "No changes recorded yet" },
  });
  await table.mount(root);
  live("audit", () => table.page === 1 && !table.q && table.load());
}
