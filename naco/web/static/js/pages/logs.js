import { TableView, clear, fmt, get, h, live, resultPill } from "/static/js/app.js";
import { segmented } from "/static/js/ui.js";

export default async function (root) {
  let result = "";
  const radius = new TableView({
    columns: [
      { label: "Time", render: (l) => h("span.muted.text-nowrap", { title: fmt.dt(l.timestamp) }, fmt.time(l.timestamp)) },
      { label: "Result", render: (l) => resultPill(l.result) },
      { label: "Who", render: (l) => [l.username ? h("b", l.username) : null, l.mac_address ? h("div.small.mono.muted", l.mac_address) : null] },
      { label: "Where", render: (l) => [l.nas_name || h("span.mono", l.nas_ip || "—"), l.ssid ? h("div.small.muted", l.ssid) : null] },
      { label: "Method", render: (l) => l.auth_method ? h("span.chip", l.auth_method) : "" },
      { label: "Why", render: (l) => [l.reason, l.vlan ? h("div.small.muted", `VLAN ${l.vlan}`) : null] },
    ],
    load: ({ page, perPage, q }) => get(`/logs/auth?page=${page}&per_page=${perPage}&q=${encodeURIComponent(q)}${result ? `&result=${result}` : ""}`),
    empty: { icon: "journal-text", title: "No authentications yet" },
    filters: [segmented([["", "All"], ["ACCEPT", "Accepted"], ["REJECT", "Rejected"]], "", (v) => { result = v; radius.page = 1; radius.load(); })],
  });
  const tacacs = new TableView({
    columns: [
      { label: "Time", render: (l) => h("span.muted.text-nowrap", { title: fmt.dt(l.timestamp) }, fmt.time(l.timestamp)) },
      { label: "Result", render: (l) => resultPill(l.result) },
      { label: "Kind", render: (l) => h("span.chip", { AUTHEN: "login", AUTHOR: "command", ACCT: "accounting" }[l.kind] || l.kind) },
      { label: "Who", render: (l) => [h("b", l.username || "—"), h("div.small.muted.mono", l.client_ip)] },
      { label: "Command", render: (l) => h("span.mono", l.command) },
      { label: "Why", render: (l) => h("span.muted", l.reason) },
    ],
    load: ({ page, perPage, q }) => get(`/logs/tacacs?page=${page}&per_page=${perPage}&q=${encodeURIComponent(q)}`),
    empty: { icon: "terminal", title: "No TACACS+ activity yet" },
  });
  const body = h("div");
  const show = (which) => { clear(body); (which === "tacacs" ? tacacs : radius).mount(body); current = which; };
  let current = "radius";
  root.append(h("div.mb-3", segmented([["radius", "RADIUS"], ["tacacs", "TACACS+"]], "radius", show)), body);
  show("radius");
  live("auth", (e) => {
    if (current !== "radius" || radius.page !== 1 || radius.q || (result && result !== e.result)) return;
    radius.prepend({ ...e, timestamp: e.ts, mac_address: e.mac, nas_name: e.nas, auth_method: e.method, policy_name: e.policy });
  });
  live("tacacs", (e) => {
    if (current !== "tacacs" || tacacs.page !== 1 || tacacs.q) return;
    tacacs.prepend({ ...e, timestamp: e.ts, client_ip: e.device, kind: { authen: "AUTHEN", author: "AUTHOR", acct: "ACCT" }[e.kind] || e.kind });
  });
}
