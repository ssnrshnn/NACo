import { TableView, api, can, confirm, fail, fmt, get, h, live, pill, toast } from "/static/js/app.js";
import { btn } from "/static/js/ui.js";

export default async function (root) {
  const table = new TableView({
    columns: [
      { label: "Who", render: (s) => [h("b", s.username || h("span.mono", s.mac_address) || "—"), h("div.small.muted.mono", s.username ? s.mac_address : "")] },
      { label: "Where", render: (s) => [s.nas_name || h("span.mono", s.nas_ip), s.ssid ? h("div.small.muted", s.ssid) : null] },
      { label: "Address", render: (s) => s.framed_ip ? h("span.mono", s.framed_ip) : h("span.faint", "—") },
      { label: "Access", render: (s) => [s.auth_method ? h("span.chip", s.auth_method) : null, s.vlan ? pill(`VLAN ${s.vlan}`, "accent") : null,
        s.policy_name ? h("div.small.muted", s.policy_name) : null] },
      { label: "Online", render: (s) => h("span", { title: `since ${fmt.dt(s.started_at)}` }, fmt.duration(s.session_time || (Date.now() - new Date(s.started_at)) / 1000)) },
      { label: "Traffic", render: (s) => h("span.small.muted", `↓ ${fmt.bytes(s.input_octets)} · ↑ ${fmt.bytes(s.output_octets)}`) },
    ],
    load: ({ page, perPage, q }) => get(`/sessions?page=${page}&per_page=${perPage}&q=${encodeURIComponent(q)}`),
    empty: { icon: "activity", title: "Nobody online", text: "Sessions appear when switches send RADIUS accounting." },
    actions: can("OPERATOR") ? (s) => [btn("plug", "Disconnect", async () => {
      if (!(await confirm(`Disconnect ${s.username || s.mac_address}? The device will reconnect and be checked again.`, { label: "Disconnect" }))) return;
      try {
        const r = await api("POST", `/sessions/${s.id}/disconnect`);
        r.acked ? toast("Disconnected") : toast(r.skipped ? "NAS is not registered — cannot send CoA" : "The NAS did not confirm the disconnect", "bad");
        setTimeout(() => table.load(), 1200);
      } catch (err) { fail(err); }
    }, "btn-danger-ghost")] : null,
  });
  await table.mount(root);
  let timer;
  live("accounting", () => { clearTimeout(timer); timer = setTimeout(() => table.load(), 800); });
}
