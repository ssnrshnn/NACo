import { barChart, countUp, fmt, get, h, icon, live, resultPill } from "/static/js/app.js";

const KPIS = [
  ["users", "Users", "people", "/users"],
  ["devices", "Devices", "pc-display", "/devices"],
  ["pending_devices", "Awaiting approval", "hourglass-split", "/devices?status=PENDING", "warn"],
  ["sessions", "Online now", "activity", "/sessions"],
  ["guests", "Guests", "person-badge", "/guests"],
  ["blocked_devices", "Blocked", "slash-circle", "/devices?status=BLOCKED", "bad"],
];

function feedItem(e) {
  const ok = e.result === "ACCEPT";
  const who = e.username || e.mac || e.mac_address || "unknown";
  const where = [e.nas || e.nas_name, e.ssid, e.method || e.auth_method].filter(Boolean).join(" · ");
  return h("li", resultPill(e.result),
    h("div.what", h("b", who), h("small", ok ? `${e.policy || e.policy_name || ""}${e.vlan ? ` → VLAN ${e.vlan}` : ""} ${where ? `· ${where}` : ""}` : `${e.reason} ${where ? `· ${where}` : ""}`)),
    h("time", fmt.time(e.ts || e.timestamp)));
}

export default async function (root) {
  const tiles = KPIS.map(([key, label, ic, href, tone]) => {
    const value = h("div.value", { dataset: { key } }, h("span.skeleton.d-inline-block", { class: "w-50" }, " "));
    return h(`a.panel.kpi.reveal${tone ? `.${tone}` : ""}`, { href }, icon(ic), h("div.label", label), value);
  });
  const chart = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  chart.setAttribute("class", "chart");
  chart.setAttribute("role", "img");
  chart.setAttribute("aria-label", "Authentications per hour over the last 24 hours");
  const feed = h("ul.feed");
  const checklist = h("ul.checklist");
  const ring = h("div.progress-ring");
  const setupPanel = h("section.panel.reveal.hidden", h("div.panel-head", ring, h("div", h("h2", "Getting started"), h("small.muted", "A few steps to a working NAC"))),
    h("div.panel-body", checklist));

  root.append(
    h("div.grid.kpis.mb-3", tiles),
    setupPanel,
    h("div.grid.cols-2.mt-3",
      h("section.panel.reveal", h("div.panel-head", h("h2", "Last 24 hours"), h("span.spacer"),
        h("div.legend", h("span.ok", "Accepted"), h("span.bad", "Rejected"))), h("div.panel-body", chart)),
      h("section.panel.reveal", h("div.panel-head", h("h2", "Live activity"), h("span.spacer"), h("a.small", { href: "/logs" }, "All logs")), feed)),
  );

  const refresh = async () => {
    const d = await get("/dashboard");
    for (const el of root.querySelectorAll(".kpi .value")) countUp(el, d.counts[el.dataset.key]);
    barChart(chart, d.last_24h);
    return d;
  };

  const d = await refresh();
  feed.append(...d.recent.map(feedItem));
  if (!d.recent.length) feed.append(h("li.empty.d-block", h("p.mb-0", "No authentications yet. Point a switch at NACo to see them appear here live.")));
  const links = { nas: "/nas", policy: "/policies", radius: "/logs", totp: "/account" };
  const done = d.checklist.filter((c) => c.done).length;
  if (done < d.checklist.length) {
    setupPanel.classList.remove("hidden");
    ring.style.setProperty("--p", Math.round((done / d.checklist.length) * 100));
    ring.dataset.label = `${done}/${d.checklist.length}`;
    checklist.append(...d.checklist.map((c) => h(`li${c.done ? ".done" : ""}`, icon(c.done ? "check-circle-fill" : "chevron-right"),
      c.done ? h("span", c.label) : h("a", { href: links[c.key] }, c.label))));
  }

  let pending = null;
  const later = () => { clearTimeout(pending); pending = setTimeout(refresh, 1500); };
  live("auth", (e) => {
    feed.querySelector(".empty")?.remove();
    const li = feedItem(e);
    li.classList.add("enter");
    feed.prepend(li);
    while (feed.children.length > 15) feed.lastElementChild.remove();
    later();
  });
  live("accounting", later);
  live("device", later);
}
