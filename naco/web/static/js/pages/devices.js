import { TableView, api, can, fail, fmt, get, h, live, pill, toast } from "/static/js/app.js";
import { btn, csvExport, csvImport, formSheet, primary, remove, segmented } from "/static/js/ui.js";

const STATUS = { APPROVED: ["Approved", "ok"], PENDING: ["Pending", "warn"], BLOCKED: ["Blocked", "bad"] };

export default async function (root) {
  const params = new URLSearchParams(location.search);
  let status = params.get("status") || "";

  const fields = (editing) => [
    ...(editing ? [] : [{ name: "mac_address", label: "MAC address", required: true, mono: true, placeholder: "aa:bb:cc:dd:ee:ff" }]),
    { name: "status", label: "Status", type: "select", options: [["APPROVED", "Approved"], ["PENDING", "Pending"], ["BLOCKED", "Blocked"]] },
    { name: "device_type", label: "Type", placeholder: "printer, phone, camera…" },
    { name: "description", label: "Description", full: true },
    { name: "notes", label: "Notes", type: "textarea" },
  ];

  const setStatus = async (d, s) => {
    try { await api("PATCH", `/devices/${d.id}`, { status: s }); toast(`${d.mac_address} ${STATUS[s][0].toLowerCase()}`); table.load(); }
    catch (err) { fail(err); }
  };

  const table = new TableView({
    columns: [
      { label: "Device", render: (d) => [h("span.mono", d.mac_address), h("div.small.muted", d.vendor || (d.randomized ? "Private (randomised) address" : "Unknown vendor"))] },
      { label: "Status", render: (d) => pill(...STATUS[d.status]) },
      { label: "Type", render: (d) => d.device_type || h("span.faint", "—") },
      { label: "Description", render: (d) => d.description || h("span.faint", "—") },
      { label: "Last seen", render: (d) => [h("span", { title: fmt.dt(d.last_seen) }, fmt.rel(d.last_seen)),
        h("div.small.muted", [d.last_username, d.last_nas_ip].filter(Boolean).join(" · "))] },
    ],
    load: ({ page, perPage, q }) => get(`/devices?page=${page}&per_page=${perPage}&q=${encodeURIComponent(q)}${status ? `&status=${status}` : ""}`),
    empty: { icon: "pc-display", title: "No devices", text: "Devices appear here automatically the first time they try to connect." },
    actions: can("OPERATOR") ? (d) => [
      d.status !== "APPROVED" ? btn("check-lg", "Approve", () => setStatus(d, "APPROVED")) : null,
      d.status !== "BLOCKED" ? btn("slash-circle", "Block", () => setStatus(d, "BLOCKED"), "btn-danger-ghost") : null,
      btn("pencil", "Edit", () => edit(d)),
      btn("trash3", "Delete", () => remove(`device ${d.mac_address}`, `/devices/${d.id}`, () => table.load()), "btn-danger-ghost"),
    ] : null,
    filters: [segmented([["", "All"], ["PENDING", "Pending"], ["APPROVED", "Approved"], ["BLOCKED", "Blocked"]], status,
      (v) => { status = v; table.page = 1; history.replaceState(null, "", v ? `?status=${v}` : location.pathname); table.load(); })],
  });

  async function edit(d) {
    const done = await formSheet({ title: d.mac_address, fields: fields(d), values: d, submit: (v) => api("PATCH", `/devices/${d.id}`, v) });
    if (done) { toast("Saved"); table.load(); }
  }
  async function add() {
    const done = await formSheet({ title: "Add device", fields: fields(null), values: { status: "APPROVED" }, label: "Add",
      submit: (v) => api("POST", "/devices", v) });
    if (done) { toast(`Added ${done.mac_address}`); table.load(); }
  }

  const extra = [csvExport("devices")];
  if (can("OPERATOR")) extra.push(csvImport("devices", "mac_address,status,device_type,description,notes", () => table.load()), primary("Add device", add));
  await table.mount(root, extra);
  if (params.get("q")) { root.querySelector(".search input").value = params.get("q"); table.q = params.get("q"); table.load(); }
  live("device", () => table.page === 1 && !table.q && table.load());
}
