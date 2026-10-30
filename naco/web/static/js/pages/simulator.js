import { api, clear, fail, get, h, icon, pill } from "/static/js/app.js";

export default async function (root) {
  const nas = await get("/nas");
  const method = h("select.form-select", ["PEAP", "EAP-TLS", "EAP-TTLS", "PAP", "MAB"].map((m) => h("option", { value: m }, m)));
  const username = h("input.form-control", { placeholder: "alice" });
  const mac = h("input.form-control.mono", { placeholder: "aa:bb:cc:dd:ee:ff" });
  const nasSel = h("select.form-select", h("option", { value: "" }, "— any —"), nas.map((n) => h("option", { value: n.name }, n.name)));
  const ssid = h("input.form-control", { placeholder: "Corp" });
  const at = h("input.form-control", { type: "datetime-local" });
  const userWrap = h("div", h("label.form-label", "Username"), username);
  method.addEventListener("change", () => userWrap.classList.toggle("hidden", method.value === "MAB"));
  const run = h("button.btn.btn-accent.w-100", { type: "submit" }, icon("lightning-charge"), " Simulate");
  const form = h("form.panel.reveal", h("div.panel-head", h("h2", "Request")),
    h("div.panel-body.d-grid.gap-3",
      h("div", h("label.form-label", "Method"), method), userWrap, h("div", h("label.form-label", "Device MAC"), mac),
      h("div", h("label.form-label", "NAS"), nasSel), h("div", h("label.form-label", "SSID"), ssid),
      h("div", h("label.form-label", "At (optional)"), at), run));
  const result = h("section.panel.reveal", h("div.empty", icon("signpost-split"), h("h3", "Fill in a request"), h("p", "and see which policy decides it, condition by condition.")));
  root.append(h("div.grid.cols-2", result, form));
  root.querySelector(".grid").style.gridTemplateColumns = "minmax(0, 2fr) minmax(280px, 1fr)";

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    run.disabled = true;
    try {
      const r = await api("POST", "/policies/simulate", {
        auth_method: method.value, username: username.value.trim(), mac: mac.value.trim(), nas: nasSel.value,
        ssid: ssid.value.trim(), at: at.value ? new Date(at.value).toISOString() : null,
      });
      show(r);
    } catch (err) { fail(err); } finally { run.disabled = false; }
  });

  function show(r) {
    clear(result);
    const verdict = r.accepted ? pill(r.vlan ? `Permit · VLAN ${r.vlan}` : "Permit", "ok") : pill("Deny", "bad");
    result.append(h("div.panel-head", h("h2", "Decision"), h("span.spacer"), verdict),
      h("div.panel-body",
        h("p.mb-3", h("b", r.policy || "No policy"), " — ", h("span.muted", r.reason)),
        Object.keys(r.reply_attributes).length ? h("p.small", "Attributes: ", Object.entries(r.reply_attributes).map(([k, v]) => h("span.chip.mono", `${k}=${v}`))) : null,
        Object.keys(r.context).length ? h("details.mb-3", h("summary.small.muted", "Request as NACo sees it"),
          h("div.d-flex.flex-wrap.gap-1.mt-2", Object.entries(r.context).filter(([, v]) => v).map(([k, v]) => h("span.chip", `${k}: ${v}`)))) : null,
        r.trace.length ? h("ol.trace", r.trace.map((t) => h(`li${t.matched && t.policy === r.policy ? ".hit" : ""}`,
          h("div.d-flex.align-items-center.gap-2", h("b", t.policy), h("span.spacer.flex-grow-1"),
            t.matched ? pill(t.policy === r.policy ? "decides" : "matches", t.policy === r.policy ? "accent" : "ok") : pill("no match")),
          t.conditions.length ? h("ul.conds", t.conditions.map((c) => h("li", h(c.matched ? "span.yes" : "span.no", c.matched ? "✓ " : "✗ "), c.label)))
            : h("div.small.muted", "no conditions — matches everything")))) : null));
  }
}
