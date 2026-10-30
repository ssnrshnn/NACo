// Small building blocks shared by the page modules.
import { api, confirm, fail, formSheet, h, icon, sheet, toast } from "/static/js/app.js";

export function btn(name, title, onClick, cls = "btn-ghost") {
  const b = h(`button.btn.btn-sm.btn-icon.${cls}`, { type: "button", title, "aria-label": title }, icon(name));
  b.addEventListener("click", onClick);
  return b;
}

export function primary(label, onClick, name = "plus-lg") {
  const b = h("button.btn.btn-accent", { type: "button" }, icon(name), ` ${label}`);
  b.addEventListener("click", onClick);
  return b;
}

export function ghost(label, onClick, name) {
  const b = h("button.btn.btn-ghost", { type: "button" }, name ? icon(name) : null, ` ${label}`);
  b.addEventListener("click", onClick);
  return b;
}

export async function remove(what, path, after) {
  if (!(await confirm(`Delete ${what}? This cannot be undone.`, { label: "Delete" }))) return;
  try { await api("DELETE", path); toast(`Deleted ${what}`); after?.(); } catch (err) { fail(err); }
}

export function segmented(options, value, onChange) {
  const wrap = h("div.btn-group", { role: "group" });
  for (const [v, label] of options) {
    const b = h(`button.btn.btn-sm${v === value ? ".btn-accent" : ".btn-ghost"}`, { type: "button" }, label);
    b.addEventListener("click", () => {
      wrap.querySelectorAll("button").forEach((x) => { x.classList.remove("btn-accent"); x.classList.add("btn-ghost"); });
      b.classList.add("btn-accent"); b.classList.remove("btn-ghost");
      onChange(v);
    });
    wrap.append(b);
  }
  return wrap;
}

export function csvExport(kind) {
  return h("a.btn.btn-ghost", { href: `/api/v1/export/${kind}.csv`, download: true }, icon("download"), " Export");
}

export function csvImport(kind, columns, after) {
  return ghost("Import", () => {
    const input = h("input.form-control", { type: "file", accept: ".csv,text/csv" });
    const result = h("div.mt-3");
    const go = h("button.btn.btn-accent", { type: "button" }, "Import");
    sheet({
      title: `Import ${kind}`,
      body: [h("p.muted", "A CSV with a header row. Existing entries are skipped, never changed."),
        h("p.small", h("b", "Columns: "), h("span.mono", columns)), input, result],
      foot: [go],
    });
    go.addEventListener("click", async () => {
      if (!input.files[0]) return;
      const data = new FormData();
      data.append("file", input.files[0]);
      go.disabled = true;
      try {
        const r = await api("POST", `/import/${kind}`, data);
        result.replaceChildren(h("p", h("b", `${r.created} created`), `, ${r.skipped} skipped`),
          r.errors.length ? h("ul.small.text-danger", r.errors.map((e) => h("li", e))) : null);
        toast(`Imported ${r.created} ${kind}`);
        after?.();
      } catch (err) { fail(err); } finally { go.disabled = false; }
    });
  }, "upload");
}

export function randomSecret(length = 24) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
}

export function secretField(label = "Shared secret", help) {
  return {
    name: "secret", label, type: "custom", full: true,
    render(value) {
      const input = h("input.form-control.mono", { type: "text", value: value || "", autocomplete: "off", placeholder: "at least 16 characters" });
      const gen = h("button.btn.btn-ghost", { type: "button" }, icon("arrow-repeat"), " Generate");
      gen.addEventListener("click", () => { input.value = randomSecret(); });
      const el = h("div", h("label.form-label", label), h("div.input-group", input, gen), help ? h("div.form-text", help) : null);
      return { el, get: () => (input.value === "" ? undefined : input.value) };
    },
  };
}

export { formSheet };
