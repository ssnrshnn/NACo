import { api, clear, h, icon, toast } from "/static/js/app.js";

const body = () => document.getElementById("setup-body");

function field(label, attrs) {
  const input = h("input.form-control", attrs);
  return [h("div.mb-3", h("label.form-label", { for: attrs.id }, label), input), input];
}

function passwordStep() {
  const [current, cur] = field("Current password", { id: "cur", type: "password", autocomplete: "current-password", required: true });
  const [next, nxt] = field("New password", { id: "new", type: "password", autocomplete: "new-password", minLength: 12, required: true });
  const [again, agn] = field("Repeat new password", { id: "again", type: "password", autocomplete: "new-password", required: true });
  const error = h("p.text-danger.small.hidden", { role: "alert" });
  const form = h("form", { novalidate: true }, h("h1", "Choose your password"),
    h("p.lead", "The initial password was temporary. Pick one only you know — at least 12 characters."),
    current, next, again, error, h("button.btn.btn-accent.w-100.py-2", { type: "submit" }, "Continue"));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    error.classList.add("hidden");
    if (nxt.value !== agn.value) { error.textContent = "The new passwords do not match."; error.classList.remove("hidden"); return; }
    try {
      await api("POST", "/auth/password", { current_password: cur.value, new_password: nxt.value });
      const me = await api("GET", "/auth/me");
      if (me.restricted === "totp") totpStep(nxt.value); else location.href = "/";
    } catch (err) { error.textContent = err.message; error.classList.remove("hidden"); }
  });
  clear(body()).append(form);
  cur.focus();
}

// `password` is known when the user has just chosen it on the previous step;
// otherwise (a reload, or only 2FA was reset) they confirm it here.
function totpStep(password) {
  document.querySelectorAll(".steps i").forEach((i) => i.classList.add("on"));
  const [pw, pwInput] = field("Your password", { id: "pw", type: "password", autocomplete: "current-password", required: true });
  const error = h("p.text-danger.small.hidden", { role: "alert" });
  const submit = h("button.btn.btn-accent.w-100.py-2", { type: "submit" }, "Set up authenticator");
  const start = h("form", { novalidate: true }, h("h1", "Two-factor authentication"),
    h("p.lead", "Protect this account with an authenticator app (1Password, Google Authenticator, Authy…)."),
    password ? [] : [h("p.small.muted", "First confirm it is you with the password you sign in with."), pw],
    error, submit);
  start.addEventListener("submit", async (e) => {
    e.preventDefault();
    try { showQr(await api("POST", "/auth/totp/setup", { password: password ?? pwInput.value })); }
    catch (err) { error.textContent = err.message; error.classList.remove("hidden"); }
  });
  clear(body()).append(start);
  (password ? submit : pwInput).focus();
}

function showQr(setup) {
  const qr = h("div.qr");
  qr.innerHTML = setup.qr_svg; // server-generated SVG (qrcode library), no user input
  const [code, codeInput] = field("6-digit code from the app", { id: "code", inputmode: "numeric", autocomplete: "one-time-code", maxLength: 6, class: "mono" });
  const error = h("p.text-danger.small.hidden", { role: "alert" });
  const form = h("form", { novalidate: true }, h("h1", "Scan the code"),
    h("p.lead", "Scan with your authenticator app, then enter the code it shows."), qr,
    h("details.mb-3", h("summary.small.muted", "Can't scan? Enter the key manually"), h("div.secret-box.mt-2", setup.secret)),
    code, error, h("button.btn.btn-accent.w-100.py-2", { type: "submit" }, "Verify"));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try { recovery((await api("POST", "/auth/totp/confirm", { code: codeInput.value.trim() })).recovery_codes); }
    catch (err) { error.textContent = err.message; error.classList.remove("hidden"); codeInput.select(); }
  });
  clear(body()).append(form);
  codeInput.focus();
}

function recovery(codes) {
  const copy = h("button.btn.btn-ghost.w-100.mb-2", { type: "button" }, icon("copy"), " Copy codes");
  copy.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(codes.join("\n")); toast("Recovery codes copied"); } catch { toast("Copy failed", "bad"); }
  });
  const done = h("a.btn.btn-accent.w-100.py-2", { href: "/" }, "I saved them — continue");
  clear(body()).append(h("h1", "Save your recovery codes"),
    h("p.lead", "Each code signs you in once if you lose your phone. They will not be shown again."),
    h("div.codes.mb-3", codes.map((c) => h("span", c))), copy, done);
}

export default function () {
  if (document.body.dataset.step === "password") passwordStep(); else totpStep();
}
