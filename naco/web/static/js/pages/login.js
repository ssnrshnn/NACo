import { api } from "/static/js/app.js";

// The server already vets ?next=; resolving it here as the browser will is
// the last word on staying on this site.
function sameOrigin(next) {
  try {
    const url = new URL(next || "/", location.origin);
    if (url.origin === location.origin) return url.pathname + url.search + url.hash;
  } catch { /* fall through */ }
  return "/";
}

export default function () {
  const form = document.getElementById("login-form");
  const error = document.getElementById("login-error");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const button = form.querySelector("button");
    button.disabled = true;
    error.classList.add("hidden");
    try {
      const me = await api("POST", "/auth/login", {
        username: form.username.value.trim(), password: form.password.value, totp_code: form.totp_code.value.trim(),
      });
      location.href = me.restricted ? "/setup" : sameOrigin(form.dataset.next);
    } catch (err) {
      error.textContent = err.message;
      error.classList.remove("hidden");
      form.classList.remove("shake"); void form.offsetWidth; form.classList.add("shake");
      form.password.value = "";
      form.totp_code.value = "";
      form.password.focus();
    } finally {
      button.disabled = false;
    }
  });
}
