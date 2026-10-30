// Applied before first paint (no flash): saved choice, else the system preference.
(function () {
  var saved = null;
  try { saved = localStorage.getItem("naco-theme"); } catch (e) { /* private mode */ }
  var theme = saved || (window.matchMedia && matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  document.documentElement.setAttribute("data-theme", theme);
  document.documentElement.setAttribute("data-bs-theme", theme);
})();
