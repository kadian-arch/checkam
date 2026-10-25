// Runs before the page draws, so a dark-mode phone never flashes white. Same rule as the app: the person's
// own choice first, then the phone's setting. The analyst desk is always dark.
(function () {
  var t = null;
  try { t = localStorage.getItem("checkam.theme"); } catch (e) {}
  if (location.pathname.indexOf("/analyst") === 0) t = "dark";
  if (t !== "light" && t !== "dark") t = window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", t);
})();
