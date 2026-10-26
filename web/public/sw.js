// Offline shell for the installed app. Checks always go to the network.
// Built files carry a hash in their name, so they are cached once and served from the cache; pages go to
// the network first. Only a page may fall back to the cached home page: a script or stylesheet never gets
// HTML in its place, which would leave a blank screen.
const SHELL = "checkam-shell-v3";
const API = /^\/(check|checks|run|auth|analyst|alerts|traces|health|stats|telegram|receipts|v\/)/;
self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(SHELL).then((c) => c.addAll(["/", "/manifest.webmanifest", "/icon.svg", "/icon-192.png", "/theme.js"])));
  self.skipWaiting();
});
self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== SHELL).map((k) => caches.delete(k)))));
  self.clients.claim();
});
const keep = (req, res) => {
  if (res && res.ok && res.type === "basic") {
    const copy = res.clone();  // before the page reads the body
    caches.open(SHELL).then((c) => c.put(req, copy));
  }
  return res;
};
self.addEventListener("fetch", (e) => {
  const req = e.request;
  const url = new URL(req.url);
  if (req.method !== "GET" || url.origin !== location.origin || API.test(url.pathname)) return;
  if (url.pathname.startsWith("/assets/")) {
    e.respondWith(caches.match(req).then((hit) => hit || fetch(req).then((r) => keep(req, r))));
    return;
  }
  if (req.mode === "navigate") {
    e.respondWith(fetch(req).then((r) => keep(req, r)).catch(() => caches.match(req).then((r) => r || caches.match("/"))));
    return;
  }
  e.respondWith(fetch(req).then((r) => keep(req, r)).catch(() => caches.match(req).then((r) => r || Response.error())));
});
