// Guardian service worker: makes the app installable and shows alerts, including when the app is closed.
// A push says what kind of threat it is and who it's from, never the message itself. Its buttons open the
// app on the right screen: acting still needs Face ID or a fingerprint in the app.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

self.addEventListener("push", (e) => {
  let data = { title: "Guardian", body: "Something new to look at." };
  try { if (e.data) data = Object.assign(data, e.data.json()); } catch (err) { /* keep the default */ }
  const max = (self.Notification && Notification.maxActions) || 2;
  const actions = (Array.isArray(data.actions) ? data.actions : [])
    .filter((a) => ["act", "undo", "read"].includes(a.action))
    .slice(0, max).map((a) => ({ action: a.action, title: String(a.title).slice(0, 30) }));
  e.waitUntil(self.registration.showNotification(String(data.title).slice(0, 80), {
    body: String(data.body).slice(0, 200), icon: "/icon.svg", badge: "/icon.svg",
    tag: data.threat ? "guardian-" + data.threat : "guardian", renotify: true,
    requireInteraction: actions.some((a) => a.action === "act"),
    actions, data: { threat: data.threat || null },
  }));
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const threat = (e.notification.data || {}).threat;
  const intent = ["act", "undo", "read"].includes(e.action) ? e.action : "read";
  const url = threat ? "/?" + intent + "=" + encodeURIComponent(threat) : "/";
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
    const client = list.find((c) => new URL(c.url).origin === self.location.origin);
    if (client) return client.navigate(url).then((c) => (c || client).focus());
    return self.clients.openWindow(url);
  }));
});
