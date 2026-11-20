// Guardian service worker: makes the app installable and shows alerts, including when the app is closed.
// Pushes carry only a short title and line ("Guardian found 2 new things"), never message text.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("push", (e) => {
  let data = { title: "Guardian", body: "Something new to look at." };
  try { if (e.data) data = Object.assign(data, e.data.json()); } catch (err) { /* keep the default */ }
  e.waitUntil(self.registration.showNotification(String(data.title).slice(0, 80),
    { body: String(data.body).slice(0, 200), icon: "/icon.svg", badge: "/icon.svg", tag: "guardian" }));
});
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: "window" }).then((list) =>
    list.length ? list[0].focus() : self.clients.openWindow("/")));
});
