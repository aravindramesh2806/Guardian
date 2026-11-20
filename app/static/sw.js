// Guardian service worker: makes the app installable and shows notifications.
// Server-sent push (alerts while the app is closed) is the next step; it needs VAPID keys and HTTPS.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: "window" }).then((list) =>
    list.length ? list[0].focus() : self.clients.openWindow("/")));
});
