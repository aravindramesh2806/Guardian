"use strict";
// Local Persona Relay sidecar. Run: cd persona && npm install && node server.js
// Open http://127.0.0.1:8787, complete the widget, and data/verification.json is updated.
// Binds to localhost only. The Relay token, secret and privacy pass never leave this process.
const fs = require("fs");
const http = require("http");
const path = require("path");
const { createVerifier } = require("./relay");

const ROOT = path.resolve(__dirname, "..");
const PORT = Number(process.env.PORT || 8787);

function loadEnv(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    const t = line.trim();
    const i = t.indexOf("=");
    if (!t || t.startsWith("#") || i < 0) continue;
    const key = t.slice(0, i).trim(), val = t.slice(i + 1).trim();
    if (val && !(key in process.env)) process.env[key] = val;
  }
}
loadEnv(path.join(ROOT, ".env"));

if (!process.env.PERSONA_API_KEY) {
  console.error("PERSONA_API_KEY is not set (put it in .env). Guardian keeps using data/verification.json as is.");
  process.exit(1);
}

const { Persona } = require("@persona/sdk-node");
const verifier = createVerifier({
  persona: new Persona({ apiKey: process.env.PERSONA_API_KEY }),
  outFile: path.join(ROOT, "data", "verification.json"),
});

const widget = path.join(__dirname, "node_modules", "@persona", "relay", "dist", "relay.umd.js");

function readBody(req, limit = 4096) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", (c) => { size += c.length; if (size > limit) { reject(new Error("body too large")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || "{}")); } catch (e) { reject(e); } });
  });
}
const send = (res, code, type, body) => { res.writeHead(code, { "Content-Type": type, "Cache-Control": "no-store" }); res.end(body); };
const json = (res, code, obj) => send(res, code, "application/json", JSON.stringify(obj));

http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/") return send(res, 200, "text/html; charset=utf-8", fs.readFileSync(path.join(__dirname, "verify.html")));
    if (req.method === "GET" && req.url === "/relay.js") return send(res, 200, "application/javascript", fs.readFileSync(widget));
    if (req.method === "POST" && req.url === "/api/session") return json(res, 200, await verifier.start());
    if (req.method === "POST" && req.url === "/api/result") {
      const { sessionId } = await readBody(req);
      return json(res, 200, await verifier.finish(String(sessionId || "")));
    }
    return json(res, 404, { error: "not found" });
  } catch (e) {
    // Never echo Persona's error details to the page; log them here.
    console.error("relay error:", e.message);
    return json(res, e.status || 502, { error: e.status === 404 ? e.message : "verification failed; Guardian's check was not changed" });
  }
}).listen(PORT, "127.0.0.1", () => console.log("Guardian Persona sidecar on http://127.0.0.1:" + PORT));
