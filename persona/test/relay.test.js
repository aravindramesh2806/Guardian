"use strict";
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { parseClaim, createVerifier, SESSION_TTL_MS } = require("../relay");

function stub({ payload = JSON.stringify({ claim_result: "passed" }), consumed = true } = {}) {
  const calls = [];
  return {
    calls,
    relays: {
      create: async (p) => { calls.push(["create", p]); return { relayToken: "TOKEN", relaySecret: "SECRET", relaySessionAccessToken: "ACCESS" }; },
      issuePrivacyPass: async (p) => { calls.push(["issue", p]); return { privacyPassToken: "PASS" }; },
      generateClaim: async (p) => { calls.push(["claim", p]); return { claimPayload: payload, tokenConsumed: consumed }; },
    },
  };
}
function setup(opts, now) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "relay-"));
  const outFile = path.join(dir, "verification.json");
  fs.writeFileSync(outFile, JSON.stringify({ result: "failed", marker: "original" }));
  const persona = stub(opts);
  return { persona, outFile, v: createVerifier({ persona, outFile, now }) };
}
const read = (f) => JSON.parse(fs.readFileSync(f, "utf8"));

test("start gives the browser only the access token, never the relay token or secret", async () => {
  const { v } = setup();
  const out = await v.start();
  assert.deepStrictEqual(Object.keys(out).sort(), ["accessToken", "sessionId"]);
  assert.strictEqual(out.accessToken, "ACCESS");
  assert.ok(!JSON.stringify(out).includes("SECRET") && !JSON.stringify(out).includes("TOKEN"));
});

test("relay is created for live_human_presence with encryption off", async () => {
  const { v, persona } = setup();
  await v.start();
  assert.strictEqual(persona.calls[0][1].claimType, "live_human_presence");
  assert.strictEqual(persona.calls[0][1].encryptionKeyJwk, null);
});

test("a passed claim writes passed in the shape the agent reads", async () => {
  const { v, outFile, persona } = setup();
  const { sessionId } = await v.start();
  assert.deepStrictEqual(await v.finish(sessionId), { result: "passed" });
  const file = read(outFile);
  assert.strictEqual(file.result, "passed");
  assert.strictEqual(file.claim_type, "live_human_presence");
  assert.match(file.checked_at, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  assert.ok(file.source);
  const claim = persona.calls.find((c) => c[0] === "claim")[1];
  assert.deepStrictEqual(claim, { privacyPassToken: "PASS", relayToken: "TOKEN", relaySecret: "SECRET" });
  assert.strictEqual(persona.calls.find((c) => c[0] === "issue")[1].claimType, "live_human_presence");
});

test("a failed claim writes failed", async () => {
  const { v, outFile } = setup({ payload: JSON.stringify({ claim_result: "failed" }) });
  const { sessionId } = await v.start();
  assert.deepStrictEqual(await v.finish(sessionId), { result: "failed" });
  assert.strictEqual(read(outFile).result, "failed");
});

test("an unreadable payload throws and leaves the file untouched", async () => {
  for (const payload of ["", "not json", JSON.stringify({ other: 1 }), JSON.stringify({ claim_result: "maybe" })]) {
    const { v, outFile } = setup({ payload });
    const { sessionId } = await v.start();
    await assert.rejects(v.finish(sessionId));
    assert.strictEqual(read(outFile).marker, "original");
  }
});

test("a token Persona did not consume is never trusted", async () => {
  const { v, outFile } = setup({ consumed: false });
  const { sessionId } = await v.start();
  await assert.rejects(v.finish(sessionId), /consume/);
  assert.strictEqual(read(outFile).marker, "original");
});

test("an error from Persona leaves the file untouched", async () => {
  const { v, outFile, persona } = setup();
  persona.relays.generateClaim = async () => { throw new Error("boom"); };
  const { sessionId } = await v.start();
  await assert.rejects(v.finish(sessionId), /boom/);
  assert.strictEqual(read(outFile).marker, "original");
});

test("a session works once, and an unknown one is a 404", async () => {
  const { v } = setup();
  const { sessionId } = await v.start();
  await v.finish(sessionId);
  await assert.rejects(v.finish(sessionId), (e) => e.status === 404);
  await assert.rejects(v.finish("nope"), (e) => e.status === 404);
});

test("a session expires after 30 minutes", async () => {
  let t = new Date("2026-11-20T10:00:00Z");
  const { v } = setup({}, () => t);
  const { sessionId } = await v.start();
  t = new Date(t.getTime() + SESSION_TTL_MS + 1000);
  await assert.rejects(v.finish(sessionId), (e) => e.status === 404);
});

test("parseClaim reads plain JSON, a JWT body, and refuses an encrypted JWE", () => {
  assert.strictEqual(parseClaim(JSON.stringify({ claim_result: "passed" })), "passed");
  const jwt = ["e30", Buffer.from(JSON.stringify({ claim_result: "failed" })).toString("base64url"), "sig"].join(".");
  assert.strictEqual(parseClaim(jwt), "failed");
  assert.throws(() => parseClaim("a.b.c.d.e"), /encrypted/);
});

test("with no output file (the web app) the result is returned and nothing is written", async () => {
  const persona = stub();
  const v = createVerifier({ persona, outFile: null });
  const { sessionId } = await v.start();
  assert.deepStrictEqual(await v.finish(sessionId), { result: "passed" });
});
