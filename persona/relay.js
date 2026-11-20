"use strict";
// Persona Relay: prove a live human is behind Guardian before it may lock a card.
//
// Flow (server side, per Persona's Relay server SDK):
//   start():   relays.create -> keep relayToken + relaySecret HERE, give the browser only the access token
//   finish():  relays.issuePrivacyPass -> relays.generateClaim -> read claim_result -> write verification.json
//
// Guardian's agent (agent/respond.py guard) reads that file: only result "passed" lets a card lock run.
// Nothing here ever writes "passed" unless Persona's claim says so. Any error leaves the file untouched.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const CLAIM_TYPE = "live_human_presence";
const SESSION_TTL_MS = 30 * 60 * 1000; // Relay sessions expire after 30 minutes

/** Pull claim_result out of a claim payload. Throws if it cannot be read: never guess "passed". */
function parseClaim(payload) {
  if (typeof payload !== "string" || !payload) throw new Error("empty claim payload");
  const parts = payload.split(".");
  if (parts.length === 5) throw new Error("claim payload is encrypted (JWE); this sidecar creates relays with encryption off");
  let body;
  try {
    body = JSON.parse(payload);
  } catch (_) {
    if (parts.length !== 3) throw new Error("claim payload is not JSON or a JWT");
    body = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  }
  const result = body.claim_result ?? body.claimResult ?? (body.claim && body.claim.claim_result);
  if (result !== "passed" && result !== "failed") throw new Error("claim_result missing or unexpected");
  return result;
}

/** Write the file the Python agent reads. Atomic, so the agent never sees half a file. */
function writeVerification(file, result, source, now = new Date()) {
  const record = {
    _note: "Written by persona/relay.js from a Persona Relay claim. Persona returns only passed or failed.",
    claim_type: CLAIM_TYPE,
    result,
    checked_at: now.toISOString().replace(/\.\d+Z$/, "Z"), // UTC with "Z": the agent converts to local time
    source,
  };
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(record, null, 2) + "\n");
  fs.renameSync(tmp, file);
  return record;
}

function createVerifier({ persona, outFile, source = "Persona Relay sandbox", sandbox = true, now = () => new Date() }) {
  const sessions = new Map(); // sessionId -> { relayToken, relaySecret, createdAt }

  function sweep() {
    for (const [id, s] of sessions) if (now() - s.createdAt > SESSION_TTL_MS) sessions.delete(id);
  }

  return {
    /** Create a Relay session. Returns only what the browser may see. */
    async start() {
      sweep();
      const r = await persona.relays.create({ claimType: CLAIM_TYPE, encryptionKeyJwk: null, sandbox });
      const sessionId = crypto.randomUUID();
      sessions.set(sessionId, { relayToken: r.relayToken, relaySecret: r.relaySecret, createdAt: now() });
      return { sessionId, accessToken: r.relaySessionAccessToken };
    },

    /** The user finished the widget. Redeem the claim and record the result. Single use. */
    async finish(sessionId) {
      sweep();
      const s = sessions.get(sessionId);
      if (!s) throw Object.assign(new Error("unknown or expired session"), { status: 404 });
      sessions.delete(sessionId);
      const pass = await persona.relays.issuePrivacyPass({ claimType: CLAIM_TYPE });
      const claim = await persona.relays.generateClaim({
        privacyPassToken: pass.privacyPassToken, relayToken: s.relayToken, relaySecret: s.relaySecret });
      if (claim.tokenConsumed === false) throw new Error("Persona did not consume the privacy pass token");
      const result = parseClaim(claim.claimPayload);
      if (outFile) writeVerification(outFile, result, source, now()); // the app stores results itself: no file
      return { result };
    },
    sessionCount: () => sessions.size,
  };
}

module.exports = { CLAIM_TYPE, SESSION_TTL_MS, parseClaim, writeVerification, createVerifier };
