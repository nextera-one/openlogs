// src/core/canonical.ts
function normalize(value) {
  if (value === null) return null;
  const t = typeof value;
  if (t === "string" || t === "boolean") return value;
  if (t === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("Non-finite numbers are not supported in canonical JSON");
    }
    return value;
  }
  if (t === "bigint") {
    throw new Error("BigInt is not supported in canonical JSON");
  }
  if (t === "undefined" || t === "function" || t === "symbol") {
    return null;
  }
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) {
    return value.map((v) => normalize(v));
  }
  if (typeof value === "object") {
    const obj = value;
    const out = {};
    for (const key of Object.keys(obj).sort()) {
      const v = obj[key];
      if (typeof v === "undefined") continue;
      out[key] = normalize(v);
    }
    return out;
  }
  throw new Error("Unsupported value for canonical JSON");
}
function canonicalize(value) {
  return JSON.stringify(normalize(value));
}

// src/core/crypto.ts
import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
function hexToBytes(hex) {
  const clean = hex.trim().toLowerCase();
  if (clean.length % 2 !== 0) throw new Error("Invalid hex");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
function utf8ToBytes(s) {
  return new TextEncoder().encode(s);
}
function sha256Hex(data) {
  const bytes = typeof data === "string" ? utf8ToBytes(data) : data;
  return bytesToHex(sha256(bytes));
}
function loadNodeCrypto() {
  try {
    const nodeRequire = Function(
      "return typeof require === 'function' ? require : undefined;"
    )();
    return nodeRequire ? nodeRequire("node:crypto") : null;
  } catch {
    return null;
  }
}
function randomBytes(length) {
  if (typeof globalThis.crypto?.getRandomValues === "function") {
    const out = new Uint8Array(length);
    globalThis.crypto.getRandomValues(out);
    return out;
  }
  const nodeCrypto = loadNodeCrypto();
  if (nodeCrypto) {
    return new Uint8Array(nodeCrypto.randomBytes(length));
  }
  throw new Error(
    "No cryptographic random source available. Use Node.js >= 19 or a browser with Web Crypto API."
  );
}
async function generateEd25519Keypair() {
  const privateKey = randomBytes(32);
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
}
async function ed25519Sign(message, privateKey) {
  return ed.signAsync(message, privateKey);
}
async function ed25519Verify(sig, message, publicKey) {
  return ed.verifyAsync(sig, message, publicKey);
}

// src/core/chain.ts
import { bytesToHex as bytesToHex3 } from "@noble/hashes/utils.js";
import { ulid } from "ulid";

// src/core/tps.ts
import { TPS } from "@nextera.one/tps-standard";
function isTpsUri(value) {
  return value.trim().startsWith("tps://");
}
function normalizeTpsUri(input) {
  return parseTPS(input).normalized;
}
function normalizeTPS(input) {
  return normalizeTpsUri(input);
}
function parseTPS(input) {
  const tps = input?.trim();
  if (!tps) {
    throw new Error("TPS URI is required");
  }
  try {
    const parsedValue = normalizeParsedValue(TPS.parse(tps));
    const normalized = toNormalizedUri(parsedValue);
    const parsed = parsedValue;
    if (typeof parsed.calendar !== "string" || parsed.calendar.length === 0) {
      throw new Error("Parsed TPS is missing a calendar");
    }
    return {
      raw: tps,
      normalized,
      calendar: parsed.calendar,
      actor: typeof parsed.actor === "string" ? parsed.actor : void 0,
      nodeName: typeof parsed.nodeName === "string" ? parsed.nodeName : void 0,
      latitude: typeof parsed.latitude === "number" ? parsed.latitude : void 0,
      longitude: typeof parsed.longitude === "number" ? parsed.longitude : void 0,
      building: typeof parsed.building === "string" ? parsed.building : void 0,
      floor: typeof parsed.floor === "string" ? parsed.floor : void 0,
      door: typeof parsed.door === "string" ? parsed.door : void 0,
      room: typeof parsed.room === "string" ? parsed.room : void 0,
      placeCountryCode: typeof parsed.placeCountryCode === "string" ? parsed.placeCountryCode : void 0,
      placeCityCode: typeof parsed.placeCityCode === "string" ? parsed.placeCityCode : void 0,
      millennium: typeof parsed.millennium === "number" ? parsed.millennium : 0,
      century: typeof parsed.century === "number" ? parsed.century : 0,
      year: typeof parsed.year === "number" ? parsed.year : 0,
      month: typeof parsed.month === "number" ? parsed.month : 0,
      day: typeof parsed.day === "number" ? parsed.day : 0,
      hour: typeof parsed.hour === "number" ? parsed.hour : 0,
      minute: typeof parsed.minute === "number" ? parsed.minute : 0,
      second: typeof parsed.second === "number" ? parsed.second : 0,
      millisecond: typeof parsed.millisecond === "number" ? parsed.millisecond : 0,
      order: typeof parsed.order === "string" ? parsed.order : void 0,
      parsed
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid TPS URI: ${message}`);
  }
}
function validateTPS(input) {
  const errors = [];
  let parsed;
  try {
    parsed = parseTPS(input);
  } catch (error) {
    return {
      valid: false,
      errors: [error instanceof Error ? error.message : String(error)]
    };
  }
  if (typeof parsed.latitude === "number" && (parsed.latitude < -90 || parsed.latitude > 90)) {
    errors.push(`Latitude out of range [-90, 90]: ${parsed.latitude}`);
  }
  if (typeof parsed.longitude === "number" && (parsed.longitude < -180 || parsed.longitude > 180)) {
    errors.push(`Longitude out of range [-180, 180]: ${parsed.longitude}`);
  }
  if (parsed.nodeName !== void 0 && parsed.nodeName.trim().length === 0) {
    errors.push("Node name must not be empty");
  }
  return {
    valid: errors.length === 0,
    normalized: parsed.normalized,
    parsed,
    errors
  };
}
function compareTPS(left, right) {
  const a = parseTPS(left);
  const b = parseTPS(right);
  const fields = [
    "millennium",
    "century",
    "year",
    "month",
    "day",
    "hour",
    "minute",
    "second",
    "millisecond"
  ];
  for (const field of fields) {
    const delta = Number(a[field]) - Number(b[field]);
    if (delta !== 0) {
      return delta < 0 ? -1 : 1;
    }
  }
  if (a.calendar !== b.calendar) {
    return a.calendar.localeCompare(b.calendar);
  }
  if ((a.nodeName ?? "") !== (b.nodeName ?? "")) {
    return (a.nodeName ?? "").localeCompare(b.nodeName ?? "");
  }
  if ((a.latitude ?? 0) !== (b.latitude ?? 0)) {
    return (a.latitude ?? 0) < (b.latitude ?? 0) ? -1 : 1;
  }
  if ((a.longitude ?? 0) !== (b.longitude ?? 0)) {
    return (a.longitude ?? 0) < (b.longitude ?? 0) ? -1 : 1;
  }
  return a.normalized.localeCompare(b.normalized);
}
function extractTPSActor(input) {
  return parseTPS(input).actor;
}
function hasTPSLocation(input) {
  const parsed = parseTPS(input);
  return Boolean(
    typeof parsed.latitude === "number" || typeof parsed.longitude === "number" || parsed.building || parsed.floor || parsed.door || parsed.room || parsed.placeCountryCode || parsed.placeCityCode || /^tps:\/(?:\/)?(?:L:|net:|node:|bldg:|floor:|door:|room:)/.test(
      parsed.normalized
    )
  );
}
function hasTPSNode(input) {
  const parsed = parseTPS(input);
  return Boolean(
    parsed.nodeName || /^tps:\/\/node:/.test(parsed.normalized) || parsed.actor?.startsWith("node:")
  );
}
function compareTemporalValues(left, right) {
  const leftEpoch = toEpochMillis(left);
  const rightEpoch = toEpochMillis(right);
  if (leftEpoch !== null && rightEpoch !== null) {
    if (leftEpoch === rightEpoch) return 0;
    return leftEpoch < rightEpoch ? -1 : 1;
  }
  if (isTpsUri(left) && isTpsUri(right)) {
    return compareTPS(left, right);
  }
  throw new Error(
    `Unable to compare temporal values ${JSON.stringify(left)} and ${JSON.stringify(right)}`
  );
}
function toEpochMillis(value) {
  const trimmed = value.trim();
  if (isTpsUri(trimmed)) {
    const parsed = parseTPS(trimmed);
    if (parsed.calendar === "greg") {
      const year = toGregorianYear(parsed);
      return Date.UTC(
        year,
        Math.max(parsed.month, 1) - 1,
        Math.max(parsed.day, 1),
        parsed.hour,
        parsed.minute,
        parsed.second,
        parsed.millisecond
      );
    }
    if (parsed.calendar === "unix") {
      const rawUnixSeconds = parsed.parsed.unixSeconds;
      if (typeof rawUnixSeconds === "number" && rawUnixSeconds > 0) {
        return rawUnixSeconds * 1e3 + parsed.millisecond;
      }
      if (parsed.millennium > 1e6) {
        return parsed.millennium * 1e3 + parsed.millisecond;
      }
    }
    return null;
  }
  const epoch = Date.parse(trimmed);
  return Number.isFinite(epoch) ? epoch : null;
}
function toGregorianYear(parsed) {
  const millennium = parsed.millennium > 0 ? (parsed.millennium - 1) * 1e3 : 0;
  const century = parsed.century > 0 ? (parsed.century - 1) * 100 : 0;
  return millennium + century + parsed.year;
}
function normalizeParsedValue(parsed) {
  if (parsed && typeof parsed === "object") {
    return parsed;
  }
  if (typeof parsed === "string") {
    const reparsed = TPS.parse(parsed);
    if (reparsed && typeof reparsed === "object") {
      return reparsed;
    }
  }
  throw new Error("Unsupported TPS parse output");
}
function toNormalizedUri(parsed) {
  const direct = parsed.uri;
  if (typeof direct === "string") return direct;
  const embedded = parsed.tps;
  if (typeof embedded === "string") return embedded;
  return TPS.toURI(parsed);
}

// src/core/tpsuid.ts
import { TPSUID7RB } from "@nextera.one/tps-standard";
import { bytesToHex as bytesToHex2 } from "@noble/hashes/utils.js";
function generateTpsUid(tpsString) {
  const randomContext = bytesToHex2(randomBytes(8));
  const suffix = tpsString.includes("#C:") ? `;ctx=${randomContext}` : `#C:ctx=${randomContext}`;
  const tpsWithContext = `${tpsString}${suffix}`;
  try {
    const uid = TPSUID7RB.encodeBinaryB64(tpsWithContext, { compress: true });
    return uid;
  } catch (err) {
    const fallbackUid = TPSUID7RB.encodeBinaryB64(tpsWithContext, {
      compress: false
    });
    return fallbackUid;
  }
}
function decodeTpsUid(uid) {
  try {
    const decoded = TPSUID7RB.decodeBinaryB64(uid);
    if (!decoded.tps) {
      throw new Error("Failed to decode TPS-UID");
    }
    let context;
    const ctxMatch = decoded.tps.match(/(?:#C:|;)ctx=([a-f0-9]+)/) || decoded.tps.match(/\?ctx=([a-f0-9]+)/);
    if (ctxMatch) {
      context = ctxMatch[1];
    }
    let tps = decoded.tps;
    tps = tps.replace(/;ctx=[a-f0-9]+$/, "");
    tps = tps.replace(/#C:ctx=[a-f0-9]+$/, "");
    tps = tps.replace(/\?ctx=[a-f0-9]+$/, "");
    return { tps, context };
  } catch (err) {
    throw new Error(
      `Failed to decode TPS-UID: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}

// src/core/chain.ts
var EVENT_NAME_RE = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
function createEntry(input) {
  if (!input.actor || input.actor.trim().length === 0) {
    throw new Error(
      'actor is required (e.g., "user:alice", "system:cron", "device:sensor-1")'
    );
  }
  const normalizedTps = normalizeTpsUri(input.tps);
  return {
    spec: "openlogs.v2",
    id: input.id ?? generateTpsUid(normalizedTps),
    actor: input.actor.trim(),
    tps: normalizedTps,
    event: input.event,
    ...input.data && { data: input.data },
    ...input.indexes && { indexes: input.indexes }
  };
}
function computeV2RecordHash(entry, prev_hash) {
  if (!entry || typeof entry !== "object" || entry.spec !== "openlogs.v2") {
    throw new Error(
      "computeV2RecordHash requires a valid OpenLogsV2Entry with spec 'openlogs.v2'"
    );
  }
  if (prev_hash !== null && typeof prev_hash !== "string") {
    throw new Error("prev_hash must be a string or null");
  }
  const body = canonicalize({ entry, prev_hash });
  return sha256Hex(body);
}
function createV2Record(input, prev_hash) {
  const entry = createEntry(input);
  const hash = computeV2RecordHash(entry, prev_hash);
  return { entry, hash, prev_hash };
}
function createV2Chain(inputs) {
  if (!inputs || inputs.length === 0) {
    throw new Error("createV2Chain requires at least one input");
  }
  const records = [];
  let prev_hash = null;
  for (const input of inputs) {
    const record = createV2Record(input, prev_hash);
    records.push(record);
    prev_hash = record.hash;
  }
  return records;
}
async function signV2Record(record, keys) {
  if (!record || !record.hash) {
    throw new Error("signV2Record requires a record with a valid hash");
  }
  if (!(keys.privateKey instanceof Uint8Array) || keys.privateKey.length !== 32) {
    throw new Error("privateKey must be a 32-byte Uint8Array");
  }
  if (!(keys.publicKey instanceof Uint8Array) || keys.publicKey.length !== 32) {
    throw new Error("publicKey must be a 32-byte Uint8Array");
  }
  const sigBytes = await ed25519Sign(utf8ToBytes(record.hash), keys.privateKey);
  const sig = {
    alg: "ed25519",
    publicKeyHex: bytesToHex3(keys.publicKey),
    sigHex: bytesToHex3(sigBytes),
    kid: keys.kid
  };
  return { ...record, sig };
}
async function verifyV2RecordSignature(record) {
  if (!record.sig) return false;
  if (record.sig.alg !== "ed25519") return false;
  const pub = hexToBytes(record.sig.publicKeyHex);
  const sig = hexToBytes(record.sig.sigHex);
  return ed25519Verify(sig, utf8ToBytes(record.hash), pub);
}
function validateRecordPolicy(record, policy = {}) {
  const tpsResult = validateTPS(record.entry.tps);
  if (!tpsResult.valid) {
    return {
      ok: false,
      error: "invalid-tps",
      details: tpsResult.errors.join("; ")
    };
  }
  if (!isValidEventName(record.entry.event)) {
    return {
      ok: false,
      error: "invalid-event",
      details: `Invalid event name: ${record.entry.event}`
    };
  }
  if (!hasValidIndexes(record.entry.indexes)) {
    return {
      ok: false,
      error: "invalid-indexes",
      details: "indexes must be an object with string values"
    };
  }
  const parsed = tpsResult.parsed;
  if (parsed.actor && parsed.actor !== record.entry.actor) {
    return {
      ok: false,
      error: "actor-tps-mismatch",
      details: `TPS actor ${parsed.actor} does not match entry actor ${record.entry.actor}`
    };
  }
  if (policy.allowedCalendars?.length && !policy.allowedCalendars.includes(parsed.calendar)) {
    return {
      ok: false,
      error: "calendar-not-allowed",
      details: `Calendar ${parsed.calendar} is not allowed by policy`
    };
  }
  const eventPolicy = resolveEventPolicy(record.entry.event, policy.eventPolicies);
  if (policy.requireEventPolicy && !eventPolicy) {
    return {
      ok: false,
      error: "missing-event-policy",
      details: `No event policy matched ${record.entry.event}`
    };
  }
  if (!eventPolicy) {
    return { ok: true };
  }
  if (eventPolicy.allowedCalendars?.length && !eventPolicy.allowedCalendars.includes(parsed.calendar)) {
    return {
      ok: false,
      error: "event-policy-calendar-not-allowed",
      details: `Calendar ${parsed.calendar} is not allowed for ${record.entry.event}`
    };
  }
  if (eventPolicy.requireLocation && !hasTPSLocation(record.entry.tps)) {
    return {
      ok: false,
      error: "event-policy-location-required",
      details: `Event ${record.entry.event} requires location data in TPS`
    };
  }
  if (eventPolicy.requireNode && !hasTPSNode(record.entry.tps)) {
    return {
      ok: false,
      error: "event-policy-node-required",
      details: `Event ${record.entry.event} requires node data in TPS`
    };
  }
  if (eventPolicy.requireActorInTps && !parsed.actor) {
    return {
      ok: false,
      error: "event-policy-actor-required",
      details: `Event ${record.entry.event} requires an actor segment inside TPS`
    };
  }
  if (eventPolicy.allowedActorPrefixes?.length && !matchesActorPrefixes(record.entry.actor, eventPolicy.allowedActorPrefixes)) {
    return {
      ok: false,
      error: "event-policy-actor-not-allowed",
      details: `Actor ${record.entry.actor} is not allowed for ${record.entry.event}`
    };
  }
  const missingIndex = eventPolicy.requiredIndexKeys?.find(
    (key) => !record.entry.indexes?.[key]
  );
  if (missingIndex) {
    return {
      ok: false,
      error: "event-policy-missing-index",
      details: `Event ${record.entry.event} requires index ${missingIndex}`
    };
  }
  return { ok: true };
}
async function verifyV2Chain(records, policy = {}) {
  const total = records.length;
  const integrity = createCheckResult();
  const signatures = createSignatureResult(total);
  const trust = createTrustResult(total);
  const semantics = createSemanticsResult(total);
  const policyResult = createPolicyResult(describePolicyMode(policy));
  const trustedKeys = policy.trustedKeys ?? [];
  const tpsValidation = records.map((record) => validateTPS(record.entry.tps));
  const trustAssessments = new Array(total);
  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    const validation = tpsValidation[i];
    if (validation.valid) {
      semantics.validTps++;
    } else {
      setFirstFailure(
        semantics,
        "invalid-tps",
        i,
        validation.errors.join("; ")
      );
    }
    if (isValidEventName(record.entry.event)) {
      semantics.validEvents++;
    } else {
      setFirstFailure(
        semantics,
        "invalid-event",
        i,
        `Invalid event name: ${record.entry.event}`
      );
    }
    if (hasValidIndexes(record.entry.indexes)) {
      semantics.validIndexes++;
    } else {
      setFirstFailure(
        semantics,
        "invalid-indexes",
        i,
        "indexes must be an object with string values"
      );
    }
    const recordPolicy = validateRecordPolicy(record, policy);
    if (recordPolicy.ok) {
      semantics.validPolicies++;
    } else {
      setFirstFailure(
        semantics,
        recordPolicy.error ?? "record-policy-failed",
        i,
        recordPolicy.details
      );
    }
  }
  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    const expectedHash = computeV2RecordHash(record.entry, record.prev_hash);
    if (record.hash !== expectedHash) {
      setFirstFailure(integrity, "hash-mismatch", i);
    }
    const expectedPrev = i === 0 ? null : records[i - 1].hash;
    if (record.prev_hash !== expectedPrev) {
      setFirstFailure(integrity, "prev-hash-mismatch", i);
    }
    let signatureOk = false;
    if (record.sig) {
      signatures.present++;
      signatureOk = await verifyV2RecordSignature(record);
      if (!signatureOk) {
        setFirstFailure(signatures, "bad-signature", i);
      }
    }
    if (!record.sig) {
      trust.unsigned++;
      setFirstFailure(trust, "unsigned-record", i, "Record is unsigned");
    } else if (!signatureOk) {
      trust.unresolved++;
      setFirstFailure(
        trust,
        "untrusted-key",
        i,
        "Signature is invalid, so trust cannot be established"
      );
    } else {
      const assessment = assessTrustedKey(record, trustedKeys);
      trustAssessments[i] = assessment;
      if (assessment.actorBound) trust.actorBound++;
      if (assessment.validAtEventTime) trust.validAtEventTime++;
      if (assessment.status === "trusted") {
        trust.trusted++;
      } else if (assessment.status === "revoked") {
        trust.revoked++;
        setFirstFailure(trust, "revoked-key", i, assessment.reason);
      } else {
        trust.unresolved++;
        setFirstFailure(trust, "untrusted-key", i, assessment.reason);
      }
    }
    if (policy.requireMonotonicTps && i > 0 && tpsValidation[i - 1].valid && tpsValidation[i].valid && compareTPS(records[i - 1].entry.tps, record.entry.tps) > 0) {
      setFirstFailure(
        policyResult,
        "non-monotonic-tps",
        i,
        `TPS moved backwards from ${records[i - 1].entry.tps} to ${record.entry.tps}`
      );
    }
  }
  if (policy.requireSignature && signatures.present < total) {
    setFirstFailure(
      policyResult,
      "policy-unsigned-record",
      records.findIndex((record) => !record.sig),
      "Policy require-signature failed"
    );
  }
  if (policy.requireKid) {
    const missingKidIndex = records.findIndex(
      (record) => record.sig && !record.sig.kid
    );
    if (missingKidIndex !== -1) {
      setFirstFailure(
        policyResult,
        "policy-missing-kid",
        missingKidIndex,
        "Policy require-kid failed"
      );
    }
  }
  if (policy.requireActorBinding) {
    const actorMismatchIndex = records.findIndex((record, index) => {
      if (!record.sig) return true;
      return !trustAssessments[index]?.actorBound;
    });
    if (actorMismatchIndex !== -1) {
      setFirstFailure(
        policyResult,
        "policy-actor-binding",
        actorMismatchIndex,
        trustAssessments[actorMismatchIndex]?.reason ?? "Policy require-actor-binding failed"
      );
    }
  }
  if (policy.requireTrustedKey) {
    const untrustedIndex = records.findIndex((record, index) => {
      if (!record.sig) return true;
      return trustAssessments[index]?.status !== "trusted";
    });
    if (untrustedIndex !== -1) {
      setFirstFailure(
        policyResult,
        "policy-untrusted-key",
        untrustedIndex,
        trustAssessments[untrustedIndex]?.reason ?? "Policy require-trusted-key failed"
      );
    }
  }
  trust.ok = trust.revoked === 0 && trust.unresolved === 0 && trust.unsigned === 0 && trust.actorBound === signatures.present && trust.validAtEventTime === signatures.present;
  const topLevelFailure = firstFailed(integrity) ?? firstFailed(signatures) ?? firstFailed(semantics) ?? firstFailed(policyResult);
  return {
    ok: integrity.ok && signatures.ok && semantics.ok && policyResult.ok,
    records: total,
    error: topLevelFailure?.error,
    index: topLevelFailure?.index,
    integrity,
    signatures,
    trust,
    semantics,
    policy: policyResult
  };
}
function createCheckResult() {
  return { ok: true };
}
function createSignatureResult(total) {
  return {
    ok: true,
    present: 0,
    total
  };
}
function createTrustResult(total) {
  return {
    ok: true,
    trusted: 0,
    unresolved: 0,
    revoked: 0,
    unsigned: 0,
    actorBound: 0,
    validAtEventTime: 0,
    total
  };
}
function createSemanticsResult(total) {
  return {
    ok: true,
    validTps: 0,
    validEvents: 0,
    validIndexes: 0,
    validPolicies: 0,
    total
  };
}
function createPolicyResult(mode) {
  return {
    ok: true,
    mode
  };
}
function setFirstFailure(target, error, index, details) {
  if (!target.ok) return;
  target.ok = false;
  target.error = error;
  target.index = index;
  if (details) target.details = details;
}
function firstFailed(target) {
  if (target.ok) return void 0;
  return { error: target.error, index: target.index };
}
function describePolicyMode(policy) {
  const modes = [];
  if (!policy.requireSignature) modes.push("allow-unsigned");
  if (policy.requireSignature) modes.push("require-signature");
  if (policy.requireKid) modes.push("require-kid");
  if (policy.requireTrustedKey) modes.push("require-trusted-key");
  if (policy.requireActorBinding) modes.push("require-actor-binding");
  if (policy.requireEventPolicy) modes.push("require-event-policy");
  if (policy.requireMonotonicTps) modes.push("require-monotonic-tps");
  return modes.join("+");
}
function isValidEventName(event) {
  return EVENT_NAME_RE.test(event);
}
function hasValidIndexes(indexes) {
  if (typeof indexes === "undefined") return true;
  if (!indexes || typeof indexes !== "object" || Array.isArray(indexes)) {
    return false;
  }
  return Object.values(indexes).every(
    (value) => typeof value === "string"
  );
}
function matchesActorPrefixes(actor, prefixes) {
  return prefixes.some((prefix) => actor.startsWith(prefix));
}
function resolveEventPolicy(event, policies) {
  if (!policies) return void 0;
  if (policies[event]) return policies[event];
  let matched;
  let matchedLength = -1;
  for (const [pattern, policy] of Object.entries(policies)) {
    if (!pattern.endsWith("*")) continue;
    const prefix = pattern.slice(0, -1);
    if (event.startsWith(prefix) && prefix.length > matchedLength) {
      matched = policy;
      matchedLength = prefix.length;
    }
  }
  return matched;
}
function assessTrustedKey(record, trustedKeys) {
  const signature = record.sig;
  if (!signature) {
    return {
      status: "unresolved",
      reason: "Record is unsigned",
      actorBound: false,
      validAtEventTime: false
    };
  }
  const key = findTrustedKey(signature, trustedKeys);
  if (!key) {
    return {
      status: "unresolved",
      reason: describeTrustIssue(signature),
      actorBound: false,
      validAtEventTime: false
    };
  }
  const actorBound = isActorAllowedForKey(record.entry.actor, key);
  const timeWindow = evaluateKeyTimeWindow(key, record.entry.tps);
  if (!actorBound) {
    return {
      status: "unresolved",
      reason: `Actor ${record.entry.actor} is not bound to key ${key.kid ?? key.publicKeyHex}`,
      actorBound: false,
      validAtEventTime: timeWindow.valid,
      key
    };
  }
  if (!timeWindow.valid) {
    return {
      status: timeWindow.revoked ? "revoked" : "unresolved",
      reason: timeWindow.reason,
      actorBound: true,
      validAtEventTime: false,
      key
    };
  }
  return {
    status: "trusted",
    actorBound: true,
    validAtEventTime: true,
    key
  };
}
function findTrustedKey(signature, trustedKeys) {
  if (signature.kid) {
    const byKid = trustedKeys.find((key) => key.kid === signature.kid);
    if (byKid) {
      if (byKid.publicKeyHex !== signature.publicKeyHex) return void 0;
      return byKid;
    }
  }
  return trustedKeys.find(
    (key) => key.publicKeyHex === signature.publicKeyHex
  );
}
function isActorAllowedForKey(actor, key) {
  const hasBindings = Boolean(key.actors?.length) || Boolean(key.actorPrefixes?.length);
  if (!hasBindings) return true;
  if (key.actors?.includes(actor)) return true;
  if (key.actorPrefixes?.some((prefix) => actor.startsWith(prefix))) {
    return true;
  }
  return false;
}
function evaluateKeyTimeWindow(key, eventTime) {
  if (key.activeFrom) {
    try {
      if (compareTemporalValues(eventTime, key.activeFrom) < 0) {
        return {
          valid: false,
          revoked: false,
          reason: `Key is not active until ${key.activeFrom}`
        };
      }
    } catch (error) {
      return {
        valid: false,
        revoked: false,
        reason: `Could not compare event time with key activation: ${error instanceof Error ? error.message : String(error)}`
      };
    }
  }
  if (key.revokedAt) {
    try {
      if (compareTemporalValues(eventTime, key.revokedAt) >= 0) {
        const reason = key.revokedReason ? `${key.revokedReason} (${key.revokedAt})` : `Key revoked at ${key.revokedAt}`;
        return {
          valid: false,
          revoked: true,
          reason
        };
      }
    } catch (error) {
      return {
        valid: false,
        revoked: false,
        reason: `Could not compare event time with key revocation: ${error instanceof Error ? error.message : String(error)}`
      };
    }
  }
  return { valid: true, revoked: false };
}
function describeTrustIssue(signature) {
  if (signature.kid) return `No trusted key match for ${signature.kid}`;
  return `No trusted key match for ${signature.publicKeyHex}`;
}
function createPayload(input) {
  return {
    actor: input.actor,
    intent: input.intent,
    tps: input.tps,
    ts: input.ts ?? (/* @__PURE__ */ new Date()).toISOString(),
    nonce: input.nonce ?? ulid(),
    location: input.location,
    data: input.data
  };
}
function computeRecordHash(payload, prevHash) {
  const body = canonicalize({ v: 1, prevHash, payload });
  return sha256Hex(body);
}
function createRecord(payloadInput, prevHash) {
  const payload = createPayload(payloadInput);
  const hash = computeRecordHash(payload, prevHash);
  return { v: 1, prevHash, payload, hash };
}
async function signRecord(record, keys) {
  const sigBytes = await ed25519Sign(utf8ToBytes(record.hash), keys.privateKey);
  const sig = {
    alg: "ed25519",
    publicKeyHex: bytesToHex3(keys.publicKey),
    sigHex: bytesToHex3(sigBytes),
    kid: keys.kid
  };
  return { ...record, sig };
}
async function verifyRecordSignature(record) {
  if (!record.sig) return false;
  if (record.sig.alg !== "ed25519") return false;
  const pub = hexToBytes(record.sig.publicKeyHex);
  const sig = hexToBytes(record.sig.sigHex);
  return ed25519Verify(sig, utf8ToBytes(record.hash), pub);
}
async function verifyChain(records) {
  const total = records.length;
  const integrity = createCheckResult();
  const signatures = createSignatureResult(total);
  for (let i = 0; i < records.length; i++) {
    const record = records[i];
    const expectedHash = computeRecordHash(record.payload, record.prevHash);
    if (record.hash !== expectedHash) {
      setFirstFailure(integrity, "hash-mismatch", i);
    }
    const expectedPrev = i === 0 ? null : records[i - 1].hash;
    if (record.prevHash !== expectedPrev) {
      setFirstFailure(integrity, "prev-hash-mismatch", i);
    }
    if (record.sig) {
      signatures.present++;
      const ok = await verifyRecordSignature(record);
      if (!ok) setFirstFailure(signatures, "bad-signature", i);
    }
  }
  const trust = {
    ok: false,
    trusted: 0,
    unresolved: signatures.present,
    revoked: 0,
    unsigned: total - signatures.present,
    actorBound: 0,
    validAtEventTime: 0,
    total,
    error: "legacy-trust-unresolved",
    index: records.findIndex((record) => !record.sig),
    details: "Legacy v1 verification does not include trust resolution"
  };
  const semantics = {
    ok: true,
    validTps: total,
    validEvents: total,
    validIndexes: total,
    validPolicies: total,
    total
  };
  const policy = {
    ok: true,
    mode: "legacy-v1"
  };
  const topLevelFailure = firstFailed(integrity) ?? firstFailed(signatures);
  return {
    ok: integrity.ok && signatures.ok,
    records: total,
    error: topLevelFailure?.error,
    index: topLevelFailure?.index,
    integrity,
    signatures,
    trust,
    semantics,
    policy
  };
}
export {
  canonicalize,
  compareTPS,
  compareTemporalValues,
  computeRecordHash,
  computeV2RecordHash,
  createEntry,
  createPayload,
  createRecord,
  createV2Chain,
  createV2Record,
  decodeTpsUid,
  ed25519Sign,
  ed25519Verify,
  extractTPSActor,
  generateEd25519Keypair,
  generateTpsUid,
  hasTPSLocation,
  hasTPSNode,
  hexToBytes,
  normalizeTPS,
  normalizeTpsUri,
  parseTPS,
  randomBytes,
  sha256Hex,
  signRecord,
  signV2Record,
  utf8ToBytes,
  validateRecordPolicy,
  validateTPS,
  verifyChain,
  verifyRecordSignature,
  verifyV2Chain,
  verifyV2RecordSignature
};
//# sourceMappingURL=index.mjs.map