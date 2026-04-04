import { canonicalize } from "./canonical";
import { bytesToHex } from "@noble/hashes/utils.js";
import { ulid } from "ulid";

import {
  OpenLogsEventPolicy,
  OpenLogsPayload,
  OpenLogsRecord,
  OpenLogsSignature,
  OpenLogsTrustedKey,
  OpenLogsV2Entry,
  OpenLogsV2Record,
  VerifyCheckResult,
  VerifyPolicy,
  VerifyResult,
} from "./types";
import {
  ed25519Sign,
  ed25519Verify,
  hexToBytes,
  sha256Hex,
  utf8ToBytes,
} from "./crypto";
import {
  compareTemporalValues,
  compareTPS,
  hasTPSLocation,
  hasTPSNode,
  normalizeTpsUri,
  validateTPS,
} from "./tps";
import { generateTpsUid } from "./tpsuid";

const EVENT_NAME_RE = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;

type TrustAssessment = {
  status: "trusted" | "revoked" | "unresolved";
  reason?: string;
  actorBound: boolean;
  validAtEventTime: boolean;
  key?: OpenLogsTrustedKey;
};

// =============================================================================
// OpenLogs v2.0 Functions
// =============================================================================

/**
 * Create an OpenLogs v2 entry
 * TPS is the primary key - time, location, calendar are intrinsic.
 * Actor is mandatory - identifies the entity responsible for the event.
 * ID is a TPS-UID with random context encoded to binary.
 */
export function createEntry(input: {
  actor: string;
  tps: string;
  event: string;
  data?: Record<string, unknown>;
  indexes?: Record<string, string>;
  id?: string;
}): OpenLogsV2Entry {
  if (!input.actor || input.actor.trim().length === 0) {
    throw new Error(
      'actor is required (e.g., "user:alice", "system:cron", "device:sensor-1")',
    );
  }

  const normalizedTps = normalizeTpsUri(input.tps);

  return {
    spec: "openlogs.v2",
    id: input.id ?? generateTpsUid(normalizedTps),
    actor: input.actor.trim(),
    tps: normalizedTps,
    event: input.event,
    ...(input.data && { data: input.data }),
    ...(input.indexes && { indexes: input.indexes }),
  };
}

/**
 * Compute hash for a v2 record
 */
export function computeV2RecordHash(
  entry: OpenLogsV2Entry,
  prev_hash: string | null,
): string {
  if (!entry || typeof entry !== "object" || entry.spec !== "openlogs.v2") {
    throw new Error(
      "computeV2RecordHash requires a valid OpenLogsV2Entry with spec 'openlogs.v2'",
    );
  }
  if (prev_hash !== null && typeof prev_hash !== "string") {
    throw new Error("prev_hash must be a string or null");
  }
  const body = canonicalize({ entry, prev_hash });
  return sha256Hex(body);
}

/**
 * Create an OpenLogs v2 record with hash chain
 * Requires actor, tps, and event at minimum.
 */
export function createV2Record(
  input: {
    actor: string;
    tps: string;
    event: string;
    data?: Record<string, unknown>;
    indexes?: Record<string, string>;
    id?: string;
  },
  prev_hash: string | null,
): OpenLogsV2Record {
  const entry = createEntry(input);
  const hash = computeV2RecordHash(entry, prev_hash);
  return { entry, hash, prev_hash };
}

/**
 * Create a batch of chained v2 records from an array of inputs.
 * Each record is automatically linked to the previous one.
 */
export function createV2Chain(
  inputs: Array<{
    actor: string;
    tps: string;
    event: string;
    data?: Record<string, unknown>;
    indexes?: Record<string, string>;
    id?: string;
  }>,
): OpenLogsV2Record[] {
  if (!inputs || inputs.length === 0) {
    throw new Error("createV2Chain requires at least one input");
  }

  const records: OpenLogsV2Record[] = [];
  let prev_hash: string | null = null;
  for (const input of inputs) {
    const record = createV2Record(input, prev_hash);
    records.push(record);
    prev_hash = record.hash;
  }
  return records;
}

/**
 * Sign a v2 record
 */
export async function signV2Record(
  record: OpenLogsV2Record,
  keys: { privateKey: Uint8Array; publicKey: Uint8Array; kid?: string },
): Promise<OpenLogsV2Record> {
  if (!record || !record.hash) {
    throw new Error("signV2Record requires a record with a valid hash");
  }
  if (
    !(keys.privateKey instanceof Uint8Array) ||
    keys.privateKey.length !== 32
  ) {
    throw new Error("privateKey must be a 32-byte Uint8Array");
  }
  if (!(keys.publicKey instanceof Uint8Array) || keys.publicKey.length !== 32) {
    throw new Error("publicKey must be a 32-byte Uint8Array");
  }

  const sigBytes = await ed25519Sign(utf8ToBytes(record.hash), keys.privateKey);
  const sig: OpenLogsSignature = {
    alg: "ed25519",
    publicKeyHex: bytesToHex(keys.publicKey),
    sigHex: bytesToHex(sigBytes),
    kid: keys.kid,
  };
  return { ...record, sig };
}

/**
 * Verify signature of a v2 record
 */
export async function verifyV2RecordSignature(
  record: OpenLogsV2Record,
): Promise<boolean> {
  if (!record.sig) return false;
  if (record.sig.alg !== "ed25519") return false;
  const pub = hexToBytes(record.sig.publicKeyHex);
  const sig = hexToBytes(record.sig.sigHex);
  return ed25519Verify(sig, utf8ToBytes(record.hash), pub);
}

/**
 * Validate record semantics and event policy rules.
 */
export function validateRecordPolicy(
  record: OpenLogsV2Record,
  policy: VerifyPolicy = {},
): VerifyCheckResult {
  const tpsResult = validateTPS(record.entry.tps);
  if (!tpsResult.valid) {
    return {
      ok: false,
      error: "invalid-tps",
      details: tpsResult.errors.join("; "),
    };
  }

  if (!isValidEventName(record.entry.event)) {
    return {
      ok: false,
      error: "invalid-event",
      details: `Invalid event name: ${record.entry.event}`,
    };
  }

  if (!hasValidIndexes(record.entry.indexes)) {
    return {
      ok: false,
      error: "invalid-indexes",
      details: "indexes must be an object with string values",
    };
  }

  const parsed = tpsResult.parsed!;

  if (parsed.actor && parsed.actor !== record.entry.actor) {
    return {
      ok: false,
      error: "actor-tps-mismatch",
      details: `TPS actor ${parsed.actor} does not match entry actor ${record.entry.actor}`,
    };
  }

  if (
    policy.allowedCalendars?.length &&
    !policy.allowedCalendars.includes(parsed.calendar)
  ) {
    return {
      ok: false,
      error: "calendar-not-allowed",
      details: `Calendar ${parsed.calendar} is not allowed by policy`,
    };
  }

  const eventPolicy = resolveEventPolicy(record.entry.event, policy.eventPolicies);
  if (policy.requireEventPolicy && !eventPolicy) {
    return {
      ok: false,
      error: "missing-event-policy",
      details: `No event policy matched ${record.entry.event}`,
    };
  }

  if (!eventPolicy) {
    return { ok: true };
  }

  if (
    eventPolicy.allowedCalendars?.length &&
    !eventPolicy.allowedCalendars.includes(parsed.calendar)
  ) {
    return {
      ok: false,
      error: "event-policy-calendar-not-allowed",
      details: `Calendar ${parsed.calendar} is not allowed for ${record.entry.event}`,
    };
  }

  if (eventPolicy.requireLocation && !hasTPSLocation(record.entry.tps)) {
    return {
      ok: false,
      error: "event-policy-location-required",
      details: `Event ${record.entry.event} requires location data in TPS`,
    };
  }

  if (eventPolicy.requireNode && !hasTPSNode(record.entry.tps)) {
    return {
      ok: false,
      error: "event-policy-node-required",
      details: `Event ${record.entry.event} requires node data in TPS`,
    };
  }

  if (eventPolicy.requireActorInTps && !parsed.actor) {
    return {
      ok: false,
      error: "event-policy-actor-required",
      details: `Event ${record.entry.event} requires an actor segment inside TPS`,
    };
  }

  if (
    eventPolicy.allowedActorPrefixes?.length &&
    !matchesActorPrefixes(record.entry.actor, eventPolicy.allowedActorPrefixes)
  ) {
    return {
      ok: false,
      error: "event-policy-actor-not-allowed",
      details: `Actor ${record.entry.actor} is not allowed for ${record.entry.event}`,
    };
  }

  const missingIndex = eventPolicy.requiredIndexKeys?.find(
    (key) => !record.entry.indexes?.[key],
  );
  if (missingIndex) {
    return {
      ok: false,
      error: "event-policy-missing-index",
      details: `Event ${record.entry.event} requires index ${missingIndex}`,
    };
  }

  return { ok: true };
}

/**
 * Verify a chain of v2 records.
 *
 * Overall ok requires integrity, signature verification for present signatures,
 * semantics, and policy checks to pass. Trust is reported separately so callers
 * can distinguish structural validity from resolver-backed trust.
 */
export async function verifyV2Chain(
  records: OpenLogsV2Record[],
  policy: VerifyPolicy = {},
): Promise<VerifyResult> {
  const total = records.length;
  const integrity = createCheckResult();
  const signatures = createSignatureResult(total);
  const trust = createTrustResult(total);
  const semantics = createSemanticsResult(total);
  const policyResult = createPolicyResult(describePolicyMode(policy));
  const trustedKeys = policy.trustedKeys ?? [];
  const tpsValidation = records.map((record) => validateTPS(record.entry.tps));
  const trustAssessments: Array<TrustAssessment | undefined> = new Array(total);

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
        validation.errors.join("; "),
      );
    }

    if (isValidEventName(record.entry.event)) {
      semantics.validEvents++;
    } else {
      setFirstFailure(
        semantics,
        "invalid-event",
        i,
        `Invalid event name: ${record.entry.event}`,
      );
    }

    if (hasValidIndexes(record.entry.indexes)) {
      semantics.validIndexes++;
    } else {
      setFirstFailure(
        semantics,
        "invalid-indexes",
        i,
        "indexes must be an object with string values",
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
        recordPolicy.details,
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
        "Signature is invalid, so trust cannot be established",
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

    if (
      policy.requireMonotonicTps &&
      i > 0 &&
      tpsValidation[i - 1].valid &&
      tpsValidation[i].valid &&
      compareTPS(records[i - 1].entry.tps, record.entry.tps) > 0
    ) {
      setFirstFailure(
        policyResult,
        "non-monotonic-tps",
        i,
        `TPS moved backwards from ${records[i - 1].entry.tps} to ${record.entry.tps}`,
      );
    }
  }

  if (policy.requireSignature && signatures.present < total) {
    setFirstFailure(
      policyResult,
      "policy-unsigned-record",
      records.findIndex((record) => !record.sig),
      "Policy require-signature failed",
    );
  }

  if (policy.requireKid) {
    const missingKidIndex = records.findIndex(
      (record) => record.sig && !record.sig.kid,
    );
    if (missingKidIndex !== -1) {
      setFirstFailure(
        policyResult,
        "policy-missing-kid",
        missingKidIndex,
        "Policy require-kid failed",
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
        trustAssessments[actorMismatchIndex]?.reason ??
          "Policy require-actor-binding failed",
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
        trustAssessments[untrustedIndex]?.reason ??
          "Policy require-trusted-key failed",
      );
    }
  }

  trust.ok =
    trust.revoked === 0 &&
    trust.unresolved === 0 &&
    trust.unsigned === 0 &&
    trust.actorBound === signatures.present &&
    trust.validAtEventTime === signatures.present;

  const topLevelFailure =
    firstFailed(integrity) ??
    firstFailed(signatures) ??
    firstFailed(semantics) ??
    firstFailed(policyResult);

  return {
    ok: integrity.ok && signatures.ok && semantics.ok && policyResult.ok,
    records: total,
    error: topLevelFailure?.error,
    index: topLevelFailure?.index,
    integrity,
    signatures,
    trust,
    semantics,
    policy: policyResult,
  };
}

function createCheckResult(): VerifyCheckResult {
  return { ok: true };
}

function createSignatureResult(total: number): VerifyResult["signatures"] {
  return {
    ok: true,
    present: 0,
    total,
  };
}

function createTrustResult(total: number): VerifyResult["trust"] {
  return {
    ok: true,
    trusted: 0,
    unresolved: 0,
    revoked: 0,
    unsigned: 0,
    actorBound: 0,
    validAtEventTime: 0,
    total,
  };
}

function createSemanticsResult(total: number): VerifyResult["semantics"] {
  return {
    ok: true,
    validTps: 0,
    validEvents: 0,
    validIndexes: 0,
    validPolicies: 0,
    total,
  };
}

function createPolicyResult(mode: string): VerifyResult["policy"] {
  return {
    ok: true,
    mode,
  };
}

function setFirstFailure(
  target: { ok: boolean; error?: string; index?: number; details?: string },
  error: string,
  index: number,
  details?: string,
): void {
  if (!target.ok) return;
  target.ok = false;
  target.error = error;
  target.index = index;
  if (details) target.details = details;
}

function firstFailed(
  target: { ok: boolean; error?: string; index?: number },
): { error?: string; index?: number } | undefined {
  if (target.ok) return undefined;
  return { error: target.error, index: target.index };
}

function describePolicyMode(policy: VerifyPolicy): string {
  const modes: string[] = [];
  if (!policy.requireSignature) modes.push("allow-unsigned");
  if (policy.requireSignature) modes.push("require-signature");
  if (policy.requireKid) modes.push("require-kid");
  if (policy.requireTrustedKey) modes.push("require-trusted-key");
  if (policy.requireActorBinding) modes.push("require-actor-binding");
  if (policy.requireEventPolicy) modes.push("require-event-policy");
  if (policy.requireMonotonicTps) modes.push("require-monotonic-tps");
  return modes.join("+");
}

function isValidEventName(event: string): boolean {
  return EVENT_NAME_RE.test(event);
}

function hasValidIndexes(indexes: unknown): boolean {
  if (typeof indexes === "undefined") return true;
  if (!indexes || typeof indexes !== "object" || Array.isArray(indexes)) {
    return false;
  }
  return Object.values(indexes as Record<string, unknown>).every(
    (value) => typeof value === "string",
  );
}

function matchesActorPrefixes(actor: string, prefixes: string[]): boolean {
  return prefixes.some((prefix) => actor.startsWith(prefix));
}

function resolveEventPolicy(
  event: string,
  policies: Record<string, OpenLogsEventPolicy> | undefined,
): OpenLogsEventPolicy | undefined {
  if (!policies) return undefined;
  if (policies[event]) return policies[event];

  let matched: OpenLogsEventPolicy | undefined;
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

function assessTrustedKey(
  record: OpenLogsV2Record,
  trustedKeys: OpenLogsTrustedKey[],
): TrustAssessment {
  const signature = record.sig;
  if (!signature) {
    return {
      status: "unresolved",
      reason: "Record is unsigned",
      actorBound: false,
      validAtEventTime: false,
    };
  }

  const key = findTrustedKey(signature, trustedKeys);
  if (!key) {
    return {
      status: "unresolved",
      reason: describeTrustIssue(signature),
      actorBound: false,
      validAtEventTime: false,
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
      key,
    };
  }

  if (!timeWindow.valid) {
    return {
      status: timeWindow.revoked ? "revoked" : "unresolved",
      reason: timeWindow.reason,
      actorBound: true,
      validAtEventTime: false,
      key,
    };
  }

  return {
    status: "trusted",
    actorBound: true,
    validAtEventTime: true,
    key,
  };
}

function findTrustedKey(
  signature: OpenLogsSignature,
  trustedKeys: OpenLogsTrustedKey[],
): OpenLogsTrustedKey | undefined {
  if (signature.kid) {
    const byKid = trustedKeys.find((key) => key.kid === signature.kid);
    if (byKid) {
      if (byKid.publicKeyHex !== signature.publicKeyHex) return undefined;
      return byKid;
    }
  }

  return trustedKeys.find(
    (key) => key.publicKeyHex === signature.publicKeyHex,
  );
}

function isActorAllowedForKey(actor: string, key: OpenLogsTrustedKey): boolean {
  const hasBindings =
    Boolean(key.actors?.length) || Boolean(key.actorPrefixes?.length);

  if (!hasBindings) return true;
  if (key.actors?.includes(actor)) return true;
  if (key.actorPrefixes?.some((prefix) => actor.startsWith(prefix))) {
    return true;
  }
  return false;
}

function evaluateKeyTimeWindow(
  key: OpenLogsTrustedKey,
  eventTime: string,
): { valid: boolean; revoked: boolean; reason?: string } {
  if (key.activeFrom) {
    try {
      if (compareTemporalValues(eventTime, key.activeFrom) < 0) {
        return {
          valid: false,
          revoked: false,
          reason: `Key is not active until ${key.activeFrom}`,
        };
      }
    } catch (error: unknown) {
      return {
        valid: false,
        revoked: false,
        reason: `Could not compare event time with key activation: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  if (key.revokedAt) {
    try {
      if (compareTemporalValues(eventTime, key.revokedAt) >= 0) {
        const reason = key.revokedReason
          ? `${key.revokedReason} (${key.revokedAt})`
          : `Key revoked at ${key.revokedAt}`;
        return {
          valid: false,
          revoked: true,
          reason,
        };
      }
    } catch (error: unknown) {
      return {
        valid: false,
        revoked: false,
        reason: `Could not compare event time with key revocation: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  return { valid: true, revoked: false };
}

function describeTrustIssue(signature: OpenLogsSignature): string {
  if (signature.kid) return `No trusted key match for ${signature.kid}`;
  return `No trusted key match for ${signature.publicKeyHex}`;
}

// =============================================================================
// Legacy v1 Functions (deprecated, kept for migration support)
// =============================================================================

/** @deprecated Use createEntry instead */
export function createPayload(
  input: Omit<OpenLogsPayload, "ts" | "nonce"> & {
    ts?: string;
    nonce?: string;
  },
): OpenLogsPayload {
  return {
    actor: input.actor,
    intent: input.intent,
    tps: input.tps,
    ts: input.ts ?? new Date().toISOString(),
    nonce: input.nonce ?? ulid(),
    location: input.location,
    data: input.data,
  };
}

/** @deprecated Use computeV2RecordHash instead */
export function computeRecordHash(
  payload: OpenLogsPayload,
  prevHash: string | null,
): string {
  const body = canonicalize({ v: 1, prevHash, payload });
  return sha256Hex(body);
}

/** @deprecated Use createV2Record instead */
export function createRecord(
  payloadInput: Omit<OpenLogsPayload, "ts" | "nonce"> & {
    ts?: string;
    nonce?: string;
  },
  prevHash: string | null,
): OpenLogsRecord {
  const payload = createPayload(payloadInput);
  const hash = computeRecordHash(payload, prevHash);
  return { v: 1, prevHash, payload, hash };
}

/** @deprecated Use signV2Record instead */
export async function signRecord(
  record: OpenLogsRecord,
  keys: { privateKey: Uint8Array; publicKey: Uint8Array; kid?: string },
): Promise<OpenLogsRecord> {
  const sigBytes = await ed25519Sign(utf8ToBytes(record.hash), keys.privateKey);
  const sig: OpenLogsSignature = {
    alg: "ed25519",
    publicKeyHex: bytesToHex(keys.publicKey),
    sigHex: bytesToHex(sigBytes),
    kid: keys.kid,
  };
  return { ...record, sig };
}

/** @deprecated Use verifyV2RecordSignature instead */
export async function verifyRecordSignature(
  record: OpenLogsRecord,
): Promise<boolean> {
  if (!record.sig) return false;
  if (record.sig.alg !== "ed25519") return false;
  const pub = hexToBytes(record.sig.publicKeyHex);
  const sig = hexToBytes(record.sig.sigHex);
  return ed25519Verify(sig, utf8ToBytes(record.hash), pub);
}

/** @deprecated Use verifyV2Chain instead */
export async function verifyChain(
  records: OpenLogsRecord[],
): Promise<VerifyResult> {
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
    details: "Legacy v1 verification does not include trust resolution",
  };

  const semantics = {
    ok: true,
    validTps: total,
    validEvents: total,
    validIndexes: total,
    validPolicies: total,
    total,
  };

  const policy = {
    ok: true,
    mode: "legacy-v1",
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
    policy,
  };
}