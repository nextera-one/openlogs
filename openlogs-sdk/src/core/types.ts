/**
 * OpenLogs SDK v2.0 Types
 * -----------------------
 * v2 consolidates actor, time, and location into the TPS Reality String.
 */

export type OpenLogsAlg = "ed25519";

export interface OpenLogsSignature {
  alg: OpenLogsAlg;
  publicKeyHex: string;
  sigHex: string;
  kid?: string;
}

/**
 * OpenLogs v2 Entry
 * TPS is the Primary Key - time, location, actor, and proof are intrinsic.
 * Actor is mandatory - identifies the entity responsible for the event.
 */
export interface OpenLogsV2Entry {
  /** Specification version */
  spec: "openlogs.v2";
  /** Unique entry identifier (ULID) */
  id: string;
  /** Actor identifier - who/what caused this event (e.g., "user:alice", "system:cron", "device:sensor-1") */
  actor: string;
  /** TPS Reality String with intrinsic L:, A:, T:, and optional ! signature */
  tps: string;
  /** Event type (e.g., "door.unlock", "step.start", "anomaly.detected") */
  event: string;
  /** Optional event-specific payload */
  data?: Record<string, unknown>;
  /** Optional explicit indexes for querying (s2, h3, host, etc.) */
  indexes?: Record<string, string>;
}

/**
 * OpenLogs v2 Record (with hash chain)
 */
export interface OpenLogsV2Record {
  /** The v2 entry */
  entry: OpenLogsV2Entry;
  /** Hash of this record for chain integrity */
  hash: string;
  /** Hash of previous record (null for first in chain) */
  prev_hash: string | null;
  /** Optional cryptographic signature */
  sig?: OpenLogsSignature;
}

export interface OpenLogsTrustedKey {
  kid?: string;
  publicKeyHex: string;
  activeFrom?: string;
  revokedAt?: string;
  actors?: string[];
  actorPrefixes?: string[];
  issuer?: string;
  revokedReason?: string;
  revocationScope?: string;
  description?: string;
}

export interface OpenLogsEventPolicy {
  requireLocation?: boolean;
  requireNode?: boolean;
  requireActorInTps?: boolean;
  allowedCalendars?: string[];
  allowedActorPrefixes?: string[];
  requiredIndexKeys?: string[];
  description?: string;
}

export interface VerifyCheckResult {
  ok: boolean;
  error?: string;
  index?: number;
  details?: string;
}

export interface VerifySignatureResult extends VerifyCheckResult {
  present: number;
  total: number;
}

export interface VerifyTrustResult extends VerifyCheckResult {
  trusted: number;
  unresolved: number;
  revoked: number;
  unsigned: number;
  actorBound: number;
  validAtEventTime: number;
  total: number;
}

export interface VerifySemanticsResult extends VerifyCheckResult {
  validTps: number;
  validEvents: number;
  validIndexes: number;
  validPolicies: number;
  total: number;
}

export interface VerifyPolicyResult extends VerifyCheckResult {
  mode: string;
}

export interface VerifyPolicy {
  requireSignature?: boolean;
  requireKid?: boolean;
  requireTrustedKey?: boolean;
  requireMonotonicTps?: boolean;
  requireActorBinding?: boolean;
  requireEventPolicy?: boolean;
  allowedCalendars?: string[];
  eventPolicies?: Record<string, OpenLogsEventPolicy>;
  trustedKeys?: OpenLogsTrustedKey[];
}

export interface VerifyResult {
  ok: boolean;
  records: number;
  error?: string;
  index?: number;
  integrity: VerifyCheckResult;
  signatures: VerifySignatureResult;
  trust: VerifyTrustResult;
  semantics: VerifySemanticsResult;
  policy: VerifyPolicyResult;
}

// =============================================================================
// Legacy v1 types (deprecated, kept for migration support)
// =============================================================================

/** @deprecated Use OpenLogsV2Entry instead */
export interface OpenLogsPayload {
  actor: string;
  intent: string;
  tps: string;
  ts: string;
  nonce: string;
  location?: unknown;
  data?: unknown;
}

/** @deprecated Use OpenLogsV2Record instead */
export interface OpenLogsRecord {
  v: 1;
  prevHash: string | null;
  payload: OpenLogsPayload;
  hash: string;
  sig?: OpenLogsSignature;
}
