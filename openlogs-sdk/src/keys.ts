/**
 * OpenLogs SDK - Key Rotation Helpers
 * ------------------------------------
 * Utilities for managing multi-key scenarios and key rotation in signed chains.
 */

import type { OpenLogsTrustedKey, OpenLogsV2Record } from "./core/types";
import { compareTemporalValues } from "./core/tps";
import { verifyV2RecordSignature } from "./core/chain";

/**
 * Represents a known signing key with metadata.
 */
export interface SigningKeyInfo extends OpenLogsTrustedKey {
  /** Key identifier (matches sig.kid) */
  kid: string;
}

export interface SigningKeyVerification {
  valid: boolean;
  trusted: boolean;
  kid?: string;
  unsigned?: boolean;
  actorBound: boolean;
  validAtEventTime: boolean;
  reason?: string;
}

/**
 * A key registry for managing trusted signing keys.
 */
export class KeyRegistry {
  private keys: Map<string, SigningKeyInfo> = new Map();

  /**
   * Register a trusted signing key.
   */
  addKey(key: SigningKeyInfo): void {
    if (!key.kid) throw new Error("Key must have a kid (key identifier)");
    if (!key.publicKeyHex) throw new Error("Key must have a publicKeyHex");
    this.keys.set(key.kid, key);
  }

  /**
   * Remove a key from the registry.
   */
  removeKey(kid: string): boolean {
    return this.keys.delete(kid);
  }

  /**
   * Mark a key as revoked at a specific time.
   */
  revokeKey(kid: string, revokedAt?: string, revokedReason?: string): void {
    const key = this.keys.get(kid);
    if (!key) throw new Error(`Key '${kid}' not found in registry`);
    key.revokedAt = revokedAt ?? new Date().toISOString();
    if (revokedReason) key.revokedReason = revokedReason;
  }

  /**
   * Get a key by its identifier.
   */
  getKey(kid: string): SigningKeyInfo | undefined {
    return this.keys.get(kid);
  }

  /**
   * Check if a key is currently trusted (registered and not revoked).
   */
  isTrusted(kid: string): boolean {
    const key = this.keys.get(kid);
    if (!key) return false;
    return !key.revokedAt;
  }

  /**
   * Check whether a key is trusted at a specific event time.
   */
  isTrustedAt(kid: string, eventTime: string): boolean {
    const key = this.keys.get(kid);
    if (!key) return false;
    return evaluateKeyTimeWindow(key, eventTime).valid;
  }

  /**
   * Check whether an actor is allowed by this key's binding rules.
   */
  isActorAllowed(kid: string, actor: string): boolean {
    const key = this.keys.get(kid);
    if (!key) return false;
    return isActorAllowedForKey(actor, key);
  }

  /**
   * List all registered keys.
   */
  listKeys(): SigningKeyInfo[] {
    return Array.from(this.keys.values());
  }

  /**
   * List only active (non-revoked) keys.
   */
  listActiveKeys(): SigningKeyInfo[] {
    return this.listKeys().filter((key) => !key.revokedAt);
  }

  /**
   * Verify a record's signature against the registry.
   * Returns signature validity, trust, actor binding, and time-window status.
   */
  async verifyRecord(record: OpenLogsV2Record): Promise<SigningKeyVerification> {
    if (!record.sig) {
      return {
        valid: false,
        trusted: false,
        unsigned: true,
        actorBound: false,
        validAtEventTime: false,
        reason: "Record is unsigned",
      };
    }

    const kid = record.sig.kid;
    const valid = await verifyV2RecordSignature(record);

    if (!valid) {
      return {
        valid: false,
        trusted: false,
        kid,
        actorBound: false,
        validAtEventTime: false,
        reason: "Signature verification failed",
      };
    }

    const key = findMatchingKey(record, this.listKeys());
    if (!key) {
      return {
        valid: true,
        trusted: false,
        kid,
        actorBound: false,
        validAtEventTime: false,
        reason: record.sig.kid
          ? `No trusted key match for ${record.sig.kid}`
          : `No trusted key match for ${record.sig.publicKeyHex}`,
      };
    }

    const actorBound = isActorAllowedForKey(record.entry.actor, key);
    const timeWindow = evaluateKeyTimeWindow(key, record.entry.tps);

    return {
      valid: true,
      trusted: actorBound && timeWindow.valid,
      kid: key.kid,
      actorBound,
      validAtEventTime: timeWindow.valid,
      reason:
        !actorBound
          ? `Actor ${record.entry.actor} is not bound to key ${key.kid}`
          : timeWindow.reason,
    };
  }

  /**
   * Verify all records in a chain against the registry.
   * Returns details about each record's signature status.
   */
  async verifyChainKeys(records: OpenLogsV2Record[]): Promise<
    Array<
      SigningKeyVerification & {
        index: number;
      }
    >
  > {
    const results = [];
    for (let i = 0; i < records.length; i++) {
      const record = records[i];
      const result = await this.verifyRecord(record);
      results.push({ index: i, ...result });
    }
    return results;
  }
}

/**
 * Extract unique signing key identifiers from a chain of records.
 */
export function extractSigningKeys(
  records: OpenLogsV2Record[],
): Array<{ kid?: string; publicKeyHex: string }> {
  const seen = new Set<string>();
  const keys: Array<{ kid?: string; publicKeyHex: string }> = [];

  for (const record of records) {
    if (!record.sig) continue;
    const identifier = record.sig.kid ?? record.sig.publicKeyHex;
    if (!seen.has(identifier)) {
      seen.add(identifier);
      keys.push({
        kid: record.sig.kid,
        publicKeyHex: record.sig.publicKeyHex,
      });
    }
  }

  return keys;
}

/**
 * Group records by their signing key.
 */
export function groupBySigningKey(
  records: OpenLogsV2Record[],
): Map<string, OpenLogsV2Record[]> {
  const groups = new Map<string, OpenLogsV2Record[]>();

  for (const record of records) {
    const key = record.sig
      ? (record.sig.kid ?? record.sig.publicKeyHex)
      : "__unsigned__";
    const group = groups.get(key) ?? [];
    group.push(record);
    groups.set(key, group);
  }

  return groups;
}

function findMatchingKey(
  record: OpenLogsV2Record,
  keys: SigningKeyInfo[],
): SigningKeyInfo | undefined {
  const signature = record.sig;
  if (!signature) return undefined;

  if (signature.kid) {
    const byKid = keys.find((key) => key.kid === signature.kid);
    if (byKid) {
      if (byKid.publicKeyHex !== signature.publicKeyHex) return undefined;
      return byKid;
    }
  }

  return keys.find((key) => key.publicKeyHex === signature.publicKeyHex);
}

function isActorAllowedForKey(actor: string, key: SigningKeyInfo): boolean {
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
  key: SigningKeyInfo,
  eventTime: string,
): { valid: boolean; reason?: string } {
  if (key.activeFrom) {
    try {
      if (compareTemporalValues(eventTime, key.activeFrom) < 0) {
        return {
          valid: false,
          reason: `Key is not active until ${key.activeFrom}`,
        };
      }
    } catch (error: unknown) {
      return {
        valid: false,
        reason: `Could not compare event time with key activation: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  if (key.revokedAt) {
    try {
      if (compareTemporalValues(eventTime, key.revokedAt) >= 0) {
        return {
          valid: false,
          reason: key.revokedReason
            ? `${key.revokedReason} (${key.revokedAt})`
            : `Key revoked at ${key.revokedAt}`,
        };
      }
    } catch (error: unknown) {
      return {
        valid: false,
        reason: `Could not compare event time with key revocation: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  return { valid: true };
}