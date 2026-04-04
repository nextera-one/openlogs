export { O as OpenLogsAlg, a as OpenLogsEventPolicy, b as OpenLogsPayload, c as OpenLogsRecord, d as OpenLogsSignature, e as OpenLogsTrustedKey, f as OpenLogsV2Entry, g as OpenLogsV2Record, V as VerifyCheckResult, h as VerifyPolicy, i as VerifyPolicyResult, j as VerifyResult, k as VerifySemanticsResult, l as VerifySignatureResult, m as VerifyTrustResult } from '../types-Cp2b7v2J.js';
export { c as computeRecordHash, a as computeV2RecordHash, b as createEntry, d as createPayload, e as createRecord, f as createV2Chain, g as createV2Record, s as signRecord, h as signV2Record, v as validateRecordPolicy, i as verifyChain, j as verifyRecordSignature, k as verifyV2Chain, l as verifyV2RecordSignature } from '../v1-CJ8KjFaa.js';

declare function canonicalize(value: unknown): string;

declare function hexToBytes(hex: string): Uint8Array;
declare function utf8ToBytes(s: string): Uint8Array;
declare function sha256Hex(data: Uint8Array | string): string;
declare function randomBytes(length: number): Uint8Array;
declare function generateEd25519Keypair(): Promise<{
    privateKey: Uint8Array;
    publicKey: Uint8Array;
}>;
declare function ed25519Sign(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
declare function ed25519Verify(sig: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean>;

type ParsedTpsObject = Record<string, unknown> & {
    calendar?: string;
    actor?: string;
    nodeName?: string;
    latitude?: number;
    longitude?: number;
    building?: string;
    floor?: string;
    door?: string;
    room?: string;
    placeCountryCode?: string;
    placeCityCode?: string;
    millennium?: number;
    century?: number;
    year?: number;
    month?: number;
    day?: number;
    hour?: number;
    minute?: number;
    second?: number;
    millisecond?: number;
    unixSeconds?: number;
    order?: string;
};
interface ParsedTPS {
    raw: string;
    normalized: string;
    calendar: string;
    actor?: string;
    nodeName?: string;
    latitude?: number;
    longitude?: number;
    building?: string;
    floor?: string;
    door?: string;
    room?: string;
    placeCountryCode?: string;
    placeCityCode?: string;
    millennium: number;
    century: number;
    year: number;
    month: number;
    day: number;
    hour: number;
    minute: number;
    second: number;
    millisecond: number;
    order?: string;
    parsed: ParsedTpsObject;
}
interface TPSValidationResult {
    valid: boolean;
    normalized?: string;
    parsed?: ParsedTPS;
    errors: string[];
}
declare function normalizeTpsUri(input: string): string;
declare function normalizeTPS(input: string): string;
declare function parseTPS(input: string): ParsedTPS;
declare function validateTPS(input: string): TPSValidationResult;
declare function compareTPS(left: string, right: string): number;
declare function extractTPSActor(input: string): string | undefined;
declare function hasTPSLocation(input: string): boolean;
declare function hasTPSNode(input: string): boolean;
declare function compareTemporalValues(left: string, right: string): number;

/**
 * Generate a TPS-UID for OpenLogs entries.
 * Uses the TPS string as temporal part and adds random context.
 * Returns a reversible binary base64url encoded ID.
 *
 * @param tpsString The normalized TPS Reality String
 * @returns TPS-UID in binary base64url format
 */
declare function generateTpsUid(tpsString: string): string;
/**
 * Decode a TPS-UID back to its original TPS string with context.
 *
 * @param uid The TPS-UID in binary base64url format
 * @returns Object with decoded TPS string and context
 */
declare function decodeTpsUid(uid: string): {
    tps: string;
    context?: string;
};

export { type ParsedTPS, type TPSValidationResult, canonicalize, compareTPS, compareTemporalValues, decodeTpsUid, ed25519Sign, ed25519Verify, extractTPSActor, generateEd25519Keypair, generateTpsUid, hasTPSLocation, hasTPSNode, hexToBytes, normalizeTPS, normalizeTpsUri, parseTPS, randomBytes, sha256Hex, utf8ToBytes, validateTPS };
