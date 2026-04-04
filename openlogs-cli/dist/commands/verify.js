"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyCommand = void 0;
const commander_1 = require("commander");
const chalk_1 = __importDefault(require("chalk"));
const openlogs_sdk_1 = require("@nextera.one/openlogs-sdk");
const fsutil_1 = require("./fsutil");
exports.verifyCommand = new commander_1.Command('verify')
    .description('Verify an OpenLogs JSONL file (integrity, signatures, trust, semantics, and policy)')
    .option('-f, --file <path>', 'Input JSONL file', './openlogs.jsonl')
    .option('--policy <path>', 'Verification policy JSON file')
    .option('--require-signature', 'Fail policy if any record is unsigned')
    .option('--require-signatures', 'Alias for --require-signature')
    .option('--require-kid', 'Fail policy if any signature is missing a key id')
    .option('--require-trusted-key', 'Fail policy if any signature is untrusted or revoked')
    .option('--require-actor-binding', 'Fail policy if any trusted key is not bound to the record actor')
    .option('--require-event-policy', 'Fail semantics if no event policy matches a record event')
    .option('--trust <path>', 'Trusted key registry JSON file')
    .option('--trusted-keys <path>', 'Alias for --trust')
    .option('--allow-calendar <calendar>', 'Restrict records to specific TPS calendars (repeatable or comma-separated)', collectOptionValues, [])
    .option('--require-monotonic-tps', 'Fail policy if TPS values move backwards in the chain')
    .action(async (options) => {
    const filePath = String(options.file);
    const rows = (0, fsutil_1.readJsonLines)(filePath);
    if (rows.length === 0) {
        console.log(chalk_1.default.yellow('⚠️  No records found'));
        return;
    }
    const filePolicy = options.policy
        ? readVerifyPolicy(String(options.policy))
        : {};
    const trustPath = options.trust ?? options.trustedKeys;
    const cliPolicy = {
        requireSignature: Boolean(options.requireSignature || options.requireSignatures),
        requireKid: Boolean(options.requireKid),
        requireTrustedKey: Boolean(options.requireTrustedKey),
        requireActorBinding: Boolean(options.requireActorBinding),
        requireEventPolicy: Boolean(options.requireEventPolicy),
        requireMonotonicTps: Boolean(options.requireMonotonicTps),
        ...(options.allowCalendar.length > 0
            ? { allowedCalendars: options.allowCalendar }
            : {}),
        ...(trustPath ? { trustedKeys: readTrustedKeys(String(trustPath)) } : {}),
    };
    const policy = mergeVerifyPolicy(filePolicy, cliPolicy);
    // Detect version from first record
    const first = rows[0];
    const isV2 = first.entry?.spec === 'openlogs.v2';
    let res;
    if (isV2) {
        console.log(chalk_1.default.cyan('📋 Detected OpenLogs v2 format'));
        res = await (0, openlogs_sdk_1.verifyV2Chain)(rows, policy);
    }
    else {
        console.log(chalk_1.default.cyan('📋 Detected OpenLogs v1 format (legacy)'));
        res = await (0, openlogs_sdk_1.verifyChain)(rows);
    }
    console.log('');
    console.log(`records:    ${res.records}`);
    console.log(`integrity:  ${formatResultLine(res.integrity.ok, describeCheck(res.integrity))}`);
    console.log(`signatures: ${formatResultLine(res.signatures.ok, `${res.signatures.present}/${res.signatures.total} signed${suffix(res.signatures)}`)}`);
    console.log(`trust:      ${formatTrustLine(res)}`);
    console.log(`semantics:  ${formatResultLine(res.semantics.ok, `${res.semantics.validTps}/${res.semantics.total} TPS, ${res.semantics.validEvents}/${res.semantics.total} events, ${res.semantics.validIndexes}/${res.semantics.total} indexes, ${res.semantics.validPolicies}/${res.semantics.total} policies${suffix(res.semantics)}`)}`);
    console.log(`policy:     ${formatResultLine(res.policy.ok, `${res.policy.mode}${suffix(res.policy)}`)}`);
    if (res.ok) {
        console.log(chalk_1.default.green('\n✅ PASS'));
        return;
    }
    console.error(chalk_1.default.red('\n❌ FAIL'));
    console.error(`error: ${res.error}`);
    if (typeof res.index === 'number')
        console.error(`index: ${res.index}`);
    process.exitCode = 1;
});
function readTrustedKeys(filePath) {
    const value = (0, fsutil_1.readJsonFile)(filePath);
    if (Array.isArray(value))
        return value;
    if (value && Array.isArray(value.keys))
        return value.keys;
    throw new Error('Trusted keys file must be an array or an object with a keys array');
}
function readVerifyPolicy(filePath) {
    const value = (0, fsutil_1.readJsonFile)(filePath);
    if (value && typeof value === 'object' && 'policy' in value) {
        return value.policy ?? {};
    }
    return value ?? {};
}
function collectOptionValues(value, previous) {
    return [...previous, ...value.split(',').map((part) => part.trim()).filter(Boolean)];
}
function mergeVerifyPolicy(base, override) {
    return {
        ...base,
        ...override,
        requireSignature: Boolean(base.requireSignature || override.requireSignature),
        requireKid: Boolean(base.requireKid || override.requireKid),
        requireTrustedKey: Boolean(base.requireTrustedKey || override.requireTrustedKey),
        requireMonotonicTps: Boolean(base.requireMonotonicTps || override.requireMonotonicTps),
        requireActorBinding: Boolean(base.requireActorBinding || override.requireActorBinding),
        requireEventPolicy: Boolean(base.requireEventPolicy || override.requireEventPolicy),
        allowedCalendars: mergeUniqueStrings(base.allowedCalendars, override.allowedCalendars),
        trustedKeys: mergeTrustedKeys(base.trustedKeys, override.trustedKeys),
        eventPolicies: override.eventPolicies ?? base.eventPolicies,
    };
}
function mergeUniqueStrings(base, override) {
    const merged = [...(base ?? []), ...(override ?? [])];
    if (merged.length === 0)
        return undefined;
    return Array.from(new Set(merged));
}
function mergeTrustedKeys(base, override) {
    const merged = [...(base ?? []), ...(override ?? [])];
    if (merged.length === 0)
        return undefined;
    const deduped = new Map();
    for (const key of merged) {
        const identifier = key.kid ?? key.publicKeyHex;
        deduped.set(identifier, key);
    }
    return Array.from(deduped.values());
}
function formatResultLine(ok, text) {
    const status = ok ? chalk_1.default.green('PASS') : chalk_1.default.red('FAIL');
    return `${status}  ${text}`;
}
function describeCheck(result) {
    if (!result.error)
        return 'ok';
    const at = typeof result.index === 'number' ? ` @${result.index}` : '';
    const details = result.details ? ` (${result.details})` : '';
    return `${result.error}${at}${details}`;
}
function suffix(result) {
    if (!result.error)
        return '';
    return ` (${describeCheck(result)})`;
}
function formatTrustLine(res) {
    const strict = res.policy.mode.includes('require-trusted-key') ||
        res.policy.mode.includes('require-actor-binding');
    const status = res.trust.ok
        ? chalk_1.default.green('PASS')
        : strict
            ? chalk_1.default.red('FAIL')
            : chalk_1.default.yellow('INFO');
    return `${status}  trusted=${res.trust.trusted}, unresolved=${res.trust.unresolved}, revoked=${res.trust.revoked}, unsigned=${res.trust.unsigned}, actorBound=${res.trust.actorBound}, validAtEventTime=${res.trust.validAtEventTime}${suffix(res.trust)}`;
}
