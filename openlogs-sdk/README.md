# @nextera.one/openlogs-sdk

TypeScript/JavaScript SDK for **OpenLogs v2** — provable execution evidence with hash-chained, cryptographically signed log entries.

## Features

- **Hash-chained records** — SHA-256 linked entries for tamper evidence
- **Ed25519 signing** — cryptographic proof per record using `@noble/ed25519`
- **TPS Reality Strings** — time, place, and space as primary keys via `@nextera.one/tps-standard`
- **TPS-UID** — globally unique, reversible IDs encoding temporal and random context
- **Geospatial indexes** — optional S2/H3 cell indexes for spatial querying
- **Multi-calendar support** — Gregorian, Unix, and more
- **Key rotation** — `KeyRegistry` for managing trusted signing keys
- **Batch operations** — `createV2Chain` for building multiple linked records at once
- **Dual CJS/ESM** — works everywhere

## Install

```bash
npm i @nextera.one/openlogs-sdk
```

## Quick Start

```ts
import {
  createEntry,
  createV2Record,
  signV2Record,
  verifyV2Chain,
  generateEd25519Keypair,
} from "@nextera.one/openlogs-sdk";

// Generate a signing keypair
const keys = await generateEd25519Keypair();

// Create a v2 record (first in chain)
const r1 = createV2Record(
  {
    actor: "user:alice",
    tps: "tps://L:40.7128,-74.0060@T:greg.m3.c1.y26.m3.d3.h16.m30.s0.m0",
    event: "auth.login",
    data: { method: "oauth2", provider: "google" },
  },
  null, // no previous hash (first record)
);

// Sign the record
const signed = await signV2Record(r1, { ...keys, kid: "key:main" });

// Verify integrity + signatures + trust/policy layers
const result = await verifyV2Chain([signed], {
  requireSignature: true,
  requireKid: true,
  requireTrustedKey: true,
  trustedKeys: [
    {
      kid: "key:main",
      publicKeyHex: signed.sig!.publicKeyHex,
      actors: ["user:alice"],
    },
  ],
});

console.log(result.ok); // true
console.log(result.integrity.ok); // true
console.log(result.signatures); // { ok: true, present: 1, total: 1 }
console.log(result.trust.trusted); // 1
console.log(result.policy.mode); // require-signature+require-kid+require-trusted-key
```

## Batch Chain Creation

```ts
import { createV2Chain } from "@nextera.one/openlogs-sdk";

const records = createV2Chain([
  { actor: "system:audit", tps: "tps://...@T:...", event: "step.start" },
  { actor: "system:audit", tps: "tps://...@T:...", event: "step.process" },
  { actor: "system:audit", tps: "tps://...@T:...", event: "step.complete" },
]);
// records are automatically hash-chained
```

## Key Rotation

```ts
import { KeyRegistry, extractSigningKeys } from "@nextera.one/openlogs-sdk";

const registry = new KeyRegistry();
registry.addKey({
  kid: "key:prod-2026",
  publicKeyHex: "...",
  activeFrom: "2026-01-01",
  actors: ["system:audit"],
});

// Verify a record's signature is valid AND from a trusted key
const { valid, trusted, kid, actorBound, validAtEventTime } =
  await registry.verifyRecord(signedRecord);
```

## Subpath Exports

| Import Path                      | Contents                                            |
| -------------------------------- | --------------------------------------------------- |
| `@nextera.one/openlogs-sdk`      | All v2 functions, types, and key rotation utilities |
| `@nextera.one/openlogs-sdk/core` | Core v2 functions and types only                    |
| `@nextera.one/openlogs-sdk/keys` | Key rotation utilities only                         |
| `@nextera.one/openlogs-sdk/v1`   | Deprecated v1 API (for migration)                   |

## API Reference

### Core Functions

| Function                          | Description                                                |
| --------------------------------- | ---------------------------------------------------------- |
| `createEntry(input)`              | Create a v2 entry (no hash chain)                          |
| `createV2Record(input, prevHash)` | Create a hash-chained v2 record                            |
| `createV2Chain(inputs[])`         | Create a batch of chained records                          |
| `signV2Record(record, keys)`      | Sign a record with Ed25519                                 |
| `verifyV2Chain(records, policy?)` | Verify integrity, signatures, trust, semantics, and policy |
| `verifyV2RecordSignature(record)` | Verify a single record's signature                         |

### Crypto Functions

| Function                   | Description                        |
| -------------------------- | ---------------------------------- |
| `generateEd25519Keypair()` | Generate a new Ed25519 keypair     |
| `sha256Hex(data)`          | SHA-256 hash as hex string         |
| `hexToBytes(hex)`          | Convert hex string to Uint8Array   |
| `utf8ToBytes(str)`         | Convert UTF-8 string to Uint8Array |

### TPS Functions

| Function                    | Description                                     |
| --------------------------- | ----------------------------------------------- |
| `parseTPS(input)`           | Parse a TPS URI into normalized structured data |
| `validateTPS(input)`        | Validate TPS syntax and location bounds         |
| `normalizeTPS(input)`       | Normalize a TPS URI string                      |
| `normalizeTpsUri(input)`    | Normalize a TPS URI string                      |
| `compareTPS(a, b)`          | Compare two TPS values for ordering             |
| `generateTpsUid(tpsString)` | Generate a TPS-UID                              |
| `decodeTpsUid(uid)`         | Decode a TPS-UID back to TPS + context          |

### Key Rotation

| Export                        | Description                              |
| ----------------------------- | ---------------------------------------- |
| `KeyRegistry`                 | Class for managing trusted signing keys  |
| `extractSigningKeys(records)` | Extract unique signing keys from a chain |
| `groupBySigningKey(records)`  | Group records by their signing key       |

## Verify Result Shape

`verifyV2Chain()` now returns layered results instead of a single boolean:

```ts
{
  ok: boolean;
  records: number;
  integrity: { ok, error?, index?, details? };
  signatures: { ok, present, total, error?, index?, details? };
  trust: {
    ok,
    trusted,
    unresolved,
    revoked,
    unsigned,
    actorBound,
    validAtEventTime,
    total,
    error?,
    index?,
    details?
  };
  semantics: {
    ok,
    validTps,
    validEvents,
    validIndexes,
    validPolicies,
    total,
    error?,
    index?,
    details?
  };
  policy: { ok, mode, error?, index?, details? };
}
```

Policy options:

- `requireSignature`
- `requireKid`
- `requireTrustedKey`
- `requireActorBinding`
- `requireEventPolicy`
- `requireMonotonicTps`
- `allowedCalendars`
- `eventPolicies`
- `trustedKeys`

Trusted keys can carry activation/revocation windows and actor binding metadata:

```ts
{
  kid: "key:prod-2026",
  publicKeyHex: "...",
  activeFrom: "tps://node:audit@T:greg.m3.c1.y26.m1.d1.h0.m0.s0.m0",
  revokedAt: "tps://node:audit@T:greg.m3.c1.y26.m6.d1.h0.m0.s0.m0",
  actors: ["system:audit"],
  actorPrefixes: ["system:"],
}
```

Event policies let you require semantics for matching event names:

```ts
{
  "door.*": {
    requireLocation: true,
    allowedActorPrefixes: ["system:"],
    requiredIndexKeys: ["doorId"],
  },
}
```

## License

Apache-2.0
