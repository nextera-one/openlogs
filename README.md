# OpenLogs

**Provable execution evidence** — tamper-evident, cryptographically signed log chains anchored to [TPS Reality Strings](https://github.com/nicholasgasior/tps-standard).

```
openlogs/
├── openlogs-sdk     →  Core TypeScript SDK (hash chains, Ed25519 signing, TPS-UID)
├── openlogs-cli     →  CLI tool (init, log, verify, inspect, export)
├── openlogs-test    →  Assertion-based integration test suite
├── openlogs-nestjs  →  NestJS integration (interceptor and middleware)
├── openlogs-sdk-java → Core Java SDK (hash chains, canonical hashing)
├── openlogs-springboot → Spring Boot integration (auto interceptor, request logging)
├── openlogs-sdk-python → Core Python SDK (hash chains, Ed25519 signing)
├── openlogs-fastapi → FastAPI integration (middleware request logging)
├── openlogs-sdk-go  → Core Go SDK (hash chains, Ed25519 signing)
├── openlogs-sdk-csharp → Core C# SDK (hash chains, Ed25519 signing)
├── openlogs-gin → Gin integration (middleware request logging)
└── openlogs-aspnetcore → ASP.NET Core integration (middleware request logging)
```

## Quick Start

```bash
# Install all workspaces
npm install

# Build everything
npm run build

# Run all tests
npm run test
```

Root npm workspace scripts currently target these packages:

- `openlogs-sdk`
- `openlogs-cli`
- `openlogs-test`
- `openlogs-nestjs`

Other language/framework directories in this repository are present as sibling
packages, but they are not currently part of the root npm workspace scripts.

## How It Works

1. **Create** a log entry with an actor, event, TPS coordinate, and optional data
2. **Chain** entries together via SHA-256 hash links — each record references the previous
3. **Sign** records with Ed25519 for cryptographic proof of authorship
4. **Verify** the entire chain to detect tampering or unauthorized modifications

```ts
import {
  createV2Chain,
  signV2Record,
  verifyV2Chain,
  generateEd25519Keypair,
} from "@nextera.one/openlogs-sdk";

// Build a chain of 3 records
const chain = createV2Chain([
  {
    actor: "user:alice",
    tps: "tps://L:40.71,-74.00@T:greg.m3.c1.y26.m3.d3.h08.m0.s0.m0",
    event: "auth.login",
  },
  {
    actor: "user:alice",
    tps: "tps://L:40.71,-74.00@T:greg.m3.c1.y26.m3.d3.h08.m5.s0.m0",
    event: "data.read",
  },
  {
    actor: "user:alice",
    tps: "tps://L:40.71,-74.00@T:greg.m3.c1.y26.m3.d3.h08.m10.s0.m0",
    event: "auth.logout",
  },
]);

// Sign & verify
const keys = await generateEd25519Keypair();
const signed = await Promise.all(chain.map((r) => signV2Record(r, keys)));
console.log(await verifyV2Chain(signed, { requireSignature: true }));
```

## Active npm Workspaces

| Package                                           | Description                                                     | Version |
| ------------------------------------------------- | --------------------------------------------------------------- | ------- |
| [@nextera.one/openlogs-sdk](./openlogs-sdk)       | Core SDK — entries, hash chains, signing, TPS-UID, key rotation | 2.2.0   |
| [@nextera.one/openlogs-cli](./openlogs-cli)       | CLI — `init`, `log`, `verify`, `inspect`, `export`              | 2.2.0   |
| [@nextera.one/openlogs-test](./openlogs-test)     | Integration test suite and examples workspace                   | 2.2.0   |
| [@nextera.one/openlogs-nestjs](./openlogs-nestjs) | NestJS integration — interceptor and middleware package         | 2.2.0   |

## Additional Packages In Repo

These directories exist in the repository, but are not currently wired into the
root npm workspace scripts:

- [openlogs-sdk-java](./openlogs-sdk-java) — Maven metadata aligned to `2.2.0`
- [openlogs-springboot](./openlogs-springboot) — Maven metadata aligned to `2.2.0`
- [openlogs-sdk-python](./openlogs-sdk-python) — Python package metadata aligned to `2.2.0`
- [openlogs-fastapi](./openlogs-fastapi) — Python package metadata aligned to `2.2.0`
- [openlogs-sdk-go](./openlogs-sdk-go) — Go module remains on the v1 import-path track until a `/v2` module-path migration
- [openlogs-sdk-csharp](./openlogs-sdk-csharp) — NuGet package metadata aligned to `2.2.0`
- [openlogs-gin](./openlogs-gin) — Go integration remains on the v1 import-path track until a `/v2` module-path migration
- [openlogs-aspnetcore](./openlogs-aspnetcore) — NuGet package metadata aligned to `2.2.0`

## Key Features

- **Hash-chained records** — SHA-256 linked entries for tamper evidence
- **Ed25519 signatures** — cryptographic proof per record
- **TPS Reality Strings** — time + place + space as primary keys
- **TPS-UID** — globally unique, reversible IDs
- **Geospatial indexes** — S2/H3 cell support
- **Multi-calendar** — Gregorian, Unix, and more
- **Key rotation** — `KeyRegistry` for managing trusted signing keys
- **Batch operations** — `createV2Chain` for multi-record creation
- **Dual CJS/ESM** — works everywhere

## Development

```bash
# Build individual packages
npm run build:sdk
npm run build:cli

# Test individual packages
npm run test:sdk
npm run test:cli
npm run test:integration
```

## Verification Policy

The verifier can now report separate layers instead of a single structural pass:

- integrity
- signatures
- trust
- semantics
- policy

Examples:

```bash
# Fail if any record is unsigned
openlogs verify --require-signatures

# Fail if any signature is not backed by a trusted key registry
openlogs verify --trust trust.json --require-trusted-key

# Fail if a trusted key is valid cryptographically but not authorized for the record actor
openlogs verify --trust trust.json --require-trusted-key --require-actor-binding

# Fail if TPS order regresses within the chain
openlogs verify --require-monotonic-tps

# Load richer trust + event policy rules from JSON
openlogs verify --policy verify-policy.json
```

Policy files can provide `trustedKeys`, `allowedCalendars`, and `eventPolicies`
for semantic enforcement such as actor binding, event-specific location/index
requirements, and key activation or revocation windows.

## License

Apache-2.0
