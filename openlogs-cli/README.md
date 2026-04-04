# @nextera.one/openlogs-cli

Command-line tool for creating, signing, verifying, and inspecting **OpenLogs v2** records on disk.

## Install

```bash
npm i -g @nextera.one/openlogs-cli
```

## Commands

### `openlogs init`

Create an Ed25519 identity keypair for signing records.

```bash
openlogs init
openlogs init --out ./my-identity.json --kid kid:prod-key
```

**Options:**

- `-o, --out <path>` — Output path (default: `.openlogs/identity.json`)
- `--kid <kid>` — Key identifier to embed in signatures (default: `kid:local`)

---

### `openlogs log`

Append a new signed v2 record to a JSONL file.

```bash
openlogs log \
  --actor "user:alice" \
  --event "auth.login" \
  --tps "tps://L:40.7128,-74.0060@T:greg.m3.c1.y26.m3.d3.h16.m30.s0.m0" \
  --data '{"method":"oauth2"}'
```

**Options:**

- `-a, --actor <actor>` — Actor identifier (**required**)
- `-e, --event <event>` — Event type (**required**)
- `-t, --tps <tps>` — TPS Reality String (**required**)
- `-d, --data <json>` — JSON payload (default: `{}`)
- `-x, --indexes <json>` — JSON indexes for querying
- `-f, --file <path>` — Output JSONL file (default: `./openlogs.jsonl`)
- `-k, --key <path>` — Identity JSON path (default: `.openlogs/identity.json`)
- `--unsigned` — Do not sign the record

---

### `openlogs verify`

Verify hash chain integrity and signatures of an OpenLogs JSONL file.

```bash
openlogs verify
openlogs verify --file ./audit.jsonl
openlogs verify --trust ./trust.json --require-trusted-key
openlogs verify --policy ./verify-policy.json
```

**Options:**

- `-f, --file <path>` — Input JSONL file (default: `./openlogs.jsonl`)
- `--policy <path>` — Load a JSON verification policy document
- `--require-signature` / `--require-signatures` — Fail if any record is unsigned
- `--require-kid` — Fail if any signature is missing a key id
- `--require-trusted-key` — Fail if any signature is not backed by the trusted key registry
- `--require-actor-binding` — Fail if a trusted key is not authorized for the record actor
- `--require-event-policy` — Fail if no event policy matches a record event
- `--trust <path>` / `--trusted-keys <path>` — Load trusted keys from JSON
- `--allow-calendar <calendar>` — Restrict verification to specific TPS calendars
- `--require-monotonic-tps` — Fail if TPS order regresses across the chain

Example policy document shape:

```json
{
  "requireSignature": true,
  "requireTrustedKey": true,
  "requireActorBinding": true,
  "allowedCalendars": ["greg"],
  "trustedKeys": [
    {
      "kid": "key:prod-main",
      "publicKeyHex": "...",
      "actors": ["system:api"],
      "activeFrom": "tps://node:api@T:greg.m3.c1.y26.m1.d1.h0.m0.s0.m0"
    }
  ],
  "eventPolicies": {
    "http.request.*": {
      "requireNode": true,
      "allowedActorPrefixes": ["system:"]
    }
  }
}
```

---

### `openlogs inspect`

Inspect records from an OpenLogs JSONL file with multiple output formats.

```bash
openlogs inspect                          # Full JSON output
openlogs inspect --last                   # Last record only
openlogs inspect -n 5                     # Last 5 records
openlogs inspect --format table           # Table view
openlogs inspect --format compact         # Compact one-line-per-record
```

**Options:**

- `-f, --file <path>` — Input JSONL file (default: `./openlogs.jsonl`)
- `--last` — Show only the last record
- `-n, --count <n>` — Show last N records
- `--format <format>` — Output format: `json` (default), `compact`, or `table`

---

### `openlogs export`

Export records to JSON array or CSV format.

```bash
openlogs export                           # JSON array output
openlogs export --format csv              # CSV with auto-detected fields
openlogs export --format csv --fields entry.id,entry.event,hash
```

**Options:**

- `-f, --file <path>` — Input JSONL file (default: `./openlogs.jsonl`)
- `--format <format>` — Output format: `json` (default) or `csv`
- `--fields <fields>` — Comma-separated fields for CSV (auto-detects if omitted)

## Typical Workflow

```bash
# 1. Initialize identity
openlogs init

# 2. Log some events
openlogs log -a "user:alice" -e "door.unlock" \
  -t "tps://L:40.71,-74.00@T:greg.m3.c1.y26.m3.d3.h08.m0.s0.m0"

openlogs log -a "system:audit" -e "data.read" \
  -t "tps://L:40.71,-74.00@T:greg.m3.c1.y26.m3.d3.h08.m5.s0.m0" \
  -d '{"query":"SELECT * FROM users"}'

# 3. Verify chain
openlogs verify

# 4. Inspect records
openlogs inspect --format table

# 5. Export
openlogs export --format csv > audit.csv
```

## License

Apache-2.0
