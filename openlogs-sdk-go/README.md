# openlogs-sdk-go

Core Go SDK for OpenLogs v2 hash-chained records.

Release track note: the Go module remains on the v1 import-path track until a
future `/v2` module-path migration. The current local integration reference is
`v1.1.0`.

## Features

- SHA-256 hash-chained records
- Ed25519 signing and verification
- In-memory chain service with integrity checks

## Test

```bash
go test ./...
```
