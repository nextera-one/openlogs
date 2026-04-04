# openlogs-gin

Gin integration for OpenLogs, modeled after the FastAPI and Spring Boot integrations.

Release track note: the Go integration remains on the v1 import-path track until
the underlying Go SDK adopts a `/v2` module path.

## Features

- Auto-registers Gin middleware for request logging
- Logs success and failure requests into an in-memory OpenLogs chain
- Exposes service access for chain inspection

## Test

```bash
go test ./...
```
