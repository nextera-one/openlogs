# openlogs-sdk-python

Core Python SDK for OpenLogs v2 style hash-chained records.

## Features

- Create tamper-evident records linked by SHA-256 previous hashes
- Deterministic canonical JSON hashing
- Ed25519 signing and verification helpers
- In-memory chain service with integrity checks

## Install

```bash
pip install openlogs-sdk-python
```

## Quick Example

```python
from openlogs_sdk import OpenLogsEntry, OpenLogsChainService, generate_ed25519_keypair

service = OpenLogsChainService()

entry = OpenLogsEntry(
    actor="system:api",
    tps="tps://node:api@T:unix.1700000000",
    event="http.request.success",
    data={"statusCode": 200},
    indexes={"status": "200"},
)

record = service.log(entry)
print(record.hash)

keys = generate_ed25519_keypair()
signed = service.log_signed(entry, keys.private_key, keys.public_key, kid="k1")
print(signed.signature.alg)
```
