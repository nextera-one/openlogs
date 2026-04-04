# openlogs-fastapi

FastAPI integration for OpenLogs, modeled after the NestJS package behavior.

## Features

- Auto-registers HTTP middleware for request logging
- Logs success and failure requests into an in-memory OpenLogs chain
- Exposes `OpenLogsFastAPIService` to read the current chain

## Install

```bash
pip install openlogs-sdk-python openlogs-fastapi
```

## Quick Use

```python
from fastapi import FastAPI
from openlogs_fastapi import OpenLogsConfig, add_openlogs

app = FastAPI()
service = add_openlogs(app, OpenLogsConfig(node_name="demo-api", context={"env": "demo"}))
```
