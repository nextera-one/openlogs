# @nextera.one/openlogs-nestjs

NestJS integration for OpenLogs v2.

## Install

```bash
npm i @nextera.one/openlogs-nestjs @nextera.one/openlogs-sdk
```

## Features

- Global NestJS interceptor for request logging
- OpenLogs chain access through `OpenLogsService`
- TPS generation with actor, node, location, and context support
- Success and failure request logging

## Quick Start

```ts
import { Module } from "@nestjs/common";
import { OpenLogsModule } from "@nextera.one/openlogs-nestjs";

@Module({
  imports: [
    OpenLogsModule.forRoot({
      actor: "system:api",
      nodeName: "gateway-eu",
      context: { env: "production" },
    }),
  ],
})
export class AppModule {}
```

## Test

```bash
npm test
```

## License

Apache-2.0
