import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Inject,
} from "@nestjs/common";
import { Observable } from "rxjs";
import { tap } from "rxjs/operators";
import { OpenLogsService } from "./openlogs.service";
import { OPENLOGS_OPTIONS, OpenLogsModuleOptions } from "./openlogs.interfaces";
import { TPS } from "@nextera.one/tps-standard";

@Injectable()
export class OpenLogsInterceptor implements NestInterceptor {
  constructor(
    private readonly openLogsService: OpenLogsService,
    @Inject(OPENLOGS_OPTIONS)
    private readonly options: OpenLogsModuleOptions = {},
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const startTime = Date.now();
    const tpsDate = new Date(startTime);

    return next.handle().pipe(
      tap({
        next: () => this.logRequest(context, tpsDate, startTime, null),
        error: (error: unknown) =>
          this.logRequest(context, tpsDate, startTime, error),
      }),
    );
  }

  private async logRequest(
    context: ExecutionContext,
    date: Date,
    startTime: number,
    error: unknown,
  ) {
    if (context.getType() !== "http") {
      return; // currently only handles HTTP
    }

    const durationMs = Date.now() - startTime;
    const httpCtx = context.switchToHttp();
    const req = httpCtx.getRequest();
    const res = httpCtx.getResponse();

    // 1. Generate TPS URI (v0.6.0 String)
    const tpsUri = this.buildTpsUri(req, date);

    // 2. Determine Actor
    const actor = this.options.actor || `client:${this.getClientIp(req)}`;

    // 3. Determine Event Name
    const hasError = error !== null && typeof error !== "undefined";
    const event = hasError ? "http.request.failed" : "http.request.success";

    // 4. Build Data Payload
    const statusCode = getStatusCode(error, res.statusCode);
    const errorMessage = getErrorMessage(error);

    const data = {
      method: req.method,
      url: req.url,
      statusCode,
      durationMs,
      userAgent: req.headers["user-agent"] || "unknown",
      ...(errorMessage && { error: errorMessage }),
    };

    // 5. Build Indexes
    const indexes = {
      method: req.method,
      status: String(statusCode),
    };

    // 6. Log it via OpenLogsService
    try {
      await this.openLogsService.log({
        actor,
        tps: tpsUri,
        event,
        data,
        indexes,
      });
    } catch (err) {
      // Interceptor should not crash the app if logging fails
      console.error("[OpenLogsInterceptor] Failed to log request", err);
    }
  }

  private buildTpsUri(req: any, date: Date): string {
    const timeTokens = TPS.fromDate(date); // e.g., T:greg...

    // Location Layers
    let locationParts = [];

    // Add server IP if available (either IPv4 or IPv6 format)
    const serverIp = req.socket?.localAddress;
    if (serverIp) {
      if (serverIp.includes(":")) {
        locationParts.push(`net:ip6:${serverIp}`);
      } else {
        locationParts.push(`net:ip4:${serverIp}`);
      }
    }

    // Add Hostname / Node
    if (this.options.nodeName) {
      locationParts.push(`node:${this.options.nodeName}`);
    } else {
      const host = req.headers["host"];
      if (host) locationParts.push(`node:${host.split(":")[0]}`);
    }

    // Fallback Location
    if (this.options.location?.latitude && this.options.location?.longitude) {
      const l = this.options.location;
      let gps = `L:${l.latitude},${l.longitude}`;
      locationParts.push(gps);

      let placeParts = [];
      if (l.placeCountryCode) placeParts.push(`cc=${l.placeCountryCode}`);
      if (l.placeCityCode) placeParts.push(`ci=${l.placeCityCode}`);
      if (placeParts.length > 0) {
        locationParts.push(`P:${placeParts.join(",")}`);
      }
    }

    // Context Fragments
    let ctxString = "";
    if (this.options.context) {
      const parts = Object.entries(this.options.context)
        .map(([k, v]) => `${k}=${v}`)
        .join(";");
      ctxString = `#C:${parts}`;
    }

    // Assemble components
    const locationPrefix =
      locationParts.length > 0 ? locationParts.join(";") : "unknown";

    return `tps://${locationPrefix}@${timeTokens}${ctxString}`;
  }

  private getClientIp(req: any): string {
    const forwardedStr = req.headers["x-forwarded-for"];
    if (forwardedStr) {
      const forwarded = forwardedStr.split(",")[0];
      return forwarded.trim();
    }
    return req.socket?.remoteAddress || "unknown";
  }
}

function getStatusCode(error: unknown, fallbackStatusCode: number): number {
  if (
    error &&
    typeof error === "object" &&
    "status" in error &&
    typeof error.status === "number"
  ) {
    return error.status;
  }

  return error ? 500 : fallbackStatusCode;
}

function getErrorMessage(error: unknown): string | undefined {
  if (!error) return undefined;
  if (error instanceof Error) return error.message;
  return String(error);
}
