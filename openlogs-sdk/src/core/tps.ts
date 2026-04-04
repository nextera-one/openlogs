import { TPS } from "@nextera.one/tps-standard";

type ParsedTpsObject = Record<string, unknown> & {
  calendar?: string;
  actor?: string;
  nodeName?: string;
  latitude?: number;
  longitude?: number;
  building?: string;
  floor?: string;
  door?: string;
  room?: string;
  placeCountryCode?: string;
  placeCityCode?: string;
  millennium?: number;
  century?: number;
  year?: number;
  month?: number;
  day?: number;
  hour?: number;
  minute?: number;
  second?: number;
  millisecond?: number;
  unixSeconds?: number;
  order?: string;
};

export interface ParsedTPS {
  raw: string;
  normalized: string;
  calendar: string;
  actor?: string;
  nodeName?: string;
  latitude?: number;
  longitude?: number;
  building?: string;
  floor?: string;
  door?: string;
  room?: string;
  placeCountryCode?: string;
  placeCityCode?: string;
  millennium: number;
  century: number;
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
  millisecond: number;
  order?: string;
  parsed: ParsedTpsObject;
}

export interface TPSValidationResult {
  valid: boolean;
  normalized?: string;
  parsed?: ParsedTPS;
  errors: string[];
}

function isTpsUri(value: string): boolean {
  return value.trim().startsWith("tps://");
}

export function normalizeTpsUri(input: string): string {
  return parseTPS(input).normalized;
}

export function normalizeTPS(input: string): string {
  return normalizeTpsUri(input);
}

export function parseTPS(input: string): ParsedTPS {
  const tps = input?.trim();
  if (!tps) {
    throw new Error("TPS URI is required");
  }

  try {
    const parsedValue = normalizeParsedValue(TPS.parse(tps));
    const normalized = toNormalizedUri(parsedValue);
    const parsed = parsedValue as ParsedTpsObject;

    if (typeof parsed.calendar !== "string" || parsed.calendar.length === 0) {
      throw new Error("Parsed TPS is missing a calendar");
    }

    return {
      raw: tps,
      normalized,
      calendar: parsed.calendar,
      actor: typeof parsed.actor === "string" ? parsed.actor : undefined,
      nodeName:
        typeof parsed.nodeName === "string" ? parsed.nodeName : undefined,
      latitude:
        typeof parsed.latitude === "number" ? parsed.latitude : undefined,
      longitude:
        typeof parsed.longitude === "number" ? parsed.longitude : undefined,
      building:
        typeof parsed.building === "string" ? parsed.building : undefined,
      floor: typeof parsed.floor === "string" ? parsed.floor : undefined,
      door: typeof parsed.door === "string" ? parsed.door : undefined,
      room: typeof parsed.room === "string" ? parsed.room : undefined,
      placeCountryCode:
        typeof parsed.placeCountryCode === "string"
          ? parsed.placeCountryCode
          : undefined,
      placeCityCode:
        typeof parsed.placeCityCode === "string"
          ? parsed.placeCityCode
          : undefined,
      millennium:
        typeof parsed.millennium === "number" ? parsed.millennium : 0,
      century: typeof parsed.century === "number" ? parsed.century : 0,
      year: typeof parsed.year === "number" ? parsed.year : 0,
      month: typeof parsed.month === "number" ? parsed.month : 0,
      day: typeof parsed.day === "number" ? parsed.day : 0,
      hour: typeof parsed.hour === "number" ? parsed.hour : 0,
      minute: typeof parsed.minute === "number" ? parsed.minute : 0,
      second: typeof parsed.second === "number" ? parsed.second : 0,
      millisecond:
        typeof parsed.millisecond === "number" ? parsed.millisecond : 0,
      order: typeof parsed.order === "string" ? parsed.order : undefined,
      parsed,
    };
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid TPS URI: ${message}`);
  }
}

export function validateTPS(input: string): TPSValidationResult {
  const errors: string[] = [];

  let parsed: ParsedTPS;
  try {
    parsed = parseTPS(input);
  } catch (error: unknown) {
    return {
      valid: false,
      errors: [error instanceof Error ? error.message : String(error)],
    };
  }

  if (
    typeof parsed.latitude === "number" &&
    (parsed.latitude < -90 || parsed.latitude > 90)
  ) {
    errors.push(`Latitude out of range [-90, 90]: ${parsed.latitude}`);
  }
  if (
    typeof parsed.longitude === "number" &&
    (parsed.longitude < -180 || parsed.longitude > 180)
  ) {
    errors.push(`Longitude out of range [-180, 180]: ${parsed.longitude}`);
  }
  if (parsed.nodeName !== undefined && parsed.nodeName.trim().length === 0) {
    errors.push("Node name must not be empty");
  }

  return {
    valid: errors.length === 0,
    normalized: parsed.normalized,
    parsed,
    errors,
  };
}

export function compareTPS(left: string, right: string): number {
  const a = parseTPS(left);
  const b = parseTPS(right);

  const fields: Array<keyof ParsedTPS> = [
    "millennium",
    "century",
    "year",
    "month",
    "day",
    "hour",
    "minute",
    "second",
    "millisecond",
  ];

  for (const field of fields) {
    const delta = Number(a[field]) - Number(b[field]);
    if (delta !== 0) {
      return delta < 0 ? -1 : 1;
    }
  }

  if (a.calendar !== b.calendar) {
    return a.calendar.localeCompare(b.calendar);
  }
  if ((a.nodeName ?? "") !== (b.nodeName ?? "")) {
    return (a.nodeName ?? "").localeCompare(b.nodeName ?? "");
  }
  if ((a.latitude ?? 0) !== (b.latitude ?? 0)) {
    return (a.latitude ?? 0) < (b.latitude ?? 0) ? -1 : 1;
  }
  if ((a.longitude ?? 0) !== (b.longitude ?? 0)) {
    return (a.longitude ?? 0) < (b.longitude ?? 0) ? -1 : 1;
  }

  return a.normalized.localeCompare(b.normalized);
}

export function extractTPSActor(input: string): string | undefined {
  return parseTPS(input).actor;
}

export function hasTPSLocation(input: string): boolean {
  const parsed = parseTPS(input);
  return Boolean(
    typeof parsed.latitude === "number" ||
      typeof parsed.longitude === "number" ||
      parsed.building ||
      parsed.floor ||
      parsed.door ||
      parsed.room ||
      parsed.placeCountryCode ||
      parsed.placeCityCode ||
      /^tps:\/(?:\/)?(?:L:|net:|node:|bldg:|floor:|door:|room:)/.test(
        parsed.normalized,
      ),
  );
}

export function hasTPSNode(input: string): boolean {
  const parsed = parseTPS(input);
  return Boolean(
    parsed.nodeName ||
      /^tps:\/\/node:/.test(parsed.normalized) ||
      parsed.actor?.startsWith("node:"),
  );
}

export function compareTemporalValues(left: string, right: string): number {
  const leftEpoch = toEpochMillis(left);
  const rightEpoch = toEpochMillis(right);

  if (leftEpoch !== null && rightEpoch !== null) {
    if (leftEpoch === rightEpoch) return 0;
    return leftEpoch < rightEpoch ? -1 : 1;
  }

  if (isTpsUri(left) && isTpsUri(right)) {
    return compareTPS(left, right);
  }

  throw new Error(
    `Unable to compare temporal values ${JSON.stringify(left)} and ${JSON.stringify(right)}`,
  );
}

function toEpochMillis(value: string): number | null {
  const trimmed = value.trim();

  if (isTpsUri(trimmed)) {
    const parsed = parseTPS(trimmed);

    if (parsed.calendar === "greg") {
      const year = toGregorianYear(parsed);
      return Date.UTC(
        year,
        Math.max(parsed.month, 1) - 1,
        Math.max(parsed.day, 1),
        parsed.hour,
        parsed.minute,
        parsed.second,
        parsed.millisecond,
      );
    }

    if (parsed.calendar === "unix") {
      const rawUnixSeconds = parsed.parsed.unixSeconds;
      if (typeof rawUnixSeconds === "number" && rawUnixSeconds > 0) {
        return rawUnixSeconds * 1000 + parsed.millisecond;
      }
      if (parsed.millennium > 1000000) {
        return parsed.millennium * 1000 + parsed.millisecond;
      }
    }

    return null;
  }

  const epoch = Date.parse(trimmed);
  return Number.isFinite(epoch) ? epoch : null;
}

function toGregorianYear(parsed: ParsedTPS): number {
  const millennium = parsed.millennium > 0 ? (parsed.millennium - 1) * 1000 : 0;
  const century = parsed.century > 0 ? (parsed.century - 1) * 100 : 0;
  return millennium + century + parsed.year;
}

function normalizeParsedValue(parsed: unknown): ParsedTpsObject {
  if (parsed && typeof parsed === "object") {
    return parsed as ParsedTpsObject;
  }

  if (typeof parsed === "string") {
    const reparsed = TPS.parse(parsed);
    if (reparsed && typeof reparsed === "object") {
      return reparsed as ParsedTpsObject;
    }
  }

  throw new Error("Unsupported TPS parse output");
}

function toNormalizedUri(parsed: ParsedTpsObject): string {
  const direct = parsed.uri;
  if (typeof direct === "string") return direct;
  const embedded = parsed.tps;
  if (typeof embedded === "string") return embedded;
  return TPS.toURI(parsed as any);
}
