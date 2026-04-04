import { describe, expect, it } from "vitest";
import {
  createV2Record,
  generateEd25519Keypair,
  KeyRegistry,
  signV2Record,
} from "../index";

describe("KeyRegistry", () => {
  const baseTps =
    "tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s25.m0";

  it("verifies a record against an active actor-bound key", async () => {
    const keys = await generateEd25519Keypair();
    const record = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test.one" },
      null,
    );
    const signed = await signV2Record(record, { ...keys, kid: "kid:test" });

    const registry = new KeyRegistry();
    registry.addKey({
      kid: "kid:test",
      publicKeyHex: signed.sig!.publicKeyHex,
      actors: ["system:test"],
      activeFrom: "tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s24.m0",
    });

    const result = await registry.verifyRecord(signed);
    expect(result.valid).toBe(true);
    expect(result.trusted).toBe(true);
    expect(result.actorBound).toBe(true);
    expect(result.validAtEventTime).toBe(true);
  });

  it("reports actor binding failures", async () => {
    const keys = await generateEd25519Keypair();
    const record = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test.binding" },
      null,
    );
    const signed = await signV2Record(record, {
      ...keys,
      kid: "kid:binding",
    });

    const registry = new KeyRegistry();
    registry.addKey({
      kid: "kid:binding",
      publicKeyHex: signed.sig!.publicKeyHex,
      actors: ["user:alice"],
    });

    const result = await registry.verifyRecord(signed);
    expect(result.valid).toBe(true);
    expect(result.trusted).toBe(false);
    expect(result.actorBound).toBe(false);
    expect(result.reason).toMatch(/not bound/);
  });

  it("reports event-time revocation failures", async () => {
    const keys = await generateEd25519Keypair();
    const record = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test.revoked" },
      null,
    );
    const signed = await signV2Record(record, {
      ...keys,
      kid: "kid:revoked",
    });

    const registry = new KeyRegistry();
    registry.addKey({
      kid: "kid:revoked",
      publicKeyHex: signed.sig!.publicKeyHex,
      revokedAt: baseTps,
      revokedReason: "rotated out of service",
    });

    const result = await registry.verifyRecord(signed);
    expect(result.valid).toBe(true);
    expect(result.trusted).toBe(false);
    expect(result.validAtEventTime).toBe(false);
    expect(result.reason).toMatch(/rotated out of service/);
  });
});