import { describe, expect, it } from "vitest";
import {
  compareTPS,
  computeV2RecordHash,
  createV2Chain,
  createV2Record,
  generateEd25519Keypair,
  normalizeTPS,
  parseTPS,
  signV2Record,
  validateTPS,
  verifyV2Chain,
  verifyV2RecordSignature,
} from "../index";

describe("openlogs-sdk chain", () => {
  const baseTps = "tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s25.m0";

  it("creates a valid hash chain", async () => {
    const r1 = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test.one", data: { n: 1 } },
      null,
    );

    const r2 = createV2Record(
      {
        actor: "system:test",
        tps: "tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s26.m0",
        event: "test.two",
        data: { n: 2 },
      },
      r1.hash,
    );

    const res = await verifyV2Chain([r1, r2]);
    expect(res.ok).toBe(true);
    expect(res.records).toBe(2);
    expect(res.integrity.ok).toBe(true);
    expect(res.signatures.present).toBe(0);
    expect(res.policy.mode).toBe("allow-unsigned");
  });

  it("detects a broken prevHash", async () => {
    const r1 = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test.one" },
      null,
    );
    const r2 = createV2Record(
      {
        actor: "system:test",
        tps: "tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s26.m0",
        event: "test.two",
      },
      "deadbeef",
    );

    const res = await verifyV2Chain([r1, r2]);
    expect(res.ok).toBe(false);
    expect(res.error).toBe("prev-hash-mismatch");
    expect(res.index).toBe(1);
    expect(res.integrity.ok).toBe(false);
  });

  it("detects tampered entry data", async () => {
    const r1 = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test.one" },
      null,
    );

    // Tamper with the entry
    const tampered = { ...r1, entry: { ...r1.entry, event: "tampered" } };
    const res = await verifyV2Chain([tampered]);
    expect(res.ok).toBe(false);
    expect(res.error).toBe("hash-mismatch");
    expect(res.integrity.ok).toBe(false);
  });

  it("signs and verifies signatures when present", async () => {
    const keys = await generateEd25519Keypair();

    const r1 = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test.sig" },
      null,
    );

    const signed = await signV2Record(r1, keys);
    expect(signed.sig).toBeTruthy();

    const res = await verifyV2Chain([signed]);
    expect(res.ok).toBe(true);
    expect(res.signatures.present).toBe(1);
    expect(res.signatures.total).toBe(1);
  });

  it("detects bad signatures", async () => {
    const keys = await generateEd25519Keypair();
    const r1 = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test.sig" },
      null,
    );

    const signed = await signV2Record(r1, keys);

    // Tamper with the signature by flipping the first hex character
    const origSig = signed.sig!.sigHex;
    const flippedChar = origSig[0] === "0" ? "1" : "0";
    const tampered = {
      ...signed,
      sig: { ...signed.sig!, sigHex: flippedChar + origSig.slice(1) },
    };
    const res = await verifyV2Chain([tampered]);
    expect(res.ok).toBe(false);
    expect(res.error).toBe("bad-signature");
    expect(res.signatures.ok).toBe(false);
  });

  it("verifyV2RecordSignature returns false for unsigned records", async () => {
    const r1 = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test" },
      null,
    );
    const result = await verifyV2RecordSignature(r1);
    expect(result).toBe(false);
  });

  it("signV2Record validates key sizes", async () => {
    const r1 = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test" },
      null,
    );

    await expect(
      signV2Record(r1, {
        privateKey: new Uint8Array(16),
        publicKey: new Uint8Array(32),
      }),
    ).rejects.toThrow("32-byte");

    await expect(
      signV2Record(r1, {
        privateKey: new Uint8Array(32),
        publicKey: new Uint8Array(16),
      }),
    ).rejects.toThrow("32-byte");
  });

  it("computeV2RecordHash validates entry spec", () => {
    expect(() => computeV2RecordHash({ spec: "wrong" } as any, null)).toThrow(
      "openlogs.v2",
    );
  });

  it("require-signature fails for unsigned records", async () => {
    const record = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test.one" },
      null,
    );

    const res = await verifyV2Chain([record], { requireSignature: true });
    expect(res.ok).toBe(false);
    expect(res.policy.ok).toBe(false);
    expect(res.error).toBe("policy-unsigned-record");
  });

  it("require-kid fails when a signature omits kid", async () => {
    const keys = await generateEd25519Keypair();
    const record = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test.kid" },
      null,
    );
    const signed = await signV2Record(record, keys);

    const res = await verifyV2Chain([signed], { requireKid: true });
    expect(res.ok).toBe(false);
    expect(res.policy.ok).toBe(false);
    expect(res.error).toBe("policy-missing-kid");
  });

  it("require-trusted-key passes when signature matches a trusted registry entry", async () => {
    const keys = await generateEd25519Keypair();
    const record = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test.trust" },
      null,
    );
    const signed = await signV2Record(record, { ...keys, kid: "kid:test" });

    const res = await verifyV2Chain([signed], {
      requireTrustedKey: true,
      trustedKeys: [
        {
          kid: "kid:test",
          publicKeyHex: signed.sig!.publicKeyHex,
        },
      ],
    });

    expect(res.ok).toBe(true);
    expect(res.trust.trusted).toBe(1);
    expect(res.policy.ok).toBe(true);
  });

  it("require-trusted-key fails when signature is not in the trust registry", async () => {
    const keys = await generateEd25519Keypair();
    const record = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test.trust" },
      null,
    );
    const signed = await signV2Record(record, { ...keys, kid: "kid:test" });

    const res = await verifyV2Chain([signed], {
      requireTrustedKey: true,
      trustedKeys: [],
    });

    expect(res.ok).toBe(false);
    expect(res.policy.ok).toBe(false);
    expect(res.error).toBe("policy-untrusted-key");
  });

  it("require-monotonic-tps fails when TPS order regresses", async () => {
    const earlier = createV2Record(
      {
        actor: "system:test",
        tps: "tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s26.m0",
        event: "test.two",
      },
      null,
    );
    const later = createV2Record(
      {
        actor: "system:test",
        tps: baseTps,
        event: "test.one",
      },
      earlier.hash,
    );

    const res = await verifyV2Chain([earlier, later], {
      requireMonotonicTps: true,
    });

    expect(res.ok).toBe(false);
    expect(res.policy.ok).toBe(false);
    expect(res.error).toBe("non-monotonic-tps");
  });

  it("require-actor-binding fails when a trusted key is not bound to the actor", async () => {
    const keys = await generateEd25519Keypair();
    const record = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test.binding" },
      null,
    );
    const signed = await signV2Record(record, { ...keys, kid: "kid:binding" });

    const res = await verifyV2Chain([signed], {
      requireTrustedKey: true,
      requireActorBinding: true,
      trustedKeys: [
        {
          kid: "kid:binding",
          publicKeyHex: signed.sig!.publicKeyHex,
          actors: ["user:alice"],
        },
      ],
    });

    expect(res.ok).toBe(false);
    expect(res.policy.ok).toBe(false);
    expect(res.error).toBe("policy-actor-binding");
    expect(res.trust.actorBound).toBe(0);
    expect(res.trust.validAtEventTime).toBe(1);
  });

  it("require-trusted-key fails when the key is not active at event time", async () => {
    const keys = await generateEd25519Keypair();
    const record = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test.active-from" },
      null,
    );
    const signed = await signV2Record(record, { ...keys, kid: "kid:future" });

    const res = await verifyV2Chain([signed], {
      requireTrustedKey: true,
      trustedKeys: [
        {
          kid: "kid:future",
          publicKeyHex: signed.sig!.publicKeyHex,
          activeFrom:
            "tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s26.m0",
        },
      ],
    });

    expect(res.ok).toBe(false);
    expect(res.policy.ok).toBe(false);
    expect(res.error).toBe("policy-untrusted-key");
    expect(res.trust.unresolved).toBe(1);
    expect(res.trust.validAtEventTime).toBe(0);
  });

  it("tracks revoked keys separately from unresolved keys", async () => {
    const keys = await generateEd25519Keypair();
    const record = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test.revoked" },
      null,
    );
    const signed = await signV2Record(record, { ...keys, kid: "kid:revoked" });

    const res = await verifyV2Chain([signed], {
      requireTrustedKey: true,
      trustedKeys: [
        {
          kid: "kid:revoked",
          publicKeyHex: signed.sig!.publicKeyHex,
          revokedAt: baseTps,
          revokedReason: "rotated out of service",
        },
      ],
    });

    expect(res.ok).toBe(false);
    expect(res.policy.ok).toBe(false);
    expect(res.trust.revoked).toBe(1);
    expect(res.trust.unresolved).toBe(0);
  });

  it("enforces event policies for location, actor prefixes, and required indexes", async () => {
    const record = createV2Record(
      {
        actor: "system:test",
        tps: "tps://bldg:vault;floor:1;door:1@T:greg.m3.c1.y26.m01.d09.h14.m30.s25.m0",
        event: "door.unlock",
        indexes: { doorId: "vault-1" },
      },
      null,
    );

    const res = await verifyV2Chain([record], {
      requireEventPolicy: true,
      eventPolicies: {
        "door.*": {
          requireLocation: true,
          allowedActorPrefixes: ["system:"],
          requiredIndexKeys: ["doorId"],
        },
      },
    });

    expect(res.ok).toBe(true);
    expect(res.semantics.validPolicies).toBe(1);
  });

  it("require-event-policy fails when no event policy matches a record", async () => {
    const record = createV2Record(
      { actor: "system:test", tps: baseTps, event: "door.unlock" },
      null,
    );

    const res = await verifyV2Chain([record], {
      requireEventPolicy: true,
      eventPolicies: {
        "auth.*": {
          allowedActorPrefixes: ["system:"],
        },
      },
    });

    expect(res.ok).toBe(false);
    expect(res.semantics.ok).toBe(false);
    expect(res.error).toBe("missing-event-policy");
  });

  it("allowedCalendars rejects TPS values outside the permitted set", async () => {
    const record = createV2Record(
      { actor: "system:test", tps: baseTps, event: "test.calendar" },
      null,
    );

    const res = await verifyV2Chain([record], {
      allowedCalendars: ["unix"],
    });

    expect(res.ok).toBe(false);
    expect(res.semantics.ok).toBe(false);
    expect(res.error).toBe("calendar-not-allowed");
  });
});

describe("createV2Chain", () => {
  it("creates a batch of chained records", async () => {
    const records = createV2Chain([
      {
        actor: "system:test",
        tps: "tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s25.m0",
        event: "step.one",
      },
      {
        actor: "system:test",
        tps: "tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s26.m0",
        event: "step.two",
      },
      {
        actor: "system:test",
        tps: "tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s27.m0",
        event: "step.three",
      },
    ]);

    expect(records.length).toBe(3);
    expect(records[0].prev_hash).toBeNull();
    expect(records[1].prev_hash).toBe(records[0].hash);
    expect(records[2].prev_hash).toBe(records[1].hash);

    const res = await verifyV2Chain(records);
    expect(res.ok).toBe(true);
  });

  it("throws on empty input", () => {
    expect(() => createV2Chain([])).toThrow("at least one input");
  });
});

describe("TPS helpers", () => {
  const tpsA = "tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s25.m0";
  const tpsB = "tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s26.m0";

  it("parseTPS returns normalized structure", () => {
    const parsed = parseTPS(tpsA);
    expect(parsed.normalized).toBe("tps://node:test@T:greg.m3.c1.y26.m1.d9.h14.m30.s25.m0");
    expect(parsed.calendar).toBe("greg");
    expect(parsed.nodeName).toBe("test");
    expect(parsed.second).toBe(25);
  });

  it("validateTPS reports invalid input", () => {
    const result = validateTPS("not-a-tps");
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
  });

  it("normalizeTPS delegates to the TPS parser", () => {
    expect(normalizeTPS(tpsA)).toBe(
      "tps://node:test@T:greg.m3.c1.y26.m1.d9.h14.m30.s25.m0",
    );
  });

  it("compareTPS orders sequential TPS values", () => {
    expect(compareTPS(tpsA, tpsB)).toBeLessThan(0);
    expect(compareTPS(tpsB, tpsA)).toBeGreaterThan(0);
    expect(compareTPS(tpsA, tpsA)).toBe(0);
  });
});
