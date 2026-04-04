import { Command } from "commander";
import chalk from "chalk";

import {
  createV2Record,
  signV2Record,
  hexToBytes,
} from "@nextera.one/openlogs-sdk";
import { appendJsonLine, readJsonFile, readJsonLines } from "./fsutil";

type IdentityFile = {
  alg: "ed25519";
  kid?: string;
  privateKeyHex: string;
  publicKeyHex: string;
};

export const logCommand = new Command("log")
  .description("Append a new OpenLogs v2 record to a JSONL file")
  .requiredOption(
    "-a, --actor <actor>",
    "Actor identifier (e.g., user:alice, system:cron, device:sensor-1)",
  )
  .requiredOption(
    "-t, --tps <tps>",
    "TPS Reality String (e.g., tps://L:31.95,35.91;P:cc=JO@T:greg.m3.c1.y26.m3.d4.h12.m0.s0.m0)",
  )
  .requiredOption(
    "-e, --event <event>",
    "Event type (e.g., door.unlock, step.start)",
  )
  .option("-d, --data <json>", "JSON payload string", "{}")
  .option(
    "-x, --indexes <json>",
    'JSON indexes for querying (e.g., {"s2":"88d9b4"})',
  )
  .option("-f, --file <path>", "Output JSONL file", "./openlogs.jsonl")
  .option(
    "-k, --key <path>",
    "Identity JSON path (for signing)",
    "./.openlogs/identity.json",
  )
  .option("--unsigned", "Do not sign (even if key is available)")
  .action(async (options) => {
    const filePath = String(options.file);

    // Read previous hash from chain
    let prev_hash: string | null = null;
    try {
      const rows = readJsonLines(filePath);
      const last = rows[rows.length - 1];
      prev_hash = last?.hash ?? null;
    } catch {
      prev_hash = null;
    }

    // Parse data payload
    let data: Record<string, unknown> | undefined;
    try {
      const parsed = options.data
        ? JSON.parse(String(options.data))
        : undefined;
      if (parsed && Object.keys(parsed).length > 0) {
        data = parsed;
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      throw new Error(`Invalid --data JSON: ${msg}`);
    }

    // Parse indexes
    let indexes: Record<string, string> | undefined;
    if (options.indexes) {
      try {
        indexes = JSON.parse(String(options.indexes));
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        throw new Error(`Invalid --indexes JSON: ${msg}`);
      }
    }

    // Create v2 record
    const record = createV2Record(
      {
        actor: String(options.actor),
        tps: String(options.tps),
        event: String(options.event),
        data,
        indexes,
      },
      prev_hash,
    );

    let out = record;

    const wantUnsigned = Boolean(options.unsigned);
    if (wantUnsigned) {
      console.warn(
        chalk.yellow(
          "WARNING: --unsigned specified; appending a record without cryptographic proof",
        ),
      );
    } else {
      let id: IdentityFile;
      try {
        id = readJsonFile<IdentityFile>(String(options.key));
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(
          `Signing required but identity file could not be loaded (${options.key}): ${message}. ` +
            "Run 'openlogs init' first or pass --unsigned explicitly.",
        );
      }

      try {
        out = await signV2Record(record, {
          privateKey: hexToBytes(id.privateKeyHex),
          publicKey: hexToBytes(id.publicKeyHex),
          kid: id.kid,
        });
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(`Failed to sign record: ${message}`);
      }
    }

    appendJsonLine(filePath, out);
    console.log(chalk.green("✅ Logged (OpenLogs v2)"));
    console.log(
      `sig:   ${out.sig ? `signed (${out.sig.kid ?? "no-kid"})` : "UNSIGNED"}`,
    );
    console.log(`id:    ${out.entry.id}`);
    console.log(`event: ${out.entry.event}`);
    console.log(`hash:  ${out.hash}`);
  });
