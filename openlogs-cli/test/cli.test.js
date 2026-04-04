const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function runOpenLogs(args, cwd) {
  const cliEntry = path.resolve(__dirname, '..', 'dist', 'index.js');
  const res = spawnSync(
    process.execPath,
    [cliEntry, ...args],
    {
      cwd,
      encoding: 'utf8',
    },
  );
  return {
    code: res.status ?? 0,
    stdout: res.stdout ?? '',
    stderr: res.stderr ?? '',
  };
}

test('openlogs --help shows commands', () => {
  const cwd = process.cwd();
  const res = runOpenLogs(['--help'], cwd);
  assert.equal(res.code, 0);
  assert.match(res.stdout, /Commands:/);
  assert.match(res.stdout, /init/);
  assert.match(res.stdout, /log/);
  assert.match(res.stdout, /verify/);
  assert.match(res.stdout, /inspect/);
});

test('init + log + verify roundtrip', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'openlogs-cli-'));

  const init = runOpenLogs(
    ['init', '--out', '.openlogs/identity.json', '--kid', 'kid:test'],
    tmp,
  );
  assert.equal(init.code, 0, init.stderr || init.stdout);

  const log1 = runOpenLogs(
    [
      'log',
      '--actor',
      'system:test',
      '--event',
      'test.one',
      '--tps',
      'tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s25.m0',
      '--data',
      '{"n":1}',
    ],
    tmp,
  );
  assert.equal(log1.code, 0, log1.stderr || log1.stdout);

  const log2 = runOpenLogs(
    [
      'log',
      '--actor',
      'system:test',
      '--event',
      'test.two',
      '--tps',
      'tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s26.m0',
      '--data',
      '{"n":2}',
    ],
    tmp,
  );
  assert.equal(log2.code, 0, log2.stderr || log2.stdout);

  const verify = runOpenLogs(['verify', '--file', 'openlogs.jsonl'], tmp);
  assert.equal(verify.code, 0, verify.stderr || verify.stdout);
  assert.match(verify.stdout, /PASS/);
  assert.match(verify.stdout, /signatures:/);
});

test('log fails if no identity is available and --unsigned is not set', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'openlogs-cli-missing-key-'));

  const log = runOpenLogs(
    [
      'log',
      '--actor',
      'system:test',
      '--event',
      'test.one',
      '--tps',
      'tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s25.m0',
    ],
    tmp,
  );

  assert.notEqual(log.code, 0);
  assert.match(log.stderr, /Signing required but identity file could not be loaded/);
});

test('log succeeds with --unsigned and verify --require-signatures fails', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'openlogs-cli-unsigned-'));

  const log = runOpenLogs(
    [
      'log',
      '--actor',
      'system:test',
      '--event',
      'test.one',
      '--tps',
      'tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s25.m0',
      '--unsigned',
    ],
    tmp,
  );

  assert.equal(log.code, 0, log.stderr || log.stdout);
  assert.match(log.stdout, /UNSIGNED/);

  const verify = runOpenLogs(
    ['verify', '--file', 'openlogs.jsonl', '--require-signatures'],
    tmp,
  );

  assert.notEqual(verify.code, 0);
  assert.match(verify.stdout, /policy:/);
  assert.match(verify.stderr, /policy-unsigned-record/);
});

test('verify --trust and --require-trusted-key passes with trusted registry', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'openlogs-cli-trust-'));

  const init = runOpenLogs(
    ['init', '--out', '.openlogs/identity.json', '--kid', 'kid:test'],
    tmp,
  );
  assert.equal(init.code, 0, init.stderr || init.stdout);

  const identity = JSON.parse(
    fs.readFileSync(path.join(tmp, '.openlogs', 'identity.json'), 'utf8'),
  );
  fs.writeFileSync(
    path.join(tmp, 'trust.json'),
    JSON.stringify([
      {
        kid: 'kid:test',
        publicKeyHex: identity.publicKeyHex,
      },
    ]),
  );

  const log = runOpenLogs(
    [
      'log',
      '--actor',
      'system:test',
      '--event',
      'test.one',
      '--tps',
      'tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s25.m0',
    ],
    tmp,
  );
  assert.equal(log.code, 0, log.stderr || log.stdout);

  const verify = runOpenLogs(
    [
      'verify',
      '--file',
      'openlogs.jsonl',
      '--trust',
      'trust.json',
      '--require-trusted-key',
    ],
    tmp,
  );
  assert.equal(verify.code, 0, verify.stderr || verify.stdout);
  assert.match(verify.stdout, /trust:/);
  assert.match(verify.stdout, /trusted=1/);
});

test('verify --policy loads event policies and actor-bound trusted keys', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'openlogs-cli-policy-'));

  const init = runOpenLogs(
    ['init', '--out', '.openlogs/identity.json', '--kid', 'kid:policy'],
    tmp,
  );
  assert.equal(init.code, 0, init.stderr || init.stdout);

  const identity = JSON.parse(
    fs.readFileSync(path.join(tmp, '.openlogs', 'identity.json'), 'utf8'),
  );
  fs.writeFileSync(
    path.join(tmp, 'policy.json'),
    JSON.stringify({
      requireSignature: true,
      requireTrustedKey: true,
      requireActorBinding: true,
      requireEventPolicy: true,
      trustedKeys: [
        {
          kid: 'kid:policy',
          publicKeyHex: identity.publicKeyHex,
          actors: ['system:test'],
          activeFrom: 'tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s24.m0',
        },
      ],
      eventPolicies: {
        'door.*': {
          requireLocation: true,
          allowedActorPrefixes: ['system:'],
          requiredIndexKeys: ['doorId'],
        },
      },
    }),
  );

  const log = runOpenLogs(
    [
      'log',
      '--actor',
      'system:test',
      '--event',
      'door.unlock',
      '--tps',
      'tps://bldg:vault;floor:1;door:1@T:greg.m3.c1.y26.m01.d09.h14.m30.s25.m0',
      '--indexes',
      '{"doorId":"vault-1"}',
    ],
    tmp,
  );
  assert.equal(log.code, 0, log.stderr || log.stdout);

  const verify = runOpenLogs(
    ['verify', '--file', 'openlogs.jsonl', '--policy', 'policy.json'],
    tmp,
  );
  assert.equal(verify.code, 0, verify.stderr || verify.stdout);
  assert.match(verify.stdout, /actorBound=1/);
  assert.match(verify.stdout, /validAtEventTime=1/);
  assert.match(verify.stdout, /1\/1 policies/);
});

test('verify --require-actor-binding fails when the trusted key is bound to a different actor', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'openlogs-cli-binding-'));

  const init = runOpenLogs(
    ['init', '--out', '.openlogs/identity.json', '--kid', 'kid:binding'],
    tmp,
  );
  assert.equal(init.code, 0, init.stderr || init.stdout);

  const identity = JSON.parse(
    fs.readFileSync(path.join(tmp, '.openlogs', 'identity.json'), 'utf8'),
  );
  fs.writeFileSync(
    path.join(tmp, 'trust.json'),
    JSON.stringify([
      {
        kid: 'kid:binding',
        publicKeyHex: identity.publicKeyHex,
        actors: ['user:alice'],
      },
    ]),
  );

  const log = runOpenLogs(
    [
      'log',
      '--actor',
      'system:test',
      '--event',
      'test.binding',
      '--tps',
      'tps://node:test@T:greg.m3.c1.y26.m01.d09.h14.m30.s25.m0',
    ],
    tmp,
  );
  assert.equal(log.code, 0, log.stderr || log.stdout);

  const verify = runOpenLogs(
    [
      'verify',
      '--file',
      'openlogs.jsonl',
      '--trust',
      'trust.json',
      '--require-trusted-key',
      '--require-actor-binding',
    ],
    tmp,
  );

  assert.notEqual(verify.code, 0);
  assert.match(verify.stdout, /actorBound=0/);
  assert.match(verify.stderr, /policy-actor-binding/);
});
