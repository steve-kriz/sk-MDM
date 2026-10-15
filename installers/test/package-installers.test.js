/**
 * Tests for scripts/package-installers.mjs and its wrapper
 * scripts/deploy/package-installers.sh.
 *
 * `aws`, `fetch` and `spawn` are always injected: no AWS call, network request
 * or installer build is ever made.
 */
import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  main,
  buildCommands,
  goBin,
  describeStackArgs,
  agentAuthConfigUrl,
  resolvePlatform,
  resolveArches,
} from '../../scripts/package-installers.mjs';

const WRAPPER = fileURLToPath(new URL('../../scripts/deploy/package-installers.sh', import.meta.url));
const NODE = '/usr/bin/node';
const URL_OUT = 'https://mdm.example.com/\n';
const AUTH = { tenantId: 'tenant-1', clientId: 'client-1', scopes: [] };

function captureConsole() {
  const stdout = [];
  const stderr = [];
  const { log, error } = console;
  console.log = (line) => stdout.push(String(line));
  console.error = (line) => stderr.push(String(line));
  return {
    stdout,
    stderr,
    restore() {
      console.log = log;
      console.error = error;
    },
  };
}

/** A fake `aws` answering describe-stacks with `stdout` and `status`. */
function fakeAws({ stdout = URL_OUT, status = 0, stderr = '' } = {}) {
  const calls = [];
  const aws = (args) => {
    calls.push(args);
    return { status, stdout, stderr };
  };
  return { aws, calls };
}

/** A fake `fetch` answering every request with `status` and `body`. */
function fakeFetch({ status = 200, body = AUTH, throws } = {}) {
  const calls = [];
  const fetch = async (url) => {
    calls.push(url);
    if (throws) throw new Error(throws);
    return {
      status,
      json: async () => (typeof body === 'string' ? JSON.parse(body) : body),
    };
  };
  return { fetch, calls };
}

function fakeSpawn(status = 0) {
  const calls = [];
  const spawn = (command, args, options) => {
    calls.push({ command, args, options });
    return { status };
  };
  return { spawn, calls };
}

async function run(argv, overrides = {}) {
  const awsFake = fakeAws(overrides.aws);
  const fetchFake = fakeFetch(overrides.fetch);
  const spawnFake = fakeSpawn(overrides.spawnStatus);
  const out = captureConsole();
  let code;
  try {
    code = await main(argv, {
      env: overrides.env ?? {},
      aws: awsFake.aws,
      fetch: fetchFake.fetch,
      spawn: spawnFake.spawn,
      hostPlatform: overrides.hostPlatform ?? 'win32',
      node: NODE,
    });
  } finally {
    out.restore();
  }
  return { code, ...out, aws: awsFake.calls, fetch: fetchFake.calls, spawn: spawnFake.calls };
}

const VALUES = ['--collection-url', 'https://mdm.example.com/', '--tenant-id', 'tenant-1', '--client-id', 'client-1'];

test('the stack output and config route values are passed to every Windows build', async () => {
  const result = await run(['1.2.3']);
  assert.equal(result.code, 0, result.stderr.join('\n'));
  assert.deepEqual(result.aws, [describeStackArgs({ stack: 'MdmStack' })]);
  assert.deepEqual(result.fetch, ['https://mdm.example.com/api/v1/agent-auth/config']);
  assert.deepEqual(
    result.spawn.map(({ command, args }) => [command, ...args]),
    [
      [NODE, 'scripts/build-agent.mjs', '--target', 'windows/amd64'],
      [NODE, 'installers/windows/build-plan.mjs', '--version', '1.2.3', '--arch', 'x64', ...VALUES],
      [NODE, 'scripts/build-agent.mjs', '--target', 'windows/arm64'],
      [NODE, 'installers/windows/build-plan.mjs', '--version', '1.2.3', '--arch', 'arm64', ...VALUES],
    ],
  );
  for (const call of result.spawn) {
    assert.notEqual(call.options.shell, true);
  }
});

test('every installer embeds an agent freshly built and stamped with the package version', async () => {
  const result = await run(['1.2.3', '--arch', 'x64'], { env: { KEEP: 'yes' } });
  assert.equal(result.code, 0, result.stderr.join('\n'));
  const [agentBuild, installerBuild] = result.spawn;
  assert.deepEqual(agentBuild.args, ['scripts/build-agent.mjs', '--target', 'windows/amd64']);
  assert.equal(agentBuild.options.env.AGENT_VERSION, '1.2.3');
  assert.equal(agentBuild.options.env.KEEP, 'yes');
  assert.equal(installerBuild.args[0], 'installers/windows/build-plan.mjs');
});

test('a failed agent build stops before any installer is built', async () => {
  const result = await run(['1.2.3', '--arch', 'x64'], { spawnStatus: 1 });
  assert.equal(result.code, 1);
  assert.equal(result.spawn.length, 1);
  assert.ok(result.stderr.some((line) => line.includes('agent (windows/amd64)')));
});

test('the repo-local Go toolchain is used when GO_BIN is unset and it exists', () => {
  assert.equal(goBin({ GO_BIN: '/custom/go' }, () => true), '/custom/go');
  assert.match(goBin({}, () => true), /\.tools[\\/]go[\\/]bin[\\/]go(\.exe)?$/);
  assert.equal(goBin({}, () => false), undefined);
});

test('macOS builds run build.sh with the same values and need a signing identity', async () => {
  const unsigned = await run(['--version', '1.2.3', '--platform', 'macos', '--arch', 'arm64']);
  assert.equal(unsigned.code, 1);
  assert.ok(unsigned.stderr.some((line) => line.includes('MDM_SIGN_IDENTITY')));
  assert.equal(unsigned.spawn.length, 0);

  const signed = await run(['--version', '1.2.3', '--platform', 'macos', '--arch', 'arm64'], {
    env: { MDM_SIGN_IDENTITY: 'Developer ID Installer: X' },
  });
  assert.equal(signed.code, 0);
  assert.deepEqual(
    signed.spawn.map(({ command, args }) => [command, ...args]),
    [
      [NODE, 'scripts/build-agent.mjs', '--target', 'darwin/arm64'],
      ['sh', 'installers/macos/build.sh', '--version', '1.2.3', '--arch', 'arm64', ...VALUES],
    ],
  );
});

test('--stack, --profile and --region reach the aws call', async () => {
  const result = await run(['1.2.3', '--stack', 'Other', '--profile', 'p1', '--region', 'ap-southeast-2', '--dry-run']);
  assert.equal(result.code, 0);
  const [args] = result.aws;
  assert.deepEqual(args.slice(0, 4), ['cloudformation', 'describe-stacks', '--stack-name', 'Other']);
  assert.ok(args.join(' ').includes("Outputs[?OutputKey=='CollectionUrl'].OutputValue"));
  assert.deepEqual(args.slice(-4), ['--profile', 'p1', '--region', 'ap-southeast-2']);
});

test('a dry run prints the values and commands and spawns no build', async () => {
  const result = await run(['1.2.3', '--arch', 'x64', '--dry-run']);
  assert.equal(result.code, 0);
  assert.equal(result.spawn.length, 0);
  assert.ok(result.stdout.includes('collection url: https://mdm.example.com/'));
  assert.ok(result.stdout.includes('tenant id:      tenant-1'));
  assert.ok(result.stdout.includes('client id:      client-1'));
  assert.ok(
    result.stdout.includes(
      'would run: node installers/windows/build-plan.mjs --version 1.2.3 --arch x64 ' + VALUES.join(' '),
    ),
    result.stdout.join('\n'),
  );
});

test('a stack without a CollectionUrl output exits 1 before building', async () => {
  for (const stdout of ['', 'None\n']) {
    const result = await run(['1.2.3'], { aws: { stdout } });
    assert.equal(result.code, 1);
    assert.deepEqual(result.stderr, ['stack MdmStack has no CollectionUrl output; deploy the backend first']);
    assert.equal(result.fetch.length, 0);
    assert.equal(result.spawn.length, 0);
  }
});

test('a failed stack read exits 1 naming the stack', async () => {
  const result = await run(['1.2.3'], { aws: { status: 254, stdout: '', stderr: 'Stack with id MdmStack does not exist' } });
  assert.equal(result.code, 1);
  assert.deepEqual(result.stderr, ['could not read stack MdmStack: Stack with id MdmStack does not exist']);
  assert.equal(result.spawn.length, 0);
});

test('a bad config response exits 1 naming the problem', async () => {
  const cases = [
    [{ status: 500, body: { error: 'not_configured' } }, 'returned 500'],
    [{ status: 200, body: 'not json' }, 'did not return JSON'],
    [{ status: 200, body: { tenantId: 'tenant-1' } }, 'no usable clientId'],
    [{ status: 200, body: { tenantId: '', clientId: '' } }, 'no usable tenantId or clientId'],
    [{ throws: 'ECONNREFUSED' }, 'could not reach https://mdm.example.com/api/v1/agent-auth/config: ECONNREFUSED'],
  ];
  for (const [fetch, message] of cases) {
    const result = await run(['1.2.3'], { fetch });
    assert.equal(result.code, 1, message);
    assert.ok(result.stderr.some((line) => line.includes(message)), `${message}: ${result.stderr}`);
    assert.equal(result.spawn.length, 0);
  }
});

test('a failed build exits 1', async () => {
  const result = await run(['1.2.3'], { spawnStatus: 2 });
  assert.equal(result.code, 1);
  assert.equal(result.spawn.length, 1);
  assert.deepEqual(result.stderr, ['build failed: agent (windows/amd64)']);
});

test('bad usage exits 2 without reading anything', async () => {
  for (const argv of [[], ['1.2'], ['1.2.3', '--bogus'], ['1.2.3', '--platform', 'linux'], ['1.2.3', '--arch', 'ppc'], ['1.2.3', '--stack']]) {
    const result = await run(argv);
    assert.equal(result.code, 2, JSON.stringify(argv));
    assert.equal(result.aws.length, 0);
    assert.equal(result.spawn.length, 0);
  }
});

test('auto picks Windows on win32 and macOS on darwin and refuses elsewhere', () => {
  assert.equal(resolvePlatform('auto', 'win32'), 'windows');
  assert.equal(resolvePlatform('auto', 'darwin'), 'macos');
  assert.equal(resolvePlatform('macos', 'win32'), 'macos');
  assert.throws(() => resolvePlatform('auto', 'linux'), /cannot build installers on linux/);
});

test('--arch narrows the build and accepts either x64 spelling', () => {
  assert.deepEqual(resolveArches('windows', undefined), ['x64', 'arm64']);
  assert.deepEqual(resolveArches('macos', undefined), ['amd64', 'arm64']);
  assert.deepEqual(resolveArches('windows', 'amd64'), ['x64']);
  assert.deepEqual(resolveArches('macos', 'x64'), ['amd64']);
});

test('the config URL tolerates a CollectionUrl with or without a trailing slash', () => {
  assert.equal(agentAuthConfigUrl('https://a.example'), 'https://a.example/api/v1/agent-auth/config');
  assert.equal(agentAuthConfigUrl('https://a.example/'), 'https://a.example/api/v1/agent-auth/config');
});

test('buildCommands builds nothing but the platform build entry points', () => {
  const commands = buildCommands({
    platform: 'windows',
    arches: ['x64'],
    version: '1.2.3',
    collectionUrl: 'https://a.example/',
    tenantId: 't',
    clientId: 'c',
    node: NODE,
  });
  assert.equal(commands.length, 1);
  assert.equal(commands[0].args[0], 'installers/windows/build-plan.mjs');
});

test('the shell wrapper is thin: usage from its header, then the Node script', () => {
  const source = readFileSync(WRAPPER, 'utf8');
  assert.ok(source.startsWith('#!/usr/bin/env bash\n'));
  assert.ok(source.includes('scripts/deploy/package-installers.sh [--version] 1.2.3 [--platform windows|macos|auto]'));
  assert.ok(source.includes("usage() { awk 'NR > 1 && /^#/"));
  assert.ok(source.includes('exec node scripts/package-installers.mjs "$@"'));
  assert.ok(source.includes('command -v aws'));
});
