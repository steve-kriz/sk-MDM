import { test } from 'node:test';
import { deepStrictEqual, ok, strictEqual, throws } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { planBuild, isSupportedArch, main, wixArgs, agentBinary, WIX_EXTENSIONS } from '../windows/build-plan.mjs';

const VALUES = ['--collection-url', 'https://x.example/', '--tenant-id', 'tenant-1', '--client-id', 'client-1'];
const BAKED = { collectionUrl: 'https://x.example/', tenantId: 'tenant-1', clientId: 'client-1' };

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(TEST_DIR, '..', '..');
const PLANNER = path.join(TEST_DIR, '..', 'windows', 'build-plan.mjs');
const WRAPPER = path.join(TEST_DIR, '..', 'windows', 'build.ps1');

function runPlanner(args) {
  return spawnSync(process.execPath, [PLANNER, ...args], { cwd: REPO_ROOT, encoding: 'utf8' });
}

test('planBuild names the package and the WiX architecture', () => {
  deepStrictEqual(planBuild({ version: '1.2.3', arch: 'x64', ...BAKED }), {
    outputPath: 'dist/OfficeHQ-MDM-1.2.3-x64.msi',
    wixArch: 'x64',
    ...BAKED,
  });
  deepStrictEqual(planBuild({ version: '2.0.0', arch: 'arm64', ...BAKED }), {
    outputPath: 'dist/OfficeHQ-MDM-2.0.0-arm64.msi',
    wixArch: 'arm64',
    ...BAKED,
  });
});

test('planBuild refuses an unsupported architecture', () => {
  throws(() => planBuild({ version: '1.2.3', arch: 'x86', ...BAKED }), { message: 'unsupported arch' });
  strictEqual(isSupportedArch('x86'), false);
  strictEqual(isSupportedArch('x64'), true);
  strictEqual(isSupportedArch('arm64'), true);
});

test('a dry run writes exactly the planned path and exits 0', () => {
  const result = runPlanner(['--version', '1.2.3', '--arch', 'x64', ...VALUES, '--dry-run']);
  strictEqual(result.status, 0);
  strictEqual(result.stdout, 'dist/OfficeHQ-MDM-1.2.3-x64.msi\n');
  strictEqual(result.stderr, '');
});

test('a dry run spawns no process', () => {
  const calls = [];
  const spawn = (...args) => {
    calls.push(args);
    return { status: 0 };
  };
  const written = [];
  const log = console.log;
  console.log = (line) => written.push(line);
  try {
    strictEqual(main(['--version', '1.2.3', '--arch', 'x64', ...VALUES, '--dry-run'], { spawn }), 0);
  } finally {
    console.log = log;
  }
  deepStrictEqual(calls, []);
  deepStrictEqual(written, ['dist/OfficeHQ-MDM-1.2.3-x64.msi']);
});

test('an unsupported architecture exits 2 with no stdout', () => {
  const result = runPlanner(['--version', '1.2.3', '--arch', 'x86', ...VALUES, '--dry-run']);
  strictEqual(result.status, 2);
  strictEqual(result.stdout, '');
  ok(result.stderr.includes('unsupported arch'));
});

test('a missing architecture exits 2', () => {
  const result = runPlanner(['--version', '1.2.3', ...VALUES, '--dry-run']);
  strictEqual(result.status, 2);
  strictEqual(result.stdout, '');
  ok(result.stderr.includes('unsupported arch'));
});

test('build.ps1 declares Version, Arch and DryRun and delegates to the planner', () => {
  const source = readFileSync(WRAPPER, 'utf8');
  ok(source.includes('$Version'));
  ok(source.includes('$Arch'));
  ok(source.includes('$DryRun'));

  const invocation = source.indexOf('node ');
  ok(invocation !== -1, 'build.ps1 invokes node');
  ok(source.includes('build-plan.mjs'));
  ok(source.includes("'--version', $Version"));
  ok(source.includes("'--arch', $Arch"));
  ok(source.includes("'--collection-url', $CollectionUrl"));
  ok(source.includes("'--tenant-id', $TenantId"));
  ok(source.includes("'--client-id', $ClientId"));
  ok(source.includes("$plannerArgs += '--dry-run'"));
  ok(source.indexOf('exit $LASTEXITCODE') > invocation, 'the planner exit code is the script exit code');
});

test('the baked values are refused unless the URL is https and tenant and client are set', () => {
  const cases = [
    [{ ...BAKED, collectionUrl: 'http://x.example/' }, 'collection url must be an https url'],
    [{ ...BAKED, collectionUrl: '' }, 'collection url must be an https url'],
    [{ ...BAKED, tenantId: '' }, 'tenant id is required'],
    [{ ...BAKED, clientId: undefined }, 'client id is required'],
    [{ ...BAKED, clientId: 'a b' }, 'client id is required'],
  ];
  for (const [values, message] of cases) {
    throws(() => planBuild({ version: '1.2.3', arch: 'x64', ...values }), (error) => error.message.startsWith(message));
  }
});

for (const [flag, message] of [
  ['--collection-url', 'collection url must be an https url'],
  ['--tenant-id', 'tenant id is required'],
  ['--client-id', 'client id is required'],
]) {
  test(`the CLI exits 2 without ${flag}`, () => {
    const values = [...VALUES];
    values.splice(values.indexOf(flag), 2);
    const result = runPlanner(['--version', '1.2.3', '--arch', 'x64', ...values, '--dry-run']);
    strictEqual(result.status, 2);
    strictEqual(result.stdout, '');
    ok(result.stderr.includes(message));
  });
}

test('the CLI exits 2 for a collection URL that is not https', () => {
  const values = [...VALUES];
  values[values.indexOf('https://x.example/')] = 'http://x.example/';
  const result = runPlanner(['--version', '1.2.3', '--arch', 'x64', ...values, '--dry-run']);
  strictEqual(result.status, 2);
  ok(result.stderr.includes('collection url must be an https url'));
});

test('wix is run with the UI and Util extensions and the baked values as variables', () => {
  deepStrictEqual(WIX_EXTENSIONS, ['WixToolset.UI.wixext', 'WixToolset.Util.wixext']);
  for (const arch of ['x64', 'arm64']) {
    const plan = planBuild({ version: '1.2.3', arch, ...BAKED });
    const args = wixArgs(plan, '1.2.3');
    const pairs = (flag) => args.flatMap((arg, i) => (arg === flag ? [args[i + 1]] : []));
    deepStrictEqual(pairs('-ext'), ['WixToolset.UI.wixext', 'WixToolset.Util.wixext']);
    deepStrictEqual(pairs('-d'), [
      'Version=1.2.3',
      `AgentBinary=${agentBinary(arch)}`,
      'DefaultCollectionUrl=https://x.example/',
      'TenantId=tenant-1',
      'ClientId=client-1',
    ]);
    strictEqual(args[0], 'build');
    deepStrictEqual(args.slice(1, 3), ['-arch', arch]);
  }
});

test('a real build passes the planned argv to wix', () => {
  const calls = [];
  const spawn = (command, argv) => {
    calls.push({ command, argv });
    return { status: 0 };
  };
  const log = console.log;
  console.log = () => {};
  try {
    strictEqual(main(['--version', '1.2.3', '--arch', 'arm64', ...VALUES], { spawn }), 0);
  } finally {
    console.log = log;
  }
  strictEqual(calls.length, 1);
  deepStrictEqual(calls[0].argv, wixArgs(planBuild({ version: '1.2.3', arch: 'arm64', ...BAKED }), '1.2.3'));
});
