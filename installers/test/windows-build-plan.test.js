import { test } from 'node:test';
import { deepStrictEqual, ok, strictEqual, throws } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { planBuild, isSupportedArch, main } from '../windows/build-plan.mjs';

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(TEST_DIR, '..', '..');
const PLANNER = path.join(TEST_DIR, '..', 'windows', 'build-plan.mjs');
const WRAPPER = path.join(TEST_DIR, '..', 'windows', 'build.ps1');

function runPlanner(args) {
  return spawnSync(process.execPath, [PLANNER, ...args], { cwd: REPO_ROOT, encoding: 'utf8' });
}

test('planBuild names the package and the WiX architecture', () => {
  deepStrictEqual(planBuild({ version: '1.2.3', arch: 'x64' }), {
    outputPath: 'dist/OfficeHQ-MDM-1.2.3-x64.msi',
    wixArch: 'x64',
  });
  deepStrictEqual(planBuild({ version: '2.0.0', arch: 'arm64' }), {
    outputPath: 'dist/OfficeHQ-MDM-2.0.0-arm64.msi',
    wixArch: 'arm64',
  });
});

test('planBuild refuses an unsupported architecture', () => {
  throws(() => planBuild({ version: '1.2.3', arch: 'x86' }), { message: 'unsupported arch' });
  strictEqual(isSupportedArch('x86'), false);
  strictEqual(isSupportedArch('x64'), true);
  strictEqual(isSupportedArch('arm64'), true);
});

test('a dry run writes exactly the planned path and exits 0', () => {
  const result = runPlanner(['--version', '1.2.3', '--arch', 'x64', '--dry-run']);
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
    strictEqual(main(['--version', '1.2.3', '--arch', 'x64', '--dry-run'], { spawn }), 0);
  } finally {
    console.log = log;
  }
  deepStrictEqual(calls, []);
  deepStrictEqual(written, ['dist/OfficeHQ-MDM-1.2.3-x64.msi']);
});

test('an unsupported architecture exits 2 with no stdout', () => {
  const result = runPlanner(['--version', '1.2.3', '--arch', 'x86', '--dry-run']);
  strictEqual(result.status, 2);
  strictEqual(result.stdout, '');
  ok(result.stderr.includes('unsupported arch'));
});

test('a missing architecture exits 2', () => {
  const result = runPlanner(['--version', '1.2.3', '--dry-run']);
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
  ok(source.includes("$plannerArgs += '--dry-run'"));
  ok(source.indexOf('exit $LASTEXITCODE') > invocation, 'the planner exit code is the script exit code');
});
