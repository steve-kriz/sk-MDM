/**
 * E2E cucumber-style and unit tests for scripts/publish-installers.mjs
 * (TASK-025).
 *
 * Every scenario creates and removes its own fixture files under the
 * worktree's (gitignored) `dist/` directory -- the paths the script itself
 * resolves relative to REPO_ROOT. `spawn` is always injected, so no real `aws`
 * process or network call is ever made.
 */

import { strict as assert } from 'node:assert';
import { after, afterEach, test } from 'node:test';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { main, planUploads, awsArgs, planAgentUploads, agentAwsArgs } from '../../scripts/publish-installers.mjs';

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(TEST_DIR, '..', '..');
const DIST_DIR = path.join(REPO_ROOT, 'dist');

// TASK-048: an empty temporary agent binary directory injected into every
// pre-existing main call, so the real <REPO_ROOT>/agent/bin never affects
// these tests and is never touched by them.
const EMPTY_AGENT_BIN_DIR = mkdtempSync(path.join(os.tmpdir(), 'mdm-agent-bin-empty-'));
after(() => rmSync(EMPTY_AGENT_BIN_DIR, { recursive: true, force: true }));

/** The four artefact file names a version produces, matching DOWNLOAD_PLATFORMS order. */
function artefactNames(version) {
  return [
    `OfficeHQ-MDM-${version}-x64.msi`,
    `OfficeHQ-MDM-${version}-arm64.msi`,
    `OfficeHQ-MDM-${version}-amd64.pkg`,
    `OfficeHQ-MDM-${version}-arm64.pkg`,
  ];
}

function createArtefacts(version, names = artefactNames(version)) {
  mkdirSync(DIST_DIR, { recursive: true });
  for (const name of names) {
    writeFileSync(path.join(DIST_DIR, name), 'fixture');
  }
}

function removeArtefacts(version) {
  for (const name of artefactNames(version)) {
    const file = path.join(DIST_DIR, name);
    if (existsSync(file)) {
      rmSync(file);
    }
  }
}

function captureConsole() {
  const stdout = [];
  const stderr = [];
  const originalLog = console.log;
  const originalError = console.error;
  console.log = (line) => stdout.push(line);
  console.error = (line) => stderr.push(line);
  return {
    stdout,
    stderr,
    restore() {
      console.log = originalLog;
      console.error = originalError;
    },
  };
}

function spyingSpawn(exitStatus = 0) {
  const calls = [];
  const spawn = (command, argv, options) => {
    calls.push({ command, argv, options });
    return { status: exitStatus };
  };
  return { spawn, calls };
}

// ============================================================================
// Scenario: Dry run lists every upload and spawns nothing
// ============================================================================
test('Scenario: Dry run lists every upload and spawns nothing', () => {
  const version = '1.2.3';
  // Given all four 1.2.3 installers exist under dist/
  createArtefacts(version);
  const console_ = captureConsole();
  const { spawn, calls } = spyingSpawn();

  try {
    // When I run main(["--bucket","B","--version","1.2.3","--dry-run"]) with a spy spawn
    const exitCode = main(['--bucket', 'B', '--version', version, '--dry-run'], { spawn, env: {}, agentBinDir: EMPTY_AGENT_BIN_DIR });

    // Then stdout is exactly the four planned lines, in DOWNLOAD_PLATFORMS order
    // (TASK-048: the four "skipped agent/bin/..." lines from the empty injected
    // agentBinDir are excluded)
    const plannedLines = console_.stdout.filter((line) => !line.startsWith('skipped agent/bin/'));
    assert.deepStrictEqual(plannedLines, [
      `dist/OfficeHQ-MDM-${version}-x64.msi -> s3://B/installers/windows-x64.msi`,
      `dist/OfficeHQ-MDM-${version}-arm64.msi -> s3://B/installers/windows-arm64.msi`,
      `dist/OfficeHQ-MDM-${version}-amd64.pkg -> s3://B/installers/macos-amd64.pkg`,
      `dist/OfficeHQ-MDM-${version}-arm64.pkg -> s3://B/installers/macos-arm64.pkg`,
    ]);

    // And spawn was not called
    assert.strictEqual(calls.length, 0);

    // And the exit code is 0
    assert.strictEqual(exitCode, 0);
  } finally {
    console_.restore();
    removeArtefacts(version);
  }
});

// ============================================================================
// Scenario: Upload invokes the AWS CLI with an exact argv array and no shell
// ============================================================================
test('Scenario: Upload invokes the AWS CLI with an exact argv array and no shell', () => {
  const version = '1.2.3';
  // Given only dist/OfficeHQ-MDM-1.2.3-x64.msi and dist/OfficeHQ-MDM-1.2.3-arm64.pkg exist
  createArtefacts(version, [`OfficeHQ-MDM-${version}-x64.msi`, `OfficeHQ-MDM-${version}-arm64.pkg`]);
  const console_ = captureConsole();
  // And env AWS_BIN is "aws-test"
  const { spawn, calls } = spyingSpawn(0);

  try {
    // When I run main(["--bucket","B","--version","1.2.3"], { spawn, env }) with a spawn that exits 0
    const exitCode = main(['--bucket', 'B', '--version', version], { spawn, env: { AWS_BIN: 'aws-test' }, agentBinDir: EMPTY_AGENT_BIN_DIR });

    // Then spawn was called twice
    assert.strictEqual(calls.length, 2);

    // And the first call's command is "aws-test"
    assert.strictEqual(calls[0].command, 'aws-test');

    // And the first call's argv deep-equals the x64 msi upload
    assert.deepStrictEqual(calls[0].argv, [
      's3',
      'cp',
      path.join(DIST_DIR, `OfficeHQ-MDM-${version}-x64.msi`),
      's3://B/installers/windows-x64.msi',
      '--content-type',
      'application/x-msi',
      '--content-disposition',
      `attachment; filename="OfficeHQ-MDM-${version}-x64.msi"`,
    ]);

    // And the second call's argv deep-equals the arm64 pkg upload
    assert.deepStrictEqual(calls[1].argv, [
      's3',
      'cp',
      path.join(DIST_DIR, `OfficeHQ-MDM-${version}-arm64.pkg`),
      's3://B/installers/macos-arm64.pkg',
      '--content-type',
      'application/octet-stream',
      '--content-disposition',
      `attachment; filename="OfficeHQ-MDM-${version}-arm64.pkg"`,
    ]);

    // And neither call's options set shell to true
    for (const call of calls) {
      assert.notStrictEqual(call.options.shell, true);
    }

    // And the exit code is 0
    assert.strictEqual(exitCode, 0);
  } finally {
    console_.restore();
    removeArtefacts(version);
  }
});

// ============================================================================
// Scenario: AWS_BIN unset falls back to aws
// ============================================================================
test('Scenario: AWS_BIN unset falls back to aws', () => {
  const version = '1.2.3';
  // Given only dist/OfficeHQ-MDM-1.2.3-x64.msi exists
  createArtefacts(version, [`OfficeHQ-MDM-${version}-x64.msi`]);
  const console_ = captureConsole();
  // And env has no AWS_BIN
  const { spawn, calls } = spyingSpawn(0);

  try {
    // When I run main(["--bucket","B","--version","1.2.3"], { spawn, env }) with a spawn that exits 0
    main(['--bucket', 'B', '--version', version], { spawn, env: {}, agentBinDir: EMPTY_AGENT_BIN_DIR });

    // Then the spawn call's command is "aws"
    assert.strictEqual(calls.length, 1);
    assert.strictEqual(calls[0].command, 'aws');
  } finally {
    console_.restore();
    removeArtefacts(version);
  }
});

// ============================================================================
// Scenario: Missing files are skipped and the rest uploaded
// ============================================================================
test('Scenario: Missing files are skipped and the rest uploaded', () => {
  const version = '1.2.3';
  // Given only dist/OfficeHQ-MDM-1.2.3-x64.msi exists
  createArtefacts(version, [`OfficeHQ-MDM-${version}-x64.msi`]);
  const console_ = captureConsole();
  const { spawn, calls } = spyingSpawn(0);

  try {
    // When I run main(["--bucket","B","--version","1.2.3"]) with a spawn that exits 0
    const exitCode = main(['--bucket', 'B', '--version', version], { spawn, env: {}, agentBinDir: EMPTY_AGENT_BIN_DIR });

    // Then stdout contains "skipped dist/OfficeHQ-MDM-1.2.3-arm64.msi" etc.
    assert.ok(console_.stdout.includes(`skipped dist/OfficeHQ-MDM-${version}-arm64.msi`));
    assert.ok(console_.stdout.includes(`skipped dist/OfficeHQ-MDM-${version}-amd64.pkg`));
    assert.ok(console_.stdout.includes(`skipped dist/OfficeHQ-MDM-${version}-arm64.pkg`));

    // And spawn was called once
    assert.strictEqual(calls.length, 1);

    // And the exit code is 0
    assert.strictEqual(exitCode, 0);
  } finally {
    console_.restore();
    removeArtefacts(version);
  }
});

// ============================================================================
// Scenario: No installers at all
// ============================================================================
test('Scenario: No installers at all', () => {
  const version = '9.9.9';
  // Given no installer for version 9.9.9 exists under dist/
  removeArtefacts(version);
  const console_ = captureConsole();
  const { spawn, calls } = spyingSpawn(0);

  try {
    // When I run main(["--bucket","B","--version","9.9.9"])
    const exitCode = main(['--bucket', 'B', '--version', version], { spawn, env: {}, agentBinDir: EMPTY_AGENT_BIN_DIR });

    // Then stderr contains "no installers found for version 9.9.9"
    assert.ok(console_.stderr.includes(`no installers found for version ${version}`));

    // And spawn was not called
    assert.strictEqual(calls.length, 0);

    // And the exit code is 1
    assert.strictEqual(exitCode, 1);
  } finally {
    console_.restore();
  }
});

// ============================================================================
// Scenario Outline: Bad usage exits 2 without spawning
// ============================================================================
const badUsageExamples = [
  { argv: ['--version', '1.2.3'], message: 'bucket is required' },
  { argv: ['--bucket', '', '--version', '1.2.3'], message: 'bucket is required' },
  { argv: ['--bucket', 'B'], message: 'version is required' },
  { argv: ['--bucket', 'B', '--version', '1.2.3', '--x'], message: 'unknown argument: --x' },
];

for (const { argv, message } of badUsageExamples) {
  test(`Scenario Outline: Bad usage exits 2 without spawning (${JSON.stringify(argv)})`, () => {
    const console_ = captureConsole();
    const { spawn, calls } = spyingSpawn(0);

    try {
      // When I run main(<argv>) with a spy spawn
      const exitCode = main(argv, { spawn, env: {}, agentBinDir: EMPTY_AGENT_BIN_DIR });

      // Then stderr contains "<message>"
      assert.ok(console_.stderr.includes(message), `expected stderr to include "${message}", got ${JSON.stringify(console_.stderr)}`);

      // And spawn was not called
      assert.strictEqual(calls.length, 0);

      // And the exit code is 2
      assert.strictEqual(exitCode, 2);
    } finally {
      console_.restore();
    }
  });
}

// ============================================================================
// Scenario: A failed upload stops the run
// ============================================================================
test('Scenario: A failed upload stops the run', () => {
  const version = '1.2.3';
  // Given all four 1.2.3 installers exist under dist/
  createArtefacts(version);
  const console_ = captureConsole();
  let callCount = 0;
  const calls = [];
  const spawn = (command, argv, options) => {
    calls.push({ command, argv, options });
    callCount += 1;
    return { status: callCount === 1 ? 1 : 0 };
  };

  try {
    // When I run main(["--bucket","B","--version","1.2.3"]) with a spawn whose
    // first call exits 1
    const exitCode = main(['--bucket', 'B', '--version', version], { spawn, env: {}, agentBinDir: EMPTY_AGENT_BIN_DIR });

    // Then stderr contains "upload failed for dist/OfficeHQ-MDM-1.2.3-x64.msi"
    assert.ok(console_.stderr.includes(`upload failed for dist/OfficeHQ-MDM-${version}-x64.msi`));

    // And spawn was called exactly once
    assert.strictEqual(calls.length, 1);

    // And the exit code is 1
    assert.strictEqual(exitCode, 1);
  } finally {
    console_.restore();
    removeArtefacts(version);
  }
});

// ============================================================================
// Scenario: Spawn error is an upload failure
// ============================================================================
test('Scenario: Spawn error is an upload failure', () => {
  const version = '1.2.3';
  // Given dist/OfficeHQ-MDM-1.2.3-x64.msi exists
  createArtefacts(version, [`OfficeHQ-MDM-${version}-x64.msi`]);
  const console_ = captureConsole();
  const spawn = () => ({ error: new Error('ENOENT') });

  try {
    // When I run main(["--bucket","B","--version","1.2.3"]) with a spawn that
    // returns an error "ENOENT"
    const exitCode = main(['--bucket', 'B', '--version', version], { spawn, env: {}, agentBinDir: EMPTY_AGENT_BIN_DIR });

    // Then stderr contains "upload failed for dist/OfficeHQ-MDM-1.2.3-x64.msi"
    assert.ok(console_.stderr.includes(`upload failed for dist/OfficeHQ-MDM-${version}-x64.msi`));

    // And the exit code is 1
    assert.strictEqual(exitCode, 1);
  } finally {
    console_.restore();
    removeArtefacts(version);
  }
});

// ============================================================================
// Scenario: Injectable main and npm script
// ============================================================================
test('Scenario: Injectable main and npm script', () => {
  // Then scripts/publish-installers.mjs exports main(argv, { spawn, env })
  assert.strictEqual(typeof main, 'function');
  // Calling it with an injected spawn and env proves both are accepted.
  const console_ = captureConsole();
  const { spawn, calls } = spyingSpawn(0);
  let exitCode;
  try {
    exitCode = main(['--bucket', '', '--version', ''], { spawn, env: {}, agentBinDir: EMPTY_AGENT_BIN_DIR });
  } finally {
    console_.restore();
  }
  assert.strictEqual(exitCode, 2);
  assert.strictEqual(calls.length, 0);

  // And the root package.json script "publish:installers" is "node scripts/publish-installers.mjs"
  const rootPackageJson = JSON.parse(readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8'));
  assert.strictEqual(rootPackageJson.scripts['publish:installers'], 'node scripts/publish-installers.mjs');
});

// ============================================================================
// Unit: planUploads and awsArgs
// ============================================================================
test('Unit: planUploads names every artefact in DOWNLOAD_PLATFORMS order', () => {
  const plans = planUploads('1.2.3');
  assert.deepStrictEqual(
    plans.map((p) => p.relativePath),
    [
      'dist/OfficeHQ-MDM-1.2.3-x64.msi',
      'dist/OfficeHQ-MDM-1.2.3-arm64.msi',
      'dist/OfficeHQ-MDM-1.2.3-amd64.pkg',
      'dist/OfficeHQ-MDM-1.2.3-arm64.pkg',
    ]
  );
  assert.deepStrictEqual(
    plans.map((p) => p.key),
    [
      'installers/windows-x64.msi',
      'installers/windows-arm64.msi',
      'installers/macos-amd64.pkg',
      'installers/macos-arm64.pkg',
    ]
  );
});

test('Unit: awsArgs builds the exact argv array for an upload', () => {
  const [upload] = planUploads('1.2.3');
  const argv = awsArgs(upload, 'my-bucket');
  assert.deepStrictEqual(argv, [
    's3',
    'cp',
    upload.absolutePath,
    's3://my-bucket/installers/windows-x64.msi',
    '--content-type',
    'application/x-msi',
    '--content-disposition',
    'attachment; filename="OfficeHQ-MDM-1.2.3-x64.msi"',
  ]);
});

// ============================================================================
// TASK-048: publishing the raw agent binaries for self-update
// ============================================================================

/** A fresh temporary directory standing in for `agent/bin/`, removed after each test. */
let tempAgentBinDir;
afterEach(() => {
  if (tempAgentBinDir) {
    rmSync(tempAgentBinDir, { recursive: true, force: true });
    tempAgentBinDir = undefined;
  }
});

function makeAgentBinDir() {
  tempAgentBinDir = mkdtempSync(path.join(os.tmpdir(), 'mdm-agent-bin-'));
  return tempAgentBinDir;
}

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

// ----------------------------------------------------------------------------
// AC1: Binary upload plan covers the four agent targets
// ----------------------------------------------------------------------------
test('Scenario: Binary upload plan covers the four agent targets', () => {
  // When I call planAgentUploads("1.4.0")
  const plans = planAgentUploads('1.4.0');

  // Then it returns 4 entries mapping each agent/bin binary to its fixed key
  assert.strictEqual(plans.length, 4);
  assert.deepStrictEqual(
    plans.map((p) => [p.relativePath, p.key]),
    [
      ['agent/bin/mdmagent-windows-amd64.exe', 'agent/windows-amd64/mdmagent.exe'],
      ['agent/bin/mdmagent-windows-arm64.exe', 'agent/windows-arm64/mdmagent.exe'],
      ['agent/bin/mdmagent-darwin-amd64', 'agent/darwin-amd64/mdmagent'],
      ['agent/bin/mdmagent-darwin-arm64', 'agent/darwin-arm64/mdmagent'],
    ]
  );

  // And each absolutePath is under <REPO_ROOT>/agent/bin
  const defaultAgentBinDir = path.join(REPO_ROOT, 'agent', 'bin');
  for (const plan of plans) {
    assert.strictEqual(path.dirname(plan.absolutePath), defaultAgentBinDir);
  }
});

// ----------------------------------------------------------------------------
// AC1 (edge): Binary directory is injectable
// ----------------------------------------------------------------------------
test('Scenario: Binary directory is injectable', () => {
  // Given a temporary directory T
  const T = makeAgentBinDir();

  // When I call planAgentUploads("1.4.0", T)
  const plans = planAgentUploads('1.4.0', T);

  // Then every absolutePath is path.join(T, <file name>) and every
  // relativePath still starts with "agent/bin/"
  const fileNames = [
    'mdmagent-windows-amd64.exe',
    'mdmagent-windows-arm64.exe',
    'mdmagent-darwin-amd64',
    'mdmagent-darwin-arm64',
  ];
  plans.forEach((plan, i) => {
    assert.strictEqual(plan.absolutePath, path.join(T, fileNames[i]));
    assert.ok(plan.relativePath.startsWith('agent/bin/'));
  });

  // And main called with injected agentBinDir T looks for binaries only in T
  writeFileSync(path.join(T, 'mdmagent-darwin-arm64'), '1.4.0');
  const console_ = captureConsole();
  const { spawn, calls } = spyingSpawn();
  let exitCode;
  try {
    exitCode = main(['--bucket', 'B', '--version', '1.4.0', '--dry-run'], { spawn, env: {}, agentBinDir: T });
  } finally {
    console_.restore();
  }
  assert.strictEqual(exitCode, 0);
  assert.ok(console_.stdout.includes('agent/bin/mdmagent-darwin-arm64 -> s3://B/agent/darwin-arm64/mdmagent'));
  assert.ok(console_.stdout.includes('skipped agent/bin/mdmagent-windows-amd64.exe'));
  assert.strictEqual(calls.length, 0);
});

// ----------------------------------------------------------------------------
// AC2: A binary is uploaded with its version and digest as metadata
// ----------------------------------------------------------------------------
test('Scenario: A binary is uploaded with its version and digest as metadata', () => {
  // Given agent/bin/mdmagent-darwin-arm64 exists, contains the bytes "1.4.0"
  const T = makeAgentBinDir();
  const bytes = Buffer.from('1.4.0');
  writeFileSync(path.join(T, 'mdmagent-darwin-arm64'), bytes);
  const digest = sha256Hex(bytes);
  const console_ = captureConsole();
  const { spawn, calls } = spyingSpawn(0);

  try {
    // When main runs with --bucket B --version 1.4.0 and a recording spawn
    const exitCode = main(['--bucket', 'B', '--version', '1.4.0'], { spawn, env: {}, agentBinDir: T });

    // Then spawn was called with s3 cp <abs path> s3://B/agent/darwin-arm64/mdmagent
    // --content-type application/octet-stream --metadata version=1.4.0,sha256=<digest>
    assert.strictEqual(calls.length, 1);
    assert.deepStrictEqual(calls[0].argv, [
      's3',
      'cp',
      path.join(T, 'mdmagent-darwin-arm64'),
      's3://B/agent/darwin-arm64/mdmagent',
      '--content-type',
      'application/octet-stream',
      '--metadata',
      `version=1.4.0,sha256=${digest}`,
    ]);
    assert.strictEqual(exitCode, 0);
  } finally {
    console_.restore();
  }
});

// ----------------------------------------------------------------------------
// AC3: Missing binaries are skipped and installers still publish
// ----------------------------------------------------------------------------
test('Scenario: Missing binaries are skipped and installers still publish', () => {
  const version = '1.4.0';
  // Given only dist/OfficeHQ-MDM-1.4.0-x64.msi exists and no agent/bin binaries exist
  createArtefacts(version, [`OfficeHQ-MDM-${version}-x64.msi`]);
  const T = makeAgentBinDir();
  const console_ = captureConsole();
  const { spawn, calls } = spyingSpawn(0);

  try {
    // When main runs with --bucket B --version 1.4.0
    const exitCode = main(['--bucket', 'B', '--version', version], { spawn, env: {}, agentBinDir: T });

    // Then stdout contains "skipped agent/bin/mdmagent-windows-amd64.exe" for each of the four binaries
    assert.ok(console_.stdout.includes('skipped agent/bin/mdmagent-windows-amd64.exe'));
    assert.ok(console_.stdout.includes('skipped agent/bin/mdmagent-windows-arm64.exe'));
    assert.ok(console_.stdout.includes('skipped agent/bin/mdmagent-darwin-amd64'));
    assert.ok(console_.stdout.includes('skipped agent/bin/mdmagent-darwin-arm64'));

    // And the msi is uploaded with its existing arguments and main returns 0
    assert.strictEqual(calls.length, 1);
    assert.deepStrictEqual(calls[0].argv, [
      's3',
      'cp',
      path.join(DIST_DIR, `OfficeHQ-MDM-${version}-x64.msi`),
      's3://B/installers/windows-x64.msi',
      '--content-type',
      'application/x-msi',
      '--content-disposition',
      `attachment; filename="OfficeHQ-MDM-${version}-x64.msi"`,
    ]);
    assert.strictEqual(exitCode, 0);
  } finally {
    console_.restore();
    removeArtefacts(version);
  }
});

// ----------------------------------------------------------------------------
// AC3 (failure): Nothing at all to publish
// ----------------------------------------------------------------------------
test('Scenario: Nothing at all to publish', () => {
  const version = '9.9.8';
  // Given no installers and no agent binaries exist
  removeArtefacts(version);
  const T = makeAgentBinDir();
  const console_ = captureConsole();
  const { spawn, calls } = spyingSpawn(0);

  try {
    // When main runs with --bucket B --version 1.4.0 (here 9.9.8, to keep its
    // own version namespace distinct from the pre-existing 9.9.9 scenario)
    const exitCode = main(['--bucket', 'B', '--version', version], { spawn, env: {}, agentBinDir: T });

    // Then stderr contains "no installers found for version 9.9.8" and main returns 1
    assert.ok(console_.stderr.includes(`no installers found for version ${version}`));
    assert.strictEqual(calls.length, 0);
    assert.strictEqual(exitCode, 1);
  } finally {
    console_.restore();
  }
});

// ----------------------------------------------------------------------------
// AC4 (failure): Binary stamped with another version is refused before any upload
// ----------------------------------------------------------------------------
test('Scenario: Binary stamped with another version is refused before any upload', () => {
  const version = '1.4.0';
  // Given agent/bin/mdmagent-windows-amd64.exe exists and does not contain the bytes "1.4.0"
  const T = makeAgentBinDir();
  writeFileSync(path.join(T, 'mdmagent-windows-amd64.exe'), 'not-the-right-version');
  // And dist/OfficeHQ-MDM-1.4.0-x64.msi exists
  createArtefacts(version, [`OfficeHQ-MDM-${version}-x64.msi`]);
  const console_ = captureConsole();
  const { spawn, calls } = spyingSpawn(0);

  try {
    // When main runs with --bucket B --version 1.4.0
    const exitCode = main(['--bucket', 'B', '--version', version], { spawn, env: {}, agentBinDir: T });

    // Then stderr contains "version mismatch: agent/bin/mdmagent-windows-amd64.exe is not stamped 1.4.0"
    assert.ok(
      console_.stderr.includes('version mismatch: agent/bin/mdmagent-windows-amd64.exe is not stamped 1.4.0')
    );

    // And main returns 1 and spawn was never called
    assert.strictEqual(exitCode, 1);
    assert.strictEqual(calls.length, 0);
  } finally {
    console_.restore();
    removeArtefacts(version);
  }
});

// ----------------------------------------------------------------------------
// AC4 (failure): Version guard also applies to a dry run
// ----------------------------------------------------------------------------
test('Scenario: Version guard also applies to a dry run', () => {
  const version = '1.4.0';
  // Given agent/bin/mdmagent-darwin-amd64 does not contain the bytes "1.4.0"
  const T = makeAgentBinDir();
  writeFileSync(path.join(T, 'mdmagent-darwin-amd64'), 'wrong-stamp');
  const console_ = captureConsole();
  const { spawn, calls } = spyingSpawn(0);

  try {
    // When main runs with --dry-run --bucket B --version 1.4.0
    const exitCode = main(['--dry-run', '--bucket', 'B', '--version', version], {
      spawn,
      env: {},
      agentBinDir: T,
    });

    // Then main returns 1 and spawn was never called
    assert.strictEqual(exitCode, 1);
    assert.strictEqual(calls.length, 0);
    assert.ok(
      console_.stderr.includes('version mismatch: agent/bin/mdmagent-darwin-amd64 is not stamped 1.4.0')
    );
  } finally {
    console_.restore();
  }
});

// ----------------------------------------------------------------------------
// AC5: Dry run lists binary uploads without spawning
// ----------------------------------------------------------------------------
test('Scenario: Dry run lists binary uploads without spawning', () => {
  const version = '1.4.0';
  // Given agent/bin/mdmagent-darwin-amd64 exists and contains the bytes "1.4.0"
  const T = makeAgentBinDir();
  writeFileSync(path.join(T, 'mdmagent-darwin-amd64'), '1.4.0');
  const console_ = captureConsole();
  const { spawn, calls } = spyingSpawn(0);

  try {
    // When main runs with --dry-run --bucket B --version 1.4.0
    const exitCode = main(['--dry-run', '--bucket', 'B', '--version', version], {
      spawn,
      env: {},
      agentBinDir: T,
    });

    // Then stdout contains "agent/bin/mdmagent-darwin-amd64 -> s3://B/agent/darwin-amd64/mdmagent"
    assert.ok(console_.stdout.includes('agent/bin/mdmagent-darwin-amd64 -> s3://B/agent/darwin-amd64/mdmagent'));

    // And main returns 0 and spawn was never called
    assert.strictEqual(exitCode, 0);
    assert.strictEqual(calls.length, 0);
  } finally {
    console_.restore();
  }
});

// ----------------------------------------------------------------------------
// AC6 (failure): A failed binary upload stops the run
// ----------------------------------------------------------------------------
test('Scenario: A failed binary upload stops the run', () => {
  const version = '1.4.0';
  // Given two stamped binaries exist and spawn returns status 1 for the first
  const T = makeAgentBinDir();
  writeFileSync(path.join(T, 'mdmagent-windows-amd64.exe'), '1.4.0');
  writeFileSync(path.join(T, 'mdmagent-windows-arm64.exe'), '1.4.0');
  const console_ = captureConsole();
  let callCount = 0;
  const calls = [];
  const spawn = (command, argv, options) => {
    calls.push({ command, argv, options });
    callCount += 1;
    return { status: callCount === 1 ? 1 : 0 };
  };

  try {
    // When main runs with --bucket B --version 1.4.0
    const exitCode = main(['--bucket', 'B', '--version', version], { spawn, env: {}, agentBinDir: T });

    // Then stderr contains "upload failed for" naming the first binary
    assert.ok(console_.stderr.includes('upload failed for agent/bin/mdmagent-windows-amd64.exe'));

    // main returns 1 and spawn was called once for binaries
    assert.strictEqual(exitCode, 1);
    assert.strictEqual(calls.length, 1);
  } finally {
    console_.restore();
  }
});

// ----------------------------------------------------------------------------
// Unit: planAgentUploads and agentAwsArgs
// ----------------------------------------------------------------------------
test('Unit: planAgentUploads names every binary with its fixed key, default dir', () => {
  const plans = planAgentUploads('1.4.0');
  assert.deepStrictEqual(
    plans.map((p) => p.relativePath),
    [
      'agent/bin/mdmagent-windows-amd64.exe',
      'agent/bin/mdmagent-windows-arm64.exe',
      'agent/bin/mdmagent-darwin-amd64',
      'agent/bin/mdmagent-darwin-arm64',
    ]
  );
  assert.deepStrictEqual(
    plans.map((p) => p.key),
    [
      'agent/windows-amd64/mdmagent.exe',
      'agent/windows-arm64/mdmagent.exe',
      'agent/darwin-amd64/mdmagent',
      'agent/darwin-arm64/mdmagent',
    ]
  );
});

test('Unit: agentAwsArgs builds the exact argv array with version and sha256 metadata', () => {
  const [upload] = planAgentUploads('1.4.0', '/tmp/agent-bin');
  const argv = agentAwsArgs(upload, 'my-bucket', '1.4.0', 'a'.repeat(64));
  assert.deepStrictEqual(argv, [
    's3',
    'cp',
    upload.absolutePath,
    's3://my-bucket/agent/windows-amd64/mdmagent.exe',
    '--content-type',
    'application/octet-stream',
    '--metadata',
    `version=1.4.0,sha256=${'a'.repeat(64)}`,
  ]);
});
