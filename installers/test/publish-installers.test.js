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
import { test } from 'node:test';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { main, planUploads, awsArgs } from '../../scripts/publish-installers.mjs';

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(TEST_DIR, '..', '..');
const DIST_DIR = path.join(REPO_ROOT, 'dist');

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
    const exitCode = main(['--bucket', 'B', '--version', version, '--dry-run'], { spawn, env: {} });

    // Then stdout is exactly the four planned lines, in DOWNLOAD_PLATFORMS order
    assert.deepStrictEqual(console_.stdout, [
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
    const exitCode = main(['--bucket', 'B', '--version', version], { spawn, env: { AWS_BIN: 'aws-test' } });

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
    main(['--bucket', 'B', '--version', version], { spawn, env: {} });

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
    const exitCode = main(['--bucket', 'B', '--version', version], { spawn, env: {} });

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
    const exitCode = main(['--bucket', 'B', '--version', version], { spawn, env: {} });

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
      const exitCode = main(argv, { spawn, env: {} });

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
    const exitCode = main(['--bucket', 'B', '--version', version], { spawn, env: {} });

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
    const exitCode = main(['--bucket', 'B', '--version', version], { spawn, env: {} });

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
    exitCode = main(['--bucket', '', '--version', ''], { spawn, env: {} });
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
