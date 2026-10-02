import { test } from 'node:test';
import { deepStrictEqual, strictEqual, throws } from 'node:assert';
import { spawnSync } from 'node:child_process';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { planPackage } from '../macos/build-plan.mjs';

const CLI = fileURLToPath(new URL('../macos/build-plan.mjs', import.meta.url));

const VALID_ARGS = [
  '--version', '1.2.3',
  '--arch', 'arm64',
  '--collection-url', 'https://x.example/',
  '--enroll-token', 't1',
  '--dry-run',
];

/** Runs the planner CLI in a child process with MDM_SIGN_IDENTITY as given. */
function runPlanner(args, signIdentity) {
  const env = { ...process.env };
  delete env.MDM_SIGN_IDENTITY;
  if (signIdentity !== undefined) {
    env.MDM_SIGN_IDENTITY = signIdentity;
  }
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env });
}

test('planPackage returns the staging and output paths', () => {
  const plan = planPackage({
    version: '1.2.3',
    arch: 'arm64',
    collectionUrl: 'https://x.example/',
    enrollToken: 't1',
    signIdentity: 'ID-A',
  });
  strictEqual(plan.stagedBinaryPath, 'build/root/usr/local/bin/mdmagent');
  strictEqual(plan.stagedPlistPath, 'build/root/Library/LaunchDaemons/au.com.officehq.mdmagent.plist');
  strictEqual(plan.unsignedPath, 'build/OfficeHQ-MDM-1.2.3-arm64-unsigned.pkg');
  strictEqual(plan.outputPath, 'dist/OfficeHQ-MDM-1.2.3-arm64.pkg');
});

test('planPackage plans an amd64 package', () => {
  const plan = planPackage({
    version: '1.2.3',
    arch: 'amd64',
    collectionUrl: 'https://x.example/',
    enrollToken: 't1',
    signIdentity: 'ID-A',
  });
  strictEqual(plan.unsignedPath, 'build/OfficeHQ-MDM-1.2.3-amd64-unsigned.pkg');
  strictEqual(plan.outputPath, 'dist/OfficeHQ-MDM-1.2.3-amd64.pkg');
});

test('planPackage pins the productsign command', () => {
  const plan = planPackage({
    version: '1.2.3',
    arch: 'arm64',
    collectionUrl: 'https://x.example/',
    enrollToken: 't1',
    signIdentity: 'ID-A',
  });
  deepStrictEqual(plan.signCommand, [
    'productsign',
    '--sign',
    'ID-A',
    'build/OfficeHQ-MDM-1.2.3-arm64-unsigned.pkg',
    'dist/OfficeHQ-MDM-1.2.3-arm64.pkg',
  ]);
});

test('planPackage returns no sign command without an identity', () => {
  const plan = planPackage({
    version: '1.2.3',
    arch: 'arm64',
    collectionUrl: 'https://x.example/',
    enrollToken: 't1',
    signIdentity: '',
  });
  strictEqual(plan.signCommand, undefined);
});

test('planPackage refuses a collection URL the agent would not load', () => {
  for (const collectionUrl of [undefined, '', 'not a url', 'http://x.example/', 'ftp://x.example/']) {
    throws(
      () => planPackage({ version: '1.2.3', arch: 'arm64', collectionUrl, enrollToken: 't1', signIdentity: 'ID-A' }),
      { message: 'collection url must be an https url' },
    );
  }
});

test('planPackage refuses an unsupported arch', () => {
  for (const arch of [undefined, '', 'ppc', '386']) {
    throws(
      () => planPackage({ version: '1.2.3', arch, collectionUrl: 'https://x.example/', enrollToken: 't1', signIdentity: 'ID-A' }),
      { message: 'unsupported arch' },
    );
  }
});

test('the dry run prints the four paths and exits 0', () => {
  const result = runPlanner(VALID_ARGS, 'Developer ID Installer: OfficeHQ');
  strictEqual(result.status, 0);
  strictEqual(result.stdout, [
    'build/root/usr/local/bin/mdmagent',
    'build/root/Library/LaunchDaemons/au.com.officehq.mdmagent.plist',
    'build/OfficeHQ-MDM-1.2.3-arm64-unsigned.pkg',
    'dist/OfficeHQ-MDM-1.2.3-arm64.pkg',
    '',
  ].join('\n'));
});

test('the CLI exits 2 without a collection URL', () => {
  const args = ['--version', '1.2.3', '--arch', 'arm64', '--enroll-token', 't1', '--dry-run'];
  const result = runPlanner(args, 'Developer ID Installer: OfficeHQ');
  strictEqual(result.status, 2);
  strictEqual(result.stdout, '');
  strictEqual(result.stderr.includes('collection url must be an https url'), true);
});

test('the CLI exits 2 for a collection URL that is not https', () => {
  const args = [...VALID_ARGS];
  args[args.indexOf('https://x.example/')] = 'http://x.example/';
  const result = runPlanner(args, 'Developer ID Installer: OfficeHQ');
  strictEqual(result.status, 2);
  strictEqual(result.stdout, '');
  strictEqual(result.stderr.includes('collection url must be an https url'), true);
});

test('the CLI exits 2 for an unsupported arch', () => {
  const args = [...VALID_ARGS];
  args[args.indexOf('arm64')] = 'ppc';
  const result = runPlanner(args, 'Developer ID Installer: OfficeHQ');
  strictEqual(result.status, 2);
  strictEqual(result.stdout, '');
  strictEqual(result.stderr.includes('unsupported arch'), true);
});

test('the CLI exits 3 when the signing identity is unset', () => {
  const result = runPlanner(VALID_ARGS, undefined);
  strictEqual(result.status, 3);
  strictEqual(result.stdout, '');
  strictEqual(result.stderr.includes('signing identity not set'), true);
});

test('the CLI exits 3 when the signing identity is empty', () => {
  const result = runPlanner(VALID_ARGS, '');
  strictEqual(result.status, 3);
  strictEqual(result.stdout, '');
  strictEqual(result.stderr.includes('signing identity not set'), true);
});
