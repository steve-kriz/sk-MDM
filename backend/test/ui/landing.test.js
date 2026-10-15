/**
 * Unit and E2E tests for landing page pure functions (TASK-024).
 *
 * Scenario: Install strings are built from the page origin
 * Scenario: signedInLocation combines admin path with hash
 * Scenario: ADMIN_PAGE_PATH is exported from app.js
 */

import test from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { collectionUrlFor, windowsInstallCommand, MACOS_INSTALL_COMMAND, versionLabel, DOWNLOADS_PATH } from '../../dist/ui/public/landing.js';
import { ADMIN_PAGE_PATH, signedInLocation } from '../../dist/ui/public/app.js';

test('Unit - collectionUrlFor returns origin followed by /', async (t) => {
  const result = collectionUrlFor('https://mdm.example.com');
  assert.strictEqual(result, 'https://mdm.example.com/', 'should return origin with trailing slash');
});

test('Unit - collectionUrlFor with different origins', async (t) => {
  const result1 = collectionUrlFor('https://example.com');
  assert.strictEqual(result1, 'https://example.com/', 'should work with different domain');

  const result2 = collectionUrlFor('http://localhost:3000');
  assert.strictEqual(result2, 'http://localhost:3000/', 'should work with localhost');
});

test('Unit - windowsInstallCommand returns msiexec command with collectionUrl', async (t) => {
  const result = windowsInstallCommand('https://mdm.example.com/');
  const expected = 'msiexec /i <downloaded .msi> /qn COLLECTIONURL=https://mdm.example.com/ OWNERSHIP=officehq';
  assert.strictEqual(result, expected, 'should return correct msiexec command');
});

test('Unit - windowsInstallCommand with different collectionUrl', async (t) => {
  const result = windowsInstallCommand('https://custom.domain.com/');
  assert.ok(result.includes('COLLECTIONURL=https://custom.domain.com/'), 'should include collectionUrl in command');
  assert.ok(!result.includes('ENROLLTOKEN'), 'the installer no longer takes an enrollment token');
  assert.ok(result.includes('OWNERSHIP=officehq'), 'should name the device type');
});

test('Unit - versionLabel names the published version, or says none is published', () => {
  assert.strictEqual(versionLabel('1.2.3'), 'Version 1.2.3');
  assert.strictEqual(versionLabel(null), 'Not yet published');
  assert.strictEqual(versionLabel(undefined), 'Not yet published');
  assert.strictEqual(versionLabel(''), 'Not yet published');
});

test('Unit - the landing page reads versions from /api/v1/downloads', () => {
  assert.strictEqual(DOWNLOADS_PATH, '/api/v1/downloads');
});

test('Landing page shows a version slot per download and no Administrators section', () => {
  const html = readFileSync(new URL('../../src/ui/public/landing.html', import.meta.url), 'utf8');
  for (const platform of ['windows-x64', 'windows-arm64', 'macos-amd64', 'macos-arm64']) {
    assert.ok(html.includes(`id="version-${platform}"`), `version slot for ${platform}`);
  }
  assert.ok(!/Administrators/.test(html), 'no Administrators heading');
  assert.ok(!html.includes('href="/admin"'), 'no admin console link');
  assert.ok(!/enrollment token/i.test(html), 'no enrollment token instructions');
});

test('Unit - MACOS_INSTALL_COMMAND is correct', async (t) => {
  const expected = 'sudo installer -pkg <downloaded .pkg> -target /';
  assert.strictEqual(MACOS_INSTALL_COMMAND, expected, 'should return correct macOS install command');
});

test('Unit - ADMIN_PAGE_PATH is /admin', async (t) => {
  assert.strictEqual(ADMIN_PAGE_PATH, '/admin', 'should be /admin');
});

test('Unit - signedInLocation returns /admin with hash', async (t) => {
  const result = signedInLocation('#/groups');
  assert.strictEqual(result, '/admin#/groups', 'should combine admin path with hash');
});

test('Unit - signedInLocation with empty hash', async (t) => {
  const result = signedInLocation('');
  assert.strictEqual(result, '/admin', 'should return /admin when hash is empty');
});

test('Unit - signedInLocation with various hashes', async (t) => {
  const hashes = ['#/devices', '#/groups', '#/enrollment-tokens', '#/policies', '#/audit', '#/settings'];
  for (const hash of hashes) {
    const result = signedInLocation(hash);
    assert.strictEqual(result, `/admin${hash}`, `should handle ${hash}`);
  }
});

test('Scenario: Install strings are built from the page origin', async (t) => {
  // Test that functions work together
  const origin = 'https://mdm.example.com';
  const collectionUrl = collectionUrlFor(origin);
  const windowsCmd = windowsInstallCommand(collectionUrl);
  const macosCmd = MACOS_INSTALL_COMMAND;

  assert.strictEqual(collectionUrl, 'https://mdm.example.com/', 'collectionUrlFor should work');
  assert.ok(windowsCmd.includes(collectionUrl), 'Windows command should include collection URL');
  assert.strictEqual(macosCmd, 'sudo installer -pkg <downloaded .pkg> -target /', 'macOS command should be constant');
});

test('Unit - Verify exports from main index.ts', async (t) => {
  const {
    ADMIN_PATH,
    LANDING_FILE,
    handleAdmin,
  } = await import('../../dist/index.js');

  assert.strictEqual(ADMIN_PATH, '/admin', 'ADMIN_PATH should be /admin');
  assert.strictEqual(LANDING_FILE, 'landing.html', 'LANDING_FILE should be landing.html');
  assert.strictEqual(typeof handleAdmin, 'function', 'handleAdmin should be a function');
});
