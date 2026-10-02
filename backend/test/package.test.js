/**
 * Tests for package.json dependencies and versioning.
 *
 * These tests validate that the AWS SDK and esbuild dependencies are pinned
 * to exact versions as required by the specification.
 */

import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendDir = path.resolve(__dirname, '..');
const packageJsonPath = path.join(backendDir, 'package.json');

test('Package - Read backend/package.json', (t) => {
  const content = fs.readFileSync(packageJsonPath, 'utf-8');
  const pkg = JSON.parse(content);
  assert.ok(pkg);
});

test('Package - @aws-sdk/client-dynamodb is in dependencies with exact version', (t) => {
  const content = fs.readFileSync(packageJsonPath, 'utf-8');
  const pkg = JSON.parse(content);
  
  assert.ok(pkg.dependencies['@aws-sdk/client-dynamodb']);
  const version = pkg.dependencies['@aws-sdk/client-dynamodb'];
  assert.match(version, /^\d+\.\d+\.\d+$/);
});

test('Package - @aws-sdk/lib-dynamodb is in dependencies with exact version', (t) => {
  const content = fs.readFileSync(packageJsonPath, 'utf-8');
  const pkg = JSON.parse(content);
  
  assert.ok(pkg.dependencies['@aws-sdk/lib-dynamodb']);
  const version = pkg.dependencies['@aws-sdk/lib-dynamodb'];
  assert.match(version, /^\d+\.\d+\.\d+$/);
});

test('Package - @aws-sdk/client-secrets-manager is in dependencies with exact version', (t) => {
  const content = fs.readFileSync(packageJsonPath, 'utf-8');
  const pkg = JSON.parse(content);
  
  assert.ok(pkg.dependencies['@aws-sdk/client-secrets-manager']);
  const version = pkg.dependencies['@aws-sdk/client-secrets-manager'];
  assert.match(version, /^\d+\.\d+\.\d+$/);
});

test('Package - esbuild is in devDependencies with exact version', (t) => {
  const content = fs.readFileSync(packageJsonPath, 'utf-8');
  const pkg = JSON.parse(content);

  assert.ok(pkg.devDependencies['esbuild']);
  const version = pkg.devDependencies['esbuild'];
  assert.match(version, /^\d+\.\d+\.\d+$/);
});

// ============================================================================
// Scenario: S3 SDK dependencies are pinned exactly (TASK-025)
// ============================================================================
test('Scenario: S3 SDK dependencies are pinned exactly', (t) => {
  // When I read backend/package.json
  const content = fs.readFileSync(packageJsonPath, 'utf-8');
  const pkg = JSON.parse(content);

  // Then its dependencies list "@aws-sdk/client-s3" and "@aws-sdk/s3-request-presigner"
  for (const name of ['@aws-sdk/client-s3', '@aws-sdk/s3-request-presigner']) {
    assert.ok(pkg.dependencies[name], `${name} should be a dependency`);
    const version = pkg.dependencies[name];

    // And neither version string contains "^", "~", ">", "<", "*" or "x"
    for (const forbidden of ['^', '~', '>', '<', '*', 'x']) {
      assert.ok(!version.includes(forbidden), `${name} version "${version}" should not contain "${forbidden}"`);
    }
    assert.match(version, /^\d+\.\d+\.\d+$/, `${name} version "${version}" should be an exact semver`);
  }
});
