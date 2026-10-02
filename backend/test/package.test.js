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
