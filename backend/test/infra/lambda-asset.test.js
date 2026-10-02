/**
 * E2e tests for the Lambda code asset configuration.
 *
 * These tests validate that LAMBDA_CODE_PATH is exported and points to the
 * correct dist-lambda directory, and that the stack uses it correctly.
 */

import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const backendDir = path.resolve(__dirname, '../..');
const distDir = path.join(backendDir, 'dist');

// ============================================================================
// LAMBDA_CODE_PATH Export Tests
// ============================================================================

test('Infra - LAMBDA_CODE_PATH is exported from mdm-stack.js', async (t) => {
  const mdmStackPath = path.join(distDir, 'infra/mdm-stack.js');
  const { LAMBDA_CODE_PATH } = await import(pathToFileURL(mdmStackPath).href);

  assert.ok(LAMBDA_CODE_PATH, 'LAMBDA_CODE_PATH should be exported');
  assert.ok(typeof LAMBDA_CODE_PATH === 'string', 'LAMBDA_CODE_PATH should be a string');
});

test('Infra - LAMBDA_CODE_PATH resolves to dist-lambda directory', async (t) => {
  const mdmStackPath = path.join(distDir, 'infra/mdm-stack.js');
  const { LAMBDA_CODE_PATH } = await import(pathToFileURL(mdmStackPath).href);

  const expectedPath = path.resolve(backendDir, 'dist-lambda');
  const resolvedPath = path.resolve(LAMBDA_CODE_PATH);

  assert.strictEqual(
    resolvedPath,
    expectedPath,
    `LAMBDA_CODE_PATH should resolve to ${expectedPath}`
  );
});

test('Infra - LAMBDA_CODE_PATH/index.mjs exists', async (t) => {
  const mdmStackPath = path.join(distDir, 'infra/mdm-stack.js');
  const { LAMBDA_CODE_PATH } = await import(pathToFileURL(mdmStackPath).href);

  const indexPath = path.join(LAMBDA_CODE_PATH, 'index.mjs');
  assert.ok(
    fs.existsSync(indexPath),
    `${indexPath} should exist`
  );
});

// ============================================================================
// Build Output Tests
// ============================================================================

test('Build - dist-lambda/index.mjs exists', (t) => {
  const bundlePath = path.join(backendDir, 'dist-lambda', 'index.mjs');
  assert.ok(fs.existsSync(bundlePath), `${bundlePath} should exist`);
});

test('Build - dist-lambda/public contains UI files', (t) => {
  const publicDir = path.join(backendDir, 'dist-lambda', 'public');
  assert.ok(fs.existsSync(publicDir), `${publicDir} should exist`);
  assert.ok(fs.statSync(publicDir).isDirectory());
  
  // Check that at least index.html exists
  const indexHtml = path.join(publicDir, 'index.html');
  assert.ok(fs.existsSync(indexHtml), `${indexHtml} should exist`);
});

test('Build - dist-lambda/views contains view files', (t) => {
  const viewsDir = path.join(backendDir, 'dist-lambda', 'views');
  assert.ok(fs.existsSync(viewsDir), `${viewsDir} should exist`);
  assert.ok(fs.statSync(viewsDir).isDirectory());
});

test('Build - dist/index.js still exists', (t) => {
  const indexJs = path.join(distDir, 'index.js');
  assert.ok(fs.existsSync(indexJs), `${indexJs} should exist`);
});

test('Build - dist/infra/app.js still exists', (t) => {
  const appJs = path.join(distDir, 'infra', 'app.js');
  assert.ok(fs.existsSync(appJs), `${appJs} should exist`);
});

test('Build - dist/ui/public still exists', (t) => {
  const publicDir = path.join(distDir, 'ui', 'public');
  assert.ok(fs.existsSync(publicDir), `${publicDir} should exist`);
  assert.ok(fs.statSync(publicDir).isDirectory());
});

test('Build - dist/package.json still exists', (t) => {
  const packageJson = path.join(distDir, 'package.json');
  assert.ok(fs.existsSync(packageJson), `${packageJson} should exist`);
});
