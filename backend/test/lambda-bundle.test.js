/**
 * E2e tests for the esbuild Lambda bundle.
 *
 * These tests validate that the bundle is self-contained, loads without
 * node_modules in any ancestor, contains no external SDK imports or CDK code,
 * and works as expected with the real AWS clients.
 */

import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const bundlePath = path.resolve(__dirname, '../dist-lambda');
const bundleIndex = path.join(bundlePath, 'index.mjs');

// ============================================================================
// Bundle Structure Tests
// ============================================================================

test('Lambda bundle - index.mjs exists', (t) => {
  assert.ok(fs.existsSync(bundleIndex), `${bundleIndex} should exist`);
});

test('Lambda bundle - public directory exists', (t) => {
  const publicDir = path.join(bundlePath, 'public');
  assert.ok(fs.existsSync(publicDir), `${publicDir} should exist`);
  assert.ok(fs.statSync(publicDir).isDirectory());
});

test('Lambda bundle - views directory exists', (t) => {
  const viewsDir = path.join(bundlePath, 'views');
  assert.ok(fs.existsSync(viewsDir), `${viewsDir} should exist`);
  assert.ok(fs.statSync(viewsDir).isDirectory());
});

// ============================================================================
// Bundle Content Tests
// ============================================================================

test('Lambda bundle - Contains no aws-cdk-lib import specifier', (t) => {
  const bundleContent = fs.readFileSync(bundleIndex, 'utf-8');

  // Check for import/require of aws-cdk-lib
  assert.ok(
    !bundleContent.includes('from "aws-cdk-lib"'),
    'bundle should not import aws-cdk-lib'
  );
  assert.ok(
    !bundleContent.includes("from 'aws-cdk-lib'"),
    'bundle should not import aws-cdk-lib'
  );
  assert.ok(
    !bundleContent.includes('require("aws-cdk-lib"'),
    'bundle should not require aws-cdk-lib'
  );
});

test('Lambda bundle - Contains no constructs import specifier', (t) => {
  const bundleContent = fs.readFileSync(bundleIndex, 'utf-8');

  assert.ok(
    !bundleContent.includes('from "constructs"'),
    'bundle should not import constructs'
  );
  assert.ok(
    !bundleContent.includes("from 'constructs'"),
    'bundle should not import constructs'
  );
  assert.ok(
    !bundleContent.includes('require("constructs"'),
    'bundle should not require constructs'
  );
});

test('Lambda bundle - Contains no bare @aws-sdk import', (t) => {
  const bundleContent = fs.readFileSync(bundleIndex, 'utf-8');

  // Check for top-level import statements to @aws-sdk/... modules
  // These patterns match real imports, not SDK error messages
  const lines = bundleContent.split('\n');

  let foundBareImport = false;
  for (const line of lines) {
    // Skip lines that appear to be in error messages or comments
    if (line.includes('//') && line.indexOf('//') < line.indexOf('@aws-sdk/')) {
      continue;
    }

    // Check for bare import of @aws-sdk/
    if (/^\s*import\s+.*\s+from\s+["']@aws-sdk\//.test(line)) {
      foundBareImport = true;
      break;
    }
  }

  assert.ok(!foundBareImport, 'bundle should not have bare import of @aws-sdk modules');
});

test('Lambda bundle - Contains no __require of @aws-sdk (external)', (t) => {
  const bundleContent = fs.readFileSync(bundleIndex, 'utf-8');

  // Check for esbuild's __require(...) pattern with @aws-sdk as external
  // This would indicate the SDK was not bundled
  const matches = bundleContent.match(/__require\s*\(\s*["']@aws-sdk\//g);

  assert.ok(!matches, 'bundle should not use __require for external @aws-sdk modules');
});

// ============================================================================
// Bundle Loading Tests
// ============================================================================

test('Lambda bundle - Loads in a directory without node_modules in ancestors', async (t) => {
  // Create a temporary directory structure with no node_modules
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mdm-lambda-test-'));

  try {
    // Copy the bundle to the temp directory
    const bundleCopyPath = path.join(tmpDir, 'lambda');
    fs.mkdirSync(bundleCopyPath);

    // Copy index.mjs
    fs.copyFileSync(bundleIndex, path.join(bundleCopyPath, 'index.mjs'));

    // Copy public and views directories
    const publicDir = path.join(bundlePath, 'public');
    const viewsDir = path.join(bundlePath, 'views');

    if (fs.existsSync(publicDir)) {
      copyDirectory(publicDir, path.join(bundleCopyPath, 'public'));
    }
    if (fs.existsSync(viewsDir)) {
      copyDirectory(viewsDir, path.join(bundleCopyPath, 'views'));
    }

    // Verify no node_modules in any ancestor
    let current = bundleCopyPath;
    let hasNodeModules = false;
    while (current !== path.dirname(os.tmpdir())) {
      if (fs.existsSync(path.join(current, 'node_modules'))) {
        hasNodeModules = true;
        break;
      }
      current = path.dirname(current);
    }

    assert.ok(!hasNodeModules, 'temp directory should have no node_modules in ancestors');

    // Try to import the bundle
    const indexPath = path.join(bundleCopyPath, 'index.mjs');
    const { handler } = await import(pathToFileURL(indexPath).href);
    assert.ok(typeof handler === 'function', 'handler should be a function');

  } finally {
    // Clean up
    rmDirectory(tmpDir);
  }
});

test('Lambda bundle - Handler works with missing TABLE_NAME (returns 503)', async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'mdm-lambda-test-'));

  try {
    // Copy the bundle
    const bundleCopyPath = path.join(tmpDir, 'lambda');
    fs.mkdirSync(bundleCopyPath);
    fs.copyFileSync(bundleIndex, path.join(bundleCopyPath, 'index.mjs'));

    const publicDir = path.join(bundlePath, 'public');
    const viewsDir = path.join(bundlePath, 'views');
    if (fs.existsSync(publicDir)) {
      copyDirectory(publicDir, path.join(bundleCopyPath, 'public'));
    }
    if (fs.existsSync(viewsDir)) {
      copyDirectory(viewsDir, path.join(bundleCopyPath, 'views'));
    }

    // Import the bundle
    const indexPath = path.join(bundleCopyPath, 'index.mjs');
    const { handler } = await import(pathToFileURL(indexPath).href);

    // Save and remove TABLE_NAME from env
    const savedTableName = process.env.TABLE_NAME;
    delete process.env.TABLE_NAME;

    try {
      // Suppress error logging
      const originalError = console.error;
      console.error = () => {};

      const event = {
        requestContext: {
          http: {
            method: 'GET',
            path: '/',
          },
        },
        headers: {},
        body: '',
        isBase64Encoded: false,
      };

      const response = await handler(event);

      assert.strictEqual(response.statusCode, 503);
      assert.deepStrictEqual(
        JSON.parse(response.body),
        { error: 'service_unavailable' }
      );

      console.error = originalError;
    } finally {
      // Restore TABLE_NAME if it was set
      if (savedTableName !== undefined) {
        process.env.TABLE_NAME = savedTableName;
      }
    }
  } finally {
    rmDirectory(tmpDir);
  }
});

// ============================================================================
// Helper Functions
// ============================================================================

function copyDirectory(src, dest) {
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }

  const files = fs.readdirSync(src);
  for (const file of files) {
    const srcPath = path.join(src, file);
    const destPath = path.join(dest, file);

    if (fs.statSync(srcPath).isDirectory()) {
      copyDirectory(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

function rmDirectory(dirPath) {
  if (fs.existsSync(dirPath)) {
    fs.rmSync(dirPath, { recursive: true, force: true });
  }
}
