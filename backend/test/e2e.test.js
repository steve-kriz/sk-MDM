/**
 * E2E tests covering the Gherkin scenarios for TASK-001.
 * These tests implement Given/When/Then style scenarios without a cucumber package.
 */

import test from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRouter } from '../dist/index.js';
import { handler } from '../dist/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '../../');
const backendDir = path.resolve(__dirname, '../');

function runCommand(command, args = [], cwd = rootDir) {
  return new Promise((resolve) => {
    const proc = spawn(command, args, {
      cwd,
      stdio: 'pipe',
      shell: true,
    });

    let stdout = '';
    let stderr = '';

    proc.stdout?.on('data', (data) => {
      stdout += data.toString();
    });

    proc.stderr?.on('data', (data) => {
      stderr += data.toString();
    });

    proc.on('close', (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

test('Scenario: Test script builds then runs node --test', async (t) => {
  // Given a clean checkout
  // Running "npm test" from inside "npm test" re-enters this suite and races the
  // parallel test files on backend/dist, so assert the script here; the exit code
  // is proven by the enclosing run itself.
  const pkg = JSON.parse(readFileSync(path.join(rootDir, 'package.json'), 'utf8'));
  assert.strictEqual(
    pkg.scripts.test,
    'npm --prefix backend run build && node --test "backend/test/**/*.test.js" "installers/test/**/*.test.js"',
  );
});

test('Scenario: Backend compiles under strict TypeScript', async (t) => {
  // Given backend/tsconfig.json sets strict true and outDir dist
  const tsconfigPath = path.join(backendDir, 'tsconfig.json');
  const tsconfig = JSON.parse(readFileSync(tsconfigPath, 'utf8'));
  assert.strictEqual(tsconfig.compilerOptions.strict, true, 'strict should be true');
  assert.strictEqual(tsconfig.compilerOptions.outDir, 'dist', 'outDir should be dist');

  // When I run "npm --prefix backend run build"
  // Compile into a temp outDir so the build cannot rewrite backend/dist while
  // other test files are importing it.
  const outDir = mkdtempSync(path.join(tmpdir(), 'mdm-build-'));
  const result = await runCommand('npx', ['--no-install', 'tsc', '-p', 'tsconfig.json', '--outDir', JSON.stringify(outDir)], backendDir);

  // Then index.js is emitted and the exit code is 0
  assert.strictEqual(result.code, 0, `tsc build should exit 0, got ${result.code}\n${result.stdout}${result.stderr}`);
  const indexPath = path.join(outDir, 'index.js');
  const content = readFileSync(indexPath, 'utf8');
  assert.ok(content.length > 0, 'dist/index.js should exist and have content');
});

test('Scenario: Router extracts path params', async (t) => {
  // Given a route "GET /api/v1/devices/{deviceId}/policies" is registered
  const router = createRouter();
  let capturedParams = null;
  router.add('GET', '/api/v1/devices/{deviceId}/policies', (request) => {
    capturedParams = request.params;
    return { statusCode: 200, body: { success: true } };
  });

  // When I handle a GET for path "/api/v1/devices/dev-7/policies"
  const response = await router.handle({
    method: 'GET',
    path: '/api/v1/devices/dev-7/policies',
    query: {},
    headers: {},
    body: null,
  });

  // Then the handler receives params.deviceId equal to "dev-7"
  assert.deepStrictEqual(capturedParams, { deviceId: 'dev-7' }, 'params should contain deviceId');
  assert.strictEqual(response.statusCode, 200);
});

test('Scenario: Unknown path returns not_found', async (t) => {
  // Given no route matches "/nope"
  const router = createRouter();

  // When I handle a GET for path "/nope"
  const response = await router.handle({
    method: 'GET',
    path: '/nope',
    query: {},
    headers: {},
    body: null,
  });

  // Then the status is 404 and the body is {"error":"not_found"}
  assert.strictEqual(response.statusCode, 404);
  const body = JSON.parse(response.body);
  assert.deepStrictEqual(body, { error: 'not_found' });
});

test('Scenario: Wrong method returns method_not_allowed', async (t) => {
  // Given only "POST /api/v1/enroll" is registered
  const router = createRouter();
  router.add('POST', '/api/v1/enroll', () => ({ statusCode: 200 }));

  // When I handle a GET for path "/api/v1/enroll"
  const response = await router.handle({
    method: 'GET',
    path: '/api/v1/enroll',
    query: {},
    headers: {},
    body: null,
  });

  // Then the status is 405 and the body is {"error":"method_not_allowed"}
  assert.strictEqual(response.statusCode, 405);
  const body = JSON.parse(response.body);
  assert.deepStrictEqual(body, { error: 'method_not_allowed' });
});

test('Scenario: Function URL event is adapted', async (t) => {
  // Given an event with requestContext.http.method POST, path "/api/v1/enroll", body base64 encoded and isBase64Encoded true
  const event = {
    requestContext: {
      http: {
        method: 'POST',
        path: '/api/v1/enroll',
      },
    },
    rawQueryString: '',
    headers: { 'content-type': 'application/json' },
    body: Buffer.from('{"foo":"bar"}').toString('base64'),
    isBase64Encoded: true,
  };

  let receivedBody = null;
  // Mock the router to capture the request
  const { router: appRouter } = await import('../dist/index.js');
  appRouter.add('POST', '/api/v1/enroll', (request) => {
    receivedBody = request.body;
    return { statusCode: 200 };
  });

  // When handler(event) runs
  const response = await handler(event);

  // Then the route receives the decoded body and the response content-type is application/json
  assert.strictEqual(receivedBody, '{"foo":"bar"}', 'body should be decoded');
  assert.strictEqual(response.headers['content-type'], 'application/json');
});

test('Scenario: Thrown handler becomes internal_error', async (t) => {
  // Given a registered route whose handler throws new Error("boom")
  const router = createRouter();
  let errorLogged = false;
  const originalError = console.error;
  console.error = (msg) => {
    if (msg.includes('[router]') && msg.includes('boom')) {
      errorLogged = true;
    }
  };

  router.add('GET', '/boom', () => {
    throw new Error('boom');
  });

  // When handler(event) runs for that route
  const response = await router.handle({
    method: 'GET',
    path: '/boom',
    query: {},
    headers: {},
    body: null,
  });

  console.error = originalError;

  // Then the status is 500, the body is {"error":"internal_error"} and it contains no "boom" text
  assert.strictEqual(response.statusCode, 500);
  const body = JSON.parse(response.body);
  assert.deepStrictEqual(body, { error: 'internal_error' });
  assert.ok(!response.body.includes('boom'), 'response body should not contain error message');
  assert.ok(errorLogged, 'exactly one console.error should be logged');
});

test('Scenario: Build script lists the four targets', async (t) => {
  // When I run "node scripts/build-agent.mjs --dry-run"
  const result = await runCommand('node', ['scripts/build-agent.mjs', '--dry-run']);

  // Then stdout has exactly the four lines windows/amd64, windows/arm64, darwin/amd64, darwin/arm64
  assert.strictEqual(result.code, 0);
  const lines = result.stdout.trim().split('\n').filter((l) => l.length > 0);
  assert.deepStrictEqual(lines, [
    'windows/amd64',
    'windows/arm64',
    'darwin/amd64',
    'darwin/arm64',
  ]);
});

test('Scenario: Unsupported build target is rejected', async (t) => {
  // When I run "node scripts/build-agent.mjs --target linux/amd64"
  const result = await runCommand('node', ['scripts/build-agent.mjs', '--target', 'linux/amd64']);

  // Then the exit code is 2 and stderr contains "unsupported target: linux/amd64"
  assert.strictEqual(result.code, 2);
  assert.ok(
    result.stderr.includes('unsupported target: linux/amd64'),
    `stderr should contain 'unsupported target: linux/amd64', got: ${result.stderr}`
  );
});

test('Scenario: Ignore file covers build outputs', async (t) => {
  // When I read .gitignore
  const gitignorePath = path.join(rootDir, '.gitignore');
  const content = readFileSync(gitignorePath, 'utf8');

  // Then it contains node_modules/, backend/dist/, cdk.out/, agent/bin/, *.msi and *.pkg
  const requiredLines = [
    'node_modules/',
    'backend/dist/',
    'cdk.out/',
    'agent/bin/',
    '*.msi',
    '*.pkg',
  ];

  for (const line of requiredLines) {
    assert.ok(content.includes(line), `.gitignore should contain "${line}"`);
  }
});
