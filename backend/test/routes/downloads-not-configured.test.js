/**
 * E2E tests for `GET /downloads/{platform}` when the route has never been
 * configured in this process (TASK-025).
 *
 * `configureDownloadRoute` sets module-level state that cannot be reset, so
 * this scenario -- the route never having been configured at all -- must run
 * in a file of its own: `node --test` runs each test file in its own process,
 * so this file never observes a `configureDownloadRoute` call made by another
 * test file. The first test below runs before any such call is made in this
 * file either.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const { createDownloadHandler, configureDownloadRoute, resolveDownloadDependencies } = await import(
  `file://${join(__dirname, '../../dist/routes/downloads.js')}`
);

function request(method, path) {
  return { method, path, query: {}, headers: {}, body: null, params: { platform: 'windows-x64' } };
}

// ============================================================================
// Scenario: Route not configured
// ============================================================================
test('Scenario: Route not configured', async () => {
  // Given configureDownloadRoute has not been called
  // When I GET "/downloads/windows-x64"
  const handler = createDownloadHandler(resolveDownloadDependencies);
  const result = await handler(request('GET', '/downloads/windows-x64'));

  // Then the status is 500 with body {"error":"not_configured"}
  assert.strictEqual(result.statusCode, 500);
  assert.deepStrictEqual(result.body, { error: 'not_configured' });
});

// ============================================================================
// Unit: resolveDownloadDependencies before any configure call
// ============================================================================
test('Unit: resolveDownloadDependencies answers undefined bucket and store before configuration', () => {
  const deps = resolveDownloadDependencies();
  assert.strictEqual(deps.bucket, undefined);
  assert.strictEqual(deps.installers, undefined);
});

// ============================================================================
// Scenario: Route configured with an empty bucket (also not_configured)
// ============================================================================
test('Scenario: Route configured with an empty bucket', async () => {
  // Given configureDownloadRoute was called with bucket ""
  configureDownloadRoute({ bucket: '', installers: { exists: async () => true, presignGet: async () => 'x' } });

  // When I GET "/downloads/windows-x64"
  const handler = createDownloadHandler(resolveDownloadDependencies);
  const result = await handler(request('GET', '/downloads/windows-x64'));

  // Then the status is 500 with body {"error":"not_configured"}
  assert.strictEqual(result.statusCode, 500);
  assert.deepStrictEqual(result.body, { error: 'not_configured' });
});
