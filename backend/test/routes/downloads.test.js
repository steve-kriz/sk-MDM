/**
 * E2E cucumber-style and unit tests for `GET /downloads/{platform}` (TASK-025).
 *
 * All scenarios here configure the route with a non-empty bucket at least
 * once, so the "never configured" scenarios live in their own file
 * (downloads-not-configured.test.js): `node --test` runs each file in its own
 * process, and the route's configured dependencies are module-level state
 * that cannot be reset mid-process.
 *
 * No AWS client is ever constructed: every store is a fake implementing
 * `InstallerStore` (`exists`, `presignGet`).
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const {
  DOWNLOAD_PATH,
  DOWNLOAD_PLATFORMS,
  DOWNLOAD_URL_TTL_SECONDS,
  installerKey,
  isDownloadPlatform,
  createDownloadHandler,
  registerDownloadRoute,
  configureDownloadRoute,
  resolveDownloadDependencies,
} = await import(`file://${join(__dirname, '../../dist/routes/downloads.js')}`);
const { createRouter } = await import(`file://${join(__dirname, '../../dist/http/router.js')}`);

/** A fake InstallerStore: records every call, and answers per-key scripted outcomes. */
class FakeStore {
  constructor() {
    this.existsCalls = [];
    this.presignCalls = [];
    this.existing = new Set();
    this.existsError = null;
    this.presignError = null;
    this.presignedUrl = 'https://example-bucket.s3.amazonaws.com/signed';
  }

  setExists(key) {
    this.existing.add(key);
  }

  async exists(key) {
    this.existsCalls.push(key);
    if (this.existsError) {
      throw this.existsError;
    }
    return this.existing.has(key);
  }

  async presignGet(key, ttlSeconds) {
    this.presignCalls.push({ key, ttlSeconds });
    if (this.presignError) {
      throw this.presignError;
    }
    return this.presignedUrl;
  }
}

function request(method, path, headers = {}) {
  return { method, path, query: {}, headers, body: null };
}

// ============================================================================
// Scenario Outline: Each slug maps to its fixed key
// ============================================================================
test('Scenario Outline: Each slug maps to its fixed key', () => {
  assert.deepStrictEqual(Array.from(DOWNLOAD_PLATFORMS), [
    'windows-x64',
    'windows-arm64',
    'macos-amd64',
    'macos-arm64',
  ]);
  assert.strictEqual(installerKey('windows-x64'), 'installers/windows-x64.msi');
  assert.strictEqual(installerKey('windows-arm64'), 'installers/windows-arm64.msi');
  assert.strictEqual(installerKey('macos-amd64'), 'installers/macos-amd64.pkg');
  assert.strictEqual(installerKey('macos-arm64'), 'installers/macos-arm64.pkg');
  assert.strictEqual(DOWNLOAD_URL_TTL_SECONDS, 300);
});

// ============================================================================
// Scenario: Existing installer redirects to a presigned URL
// ============================================================================
test('Scenario: Existing installer redirects to a presigned URL', async () => {
  // Given the download route is configured with bucket "b" and a fake store
  // where "installers/macos-arm64.pkg" exists
  const store = new FakeStore();
  store.setExists('installers/macos-arm64.pkg');
  store.presignedUrl = 'https://b.s3.amazonaws.com/installers/macos-arm64.pkg?X-Amz-Signature=abc';
  configureDownloadRoute({ bucket: 'b', installers: store });

  // When I GET "/downloads/macos-arm64"
  const handler = createDownloadHandler(resolveDownloadDependencies);
  const result = await handler({ ...request('GET', '/downloads/macos-arm64'), params: { platform: 'macos-arm64' } });

  // Then the status is 302, location and cache-control headers are set
  assert.strictEqual(result.statusCode, 302);
  assert.strictEqual(result.headers.location, 'https://b.s3.amazonaws.com/installers/macos-arm64.pkg?X-Amz-Signature=abc');
  assert.strictEqual(result.headers['cache-control'], 'no-store');

  // And presignGet was called once with "installers/macos-arm64.pkg" and 300
  assert.strictEqual(store.presignCalls.length, 1);
  assert.deepStrictEqual(store.presignCalls[0], { key: 'installers/macos-arm64.pkg', ttlSeconds: 300 });
});

// ============================================================================
// Scenario Outline: Unknown slug is not found and S3 is not touched
// ============================================================================
for (const slug of ['linux-x64', 'Windows-x64', 'windows']) {
  test(`Scenario Outline: Unknown slug "${slug}" is not found and S3 is not touched`, async () => {
    // Given the download route is configured with a fake store
    const store = new FakeStore();
    store.setExists('installers/windows-x64.msi');
    configureDownloadRoute({ bucket: 'b', installers: store });

    // When I GET "/downloads/<slug>"
    const handler = createDownloadHandler(resolveDownloadDependencies);
    const result = await handler({ ...request('GET', `/downloads/${slug}`), params: { platform: slug } });

    // Then the status is 404 with body {"error":"not_found"}
    assert.strictEqual(result.statusCode, 404);
    assert.deepStrictEqual(result.body, { error: 'not_found' });

    // And the store's exists and presignGet were not called
    assert.strictEqual(store.existsCalls.length, 0);
    assert.strictEqual(store.presignCalls.length, 0);
    assert.strictEqual(isDownloadPlatform(slug), false);
  });
}

// ============================================================================
// Scenario: Known slug with no uploaded installer
// ============================================================================
test('Scenario: Known slug with no uploaded installer', async () => {
  // Given the download route is configured with a fake store where no object exists
  const store = new FakeStore();
  configureDownloadRoute({ bucket: 'b', installers: store });

  // When I GET "/downloads/windows-arm64"
  const handler = createDownloadHandler(resolveDownloadDependencies);
  const result = await handler({
    ...request('GET', '/downloads/windows-arm64'),
    params: { platform: 'windows-arm64' },
  });

  // Then the status is 404 with body {"error":"installer_not_available"}
  assert.strictEqual(result.statusCode, 404);
  assert.deepStrictEqual(result.body, { error: 'installer_not_available' });

  // And presignGet was not called
  assert.strictEqual(store.presignCalls.length, 0);
});

// ============================================================================
// Scenario: S3 failure does not leak details
// ============================================================================
test('Scenario: S3 failure does not leak details', async () => {
  // Given the download route is configured with bucket "secret-bucket" and a
  // store whose exists rejects with "AccessDenied"
  const store = new FakeStore();
  const error = new Error('AccessDenied');
  error.name = 'AccessDenied';
  store.existsError = error;
  configureDownloadRoute({ bucket: 'secret-bucket', installers: store });

  const router = createRouter();
  registerDownloadRoute(router, resolveDownloadDependencies);

  const errorLines = [];
  const originalError = console.error;
  console.error = (line) => errorLines.push(line);
  let response;
  try {
    // When I GET "/downloads/windows-x64"
    response = await router.handle(request('GET', '/downloads/windows-x64'));
  } finally {
    console.error = originalError;
  }

  // Then the status is 500 with body {"error":"internal_error"}
  assert.strictEqual(response.statusCode, 500);
  assert.deepStrictEqual(JSON.parse(response.body), { error: 'internal_error' });

  // And exactly one console.error line was written
  assert.strictEqual(errorLines.length, 1);

  // And the body contains neither "secret-bucket" nor "https://"
  assert.ok(!response.body.includes('secret-bucket'));
  assert.ok(!response.body.includes('https://'));
});

// ============================================================================
// Scenario: Route configured with an empty bucket
// ============================================================================
test('Scenario: Route configured with an empty bucket', async () => {
  // Given configureDownloadRoute was called with bucket ""
  configureDownloadRoute({ bucket: '', installers: new FakeStore() });

  // When I GET "/downloads/windows-x64"
  const handler = createDownloadHandler(resolveDownloadDependencies);
  const result = await handler({
    ...request('GET', '/downloads/windows-x64'),
    params: { platform: 'windows-x64' },
  });

  // Then the status is 500 with body {"error":"not_configured"}
  assert.strictEqual(result.statusCode, 500);
  assert.deepStrictEqual(result.body, { error: 'not_configured' });
});

// ============================================================================
// Scenario: Download is public and GET-only
// ============================================================================
test('Scenario: Download is public and GET-only', async () => {
  // Given the download route is configured with a fake store where every
  // object exists
  const store = new FakeStore();
  for (const slug of DOWNLOAD_PLATFORMS) {
    store.setExists(installerKey(slug));
  }
  configureDownloadRoute({ bucket: 'b', installers: store });

  const router = createRouter();
  registerDownloadRoute(router, resolveDownloadDependencies);

  // When I GET "/downloads/windows-x64" with no authorization or device
  // signature headers
  const getResponse = await router.handle(request('GET', '/downloads/windows-x64', {}));
  // Then the status is 302
  assert.strictEqual(getResponse.statusCode, 302);

  // When I POST "/downloads/windows-x64"
  const postResponse = await router.handle(request('POST', '/downloads/windows-x64', {}));
  // Then the status is 405 with body {"error":"method_not_allowed"}
  assert.strictEqual(postResponse.statusCode, 405);
  assert.deepStrictEqual(JSON.parse(postResponse.body), { error: 'method_not_allowed' });
});

// ============================================================================
// Unit: createDownloadHandler accepts a dependency-resolving function
// ============================================================================
test('Unit: createDownloadHandler accepts a function source resolved per request', async () => {
  const store = new FakeStore();
  store.setExists('installers/windows-x64.msi');
  let calls = 0;
  const handler = createDownloadHandler(() => {
    calls += 1;
    return { bucket: 'b', installers: store };
  });

  const result = await handler({ ...request('GET', '/downloads/windows-x64'), params: { platform: 'windows-x64' } });
  assert.strictEqual(result.statusCode, 302);
  assert.strictEqual(calls, 1);
});

// ============================================================================
// Unit: DOWNLOAD_PATH is registered on the router
// ============================================================================
test('Unit: DOWNLOAD_PATH is the expected pattern', () => {
  assert.strictEqual(DOWNLOAD_PATH, '/downloads/{platform}');
});

// ============================================================================
// Unit: presignGet rejection also answers 500 internal_error
// ============================================================================
test('Unit: presignGet rejection answers 500 internal_error', async () => {
  const store = new FakeStore();
  store.setExists('installers/windows-x64.msi');
  const error = new Error('presign failed');
  store.presignError = error;
  configureDownloadRoute({ bucket: 'b', installers: store });

  const router = createRouter();
  registerDownloadRoute(router, resolveDownloadDependencies);

  const errorLines = [];
  const originalError = console.error;
  console.error = (line) => errorLines.push(line);
  let response;
  try {
    response = await router.handle(request('GET', '/downloads/windows-x64'));
  } finally {
    console.error = originalError;
  }

  assert.strictEqual(response.statusCode, 500);
  assert.deepStrictEqual(JSON.parse(response.body), { error: 'internal_error' });
  assert.strictEqual(errorLines.length, 1);
});
