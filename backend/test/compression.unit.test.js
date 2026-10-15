/**
 * Unit tests for TASK-068's backend compression helpers (`readRequestBody`,
 * `acceptsGzip`, `compressResponse`, `toRouterRequest`). None of these are
 * exported from `dist/index.js`, so each is exercised through the smallest
 * public surface that reaches it: `toRouterRequest` directly, or `handler`
 * with a throwaway route registered for this file alone. No database call is
 * made anywhere in this file.
 */

import test from 'node:test';
import assert from 'node:assert';
import { gzipSync, gunzipSync } from 'node:zlib';

import { handler, toRouterRequest, router, COMPRESS_MIN_BYTES } from '../dist/index.js';

// ---------------------------------------------------------------------------
// acceptsGzip, exercised through the response-compression path
// ---------------------------------------------------------------------------

function registerSizedRoute(path, bodyText, headers) {
  router.add('GET', path, () => ({ statusCode: 200, rawBody: bodyText, headers: { 'content-type': 'text/plain', ...headers } }));
}

async function compressedFor(path, acceptEncoding) {
  const headers = acceptEncoding === undefined ? {} : { 'accept-encoding': acceptEncoding };
  return handler({ requestContext: { http: { method: 'GET', path } }, headers });
}

test('Unit: accept-encoding is case-insensitive', async () => {
  const body = 'y'.repeat(2000);
  registerSizedRoute('/api/v1/unit-ae-case', body);
  const resp = await compressedFor('/api/v1/unit-ae-case', 'GZIP');
  assert.strictEqual(resp.headers['content-encoding'], 'gzip');
  assert.strictEqual(resp.isBase64Encoded, true);
});

test('Unit: a comma-separated accept-encoding list with gzip among others is accepted', async () => {
  const body = 'y'.repeat(2000);
  registerSizedRoute('/api/v1/unit-ae-list', body);
  const resp = await compressedFor('/api/v1/unit-ae-list', 'br, gzip, deflate');
  assert.strictEqual(resp.headers['content-encoding'], 'gzip');
});

test('Unit: gzip;q=0 anywhere in the list refuses compression for that token', async () => {
  const body = 'y'.repeat(2000);
  registerSizedRoute('/api/v1/unit-ae-q0', body);
  const resp = await compressedFor('/api/v1/unit-ae-q0', 'gzip;q=0');
  assert.strictEqual(resp.headers['content-encoding'], undefined);
  assert.notStrictEqual(resp.isBase64Encoded, true);
  assert.strictEqual(resp.body, body);
});

test('Unit: a non-zero quality value still accepts gzip', async () => {
  const body = 'y'.repeat(2000);
  registerSizedRoute('/api/v1/unit-ae-q05', body);
  const resp = await compressedFor('/api/v1/unit-ae-q05', 'gzip;q=0.5');
  assert.strictEqual(resp.headers['content-encoding'], 'gzip');
});

test('Unit: a wildcard accept-encoding does not count as gzip', async () => {
  const body = 'y'.repeat(2000);
  registerSizedRoute('/api/v1/unit-ae-star', body);
  const resp = await compressedFor('/api/v1/unit-ae-star', '*');
  assert.strictEqual(resp.headers['content-encoding'], undefined);
});

test('Unit: "br" alone does not accept gzip', async () => {
  const body = 'y'.repeat(2000);
  registerSizedRoute('/api/v1/unit-ae-br-only', body);
  const resp = await compressedFor('/api/v1/unit-ae-br-only', 'br');
  assert.strictEqual(resp.headers['content-encoding'], undefined);
});

// ---------------------------------------------------------------------------
// The 1024-byte threshold, exact boundary
// ---------------------------------------------------------------------------

test('Unit: a response of exactly COMPRESS_MIN_BYTES is compressed', async () => {
  assert.strictEqual(COMPRESS_MIN_BYTES, 1024);
  const body = 'z'.repeat(COMPRESS_MIN_BYTES);
  registerSizedRoute('/api/v1/unit-size-exact', body);
  const resp = await compressedFor('/api/v1/unit-size-exact', 'gzip');
  assert.strictEqual(resp.headers['content-encoding'], 'gzip');
});

test('Unit: a response one byte under COMPRESS_MIN_BYTES is not compressed', async () => {
  const body = 'z'.repeat(COMPRESS_MIN_BYTES - 1);
  registerSizedRoute('/api/v1/unit-size-under', body);
  const resp = await compressedFor('/api/v1/unit-size-under', 'gzip');
  assert.strictEqual(resp.headers['content-encoding'], undefined);
  assert.strictEqual(resp.body, body);
});

// ---------------------------------------------------------------------------
// Vary header handling
// ---------------------------------------------------------------------------

test('Unit: an existing Vary header gets accept-encoding appended', async () => {
  const body = 'y'.repeat(2000);
  registerSizedRoute('/api/v1/unit-vary-append', body, { vary: 'Origin' });
  const resp = await compressedFor('/api/v1/unit-vary-append', 'gzip');
  assert.strictEqual(resp.headers.vary, 'Origin, accept-encoding');
});

test('Unit: a Vary header that already names accept-encoding is not duplicated', async () => {
  const body = 'y'.repeat(2000);
  registerSizedRoute('/api/v1/unit-vary-dup', body, { vary: 'Accept-Encoding' });
  const resp = await compressedFor('/api/v1/unit-vary-dup', 'gzip');
  assert.strictEqual(resp.headers.vary, 'Accept-Encoding');
});

// ---------------------------------------------------------------------------
// A route that already encoded its own response is left alone
// ---------------------------------------------------------------------------

test('Unit: a route that already set content-encoding is never compressed again', async () => {
  const body = 'already-encoded-body';
  router.add('GET', '/api/v1/unit-already-encoded', () => ({
    statusCode: 200,
    rawBody: body,
    headers: { 'content-type': 'application/octet-stream', 'content-encoding': 'identity' },
  }));
  const resp = await compressedFor('/api/v1/unit-already-encoded', 'gzip');
  assert.strictEqual(resp.headers['content-encoding'], 'identity');
  assert.notStrictEqual(resp.isBase64Encoded, true);
  assert.strictEqual(resp.body, body);
});

// ---------------------------------------------------------------------------
// Content-type retention through compression
// ---------------------------------------------------------------------------

test('Unit: a non-JSON content-type survives compression unchanged', async () => {
  const body = 'h'.repeat(2000);
  router.add('GET', '/api/v1/unit-content-type', () => ({
    statusCode: 200,
    rawBody: body,
    headers: { 'content-type': 'text/html; charset=utf-8' },
  }));
  const resp = await compressedFor('/api/v1/unit-content-type', 'gzip');
  assert.strictEqual(resp.headers['content-type'], 'text/html; charset=utf-8');
  assert.strictEqual(gunzipSync(Buffer.from(resp.body, 'base64')).toString('utf8'), body);
});

// ---------------------------------------------------------------------------
// readRequestBody edge cases
// ---------------------------------------------------------------------------

test('Unit: a gzip request with an empty body routes body null, with no decompression attempted', async () => {
  let received;
  router.add('POST', '/api/v1/unit-empty-gzip-body', (request) => {
    received = request.body;
    return { statusCode: 200 };
  });
  const resp = await handler({
    requestContext: { http: { method: 'POST', path: '/api/v1/unit-empty-gzip-body' } },
    headers: { 'content-encoding': 'gzip' },
    body: '',
    isBase64Encoded: false,
  });
  assert.strictEqual(resp.statusCode, 200);
  assert.strictEqual(received, null);
});

test('Unit: a gzip request with a null body routes body null', async () => {
  let received = 'unset';
  router.add('POST', '/api/v1/unit-null-gzip-body', (request) => {
    received = request.body;
    return { statusCode: 200 };
  });
  const resp = await handler({
    requestContext: { http: { method: 'POST', path: '/api/v1/unit-null-gzip-body' } },
    headers: { 'content-encoding': 'gzip' },
    body: null,
    isBase64Encoded: false,
  });
  assert.strictEqual(resp.statusCode, 200);
  assert.strictEqual(received, null);
});

test('Unit: an absent content-encoding header is treated the same as none', async () => {
  const event = {
    requestContext: { http: { method: 'GET', path: '/api/v1/unit-no-header' } },
    headers: undefined,
    body: '{"x":1}',
    isBase64Encoded: false,
  };
  const request = toRouterRequest(event);
  assert.strictEqual(request.body, '{"x":1}');
});

test('Unit: toRouterRequest called directly throws on an undecodable gzip body', () => {
  const event = {
    requestContext: { http: { method: 'POST', path: '/api/v1/unit-bad-gzip-direct' } },
    headers: { 'content-encoding': 'gzip' },
    body: 'not gzip',
    isBase64Encoded: false,
  };
  assert.throws(() => toRouterRequest(event));
});

test('Unit: handler does not rely on toRouterRequest for an undecodable body (answers 400, not a throw)', async () => {
  const resp = await handler({
    requestContext: { http: { method: 'POST', path: '/api/v1/unit-bad-gzip-via-handler' } },
    headers: { 'content-encoding': 'gzip' },
    body: 'not gzip',
    isBase64Encoded: false,
  });
  assert.strictEqual(resp.statusCode, 400);
});

// ---------------------------------------------------------------------------
// Round trip sanity: compressing a gzip request body and inflating a gzip
// response body in the same call.
// ---------------------------------------------------------------------------

test('Unit: a gzip request to a compressible route can itself receive a gzip response', async () => {
  const requestPlain = JSON.stringify({ hello: 'world' });
  const responseBody = 'r'.repeat(5000);
  router.add('POST', '/api/v1/unit-roundtrip', (request) => {
    assert.strictEqual(request.body, requestPlain);
    return { statusCode: 200, rawBody: responseBody, headers: { 'content-type': 'text/plain' } };
  });

  const event = {
    requestContext: { http: { method: 'POST', path: '/api/v1/unit-roundtrip' } },
    headers: { 'content-encoding': 'gzip', 'accept-encoding': 'gzip' },
    body: gzipSync(Buffer.from(requestPlain, 'utf8')).toString('base64'),
    isBase64Encoded: true,
  };

  const resp = await handler(event);
  assert.strictEqual(resp.headers['content-encoding'], 'gzip');
  assert.strictEqual(gunzipSync(Buffer.from(resp.body, 'base64')).toString('utf8'), responseBody);
});
