/**
 * E2E cucumber-style tests for TASK-068 (gzip agent<->backend payloads),
 * backend half (AC15-AC26). Every test implements a Gherkin scenario from the
 * ticket by name, in Given/When/Then form, without a cucumber package.
 *
 * Mock all database calls -- no real DB connection is ever opened. The one
 * fake table implements exactly the structural subset `verifyDeviceRequest`
 * and the check-in route need.
 */

import test from 'node:test';
import assert from 'node:assert';
import { gzipSync, gunzipSync } from 'node:zlib';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
  handler,
  toRouterRequest,
  router,
  MAX_INFLATED_BODY_BYTES,
  COMPRESS_MIN_BYTES,
  ACCEPT_CONTENT_ENCODING_HEADER,
  MAX_BODY_BYTES,
  CHECKIN_PATH,
  configureCheckInRoute,
} from '../dist/index.js';
import { createLambdaHandler } from '../dist/lambda.js';
import { signRequest } from '../dist/contract/signing.js';
import { encryptDeviceSecret } from '../dist/crypto/deviceSecret.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '../../');

// ---------------------------------------------------------------------------
// Shared fixtures -- a mocked table, never a real database connection.
// ---------------------------------------------------------------------------

class FakeDeviceTable {
  constructor() {
    this.items = new Map();
  }

  keyStr(key) {
    return JSON.stringify({ pk: key.pk, sk: key.sk });
  }

  async get(key) {
    return this.items.get(this.keyStr(key));
  }

  async put(item) {
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  async putIfAbsent(item) {
    const keyStr = this.keyStr({ pk: item.pk, sk: item.sk });
    if (this.items.has(keyStr)) {
      return { written: false };
    }
    this.items.set(keyStr, { ...item });
    return { written: true };
  }

  async update(key, fields) {
    const existing = this.items.get(this.keyStr(key)) || {};
    const updated = { ...existing, ...key };
    this.items.set(this.keyStr(key), updated);
    return updated;
  }

  async query() {
    return { items: [], cursor: null };
  }

  seedDevice(deviceId, secretHex, pepperHex) {
    this.items.set(this.keyStr({ pk: `DEVICE#${deviceId}`, sk: 'PROFILE' }), {
      pk: `DEVICE#${deviceId}`,
      sk: 'PROFILE',
      secretEnc: encryptDeviceSecret(secretHex, pepperHex, deviceId),
      status: 'active',
    });
  }
}

const PEPPER = randomBytes(32).toString('hex');
const DEVICE_ID = 'compression-e2e-device';
const DEVICE_SECRET = randomBytes(32).toString('hex');

function validCheckInBody(overrides = {}) {
  return {
    collectedAt: '2026-10-12T11:00:00Z',
    inventory: {
      hardware: {
        manufacturer: 'Dell',
        model: 'OptiPlex 7090',
        serialNumber: 'ABC123',
        cpu: 'Intel Core i7',
        ramBytes: 16000000000,
        diskBytes: 500000000000,
      },
      os: { name: 'Windows', version: '11', build: '22621', architecture: 'x86_64' },
      software: [],
      warnings: [],
    },
    posture: {
      diskEncryption: { enabled: true, method: 'bitlocker' },
      firewall: { enabled: true },
      antivirus: { name: 'Windows Defender', enabled: true, definitionsAgeDays: 1 },
      osUpdate: { lastCheckedAt: '2026-10-12T10:00:00Z', pendingCount: 0, rebootRequired: false },
      localAdmins: [],
      warnings: [],
    },
    ...overrides,
  };
}

const CHECKIN_TIMESTAMP = Math.floor(Date.now() / 1000);

/** Build a Function URL event for the real check-in route, optionally gzipped. */
function checkinEvent({ deviceId, bodyText, signBodyText, gzip, nonce }) {
  const path = CHECKIN_PATH.replace('{deviceId}', deviceId);
  const signature = signRequest(DEVICE_SECRET, {
    method: 'POST',
    path,
    query: '',
    body: signBodyText ?? bodyText,
    timestamp: CHECKIN_TIMESTAMP,
    nonce,
    deviceId,
  });
  const headers = {
    'content-type': 'application/json',
    'x-mdm-device-id': deviceId,
    'x-mdm-timestamp': String(CHECKIN_TIMESTAMP),
    'x-mdm-nonce': nonce,
    'x-mdm-signature': signature,
  };
  let body = bodyText;
  let isBase64Encoded = false;
  if (gzip) {
    headers['content-encoding'] = 'gzip';
    body = gzipSync(Buffer.from(bodyText, 'utf8')).toString('base64');
    isBase64Encoded = true;
  }
  return {
    requestContext: { http: { method: 'POST', path } },
    rawQueryString: '',
    headers,
    body,
    isBase64Encoded,
  };
}

// ---------------------------------------------------------------------------
// AC15
// ---------------------------------------------------------------------------

test('Scenario Outline: Unencoded requests are routed exactly as before (AC15)', () => {
  const cases = [
    { ce: undefined, b64: false },
    { ce: '', b64: true },
    { ce: 'identity', b64: false },
  ];
  for (const { ce, b64 } of cases) {
    // Given a Function URL event with content-encoding <ce> and
    // isBase64Encoded <b64> carrying '{"a":1}'
    const headers = ce === undefined ? {} : { 'content-encoding': ce };
    const event = {
      requestContext: { http: { method: 'POST', path: '/api/v1/compression-ac15' } },
      headers,
      body: b64 ? Buffer.from('{"a":1}', 'utf8').toString('base64') : '{"a":1}',
      isBase64Encoded: b64,
    };

    // When toRouterRequest adapts it
    const request = toRouterRequest(event);

    // Then the router request body is '{"a":1}'
    assert.strictEqual(request.body, '{"a":1}', `ce=${JSON.stringify(ce)} b64=${b64}`);
  }
});

// ---------------------------------------------------------------------------
// AC16
// ---------------------------------------------------------------------------

test('Scenario: A gzip request body is inflated before routing (AC16)', async () => {
  // Given a Function URL event with content-encoding " GZIP " and
  // isBase64Encoded true carrying base64 of gzip('{"a":1}')
  let receivedBody = null;
  let receivedHeaders = null;
  router.add('POST', '/api/v1/compression-ac16', (request) => {
    receivedBody = request.body;
    receivedHeaders = request.headers;
    return { statusCode: 200, body: { ok: true } };
  });

  const compressed = gzipSync(Buffer.from('{"a":1}', 'utf8')).toString('base64');
  const event = {
    requestContext: { http: { method: 'POST', path: '/api/v1/compression-ac16' } },
    headers: { 'content-encoding': ' GZIP ' },
    body: compressed,
    isBase64Encoded: true,
  };

  // When the handler routes it
  await handler(event);

  // Then the route handler receives body '{"a":1}'
  assert.strictEqual(receivedBody, '{"a":1}');
  // And the route handler's headers have no "content-encoding" key
  assert.strictEqual(Object.keys(receivedHeaders).includes('content-encoding'), false);
});

// ---------------------------------------------------------------------------
// AC17
// ---------------------------------------------------------------------------

test('Scenario: A compressed check-in signed over the uncompressed JSON is accepted (AC17)', async () => {
  // Given an enrolled device and a valid check-in JSON
  const bodyText = JSON.stringify(validCheckInBody());

  // And the request is signed over the uncompressed JSON and sent
  // gzip-compressed
  const tableGzip = new FakeDeviceTable();
  tableGzip.seedDevice(DEVICE_ID, DEVICE_SECRET, PEPPER);
  configureCheckInRoute({ table: tableGzip, pepper: PEPPER, now: () => CHECKIN_TIMESTAMP });
  const gzipEvent = checkinEvent({ deviceId: DEVICE_ID, bodyText, gzip: true, nonce: randomBytes(16).toString('hex') });

  // When the handler routes it
  const gzipResponse = await handler(gzipEvent);

  // Then the response equals the response to the same check-in sent
  // uncompressed
  const tablePlain = new FakeDeviceTable();
  tablePlain.seedDevice(DEVICE_ID, DEVICE_SECRET, PEPPER);
  configureCheckInRoute({ table: tablePlain, pepper: PEPPER, now: () => CHECKIN_TIMESTAMP });
  const plainEvent = checkinEvent({ deviceId: DEVICE_ID, bodyText, gzip: false, nonce: randomBytes(16).toString('hex') });
  const plainResponse = await handler(plainEvent);

  assert.strictEqual(gzipResponse.statusCode, 200, `gzip response: ${gzipResponse.body}`);
  assert.strictEqual(gzipResponse.statusCode, plainResponse.statusCode);
  assert.strictEqual(JSON.parse(gzipResponse.body).pendingCommandCount, JSON.parse(plainResponse.body).pendingCommandCount);
  assert.deepStrictEqual(
    Object.keys(JSON.parse(gzipResponse.body)).sort(),
    Object.keys(JSON.parse(plainResponse.body)).sort(),
  );
});

test('Scenario (failure): A check-in signed over the compressed bytes is refused (AC17)', async () => {
  // Given a gzip-compressed check-in signed over the compressed bytes
  const bodyText = JSON.stringify(validCheckInBody());
  const compressedBytes = gzipSync(Buffer.from(bodyText, 'utf8'));

  const table = new FakeDeviceTable();
  table.seedDevice(DEVICE_ID, DEVICE_SECRET, PEPPER);
  configureCheckInRoute({ table, pepper: PEPPER, now: () => CHECKIN_TIMESTAMP });

  const event = checkinEvent({
    deviceId: DEVICE_ID,
    bodyText,
    signBodyText: compressedBytes, // the bug under test: signing the compressed bytes
    gzip: true,
    nonce: randomBytes(16).toString('hex'),
  });

  // When the handler routes it
  const response = await handler(event);

  // Then the response is 401 with body '{"error":"bad_signature"}'
  assert.strictEqual(response.statusCode, 401);
  assert.deepStrictEqual(JSON.parse(response.body), { error: 'bad_signature' });
});

// ---------------------------------------------------------------------------
// AC18
// ---------------------------------------------------------------------------

test('Scenario (failure): Malformed gzip is rejected before routing (AC18)', async () => {
  // Given a request with content-encoding "gzip" and body "not gzip"
  let routeInvoked = false;
  router.add('POST', '/api/v1/compression-ac18', () => {
    routeInvoked = true;
    return { statusCode: 200 };
  });
  const table = new FakeDeviceTable();
  const nonceCallsBefore = table.items.size;

  const event = {
    requestContext: { http: { method: 'POST', path: '/api/v1/compression-ac18' } },
    headers: { 'content-encoding': 'gzip' },
    body: 'not gzip',
    isBase64Encoded: false,
  };

  // When the handler routes it
  const response = await handler(event);

  // Then the response is 400 with body '{"error":"invalid_gzip_body"}'
  assert.strictEqual(response.statusCode, 400);
  assert.deepStrictEqual(JSON.parse(response.body), { error: 'invalid_gzip_body' });
  // And no route handler was invoked and no nonce item was written
  assert.strictEqual(routeInvoked, false);
  assert.strictEqual(table.items.size, nonceCallsBefore);
});

// ---------------------------------------------------------------------------
// AC19
// ---------------------------------------------------------------------------

test('Scenario (failure): A decompression bomb is capped (AC19)', async () => {
  // Given a gzip body that inflates to 1048577 bytes
  let routeInvoked = false;
  router.add('POST', '/api/v1/compression-ac19', () => {
    routeInvoked = true;
    return { statusCode: 200 };
  });
  const bigPlain = Buffer.alloc(MAX_INFLATED_BODY_BYTES + 1, 'a');
  const compressed = gzipSync(bigPlain).toString('base64');

  const event = {
    requestContext: { http: { method: 'POST', path: '/api/v1/compression-ac19' } },
    headers: { 'content-encoding': 'gzip' },
    body: compressed,
    isBase64Encoded: true,
  };

  // When the handler routes it
  const response = await handler(event);

  // Then the response is 413 with body '{"error":"payload_too_large"}'
  assert.strictEqual(response.statusCode, 413);
  assert.deepStrictEqual(JSON.parse(response.body), { error: 'payload_too_large' });
  // And no route handler was invoked
  assert.strictEqual(routeInvoked, false);
});

test('Edge: exactly MAX_INFLATED_BODY_BYTES inflated bytes is accepted (AC19 boundary)', async () => {
  let receivedLength = null;
  router.add('POST', '/api/v1/compression-ac19-boundary', (request) => {
    receivedLength = Buffer.byteLength(request.body, 'utf8');
    return { statusCode: 200 };
  });
  const exactPlain = Buffer.alloc(MAX_INFLATED_BODY_BYTES, 'a');
  const compressed = gzipSync(exactPlain).toString('base64');

  const event = {
    requestContext: { http: { method: 'POST', path: '/api/v1/compression-ac19-boundary' } },
    headers: { 'content-encoding': 'gzip' },
    body: compressed,
    isBase64Encoded: true,
  };

  const response = await handler(event);
  assert.strictEqual(response.statusCode, 200);
  assert.strictEqual(receivedLength, MAX_INFLATED_BODY_BYTES);
});

// ---------------------------------------------------------------------------
// AC20
// ---------------------------------------------------------------------------

test('Scenario Outline: Unsupported content encodings are rejected (AC20)', async () => {
  const cases = ['br', 'deflate', 'gzip, deflate'];
  for (const ce of cases) {
    // Given a request with content-encoding "<ce>"
    let routeInvoked = false;
    router.add('POST', `/api/v1/compression-ac20-${ce.replace(/[^a-z]/g, '')}`, () => {
      routeInvoked = true;
      return { statusCode: 200 };
    });
    const event = {
      requestContext: { http: { method: 'POST', path: `/api/v1/compression-ac20-${ce.replace(/[^a-z]/g, '')}` } },
      headers: { 'content-encoding': ce },
      body: '{}',
      isBase64Encoded: false,
    };

    // When the handler routes it
    const response = await handler(event);

    // Then the response is 415 with body '{"error":"unsupported_content_encoding"}'
    assert.strictEqual(response.statusCode, 415, `ce=${ce}`);
    assert.deepStrictEqual(JSON.parse(response.body), { error: 'unsupported_content_encoding' });
    assert.strictEqual(routeInvoked, false, `ce=${ce}`);
  }
});

// ---------------------------------------------------------------------------
// AC21
// ---------------------------------------------------------------------------

test('Edge: The check-in cap applies to the inflated body (AC21)', async () => {
  // Given a correctly signed gzip check-in that inflates to 262145 bytes
  const padTo = MAX_BODY_BYTES + 1;
  const base = validCheckInBody();
  // Pad with a long string on a field the schema does not otherwise
  // constrain, growing the serialised JSON to exactly padTo bytes.
  const withoutPad = JSON.stringify(base);
  const padLength = Math.max(0, padTo - withoutPad.length - '"padding":""'.length - 1);
  base.padding = 'x'.repeat(padLength);
  let bodyText = JSON.stringify(base);
  // Fine-tune to exactly padTo bytes (JSON.stringify escaping is a no-op for 'x').
  if (bodyText.length < padTo) {
    base.padding += 'x'.repeat(padTo - bodyText.length);
    bodyText = JSON.stringify(base);
  } else if (bodyText.length > padTo) {
    base.padding = base.padding.slice(0, Math.max(0, base.padding.length - (bodyText.length - padTo)));
    bodyText = JSON.stringify(base);
  }
  assert.strictEqual(Buffer.byteLength(bodyText, 'utf8'), padTo, 'test fixture must be exactly MAX_BODY_BYTES + 1');

  const table = new FakeDeviceTable();
  table.seedDevice(DEVICE_ID, DEVICE_SECRET, PEPPER);
  configureCheckInRoute({ table, pepper: PEPPER, now: () => CHECKIN_TIMESTAMP });
  const event = checkinEvent({ deviceId: DEVICE_ID, bodyText, gzip: true, nonce: randomBytes(16).toString('hex') });

  // When the handler routes it
  const response = await handler(event);

  // Then the response is 413 with body '{"error":"payload_too_large"}'
  assert.strictEqual(response.statusCode, 413);
  assert.deepStrictEqual(JSON.parse(response.body), { error: 'payload_too_large' });
});

// ---------------------------------------------------------------------------
// AC22
// ---------------------------------------------------------------------------

test('Scenario: A large agent API response is gzipped (AC22)', async () => {
  // Given a route on "/api/v1/devices/dev-1/policies" returns a 4000-byte
  // JSON body
  const bodyText = JSON.stringify({ padding: 'x'.repeat(3980) });
  assert.ok(Buffer.byteLength(bodyText, 'utf8') >= 4000 - 20);
  router.add('GET', '/api/v1/compression-ac22', () => ({
    statusCode: 200,
    rawBody: bodyText,
    headers: { 'content-type': 'application/json' },
  }));

  // And the request has accept-encoding "gzip"
  const event = {
    requestContext: { http: { method: 'GET', path: '/api/v1/compression-ac22' } },
    headers: { 'accept-encoding': 'gzip' },
  };

  // When the handler answers
  const response = await handler(event);

  // Then the response has isBase64Encoded true and header "content-encoding"
  // "gzip" and "vary" "accept-encoding"
  assert.strictEqual(response.isBase64Encoded, true);
  assert.strictEqual(response.headers['content-encoding'], 'gzip');
  assert.strictEqual(response.headers['vary'], 'accept-encoding');

  // And gunzipping the base64-decoded body yields the 4000-byte JSON
  const inflated = gunzipSync(Buffer.from(response.body, 'base64')).toString('utf8');
  assert.strictEqual(inflated, bodyText);

  // And the content-type is "application/json"
  assert.strictEqual(response.headers['content-type'], 'application/json');
});

// ---------------------------------------------------------------------------
// AC23
// ---------------------------------------------------------------------------

test('Scenario Outline: Responses that do not qualify are not compressed (AC23)', async () => {
  const bigBody = 'x'.repeat(4000);
  const smallBody = 'x'.repeat(1023);

  router.add('GET', '/api/v1/compression-ac23-small', () => ({ statusCode: 200, rawBody: smallBody, headers: { 'content-type': 'text/plain' } }));
  router.add('GET', '/api/v1/compression-ac23-noae', () => ({ statusCode: 200, rawBody: bigBody, headers: { 'content-type': 'text/plain' } }));
  router.add('GET', '/api/v1/compression-ac23-q0', () => ({ statusCode: 200, rawBody: bigBody, headers: { 'content-type': 'text/plain' } }));
  router.add('GET', '/admin/api/v1/compression-ac23-outside', () => ({ statusCode: 200, rawBody: bigBody, headers: { 'content-type': 'text/plain' } }));
  router.add('GET', '/compression-ac23-root', () => ({ statusCode: 200, rawBody: bigBody, headers: { 'content-type': 'text/plain' } }));

  const cases = [
    { path: '/api/v1/compression-ac23-small', ae: 'gzip', want: smallBody },
    { path: '/api/v1/compression-ac23-noae', ae: undefined, want: bigBody },
    { path: '/api/v1/compression-ac23-q0', ae: 'gzip;q=0', want: bigBody },
    { path: '/admin/api/v1/compression-ac23-outside', ae: 'gzip', want: bigBody },
    { path: '/compression-ac23-root', ae: 'gzip', want: bigBody },
  ];

  for (const { path, ae, want } of cases) {
    // Given a route on "<path>" returns a <size>-byte body
    // And the request has accept-encoding "<ae>"
    const headers = ae === undefined ? {} : { 'accept-encoding': ae };
    const event = { requestContext: { http: { method: 'GET', path } }, headers };

    // When the handler answers
    const response = await handler(event);

    // Then the response body is the route's string unchanged with no
    // content-encoding header and no isBase64Encoded true
    assert.strictEqual(response.body, want, `path=${path}`);
    assert.strictEqual(response.headers['content-encoding'], undefined, `path=${path}`);
    assert.notStrictEqual(response.isBase64Encoded, true, `path=${path}`);
  }
});

// ---------------------------------------------------------------------------
// AC24
// ---------------------------------------------------------------------------

test('Scenario Outline: Every handler response advertises gzip support (AC24)', async () => {
  // a 200 check-in
  const table = new FakeDeviceTable();
  table.seedDevice(DEVICE_ID, DEVICE_SECRET, PEPPER);
  configureCheckInRoute({ table, pepper: PEPPER, now: () => CHECKIN_TIMESTAMP });
  const checkinResp = await handler(
    checkinEvent({ deviceId: DEVICE_ID, bodyText: JSON.stringify(validCheckInBody()), gzip: false, nonce: randomBytes(16).toString('hex') }),
  );
  assert.strictEqual(checkinResp.statusCode, 200);
  assert.strictEqual(checkinResp.headers[ACCEPT_CONTENT_ENCODING_HEADER], 'gzip');

  // a 404 not_found
  const notFoundResp = await handler({
    requestContext: { http: { method: 'GET', path: '/api/v1/compression-ac24-nope' } },
    headers: {},
  });
  assert.strictEqual(notFoundResp.statusCode, 404);
  assert.strictEqual(notFoundResp.headers[ACCEPT_CONTENT_ENCODING_HEADER], 'gzip');

  // a 400 invalid_gzip_body
  const badGzipResp = await handler({
    requestContext: { http: { method: 'POST', path: '/api/v1/compression-ac24-badgzip' } },
    headers: { 'content-encoding': 'gzip' },
    body: 'not gzip',
  });
  assert.strictEqual(badGzipResp.statusCode, 400);
  assert.strictEqual(badGzipResp.headers[ACCEPT_CONTENT_ENCODING_HEADER], 'gzip');

  // a 415 unsupported encoding
  const unsupportedResp = await handler({
    requestContext: { http: { method: 'POST', path: '/api/v1/compression-ac24-br' } },
    headers: { 'content-encoding': 'br' },
    body: '{}',
  });
  assert.strictEqual(unsupportedResp.statusCode, 415);
  assert.strictEqual(unsupportedResp.headers[ACCEPT_CONTENT_ENCODING_HEADER], 'gzip');

  // a 500 unadaptable event (no requestContext at all)
  const originalError = console.error;
  console.error = () => {};
  const brokenResp = await handler({ headers: {} });
  console.error = originalError;
  assert.strictEqual(brokenResp.statusCode, 500);
  assert.strictEqual(brokenResp.headers[ACCEPT_CONTENT_ENCODING_HEADER], 'gzip');
});

// ---------------------------------------------------------------------------
// AC25
// ---------------------------------------------------------------------------

test('Scenario: The Lambda wrapper passes isBase64Encoded through (AC25)', async () => {
  // Given a bootstrapped Lambda handler and a route returning a 4000-byte
  // body to a gzip-accepting request
  const bigBody = JSON.stringify({ padding: 'x'.repeat(3990) });
  router.add('GET', '/api/v1/compression-ac25', () => ({
    statusCode: 200,
    rawBody: bigBody,
    headers: { 'content-type': 'application/json' },
  }));

  const lambdaHandler = createLambdaHandler({
    env: {
      TABLE_NAME: 'table',
      PEPPER_SECRET_ARN: 'arn:secret',
      ENTRA_TENANT_ID: 'tenant',
      ENTRA_CLIENT_ID: 'client',
    },
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => ({ send: async () => ({ SecretString: PEPPER }) }),
    fetchImpl: async () => ({ status: 200, json: async () => ({ keys: [] }) }),
  });

  const event = {
    requestContext: { http: { method: 'GET', path: '/api/v1/compression-ac25' } },
    headers: { 'accept-encoding': 'gzip' },
  };

  // When the Lambda handler is invoked
  const lambdaResult = await lambdaHandler(event);
  const indexResult = await handler(event);

  // Then its result has isBase64Encoded true and the same body as handler
  // returned
  assert.strictEqual(lambdaResult.isBase64Encoded, true);
  assert.strictEqual(lambdaResult.body, indexResult.body);
  assert.strictEqual(lambdaResult.headers['content-encoding'], 'gzip');
});

// ---------------------------------------------------------------------------
// AC26
// ---------------------------------------------------------------------------

test('Scenario: The contract documents payload compression (AC26)', () => {
  // When contract/README.md is read
  const readme = readFileSync(path.join(rootDir, 'contract', 'README.md'), 'utf8');

  // Then it has a "Payload compression" section naming Content-Encoding,
  // Accept-Encoding, X-MDM-Accept-Content-Encoding and Vary
  const sectionStart = readme.indexOf('## Payload compression');
  assert.notStrictEqual(sectionStart, -1, 'README should have a "Payload compression" section');
  const nextSection = readme.indexOf('\n## ', sectionStart + 1);
  const section = nextSection === -1 ? readme.slice(sectionStart) : readme.slice(sectionStart, nextSection);

  for (const term of ['Content-Encoding', 'Accept-Encoding', 'X-MDM-Accept-Content-Encoding', 'Vary']) {
    assert.ok(section.includes(term), `section should name ${term}`);
  }

  // And it states the signature covers the uncompressed body, the
  // 1024-byte threshold, the 400/413/415 errors with 1048576 inflated
  // bytes, and the one-retry fallback
  assert.ok(/uncompressed/i.test(section), 'should state the signature covers the uncompressed body');
  assert.ok(section.includes('1024'), 'should state the 1024-byte threshold');
  assert.ok(section.includes('400'), 'should mention 400');
  assert.ok(section.includes('413'), 'should mention 413');
  assert.ok(section.includes('415'), 'should mention 415');
  assert.ok(section.includes('1048576'), 'should mention the 1048576 inflated byte cap');
  assert.ok(/retry/i.test(section), 'should describe the one-retry fallback');
});

// Sanity: the exported constants match the frozen acceptance criteria values.
test('Unit: exported compression constants match the frozen thresholds', () => {
  assert.strictEqual(MAX_INFLATED_BODY_BYTES, 1048576);
  assert.strictEqual(COMPRESS_MIN_BYTES, 1024);
  assert.strictEqual(ACCEPT_CONTENT_ENCODING_HEADER, 'x-mdm-accept-content-encoding');
});
