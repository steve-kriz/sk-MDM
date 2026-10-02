/**
 * Unit tests for the HTTP router.
 */

import test from 'node:test';
import assert from 'node:assert';
import { createRouter } from '../dist/index.js';

test('Router - basic route matching', async (t) => {
  const router = createRouter();
  let called = false;

  router.add('GET', '/hello', () => {
    called = true;
    return { statusCode: 200, body: { message: 'hello' } };
  });

  const response = await router.handle({
    method: 'GET',
    path: '/hello',
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(called, true, 'handler should be called');
  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.deepStrictEqual(body, { message: 'hello' });
});

test('Router - parameter extraction', async (t) => {
  const router = createRouter();
  let capturedParams = null;

  router.add('GET', '/users/{userId}', (request) => {
    capturedParams = request.params;
    return { statusCode: 200 };
  });

  await router.handle({
    method: 'GET',
    path: '/users/123',
    query: {},
    headers: {},
    body: null,
  });

  assert.deepStrictEqual(capturedParams, { userId: '123' });
});

test('Router - multiple parameters', async (t) => {
  const router = createRouter();
  let capturedParams = null;

  router.add('GET', '/users/{userId}/posts/{postId}', (request) => {
    capturedParams = request.params;
    return { statusCode: 200 };
  });

  await router.handle({
    method: 'GET',
    path: '/users/john/posts/42',
    query: {},
    headers: {},
    body: null,
  });

  assert.deepStrictEqual(capturedParams, { userId: 'john', postId: '42' });
});

test('Router - URI component decoding', async (t) => {
  const router = createRouter();
  let capturedParams = null;

  router.add('GET', '/search/{query}', (request) => {
    capturedParams = request.params;
    return { statusCode: 200 };
  });

  await router.handle({
    method: 'GET',
    path: '/search/hello%20world',
    query: {},
    headers: {},
    body: null,
  });

  assert.deepStrictEqual(capturedParams, { query: 'hello world' });
});

test('Router - 404 for unknown path', async (t) => {
  const router = createRouter();

  const response = await router.handle({
    method: 'GET',
    path: '/notfound',
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(response.statusCode, 404);
  const body = JSON.parse(response.body);
  assert.deepStrictEqual(body, { error: 'not_found' });
});

test('Router - 405 for wrong method', async (t) => {
  const router = createRouter();

  router.add('POST', '/api/data', () => ({ statusCode: 201 }));

  const response = await router.handle({
    method: 'GET',
    path: '/api/data',
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(response.statusCode, 405);
  const body = JSON.parse(response.body);
  assert.deepStrictEqual(body, { error: 'method_not_allowed' });
});

test('Router - multiple methods on same path', async (t) => {
  const router = createRouter();

  router.add('GET', '/resource', () => ({ statusCode: 200, body: { method: 'GET' } }));
  router.add('POST', '/resource', () => ({ statusCode: 201, body: { method: 'POST' } }));
  router.add('DELETE', '/resource', () => ({ statusCode: 204 }));

  const getResponse = await router.handle({
    method: 'GET',
    path: '/resource',
    query: {},
    headers: {},
    body: null,
  });

  const postResponse = await router.handle({
    method: 'POST',
    path: '/resource',
    query: {},
    headers: {},
    body: null,
  });

  const deleteResponse = await router.handle({
    method: 'DELETE',
    path: '/resource',
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(getResponse.statusCode, 200);
  assert.strictEqual(postResponse.statusCode, 201);
  assert.strictEqual(deleteResponse.statusCode, 204);
});

test('Router - case insensitive method matching', async (t) => {
  const router = createRouter();

  router.add('GET', '/test', () => ({ statusCode: 200 }));

  const response = await router.handle({
    method: 'get',
    path: '/test',
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(response.statusCode, 200);
});

test('Router - handler throws error', async (t) => {
  const router = createRouter();
  let loggedMessage = null;
  const originalError = console.error;
  console.error = (msg) => {
    loggedMessage = msg;
  };

  router.add('GET', '/error', () => {
    throw new Error('test error');
  });

  const response = await router.handle({
    method: 'GET',
    path: '/error',
    query: {},
    headers: {},
    body: null,
  });

  console.error = originalError;

  assert.strictEqual(response.statusCode, 500);
  const body = JSON.parse(response.body);
  assert.deepStrictEqual(body, { error: 'internal_error' });
  assert.ok(loggedMessage.includes('[router]'), 'should log [router] prefix');
  assert.ok(loggedMessage.includes('GET /error failed'), 'should log method and path');
  assert.ok(loggedMessage.includes('test error'), 'should log error message');
  assert.ok(!response.body.includes('test error'), 'response should not contain error details');
});

test('Router - async handler', async (t) => {
  const router = createRouter();

  router.add('GET', '/async', async () => {
    // Simulate async operation
    await new Promise((resolve) => setTimeout(resolve, 10));
    return { statusCode: 200, body: { async: true } };
  });

  const response = await router.handle({
    method: 'GET',
    path: '/async',
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(response.statusCode, 200);
  const body = JSON.parse(response.body);
  assert.deepStrictEqual(body, { async: true });
});

test('Router - response includes content-type header', async (t) => {
  const router = createRouter();

  router.add('GET', '/test', () => ({ statusCode: 200, body: { foo: 'bar' } }));

  const response = await router.handle({
    method: 'GET',
    path: '/test',
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(response.headers['content-type'], 'application/json');
});

test('Router - custom headers in handler response', async (t) => {
  const router = createRouter();

  router.add('GET', '/custom-headers', () => ({
    statusCode: 200,
    headers: { 'x-custom': 'value' },
    body: {},
  }));

  const response = await router.handle({
    method: 'GET',
    path: '/custom-headers',
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(response.headers['content-type'], 'application/json');
  assert.strictEqual(response.headers['x-custom'], 'value');
});

test('Router - request body passed to handler', async (t) => {
  const router = createRouter();
  let capturedBody = null;

  router.add('POST', '/echo', (request) => {
    capturedBody = request.body;
    return { statusCode: 200 };
  });

  await router.handle({
    method: 'POST',
    path: '/echo',
    query: {},
    headers: {},
    body: '{"test":"data"}',
  });

  assert.strictEqual(capturedBody, '{"test":"data"}');
});

test('Router - request query passed to handler', async (t) => {
  const router = createRouter();
  let capturedQuery = null;

  router.add('GET', '/search', (request) => {
    capturedQuery = request.query;
    return { statusCode: 200 };
  });

  await router.handle({
    method: 'GET',
    path: '/search',
    query: { q: 'test', limit: '10' },
    headers: {},
    body: null,
  });

  assert.deepStrictEqual(capturedQuery, { q: 'test', limit: '10' });
});

test('Router - fluent chaining', async (t) => {
  const router = createRouter();

  const result = router
    .add('GET', '/a', () => ({ statusCode: 200 }))
    .add('GET', '/b', () => ({ statusCode: 200 }))
    .add('GET', '/c', () => ({ statusCode: 200 }));

  assert.strictEqual(result, router, 'add should return router for chaining');

  const responseA = await router.handle({
    method: 'GET',
    path: '/a',
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(responseA.statusCode, 200);
});

test('Router - trailing slash handling', async (t) => {
  const router = createRouter();

  router.add('GET', '/api/users', () => ({ statusCode: 200 }));

  // Path with trailing slash should match because empty segments are filtered
  const response = await router.handle({
    method: 'GET',
    path: '/api/users/',
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(response.statusCode, 200);
});

test('Router - empty path segments ignored', async (t) => {
  const router = createRouter();

  router.add('GET', '/api/users', () => ({ statusCode: 200 }));

  // Consecutive slashes result in empty segments that should be filtered
  const response = await router.handle({
    method: 'GET',
    path: '/api/users',
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(response.statusCode, 200);
});

test('Router - request headers passed to handler', async (t) => {
  const router = createRouter();
  let capturedHeaders = null;

  router.add('GET', '/headers', (request) => {
    capturedHeaders = request.headers;
    return { statusCode: 200 };
  });

  await router.handle({
    method: 'GET',
    path: '/headers',
    query: {},
    headers: { authorization: 'Bearer token', 'user-agent': 'test' },
    body: null,
  });

  assert.deepStrictEqual(capturedHeaders, { authorization: 'Bearer token', 'user-agent': 'test' });
});

// ============================================================================
// rawBody tests (TASK-013)
// ============================================================================

test('Router - rawBody is passed through unserialised', async (t) => {
  const router = createRouter();

  router.add('GET', '/html', () => ({
    statusCode: 200,
    headers: { 'content-type': 'text/html' },
    rawBody: '<html><body>hello</body></html>',
  }));

  const response = await router.handle({
    method: 'GET',
    path: '/html',
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(response.statusCode, 200);
  assert.strictEqual(response.body, '<html><body>hello</body></html>');
  assert.strictEqual(response.headers['content-type'], 'text/html');
  assert.strictEqual(response.headers['content-type'] === 'application/json', false);
});

test('Router - rawBody wins when both body and rawBody are present', async (t) => {
  const router = createRouter();

  router.add('GET', '/test', () => ({
    statusCode: 200,
    headers: { 'content-type': 'text/plain' },
    body: { ignored: true },
    rawBody: 'raw text',
  }));

  const response = await router.handle({
    method: 'GET',
    path: '/test',
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(response.body, 'raw text');
  assert.strictEqual(response.headers['content-type'], 'text/plain');
});

test('Router - rawBody with no headers uses empty header set', async (t) => {
  const router = createRouter();

  router.add('GET', '/test', () => ({
    statusCode: 200,
    rawBody: '<div>test</div>',
  }));

  const response = await router.handle({
    method: 'GET',
    path: '/test',
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(response.body, '<div>test</div>');
  assert.strictEqual(response.headers['content-type'], undefined);
});

test('Router - JSON body unaffected when rawBody is absent', async (t) => {
  const router = createRouter();

  router.add('GET', '/json', () => ({
    statusCode: 200,
    body: { ok: true },
  }));

  const response = await router.handle({
    method: 'GET',
    path: '/json',
    query: {},
    headers: {},
    body: null,
  });

  const parsed = JSON.parse(response.body);
  assert.deepStrictEqual(parsed, { ok: true });
  assert.strictEqual(response.headers['content-type'], 'application/json');
});

test('Router - 404 still returns JSON', async (t) => {
  const router = createRouter();

  const response = await router.handle({
    method: 'GET',
    path: '/notfound',
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(response.statusCode, 404);
  const parsed = JSON.parse(response.body);
  assert.deepStrictEqual(parsed, { error: 'not_found' });
  assert.strictEqual(response.headers['content-type'], 'application/json');
});

test('Router - 405 still returns JSON', async (t) => {
  const router = createRouter();

  router.add('POST', '/test', () => ({ statusCode: 201 }));

  const response = await router.handle({
    method: 'GET',
    path: '/test',
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(response.statusCode, 405);
  const parsed = JSON.parse(response.body);
  assert.deepStrictEqual(parsed, { error: 'method_not_allowed' });
  assert.strictEqual(response.headers['content-type'], 'application/json');
});

test('Router - 500 on thrown handler still returns JSON', async (t) => {
  const router = createRouter();
  const originalError = console.error;
  console.error = () => {};

  router.add('GET', '/throw', () => {
    throw new Error('test error');
  });

  const response = await router.handle({
    method: 'GET',
    path: '/throw',
    query: {},
    headers: {},
    body: null,
  });

  console.error = originalError;

  assert.strictEqual(response.statusCode, 500);
  const parsed = JSON.parse(response.body);
  assert.deepStrictEqual(parsed, { error: 'internal_error' });
  assert.strictEqual(response.headers['content-type'], 'application/json');
});

test('Router - rawBody respects custom headers', async (t) => {
  const router = createRouter();

  router.add('GET', '/css', () => ({
    statusCode: 200,
    headers: {
      'content-type': 'text/css; charset=utf-8',
      'x-custom-header': 'value',
    },
    rawBody: 'body { color: blue; }',
  }));

  const response = await router.handle({
    method: 'GET',
    path: '/css',
    query: {},
    headers: {},
    body: null,
  });

  assert.strictEqual(response.body, 'body { color: blue; }');
  assert.strictEqual(response.headers['content-type'], 'text/css; charset=utf-8');
  assert.strictEqual(response.headers['x-custom-header'], 'value');
});
