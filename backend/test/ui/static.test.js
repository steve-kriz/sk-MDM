/**
 * E2E cucumber-style tests for Admin UI static assets (TASK-013).
 *
 * Scenario: Console page is served at /admin
 * Scenario: Assets are served with their own media types
 * Scenario: Unknown asset is not served
 * Scenario: Security headers are present
 */

import test from 'node:test';
import assert from 'node:assert';
import { handler } from '../../dist/index.js';

test('Scenario: Console page is served - GET /admin returns 200 with text/html and <div id="app">', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/admin',
      },
    },
    headers: {},
  };

  const response = await handler(event);

  assert.strictEqual(response.statusCode, 200, 'should return 200');
  assert.strictEqual(response.headers['content-type'], 'text/html; charset=utf-8', 'should have text/html content-type');
  assert.ok(response.body.includes('<div id="app">'), 'body should contain mount element');
});

test('Scenario: Assets are served - GET /assets/app.js returns 200 with application/javascript', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/assets/app.js',
      },
    },
    headers: {},
  };

  const response = await handler(event);

  assert.strictEqual(response.statusCode, 200, 'should return 200');
  assert.strictEqual(
    response.headers['content-type'],
    'application/javascript; charset=utf-8',
    'should have application/javascript content-type'
  );
  assert.ok(typeof response.body === 'string', 'body should be a string');
  assert.ok(response.body.length > 0, 'body should not be empty');
});

test('Scenario: Assets are served - GET /assets/styles.css returns 200 with text/css', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/assets/styles.css',
      },
    },
    headers: {},
  };

  const response = await handler(event);

  assert.strictEqual(response.statusCode, 200, 'should return 200');
  assert.strictEqual(response.headers['content-type'], 'text/css; charset=utf-8', 'should have text/css content-type');
  assert.ok(typeof response.body === 'string', 'body should be a string');
  assert.ok(response.body.length > 0, 'body should not be empty');
});

test('Scenario: Unknown asset is not served - GET /assets/nope.js returns 404', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/assets/nope.js',
      },
    },
    headers: {},
  };

  const response = await handler(event);

  assert.strictEqual(response.statusCode, 404, 'should return 404');
  assert.strictEqual(response.headers['content-type'], 'application/json', 'should have application/json content-type');
  const body = JSON.parse(response.body);
  assert.deepStrictEqual(body, { error: 'not_found' }, 'should return not_found error');
});

test('Scenario: Security headers are present - CSP contains default-src', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/',
      },
    },
    headers: {},
  };

  const response = await handler(event);

  const csp = response.headers['content-security-policy'];
  assert.ok(csp, 'should have content-security-policy header');
  assert.ok(csp.includes("default-src 'self'"), "CSP should contain default-src 'self'");
});

test('Scenario: Security headers are present - x-content-type-options is nosniff', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/',
      },
    },
    headers: {},
  };

  const response = await handler(event);

  assert.strictEqual(
    response.headers['x-content-type-options'],
    'nosniff',
    'should have x-content-type-options: nosniff'
  );
});

test('Scenario: Security headers are present - referrer-policy is no-referrer', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/',
      },
    },
    headers: {},
  };

  const response = await handler(event);

  assert.strictEqual(
    response.headers['referrer-policy'],
    'no-referrer',
    'should have referrer-policy: no-referrer'
  );
});

test('Scenario: HTML responses carry security headers - /assets/app.js', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/assets/app.js',
      },
    },
    headers: {},
  };

  const response = await handler(event);

  assert.ok(response.headers['content-security-policy'], 'should have CSP header');
  assert.ok(response.headers['x-content-type-options'], 'should have x-content-type-options header');
  assert.ok(response.headers['referrer-policy'], 'should have referrer-policy header');
});

test('Scenario: Asset path traversal is blocked - GET /assets/../config.json', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/assets/../config.json',
      },
    },
    headers: {},
  };

  const response = await handler(event);

  assert.strictEqual(response.statusCode, 404, 'should return 404 for path traversal');
});
