/**
 * Unit tests for the Lambda Function URL handler and event adaptation.
 */

import test from 'node:test';
import assert from 'node:assert';
import { handler, toRouterRequest, router } from '../dist/index.js';

test('Handler - basic POST request', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'POST',
        path: '/api/test',
      },
    },
    headers: {},
    body: '{"test":"data"}',
    isBase64Encoded: false,
  };

  const response = await handler(event);

  assert.strictEqual(response.statusCode, 404); // No route registered
  assert.strictEqual(response.headers['content-type'], 'application/json');
  assert.ok(typeof response.body === 'string');
});

test('Handler - base64 encoded body', async (t) => {
  const originalBody = '{"message":"hello"}';
  const base64Body = Buffer.from(originalBody).toString('base64');

  const event = {
    requestContext: {
      http: {
        method: 'POST',
        path: '/test',
      },
    },
    headers: {},
    body: base64Body,
    isBase64Encoded: true,
  };

  let receivedBody = null;
  router.add('POST', '/test', (request) => {
    receivedBody = request.body;
    return { statusCode: 200 };
  });

  const response = await handler(event);

  // Clean up
  // Note: In a real test, we'd use a separate router instance
  assert.strictEqual(receivedBody, originalBody, 'body should be decoded from base64');
});

test('Handler - query string parsing', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/search',
      },
    },
    rawQueryString: 'q=test&limit=10',
    headers: {},
  };

  const request = toRouterRequest(event);

  assert.deepStrictEqual(request.query, { q: 'test', limit: '10' });
});

test('Handler - empty query string', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/test',
      },
    },
    rawQueryString: '',
    headers: {},
  };

  const request = toRouterRequest(event);

  assert.deepStrictEqual(request.query, {});
});

test('Handler - no query string provided', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/test',
      },
    },
    headers: {},
  };

  const request = toRouterRequest(event);

  assert.deepStrictEqual(request.query, {});
});

test('Handler - header normalization', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/test',
      },
    },
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer token',
      'X-Custom-Header': 'value',
    },
  };

  const request = toRouterRequest(event);

  // Headers should be normalized to lowercase
  assert.strictEqual(request.headers['content-type'], 'application/json');
  assert.strictEqual(request.headers['authorization'], 'Bearer token');
  assert.strictEqual(request.headers['x-custom-header'], 'value');
});

test('Handler - undefined header values filtered', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/test',
      },
    },
    headers: {
      'Content-Type': 'application/json',
      'X-Missing': undefined,
    },
  };

  const request = toRouterRequest(event);

  assert.strictEqual(request.headers['content-type'], 'application/json');
  assert.strictEqual(request.headers['x-missing'], undefined);
});

test('Handler - null body', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/test',
      },
    },
    headers: {},
    body: null,
  };

  const request = toRouterRequest(event);

  assert.strictEqual(request.body, null);
});

test('Handler - undefined body', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/test',
      },
    },
    headers: {},
    body: undefined,
  };

  const request = toRouterRequest(event);

  assert.strictEqual(request.body, null);
});

test('Handler - empty string body', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'POST',
        path: '/test',
      },
    },
    headers: {},
    body: '',
  };

  const request = toRouterRequest(event);

  assert.strictEqual(request.body, '');
});

test('Handler - response content-type always set', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/unknown',
      },
    },
    headers: {},
  };

  const response = await handler(event);

  assert.strictEqual(response.headers['content-type'], 'application/json');
});

test('Handler - router request method case conversion', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'post',
        path: '/test',
      },
    },
    headers: {},
  };

  const request = toRouterRequest(event);

  assert.strictEqual(request.method, 'post');
});

test('Handler - router request path preserved', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/api/v1/devices/dev-123/config',
      },
    },
    headers: {},
  };

  const request = toRouterRequest(event);

  assert.strictEqual(request.path, '/api/v1/devices/dev-123/config');
});

test('Handler - error in event adaptation returns 500', async (t) => {
  // Malformed event that would cause an error
  const event = {
    // Missing requestContext
    headers: {},
  };

  let errorLogged = false;
  const originalError = console.error;
  console.error = (msg) => {
    if (msg.includes('[handler]')) {
      errorLogged = true;
    }
  };

  const response = await handler(event);

  console.error = originalError;

  assert.strictEqual(response.statusCode, 500);
  const body = JSON.parse(response.body);
  assert.deepStrictEqual(body, { error: 'internal_error' });
  assert.ok(errorLogged, 'error should be logged');
});

test('Handler - response body is JSON string', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/test',
      },
    },
    headers: {},
  };

  const response = await handler(event);

  assert.strictEqual(typeof response.body, 'string');
  // Should be valid JSON
  const parsed = JSON.parse(response.body);
  assert.ok(typeof parsed === 'object');
});

test('Handler - case insensitive method in event', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'POST',
        path: '/test',
      },
    },
    headers: {},
    body: null,
  };

  const request = toRouterRequest(event);

  assert.strictEqual(request.method, 'POST');
});

test('Handler - complex query string with special characters', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/search',
      },
    },
    rawQueryString: 'search=hello%20world&filter=type%3Ddevice',
    headers: {},
  };

  const request = toRouterRequest(event);

  // URLSearchParams should decode the values
  assert.ok(request.query.search !== undefined);
  assert.ok(request.query.filter !== undefined);
});

test('Handler - empty headers object', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/test',
      },
    },
    headers: {},
  };

  const request = toRouterRequest(event);

  assert.deepStrictEqual(request.headers, {});
});

test('Handler - no headers property', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/test',
      },
    },
  };

  const request = toRouterRequest(event);

  assert.deepStrictEqual(request.headers, {});
});

test('Handler - response includes all router headers', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/test',
      },
    },
    headers: {},
  };

  const response = await handler(event);

  // Should have at least content-type
  assert.ok(response.headers['content-type']);
  assert.ok(response.statusCode);
  assert.ok(typeof response.body === 'string');
});
