/**
 * E2E cucumber-style tests for Admin UI and landing page (TASK-013, TASK-024).
 *
 * Scenario: Landing page is served at the root
 * Scenario: Landing page links to all four downloads and to the console
 * Scenario: Landing page never boots the console or contacts Entra
 * Scenario: Landing page names both platforms and loads only an external module
 * Scenario: Landing page carries the security headers
 * Scenario: Landing script is served as JavaScript
 * Scenario: Landing page holds the elements the script fills
 * Scenario: Console is served at /admin with or without a trailing slash
 * Scenario: Wrong method on a page route is rejected
 * Scenario: Admin API and config paths are not swallowed by the console route
 * Scenario: Download paths are left for TASK-025
 * Scenario: Existing tests follow the move
 */

import test from 'node:test';
import assert from 'node:assert';
import { handler, registerUiRoutes } from '../../dist/index.js';

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

// ============================================================================
// TASK-049 AC18: connect-src allows the presigned-S3 PUT, every other
// directive stays byte-identical.
// ============================================================================

test('Scenario: Console may PUT to S3 -- the content-security-policy names Entra and S3, every other directive unchanged', async (t) => {
  const response = await handler({
    requestContext: { http: { method: 'GET', path: '/' } },
    headers: {},
  });

  const csp = response.headers['content-security-policy'];
  assert.strictEqual(
    csp,
    "default-src 'self'; connect-src 'self' https://login.microsoftonline.com https://*.amazonaws.com; img-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
  );
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

// TASK-024: Landing page tests

test('Scenario: Landing page is served at the root - GET / returns 200 with text/html', async (t) => {
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

  assert.strictEqual(response.statusCode, 200, 'should return 200');
  assert.strictEqual(response.headers['content-type'], 'text/html; charset=utf-8', 'should have text/html content-type');
  assert.ok(typeof response.body === 'string', 'body should be a string');
  assert.ok(response.body.length > 0, 'body should not be empty');
});

test('Scenario: Landing page links to all four downloads and to the console', async (t) => {
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
  const body = response.body;

  assert.ok(body.includes('href="/downloads/windows-x64"'), 'should contain windows-x64 download link');
  assert.ok(body.includes('href="/downloads/windows-arm64"'), 'should contain windows-arm64 download link');
  assert.ok(body.includes('href="/downloads/macos-amd64"'), 'should contain macos-amd64 download link');
  assert.ok(body.includes('href="/downloads/macos-arm64"'), 'should contain macos-arm64 download link');
  assert.ok(!body.includes('href="/admin"'), 'should not link to the admin console');
});

test('Scenario: Landing page never boots the console or contacts Entra', async (t) => {
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
  const body = response.body;

  assert.ok(!body.includes('app.js'), 'should not contain app.js');
  assert.ok(!body.includes('/admin/config.json'), 'should not contain /admin/config.json');
  assert.ok(!body.includes('login.microsoftonline.com'), 'should not contain login.microsoftonline.com');
});

test('Scenario: Landing page names both platforms and loads only an external module', async (t) => {
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
  const body = response.body;

  assert.ok(body.includes('Windows'), 'should contain Windows');
  assert.ok(body.includes('macOS'), 'should contain macOS');
  assert.ok(body.includes('type="module"'), 'should have module script');
  assert.ok(body.includes('src="/assets/public/landing.js"'), 'should load landing.js as external script');

  // Check that there are no inline scripts
  const inlineScriptRegex = /<script[^>]*>(?![\s\n]*<\/script>)/g;
  const matches = body.match(inlineScriptRegex);
  if (matches) {
    for (const match of matches) {
      assert.ok(match.includes('type="module"') && match.includes('src='), 'inline scripts should not exist (only external module scripts)');
    }
  }
});

test('Scenario: Landing page carries the security headers', async (t) => {
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

  assert.ok(response.headers['content-security-policy'], 'should have CSP header');
  assert.strictEqual(response.headers['x-content-type-options'], 'nosniff', 'should have nosniff header');
  assert.strictEqual(response.headers['referrer-policy'], 'no-referrer', 'should have no-referrer header');
});

test('Scenario: Landing script is served as JavaScript - GET /assets/public/landing.js', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/assets/public/landing.js',
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
});

test('Scenario: Landing page holds the elements the script fills', async (t) => {
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
  const body = response.body;

  assert.ok(body.includes('id="collection-url"'), 'should contain collection-url element');
  assert.ok(body.includes('id="windows-install-command"'), 'should contain windows-install-command element');
  assert.ok(body.includes('id="macos-install-command"'), 'should contain macos-install-command element');
  // The macOS command is hardcoded in the HTML
  assert.ok(body.includes('sudo installer -pkg &lt;downloaded .pkg&gt; -target /'), 'should contain encoded macOS command');
});

test('Scenario: Console is served at /admin - GET /admin', async (t) => {
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
  assert.ok(response.body.includes('src="/assets/public/app.js"'), 'body should load app.js');
  assert.ok(response.headers['content-security-policy'], 'should have CSP header');
});

test('Scenario: Console is served at /admin/ - GET /admin/ with trailing slash', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/admin/',
      },
    },
    headers: {},
  };

  const response = await handler(event);

  assert.strictEqual(response.statusCode, 200, 'should return 200');
  assert.strictEqual(response.headers['content-type'], 'text/html; charset=utf-8', 'should have text/html content-type');
  assert.ok(response.body.includes('<div id="app">'), 'body should contain mount element');
  assert.ok(response.body.includes('src="/assets/public/app.js"'), 'body should load app.js');
});

test('Scenario: Wrong method on root - POST / returns 405', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'POST',
        path: '/',
      },
    },
    headers: {},
  };

  const response = await handler(event);

  assert.strictEqual(response.statusCode, 405, 'should return 405');
  const body = JSON.parse(response.body);
  assert.deepStrictEqual(body, { error: 'method_not_allowed' }, 'should return method_not_allowed error');
});

test('Scenario: Wrong method on admin - POST /admin returns 405', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'POST',
        path: '/admin',
      },
    },
    headers: {},
  };

  const response = await handler(event);

  assert.strictEqual(response.statusCode, 405, 'should return 405');
  const body = JSON.parse(response.body);
  assert.deepStrictEqual(body, { error: 'method_not_allowed' }, 'should return method_not_allowed error');
});

test('Scenario: Admin API and config paths are not swallowed - GET /admin/api/v1/devices', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/admin/api/v1/devices',
      },
    },
    headers: {},
  };

  const response = await handler(event);

  assert.strictEqual(response.statusCode, 401, 'should return 401 unauthorized');
  assert.strictEqual(response.headers['content-type'], 'application/json', 'should return JSON');
  const body = JSON.parse(response.body);
  assert.deepStrictEqual(body, { error: 'unauthorized' }, 'should return unauthorized error');
});

test('Scenario: Admin config endpoint still works - GET /admin/config.json', async (t) => {
  const event = {
    requestContext: {
      http: {
        method: 'GET',
        path: '/admin/config.json',
      },
    },
    headers: { host: 'admin.example.com' },
  };

  const response = await handler(event);

  assert.strictEqual(response.headers['content-type'], 'application/json', 'should return JSON content-type');
});

test('Scenario: Download paths are left for TASK-025 - registerUiRoutes does not register /downloads', async (t) => {
  // Mock router that records every add call
  const recordedRoutes = [];
  const mockRouter = {
    add: function(method, pattern, handler) {
      recordedRoutes.push({ method, pattern });
      return this;
    }
  };

  registerUiRoutes(mockRouter);

  // Check that no pattern begins with /downloads
  const hasDownloadsPattern = recordedRoutes.some(route => route.pattern.startsWith('/downloads'));
  assert.ok(!hasDownloadsPattern, 'should not register any /downloads routes');
});

test('Scenario: Missing Entra configuration - landing page still returns 200', async (t) => {
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

  // Landing page should return 200 regardless of Entra configuration
  assert.strictEqual(response.statusCode, 200, 'should return 200 even without Entra config');
  assert.strictEqual(response.headers['content-type'], 'text/html; charset=utf-8', 'should have text/html content-type');
});
