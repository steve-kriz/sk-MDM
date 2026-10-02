/**
 * Unit + e2e (Given/When/Then) tests for TASK-027's Microsoft Graph client
 * (`backend/src/graph/client.ts`).
 *
 * Every test injects a fake `fetch` and a fake clock; nothing here opens a
 * real network connection, and the secrets client (when used) is a plain
 * in-memory fake, never a real AWS SDK client.
 *
 * Covers AC1-AC9.
 */

import test from 'node:test';
import assert from 'node:assert';
import {
  createGraphClient,
  createGraphSecretProvider,
  createGraphDirectoryFromEnv,
  isGraphFailure,
  tokenUrl,
  odataString,
  GRAPH_BASE_URL,
  GRAPH_SCOPE,
  DEFAULT_GRAPH_SECRET_KEY,
} from '../../dist/graph/client.js';

// ============================================================================
// Helpers
// ============================================================================

function jsonResponse(status, body) {
  return { status, text: async () => JSON.stringify(body) };
}

function tokenOk(token = 'TOKEN-SENTINEL', expiresIn = 3600) {
  return jsonResponse(200, { access_token: token, expires_in: expiresIn });
}

/** A recording fake fetch; `handler(url, init, calls)` decides the response. */
function makeFetch(handler) {
  const calls = [];
  const fetchFn = async (url, init) => {
    calls.push({ url, init });
    return handler(url, init, calls);
  };
  fetchFn.calls = calls;
  return fetchFn;
}

async function rejectsWith(promise, expected) {
  let caught;
  try {
    await promise;
  } catch (error) {
    caught = error;
  }
  assert.ok(caught !== undefined, 'expected the promise to reject');
  assert.deepStrictEqual(caught, expected);
}

// ============================================================================
// AC1: Client-credentials token request and bearer header
// ============================================================================

test('AC1: token request is POSTed and the Graph GET carries the bearer header', async () => {
  const fetchFn = makeFetch((url) => {
    if (url === tokenUrl('t-1')) {
      return tokenOk();
    }
    return jsonResponse(200, { value: [] });
  });
  const graph = createGraphClient({
    tenantId: 't-1',
    clientId: 'c-1',
    clientSecret: 'S3CRET-SENTINEL',
    fetch: fetchFn,
    now: () => 1790000000,
  });

  await graph.findDevicesByDisplayName('LAT-7440');

  const tokenCall = fetchFn.calls.find((c) => c.url === 'https://login.microsoftonline.com/t-1/oauth2/v2.0/token');
  assert.ok(tokenCall, 'a POST should have been sent to the token endpoint');
  assert.strictEqual(tokenCall.init.method, 'POST');
  const params = new URLSearchParams(tokenCall.init.body);
  assert.strictEqual(params.get('grant_type'), 'client_credentials');
  assert.strictEqual(params.get('client_id'), 'c-1');
  assert.strictEqual(params.get('client_secret'), 'S3CRET-SENTINEL');
  assert.strictEqual(params.get('scope'), GRAPH_SCOPE);

  const graphCall = fetchFn.calls.find((c) => c.url.startsWith(GRAPH_BASE_URL));
  assert.ok(graphCall, 'a Graph GET should have been sent');
  assert.strictEqual(graphCall.init.headers.authorization, 'Bearer TOKEN-SENTINEL');
});

test('Unit: clientSecret may be an async function provider', async () => {
  const fetchFn = makeFetch((url) => (url === tokenUrl('t-1') ? tokenOk() : jsonResponse(200, { value: [] })));
  const graph = createGraphClient({
    tenantId: 't-1',
    clientId: 'c-1',
    clientSecret: async () => 'FROM-PROVIDER',
    fetch: fetchFn,
    now: () => 1000,
  });
  await graph.findDevicesByDisplayName('a');
  const tokenCall = fetchFn.calls.find((c) => c.url === tokenUrl('t-1'));
  const params = new URLSearchParams(tokenCall.init.body);
  assert.strictEqual(params.get('client_secret'), 'FROM-PROVIDER');
});

// ============================================================================
// AC2: Token reuse and renewal
// ============================================================================

test('AC2: token reused inside its lifetime and renewed after', async () => {
  let epoch = 1790000000;
  const fetchFn = makeFetch((url) => (url === tokenUrl('t-1') ? tokenOk() : jsonResponse(200, { value: [] })));
  const graph = createGraphClient({
    tenantId: 't-1',
    clientId: 'c-1',
    clientSecret: 's',
    fetch: fetchFn,
    now: () => epoch,
  });

  epoch = 1790000000;
  await graph.findDevicesByDisplayName('a');
  epoch = 1790003539;
  await graph.findDevicesByDisplayName('a');
  assert.strictEqual(fetchFn.calls.filter((c) => c.url === tokenUrl('t-1')).length, 1);

  epoch = 1790003540;
  await graph.findDevicesByDisplayName('a');
  assert.strictEqual(fetchFn.calls.filter((c) => c.url === tokenUrl('t-1')).length, 2);
});

test('AC2 (failure): a failed token request is not cached', async () => {
  let tokenCalls = 0;
  const fetchFn = makeFetch((url) => {
    if (url === tokenUrl('t-1')) {
      tokenCalls += 1;
      return tokenCalls === 1 ? { status: 500, text: async () => 'server error' } : tokenOk('TOKEN-2');
    }
    return jsonResponse(200, { value: [] });
  });
  const graph = createGraphClient({ tenantId: 't-1', clientId: 'c-1', clientSecret: 's', fetch: fetchFn, now: () => 1000 });

  await assert.rejects(() => graph.findDevicesByDisplayName('a'));
  await assert.doesNotReject(() => graph.findDevicesByDisplayName('a'));
  assert.strictEqual(tokenCalls, 2);
});

// ============================================================================
// AC3 (edge): single quotes doubled, query encoded
// ============================================================================

test('AC3: single quotes in the device name are doubled and the query is encoded', async () => {
  let graphUrl;
  const fetchFn = makeFetch((url) => {
    if (url === tokenUrl('t-1')) {
      return tokenOk();
    }
    graphUrl = url;
    return jsonResponse(200, { value: [] });
  });
  const graph = createGraphClient({ tenantId: 't-1', clientId: 'c-1', clientSecret: 's', fetch: fetchFn, now: () => 1000 });

  await graph.findDevicesByDisplayName("O'Brien-PC");

  const parsed = new URL(graphUrl);
  assert.strictEqual(parsed.searchParams.get('$filter'), "displayName eq 'O''Brien-PC'");
  assert.strictEqual(parsed.searchParams.get('$select'), 'id,displayName,accountEnabled');
  assert.ok(!graphUrl.includes(' '), 'the raw URL should contain no unencoded space');
});

test('Unit: odataString doubles every single quote', () => {
  assert.strictEqual(odataString("O'Brien"), "'O''Brien'");
  assert.strictEqual(odataString('plain'), "'plain'");
});

// ============================================================================
// AC4 (edge): non-user registered objects dropped
// ============================================================================

test('AC4: non-user registered objects are dropped', async () => {
  const fetchFn = makeFetch((url) => {
    if (url === tokenUrl('t-1')) {
      return tokenOk();
    }
    if (url.includes('/registeredUsers')) {
      return jsonResponse(200, {
        value: [
          { id: 'u1', displayName: 'User One', userPrincipalName: 'u1@x.com', mail: null, '@odata.type': '#microsoft.graph.user' },
          { id: 'sp1', displayName: 'SP', '@odata.type': '#microsoft.graph.servicePrincipal' },
        ],
      });
    }
    return jsonResponse(200, { value: [] });
  });
  const graph = createGraphClient({ tenantId: 't-1', clientId: 'c-1', clientSecret: 's', fetch: fetchFn, now: () => 1000 });

  const users = await graph.listRegisteredUsers('obj-1');
  assert.strictEqual(users.length, 1);
  assert.strictEqual(users[0].id, 'u1');

  const call = fetchFn.calls.find((c) => c.url.includes('registeredUsers'));
  assert.ok(call.url.startsWith(`${GRAPH_BASE_URL}/devices/obj-1/registeredUsers`));
  assert.strictEqual(new URL(call.url).searchParams.get('$select'), 'id,displayName,userPrincipalName,mail');
});

// ============================================================================
// AC5 (edge): paging stops after 10 pages
// ============================================================================

test('AC5: paging follows nextLink up to ten pages', async () => {
  let page = 0;
  const fetchFn = makeFetch((url) => {
    if (url === tokenUrl('t-1')) {
      return tokenOk();
    }
    page += 1;
    return jsonResponse(200, {
      value: [{ id: `u${page}`, '@odata.type': '#microsoft.graph.user' }],
      '@odata.nextLink': `${GRAPH_BASE_URL}/devices/obj-1/registeredUsers?page=${page + 1}`,
    });
  });
  const graph = createGraphClient({ tenantId: 't-1', clientId: 'c-1', clientSecret: 's', fetch: fetchFn, now: () => 1000 });

  const users = await graph.listRegisteredUsers('obj-1');
  assert.strictEqual(users.length, 10);
  assert.strictEqual(fetchFn.calls.filter((c) => c.url !== tokenUrl('t-1')).length, 10);
});

// ============================================================================
// AC6: Graph and token failures map to fixed errors
// ============================================================================

test('AC6: the token endpoint returns 401 -> graph_auth_failed', async () => {
  const fetchFn = makeFetch((url) => (url === tokenUrl('t-1') ? { status: 401, text: async () => '{}' } : jsonResponse(200, { value: [] })));
  const graph = createGraphClient({ tenantId: 't-1', clientId: 'c-1', clientSecret: 's', fetch: fetchFn, now: () => 1000 });
  await rejectsWith(graph.findDevicesByDisplayName('LAT-7440'), { status: 502, error: 'graph_auth_failed' });
});

test('AC6: the token endpoint returns 200 with no access_token -> graph_auth_failed', async () => {
  const fetchFn = makeFetch((url) => (url === tokenUrl('t-1') ? jsonResponse(200, { expires_in: 3600 }) : jsonResponse(200, { value: [] })));
  const graph = createGraphClient({ tenantId: 't-1', clientId: 'c-1', clientSecret: 's', fetch: fetchFn, now: () => 1000 });
  await rejectsWith(graph.findDevicesByDisplayName('LAT-7440'), { status: 502, error: 'graph_auth_failed' });
});

test('AC6: Graph returns 403 -> graph_forbidden', async () => {
  const fetchFn = makeFetch((url) => (url === tokenUrl('t-1') ? tokenOk() : jsonResponse(403, {})));
  const graph = createGraphClient({ tenantId: 't-1', clientId: 'c-1', clientSecret: 's', fetch: fetchFn, now: () => 1000 });
  await rejectsWith(graph.findDevicesByDisplayName('LAT-7440'), { status: 502, error: 'graph_forbidden' });
});

test('AC6: Graph returns 401 -> graph_forbidden', async () => {
  const fetchFn = makeFetch((url) => (url === tokenUrl('t-1') ? tokenOk() : jsonResponse(401, {})));
  const graph = createGraphClient({ tenantId: 't-1', clientId: 'c-1', clientSecret: 's', fetch: fetchFn, now: () => 1000 });
  await rejectsWith(graph.findDevicesByDisplayName('LAT-7440'), { status: 502, error: 'graph_forbidden' });
});

test('AC6: Graph returns 429 -> graph_unavailable', async () => {
  const fetchFn = makeFetch((url) => (url === tokenUrl('t-1') ? tokenOk() : jsonResponse(429, {})));
  const graph = createGraphClient({ tenantId: 't-1', clientId: 'c-1', clientSecret: 's', fetch: fetchFn, now: () => 1000 });
  await rejectsWith(graph.findDevicesByDisplayName('LAT-7440'), { status: 502, error: 'graph_unavailable' });
});

test('AC6: Graph returns 503 -> graph_unavailable', async () => {
  const fetchFn = makeFetch((url) => (url === tokenUrl('t-1') ? tokenOk() : jsonResponse(503, {})));
  const graph = createGraphClient({ tenantId: 't-1', clientId: 'c-1', clientSecret: 's', fetch: fetchFn, now: () => 1000 });
  await rejectsWith(graph.findDevicesByDisplayName('LAT-7440'), { status: 502, error: 'graph_unavailable' });
});

test('AC6: fetch rejects with a network error -> graph_unavailable', async () => {
  const fetchFn = makeFetch((url) => {
    if (url === tokenUrl('t-1')) {
      return tokenOk();
    }
    throw new Error('network down');
  });
  const graph = createGraphClient({ tenantId: 't-1', clientId: 'c-1', clientSecret: 's', fetch: fetchFn, now: () => 1000 });
  await rejectsWith(graph.findDevicesByDisplayName('LAT-7440'), { status: 502, error: 'graph_unavailable' });
});

test('AC6: Graph returns 200 with body "not json" -> graph_unavailable', async () => {
  const fetchFn = makeFetch((url) => (url === tokenUrl('t-1') ? tokenOk() : { status: 200, text: async () => 'not json' }));
  const graph = createGraphClient({ tenantId: 't-1', clientId: 'c-1', clientSecret: 's', fetch: fetchFn, now: () => 1000 });
  await rejectsWith(graph.findDevicesByDisplayName('LAT-7440'), { status: 502, error: 'graph_unavailable' });
});

test('AC6: Graph does not answer before timeoutMillis 50 elapses -> graph_unavailable', async () => {
  const fetchFn = makeFetch((url) => {
    if (url === tokenUrl('t-1')) {
      return tokenOk();
    }
    return new Promise(() => {
      // Never resolves: the client's own timeout must still reject.
    });
  });
  const graph = createGraphClient({
    tenantId: 't-1',
    clientId: 'c-1',
    clientSecret: 's',
    fetch: fetchFn,
    now: () => 1000,
    timeoutMillis: 50,
  });
  await rejectsWith(graph.findDevicesByDisplayName('LAT-7440'), { status: 502, error: 'graph_unavailable' });
});

test('Unit: isGraphFailure recognises a {status, error} object and rejects anything else', () => {
  assert.strictEqual(isGraphFailure({ status: 502, error: 'graph_unavailable' }), true);
  assert.strictEqual(isGraphFailure(new Error('x')), false);
  assert.strictEqual(isGraphFailure(null), false);
  assert.strictEqual(isGraphFailure('x'), false);
});

// ============================================================================
// AC7: Secret provider
// ============================================================================

test('AC7: secret provider reads the configured JSON key once', async () => {
  let calls = 0;
  const secretsClient = {
    send: async () => {
      calls += 1;
      return { SecretString: JSON.stringify({ ENTRA_CLIENT_SECRET: 'S3CRET-SENTINEL' }) };
    },
  };
  const provider = createGraphSecretProvider({ secretsClient, secretId: 'prod/sk-mdm', key: 'ENTRA_CLIENT_SECRET' });

  const first = await provider();
  const second = await provider();

  assert.strictEqual(first, 'S3CRET-SENTINEL');
  assert.strictEqual(second, 'S3CRET-SENTINEL');
  assert.strictEqual(calls, 1);
});

test('AC7 (failure): SecretString is plain text -> graph_not_configured, retried next call', async () => {
  let calls = 0;
  const secretsClient = { send: async () => { calls += 1; return { SecretString: 'plain text' }; } };
  const provider = createGraphSecretProvider({ secretsClient, secretId: 's', key: 'K' });
  await rejectsWith(provider(), { status: 503, error: 'graph_not_configured' });
  await rejectsWith(provider(), { status: 503, error: 'graph_not_configured' });
  assert.strictEqual(calls, 2);
});

test('AC7 (failure): SecretString lacks the key -> graph_not_configured, retried next call', async () => {
  let calls = 0;
  const secretsClient = { send: async () => { calls += 1; return { SecretString: JSON.stringify({ OTHER: 'x' }) }; } };
  const provider = createGraphSecretProvider({ secretsClient, secretId: 's', key: 'K' });
  await rejectsWith(provider(), { status: 503, error: 'graph_not_configured' });
  await rejectsWith(provider(), { status: 503, error: 'graph_not_configured' });
  assert.strictEqual(calls, 2);
});

test('AC7 (failure): the key is an empty string -> graph_not_configured, retried next call', async () => {
  let calls = 0;
  const secretsClient = { send: async () => { calls += 1; return { SecretString: JSON.stringify({ ENTRA_CLIENT_SECRET: '' }) }; } };
  const provider = createGraphSecretProvider({ secretsClient, secretId: 's', key: 'ENTRA_CLIENT_SECRET' });
  await rejectsWith(provider(), { status: 503, error: 'graph_not_configured' });
  await rejectsWith(provider(), { status: 503, error: 'graph_not_configured' });
  assert.strictEqual(calls, 2);
});

test('AC7 (failure): the secrets client rejects -> graph_secret_unavailable, retried next call', async () => {
  let calls = 0;
  const secretsClient = { send: async () => { calls += 1; throw new Error('AccessDenied'); } };
  const provider = createGraphSecretProvider({ secretsClient, secretId: 's', key: 'K' });
  await rejectsWith(provider(), { status: 503, error: 'graph_secret_unavailable' });
  await rejectsWith(provider(), { status: 503, error: 'graph_secret_unavailable' });
  assert.strictEqual(calls, 2);
});

// ============================================================================
// AC8: Building the directory from the environment
// ============================================================================

test('AC8: GRAPH_SECRET_ID empty -> undefined', () => {
  const result = createGraphDirectoryFromEnv(
    { ENTRA_TENANT_ID: 't-1', ENTRA_CLIENT_ID: 'c-1', GRAPH_SECRET_ID: '' },
    { secretsClient: {}, fetch: async () => ({}), now: () => 1 },
  );
  assert.strictEqual(result, undefined);
});

test('AC8: ENTRA_TENANT_ID absent -> undefined', () => {
  const result = createGraphDirectoryFromEnv(
    { ENTRA_CLIENT_ID: 'c-1', GRAPH_SECRET_ID: 'prod/sk-mdm' },
    { secretsClient: {}, fetch: async () => ({}), now: () => 1 },
  );
  assert.strictEqual(result, undefined);
});

test('AC8: every value present -> a client reading the default key ENTRA_CLIENT_SECRET', async () => {
  const secretsClient = {
    send: async () => ({
      SecretString: JSON.stringify({ ENTRA_CLIENT_SECRET: 'default-secret', GRAPH_SECRET: 'custom-secret' }),
    }),
  };
  const fetchFn = makeFetch((url) => (url === tokenUrl('t-1') ? tokenOk() : jsonResponse(200, { value: [] })));
  const directory = createGraphDirectoryFromEnv(
    { ENTRA_TENANT_ID: 't-1', ENTRA_CLIENT_ID: 'c-1', GRAPH_SECRET_ID: 'prod/sk-mdm' },
    { secretsClient, fetch: fetchFn, now: () => 1000 },
  );
  assert.ok(directory);
  assert.strictEqual(fetchFn.calls.length, 0, 'building the directory sends no request');

  await directory.findDevicesByDisplayName('a');
  const tokenCall = fetchFn.calls.find((c) => c.url === tokenUrl('t-1'));
  assert.strictEqual(new URLSearchParams(tokenCall.init.body).get('client_secret'), 'default-secret');
});

test('AC8: GRAPH_SECRET_KEY overrides the default key', async () => {
  const secretsClient = {
    send: async () => ({
      SecretString: JSON.stringify({ ENTRA_CLIENT_SECRET: 'default-secret', GRAPH_SECRET: 'custom-secret' }),
    }),
  };
  const fetchFn = makeFetch((url) => (url === tokenUrl('t-1') ? tokenOk() : jsonResponse(200, { value: [] })));
  const directory = createGraphDirectoryFromEnv(
    { ENTRA_TENANT_ID: 't-1', ENTRA_CLIENT_ID: 'c-1', GRAPH_SECRET_ID: 'prod/sk-mdm', GRAPH_SECRET_KEY: 'GRAPH_SECRET' },
    { secretsClient, fetch: fetchFn, now: () => 1000 },
  );
  assert.ok(directory);

  await directory.findDevicesByDisplayName('a');
  const tokenCall = fetchFn.calls.find((c) => c.url === tokenUrl('t-1'));
  assert.strictEqual(new URLSearchParams(tokenCall.init.body).get('client_secret'), 'custom-secret');
});

test('Unit: DEFAULT_GRAPH_SECRET_KEY is ENTRA_CLIENT_SECRET', () => {
  assert.strictEqual(DEFAULT_GRAPH_SECRET_KEY, 'ENTRA_CLIENT_SECRET');
});

// ============================================================================
// AC9 (unit-level): the secret and token never appear in a rejection object
// ============================================================================

test('AC9: the client secret and access token never appear in a rejection object', async () => {
  const sentinelSecret = 'S3CRET-SENTINEL';
  const sentinelToken = 'TOKEN-SENTINEL';

  // Graph failure path.
  const fetchFn1 = makeFetch((url) => (url === tokenUrl('t-1') ? tokenOk(sentinelToken) : jsonResponse(503, {})));
  const graph1 = createGraphClient({ tenantId: 't-1', clientId: 'c-1', clientSecret: sentinelSecret, fetch: fetchFn1, now: () => 1000 });
  let rejection1;
  try {
    await graph1.findDevicesByDisplayName('a');
  } catch (error) {
    rejection1 = error;
  }
  const text1 = JSON.stringify(rejection1);
  assert.ok(!text1.includes(sentinelSecret) && !text1.includes(sentinelToken));

  // Token failure path.
  const fetchFn2 = makeFetch((url) => (url === tokenUrl('t-1') ? { status: 401, text: async () => '{}' } : jsonResponse(200, {})));
  const graph2 = createGraphClient({ tenantId: 't-1', clientId: 'c-1', clientSecret: sentinelSecret, fetch: fetchFn2, now: () => 1000 });
  let rejection2;
  try {
    await graph2.findDevicesByDisplayName('a');
  } catch (error) {
    rejection2 = error;
  }
  const text2 = JSON.stringify(rejection2);
  assert.ok(!text2.includes(sentinelSecret) && !text2.includes(sentinelToken));
});
