/**
 * E2E cucumber-style and unit tests for the URL hasher (TASK-050, AC5-AC7):
 * `backend/src/hashing/urlHasher.ts`.
 *
 * `hashUrl` never performs a real network call: `fetch` is always a fake
 * function supplied by the test. No database is touched by this module, so
 * nothing here needs a fake table either.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { createHash } from 'node:crypto';

const { hashUrl, HASH_MAX_BYTES, HASH_DEADLINE_MS, HASH_MAX_REDIRECTS, HASH_OUTCOME_CONDITION, hashOutcomeUpdate } =
  await import('../../dist/hashing/urlHasher.js');

function sha256Of(text) {
  return createHash('sha256').update(text).digest('hex');
}

/** An async-iterable body yielding `chunks`, tracking whether it was cancelled. */
function bodyOf(chunks, { throwsOnRead = false } = {}) {
  const calls = { cancelled: false };
  const body = {
    [Symbol.asyncIterator]() {
      let index = 0;
      return {
        async next() {
          if (throwsOnRead) {
            throw new Error('boom');
          }
          if (index >= chunks.length) {
            return { done: true, value: undefined };
          }
          return { done: false, value: chunks[index++] };
        },
        async return(value) {
          return { done: true, value };
        },
      };
    },
    cancel() {
      calls.cancelled = true;
    },
    arrayBuffer() {
      throw new Error('arrayBuffer must never be called');
    },
    text() {
      throw new Error('text must never be called');
    },
    blob() {
      throw new Error('blob must never be called');
    },
    json() {
      throw new Error('json must never be called');
    },
  };
  return { body, calls };
}

/** A response with the given status, headers map and body. */
function response(status, headers = {}, body) {
  return {
    status,
    headers: { get: (name) => headers[name.toLowerCase()] ?? null },
    body,
  };
}

// ============================================================================
// AC5: streamed hashing, never buffered whole
// ============================================================================

test('Scenario: Streamed hash without buffering', async () => {
  // Given a fetch answering 200 with a body yielding chunks "ab", "cd", "ef"
  // and arrayBuffer, text, blob and json that throw
  const { body } = bodyOf(['ab', 'cd', 'ef']);
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    return response(200, {}, body);
  };

  // When hashUrl("https://x.test/a.msi", {fetch}) runs
  const result = await hashUrl('https://x.test/a.msi', { fetch });

  // Then it resolves {ok:true, sha256:<sha256 of "abcdef">}
  assert.deepEqual(result, { ok: true, sha256: sha256Of('abcdef') });
  // And fetch received redirect "manual" and an AbortSignal
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.redirect, 'manual');
  assert.ok(calls[0].init.signal instanceof AbortSignal, 'expected an AbortSignal');
});

test('Unit: hashUrl accepts Buffer/Uint8Array and ArrayBuffer chunks', async () => {
  const chunks = [Buffer.from('ab'), new Uint8Array(Buffer.from('cd')), new TextEncoder().encode('ef').buffer];
  const { body } = bodyOf(chunks);
  const fetch = async () => response(200, {}, body);

  const result = await hashUrl('https://x.test/a.msi', { fetch });

  assert.deepEqual(result, { ok: true, sha256: sha256Of('abcdef') });
});

test('Unit: exported constants', () => {
  assert.equal(HASH_MAX_BYTES, 2147483648);
  assert.equal(HASH_DEADLINE_MS, 840000);
  assert.equal(HASH_MAX_REDIRECTS, 5);
  assert.equal(HASH_OUTCOME_CONDITION, 'attribute_exists(pk) AND hashRunId = :runId');
});

// ============================================================================
// AC6: redirect handling
// ============================================================================

test('Scenario: A relative https redirect is followed', async () => {
  // Given "https://x.test/a" answers 302 with location "/b.msi" and
  // "https://x.test/b.msi" answers 200 with "abc"
  const { body } = bodyOf(['abc']);
  const fetch = async (url) => {
    if (url === 'https://x.test/a') {
      return response(302, { location: '/b.msi' });
    }
    if (url === 'https://x.test/b.msi') {
      return response(200, {}, body);
    }
    throw new Error(`unexpected fetch ${url}`);
  };

  // When hashUrl("https://x.test/a") runs
  const result = await hashUrl('https://x.test/a', { fetch });

  // Then it resolves ok with the sha256 of "abc"
  assert.deepEqual(result, { ok: true, sha256: sha256Of('abc') });
});

const redirectFailures = [
  {
    name: 'a 301 to "http://x.test/a.msi"',
    error: 'redirect_not_https',
    fetch: async () => response(301, { location: 'http://x.test/a.msi' }),
  },
  {
    name: 'six consecutive 302 redirects',
    error: 'too_many_redirects',
    fetch: (() => {
      let hop = 0;
      return async () => {
        hop += 1;
        return response(302, { location: `https://x.test/${hop}` });
      };
    })(),
  },
  {
    name: 'a 302 with no location header',
    error: 'http_302',
    fetch: async () => response(302, {}),
  },
];

for (const { name, error, fetch } of redirectFailures) {
  test(`Scenario Outline: Redirect failures -- ${name}`, async () => {
    // Given <setup>
    // When hashUrl runs
    const result = await hashUrl('https://x.test/start', { fetch });
    // Then it resolves {ok:false, error:"<error>"}
    assert.deepEqual(result, { ok: false, error });
  });
}

// ============================================================================
// AC7: failure codes
// ============================================================================

test('Scenario Outline: Hashing failure codes -- invalid_url (fetch not called)', async () => {
  // Given the URL "ftp://x.test/a.msi" (fetch not called)
  let called = false;
  const fetch = async () => {
    called = true;
    return response(200, {}, bodyOf(['x']).body);
  };

  // When hashUrl runs
  const result = await hashUrl('ftp://x.test/a.msi', { fetch });

  // Then it resolves {ok:false, error:"invalid_url"}
  assert.deepEqual(result, { ok: false, error: 'invalid_url' });
  assert.equal(called, false, 'fetch must not be called for an invalid url');
});

test('Scenario Outline: Hashing failure codes -- fetch rejects with a TypeError', async () => {
  const fetch = async () => {
    throw new TypeError('network down');
  };

  const result = await hashUrl('https://x.test/a.msi', { fetch });

  assert.deepEqual(result, { ok: false, error: 'fetch_failed' });
});

test('Scenario Outline: Hashing failure codes -- the response is 404', async () => {
  const fetch = async () => response(404, {});

  const result = await hashUrl('https://x.test/a.msi', { fetch });

  assert.deepEqual(result, { ok: false, error: 'http_404' });
});

test('Scenario Outline: Hashing failure codes -- content-length over max (body never read)', async () => {
  const { body } = bodyOf(['should-not-be-read']);
  let bodyRead = false;
  const fetch = async () =>
    response(200, { 'content-length': '2147483649' }, {
      ...body,
      [Symbol.asyncIterator]() {
        bodyRead = true;
        return body[Symbol.asyncIterator]();
      },
    });

  const result = await hashUrl('https://x.test/a.msi', { fetch });

  assert.deepEqual(result, { ok: false, error: 'too_large' });
  assert.equal(bodyRead, false, 'the body must not be read when content-length already exceeds the limit');
});

test('Scenario Outline: Hashing failure codes -- no content-length, streamed past maxBytes (cancelled)', async () => {
  const { body, calls } = bodyOf(['a', 'b', 'c', 'd', 'e']);
  const fetch = async () => response(200, {}, body);

  const result = await hashUrl('https://x.test/a.msi', { fetch, maxBytes: 4 });

  assert.deepEqual(result, { ok: false, error: 'too_large' });
  assert.equal(calls.cancelled, true, 'the body should be cancelled once the limit is exceeded');
});

test('Scenario Outline: Hashing failure codes -- a 200 with an empty body', async () => {
  const { body } = bodyOf([]);
  const fetch = async () => response(200, {}, body);

  const result = await hashUrl('https://x.test/a.msi', { fetch });

  assert.deepEqual(result, { ok: false, error: 'empty_body' });
});

test('Scenario Outline: Hashing failure codes -- deadlineMs elapsing before the body is fully read', async () => {
  // A fetch that never settles until aborted: hashUrl's own deadline must fire.
  const fetch = (url, init) =>
    new Promise((_resolve, reject) => {
      init.signal.addEventListener('abort', () => reject(new Error('aborted')));
    });

  const result = await hashUrl('https://x.test/a.msi', { fetch, deadlineMs: 10 });

  assert.deepEqual(result, { ok: false, error: 'timeout' });
});

test('Unit: a streamed body that stalls mid-read past the deadline also times out', async () => {
  const fetch = async (url, init) =>
    response(200, {}, {
      [Symbol.asyncIterator]() {
        let yielded = false;
        return {
          async next() {
            if (!yielded) {
              yielded = true;
              return { done: false, value: 'a' };
            }
            // Hang until the deadline aborts the signal.
            return new Promise((resolve) => {
              init.signal.addEventListener('abort', () => resolve({ done: true, value: undefined }));
            });
          },
        };
      },
    });

  const result = await hashUrl('https://x.test/a.msi', { fetch, deadlineMs: 15 });

  assert.deepEqual(result, { ok: false, error: 'timeout' });
});

// ============================================================================
// hashOutcomeUpdate: the hasher's conditional write builder
// ============================================================================

test('Unit: hashOutcomeUpdate for a success sets sha256, ready, no error', () => {
  const update = hashOutcomeUpdate('r1', { ok: true, sha256: 'a'.repeat(64) }, '2026-10-11T00:00:00.000Z');

  assert.equal(update.ConditionExpression, HASH_OUTCOME_CONDITION);
  assert.equal(update.ExpressionAttributeValues[':runId'], 'r1');
  assert.equal(update.ExpressionAttributeValues[':sha256'], 'a'.repeat(64));
  assert.equal(update.ExpressionAttributeValues[':hashStatus'], 'ready');
  assert.equal(update.ExpressionAttributeValues[':hashError'], null);
  assert.equal(update.ExpressionAttributeValues[':hashedAt'], '2026-10-11T00:00:00.000Z');
});

test('Unit: hashOutcomeUpdate for a failure sets hashError, leaves sha256 unset', () => {
  const update = hashOutcomeUpdate('r1', { ok: false, error: 'http_404' }, '2026-10-11T00:00:00.000Z');

  assert.equal(update.ExpressionAttributeValues[':hashStatus'], 'failed');
  assert.equal(update.ExpressionAttributeValues[':hashError'], 'http_404');
  assert.equal(':sha256' in update.ExpressionAttributeValues, false);
  assert.ok(!update.UpdateExpression.includes('sha256'));
});
