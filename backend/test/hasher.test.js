/**
 * E2E cucumber-style and unit tests for the hasher Lambda entry point
 * (TASK-050, AC8): `backend/src/hasher.ts`.
 *
 * All table access is a fake `{update}` object -- no real DynamoDB connection
 * is ever opened -- and `fetch` is always a fake function. `handler` itself
 * (the production entry) is only checked for safe lazy construction, since it
 * would otherwise require real AWS credentials and a real TABLE_NAME.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { createHash } from 'node:crypto';

const { createHasherHandler, handler } = await import('../dist/hasher.js');
const { application: applicationKey } = await import('../dist/db/keys.js');
const { CONDITIONAL_CHECK_FAILED } = await import('../dist/db/table.js');

function sha256Of(text) {
  return createHash('sha256').update(text).digest('hex');
}

function bodyOf(chunks) {
  return {
    [Symbol.asyncIterator]() {
      let index = 0;
      return {
        async next() {
          if (index >= chunks.length) {
            return { done: true, value: undefined };
          }
          return { done: false, value: chunks[index++] };
        },
      };
    },
    cancel() {},
  };
}

function response(status, headers = {}, body) {
  return { status, headers: { get: (name) => headers[name.toLowerCase()] ?? null }, body };
}

/** A fake table exposing only `update`, scripted per test. */
class FakeTable {
  constructor() {
    this.calls = [];
    this.outcome = { kind: 'resolve', value: undefined };
  }

  async update(key, fields) {
    this.calls.push({ key, fields });
    if (this.outcome.kind === 'reject') {
      throw this.outcome.value;
    }
    return this.outcome.value;
  }
}

const originalConsoleLog = console.log;
const originalConsoleError = console.error;
function captureLogs() {
  const lines = { log: [], error: [] };
  console.log = (...args) => lines.log.push(args.join(' '));
  console.error = (...args) => lines.error.push(args.join(' '));
  return {
    lines,
    restore() {
      console.log = originalConsoleLog;
      console.error = originalConsoleError;
    },
  };
}

// ============================================================================
// AC8
// ============================================================================

test('Scenario: Hasher stores a successful hash conditionally', async () => {
  // Given a fake table and a fetch serving "abc"
  const table = new FakeTable();
  const fetch = async () => response(200, {}, bodyOf(['abc']));
  const now = () => new Date('2026-10-11T12:00:00.000Z');
  // deadlineMs is kept short so the hasher's own real (ref'd) deadline timer
  // -- unused in this fast-resolving test, but still created -- can never
  // outlive the test file's process by a meaningful amount.
  const hasherHandler = createHasherHandler({ table, fetch, now, deadlineMs: 5000 });

  // When the hasher handler receives {applicationId:"app-1", url:..., hashRunId:"r1"}
  await hasherHandler({ applicationId: 'app-1', url: 'https://x.test/a.msi', hashRunId: 'r1' });

  // Then exactly one table.update was made on application("app-1") with
  // condition "attribute_exists(pk) AND hashRunId = :runId" and :runId "r1"
  assert.equal(table.calls.length, 1, 'no table operation other than one update should be used');
  const [{ key, fields }] = table.calls;
  assert.deepEqual(key, applicationKey('app-1'));
  assert.equal(fields.ConditionExpression, 'attribute_exists(pk) AND hashRunId = :runId');
  assert.equal(fields.ExpressionAttributeValues[':runId'], 'r1');
  // And it sets sha256 to the sha256 of "abc", hashStatus "ready", hashError null and hashedAt
  assert.equal(fields.ExpressionAttributeValues[':sha256'], sha256Of('abc'));
  assert.equal(fields.ExpressionAttributeValues[':hashStatus'], 'ready');
  assert.equal(fields.ExpressionAttributeValues[':hashError'], null);
  assert.equal(fields.ExpressionAttributeValues[':hashedAt'], '2026-10-11T12:00:00Z');
});

test('Scenario: Hasher stores a failure', async () => {
  // Given a fetch answering 500
  const table = new FakeTable();
  const fetch = async () => response(500, {});
  const hasherHandler = createHasherHandler({ table, fetch, deadlineMs: 5000 });

  // When the hasher handler runs
  await hasherHandler({ applicationId: 'app-1', url: 'https://x.test/a.msi', hashRunId: 'r1' });

  // Then the update sets hashStatus "failed" and hashError "http_500" and does not set sha256
  const [{ fields }] = table.calls;
  assert.equal(fields.ExpressionAttributeValues[':hashStatus'], 'failed');
  assert.equal(fields.ExpressionAttributeValues[':hashError'], 'http_500');
  assert.equal(':sha256' in fields.ExpressionAttributeValues, false);
});

test('Scenario: Deleted application or stale run is not overwritten', async () => {
  // Given table.update rejects with ConditionalCheckFailedException
  const table = new FakeTable();
  const error = new Error('condition failed');
  error.name = CONDITIONAL_CHECK_FAILED;
  table.outcome = { kind: 'reject', value: error };
  const fetch = async () => response(200, {}, bodyOf(['abc']));
  const hasherHandler = createHasherHandler({ table, fetch, deadlineMs: 5000 });

  const capture = captureLogs();
  try {
    // When the hasher handler runs
    await hasherHandler({ applicationId: 'app-1', url: 'https://x.test/a.msi', hashRunId: 'r1' });
  } finally {
    capture.restore();
  }

  // Then it resolves without throwing and logs one line
  assert.equal(capture.lines.log.length, 1);
  assert.equal(capture.lines.error.length, 0);
});

test('Unit: a non-conditional table error is rethrown', async () => {
  const table = new FakeTable();
  table.outcome = { kind: 'reject', value: new Error('boom') };
  const fetch = async () => response(200, {}, bodyOf(['abc']));
  const hasherHandler = createHasherHandler({ table, fetch, deadlineMs: 5000 });

  await assert.rejects(
    hasherHandler({ applicationId: 'app-1', url: 'https://x.test/a.msi', hashRunId: 'r1' }),
    /boom/,
  );
});

test('Scenario: Malformed event', async () => {
  const table = new FakeTable();
  let fetchCalled = false;
  const fetch = async () => {
    fetchCalled = true;
    return response(200, {}, bodyOf(['abc']));
  };
  const hasherHandler = createHasherHandler({ table, fetch, deadlineMs: 5000 });

  const capture = captureLogs();
  try {
    // When the hasher handler receives {applicationId:"app-1"}
    await hasherHandler({ applicationId: 'app-1' });
  } finally {
    capture.restore();
  }

  // Then fetch was not called, no table call was made and it resolves
  assert.equal(fetchCalled, false);
  assert.equal(table.calls.length, 0);
  assert.equal(capture.lines.error.length, 1);
});

test('Unit: an event with non-string fields is treated as malformed', async () => {
  const table = new FakeTable();
  let fetchCalled = false;
  const fetch = async () => {
    fetchCalled = true;
    return response(200, {}, bodyOf(['abc']));
  };
  const hasherHandler = createHasherHandler({ table, fetch, deadlineMs: 5000 });

  const capture = captureLogs();
  try {
    await hasherHandler({ applicationId: 'app-1', url: 123, hashRunId: 'r1' });
  } finally {
    capture.restore();
  }

  assert.equal(fetchCalled, false);
  assert.equal(table.calls.length, 0);
});

test('Unit: an event naming an id that cannot form a key resolves with no table call', async () => {
  const table = new FakeTable();
  const fetch = async () => response(200, {}, bodyOf(['abc']));
  const hasherHandler = createHasherHandler({ table, fetch, deadlineMs: 5000 });

  await hasherHandler({ applicationId: '', url: 'https://x.test/a.msi', hashRunId: 'r1' });

  assert.equal(table.calls.length, 0);
});

test('Unit: the production handler is built lazily; importing without TABLE_NAME does not throw', async () => {
  // The module was already imported above with no TABLE_NAME set, which must
  // not have thrown. Invoking the exported handler without TABLE_NAME must
  // reject only once actually called, never at import time.
  assert.equal(typeof handler, 'function');
  const hadEnvVar = Object.prototype.hasOwnProperty.call(process.env, 'TABLE_NAME');
  const previous = process.env.TABLE_NAME;
  delete process.env.TABLE_NAME;
  // Awaited in a plain try/catch -- rather than handed to assert.rejects --
  // so there is exactly one promise in play and no risk of it ever being
  // observed as unhandled.
  let rejected = false;
  let rejectionMessage = '';
  try {
    await handler({ applicationId: 'app-1', url: 'https://x', hashRunId: 'r1' });
  } catch (error) {
    rejected = true;
    rejectionMessage = error instanceof Error ? error.message : String(error);
  } finally {
    if (hadEnvVar) {
      process.env.TABLE_NAME = previous;
    } else {
      delete process.env.TABLE_NAME;
    }
  }
  assert.equal(rejected, true, 'handler should reject when TABLE_NAME is not configured');
  assert.match(rejectionMessage, /TABLE_NAME/);
});
