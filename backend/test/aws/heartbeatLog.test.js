/**
 * Unit + e2e cucumber-style tests for TASK-044's CloudWatch Logs heartbeat
 * adapter (`backend/src/aws/heartbeatLog.ts`).
 *
 * The CloudWatch Logs client is stubbed entirely in-process: `send(command)`
 * inspects the command's constructor name and its `input`. No AWS SDK call
 * ever leaves the process and no real database or network connection is made.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const { createCloudWatchHeartbeatLog } = await import('../../dist/aws/heartbeatLog.js');
const {
  PutLogEventsCommand,
  CreateLogStreamCommand,
  GetLogEventsCommand,
} = await import('@aws-sdk/client-cloudwatch-logs');

function namedError(name, message = name) {
  const error = new Error(message);
  error.name = name;
  return error;
}

/** A stub CloudWatch Logs client: `send` is driven by `onSend(command)`. */
function stubClient(onSend) {
  const calls = [];
  return {
    calls,
    async send(command) {
      calls.push(command);
      return onSend(command, calls);
    },
  };
}

// ============================================================================
// Scenario: Writing to an existing stream
// ============================================================================

test('Scenario: Writing to an existing stream sends one PutLogEventsCommand', async () => {
  const client = stubClient(async () => ({}));
  const log = createCloudWatchHeartbeatLog({ client, logGroupName: 'grp' });

  const event = {
    deviceId: 'd1',
    collectedAt: '2026-10-11T11:59:58Z',
    receivedAt: '2026-10-11T12:00:00Z',
    performance: { cpuPercent: 1, memoryUsedBytes: 1, memoryTotalBytes: 2, systemDiskFreeBytes: 1, systemDiskTotalBytes: 2 },
  };

  await log.write('d1', event);

  assert.strictEqual(client.calls.length, 1);
  const cmd = client.calls[0];
  assert.ok(cmd instanceof PutLogEventsCommand);
  assert.strictEqual(cmd.input.logGroupName, 'grp');
  assert.strictEqual(cmd.input.logStreamName, 'd1');
  assert.strictEqual(cmd.input.logEvents.length, 1);
  assert.strictEqual(cmd.input.logEvents[0].timestamp, Date.parse('2026-10-11T12:00:00Z'));
  assert.strictEqual(cmd.input.logEvents[0].message, JSON.stringify(event));
});

// ============================================================================
// Scenario: First write creates the stream and retries once
// ============================================================================

test('Scenario: First write creates the stream and retries once', async () => {
  let putCount = 0;
  const client = stubClient(async (cmd) => {
    if (cmd instanceof PutLogEventsCommand) {
      putCount += 1;
      if (putCount === 1) {
        throw namedError('ResourceNotFoundException');
      }
      return {};
    }
    if (cmd instanceof CreateLogStreamCommand) {
      return {};
    }
    throw new Error('unexpected command');
  });
  const log = createCloudWatchHeartbeatLog({ client, logGroupName: 'grp' });

  const event = { deviceId: 'd1', collectedAt: 'x', receivedAt: '2026-10-11T12:00:00Z', performance: {} };
  await log.write('d1', event);

  assert.strictEqual(client.calls.length, 3, 'put, create, put again');
  assert.ok(client.calls[0] instanceof PutLogEventsCommand);
  assert.ok(client.calls[1] instanceof CreateLogStreamCommand);
  assert.strictEqual(client.calls[1].input.logGroupName, 'grp');
  assert.strictEqual(client.calls[1].input.logStreamName, 'd1');
  assert.ok(client.calls[2] instanceof PutLogEventsCommand);
});

// ============================================================================
// Scenario Outline: Stream creation races and failures
// ============================================================================

test('Scenario Outline: A concurrent create (ResourceAlreadyExistsException) is ignored and the retried put resolves', async () => {
  let putCount = 0;
  const client = stubClient(async (cmd) => {
    if (cmd instanceof PutLogEventsCommand) {
      putCount += 1;
      if (putCount === 1) {
        throw namedError('ResourceNotFoundException');
      }
      return {};
    }
    if (cmd instanceof CreateLogStreamCommand) {
      throw namedError('ResourceAlreadyExistsException');
    }
    throw new Error('unexpected command');
  });
  const log = createCloudWatchHeartbeatLog({ client, logGroupName: 'grp' });

  await assert.doesNotReject(() =>
    log.write('d1', { deviceId: 'd1', collectedAt: 'x', receivedAt: '2026-10-11T12:00:00Z', performance: {} }),
  );
});

test('Scenario Outline: A second failure on the retried put is thrown', async () => {
  let putCount = 0;
  const client = stubClient(async (cmd) => {
    if (cmd instanceof PutLogEventsCommand) {
      putCount += 1;
      if (putCount === 1) {
        throw namedError('ResourceNotFoundException');
      }
      throw namedError('ThrottlingException');
    }
    if (cmd instanceof CreateLogStreamCommand) {
      return {};
    }
    throw new Error('unexpected command');
  });
  const log = createCloudWatchHeartbeatLog({ client, logGroupName: 'grp' });

  await assert.rejects(
    () => log.write('d1', { deviceId: 'd1', collectedAt: 'x', receivedAt: '2026-10-11T12:00:00Z', performance: {} }),
    (error) => error.name === 'ThrottlingException',
  );
});

test('Scenario: Any other error on the first put is rethrown without creating a stream', async () => {
  const client = stubClient(async (cmd) => {
    if (cmd instanceof PutLogEventsCommand) {
      throw namedError('AccessDeniedException');
    }
    throw new Error('unexpected command');
  });
  const log = createCloudWatchHeartbeatLog({ client, logGroupName: 'grp' });

  await assert.rejects(
    () => log.write('d1', { deviceId: 'd1', collectedAt: 'x', receivedAt: '2026-10-11T12:00:00Z', performance: {} }),
    (error) => error.name === 'AccessDeniedException',
  );
  assert.strictEqual(client.calls.length, 1, 'no CreateLogStream, no retried put');
});

// ============================================================================
// Scenario: Reading a device's history
// ============================================================================

test('Scenario: Reading a device history returns parsed events newest first, skipping non-JSON', async () => {
  const client = stubClient(async (cmd) => {
    assert.ok(cmd instanceof GetLogEventsCommand);
    return {
      events: [
        { timestamp: 1000, message: JSON.stringify({ deviceId: 'd1', collectedAt: 'a' }) },
        { timestamp: 3000, message: JSON.stringify({ deviceId: 'd1', collectedAt: 'c' }) },
        { timestamp: 2000, message: 'not json' },
      ],
    };
  });
  const log = createCloudWatchHeartbeatLog({ client, logGroupName: 'grp' });

  const items = await log.read('d1', 100);

  assert.strictEqual(client.calls.length, 1);
  const cmd = client.calls[0];
  assert.strictEqual(cmd.input.logGroupName, 'grp');
  assert.strictEqual(cmd.input.logStreamName, 'd1');
  assert.strictEqual(cmd.input.limit, 100);
  assert.strictEqual(cmd.input.startFromHead, false);

  assert.strictEqual(items.length, 2, 'the non-JSON message is skipped');
  assert.deepStrictEqual(items[0], { deviceId: 'd1', collectedAt: 'c' });
  assert.deepStrictEqual(items[1], { deviceId: 'd1', collectedAt: 'a' });
});

test('Scenario: A message that is JSON but not an object is skipped', async () => {
  const client = stubClient(async () => ({
    events: [
      { timestamp: 1000, message: JSON.stringify(['array']) },
      { timestamp: 2000, message: JSON.stringify('a string') },
      { timestamp: 3000, message: JSON.stringify(null) },
      { timestamp: 4000, message: JSON.stringify({ ok: true }) },
    ],
  }));
  const log = createCloudWatchHeartbeatLog({ client, logGroupName: 'grp' });

  const items = await log.read('d1', 100);
  assert.deepStrictEqual(items, [{ ok: true }]);
});

// ============================================================================
// Scenario: Reading a stream that does not exist
// ============================================================================

test('Scenario: Reading a stream that does not exist resolves to []', async () => {
  const client = stubClient(async () => {
    throw namedError('ResourceNotFoundException');
  });
  const log = createCloudWatchHeartbeatLog({ client, logGroupName: 'grp' });

  const items = await log.read('d1', 100);
  assert.deepStrictEqual(items, []);
});

test('Scenario: Any other error on read is rethrown', async () => {
  const client = stubClient(async () => {
    throw namedError('AccessDeniedException');
  });
  const log = createCloudWatchHeartbeatLog({ client, logGroupName: 'grp' });

  await assert.rejects(() => log.read('d1', 100), (error) => error.name === 'AccessDeniedException');
});
