/**
 * E2E cucumber-style and unit tests for the hasher Lambda invoker (TASK-050,
 * AC9): `backend/src/aws/hasherInvoker.ts`.
 *
 * The Lambda client is always a fake `{send}` -- no real AWS call is ever made.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';

const { createLambdaHasherInvoker, ASYNC_INVOKE_ACCEPTED } = await import('../../dist/aws/hasherInvoker.js');
const { InvokeCommand } = await import('@aws-sdk/client-lambda');

const __dirname = dirname(fileURLToPath(import.meta.url));

/** A fake SDK-shaped Lambda client: records every command and answers scripted outcomes. */
class FakeLambdaClient {
  constructor() {
    this.calls = [];
    this.outcome = { kind: 'resolve', value: { StatusCode: ASYNC_INVOKE_ACCEPTED } };
  }

  async send(command) {
    this.calls.push(command);
    if (this.outcome.kind === 'reject') {
      throw this.outcome.value;
    }
    return this.outcome.value;
  }
}

// ============================================================================
// AC9
// ============================================================================

test('Scenario: Asynchronous invoke', async () => {
  // Given a fake Lambda client answering StatusCode 202
  const client = new FakeLambdaClient();
  const invoker = createLambdaHasherInvoker({ client, functionName: 'hasher' });
  const event = { applicationId: 'app-1', url: 'https://x', hashRunId: 'r1' };

  // When invoke runs
  await invoker.invoke(event);

  // Then one InvokeCommand was sent with FunctionName "hasher",
  // InvocationType "Event" and the event's JSON bytes as Payload
  assert.equal(client.calls.length, 1);
  const [command] = client.calls;
  assert.ok(command instanceof InvokeCommand);
  assert.equal(command.input.FunctionName, 'hasher');
  assert.equal(command.input.InvocationType, 'Event');
  assert.ok(command.input.Payload instanceof Uint8Array);
  assert.deepEqual(JSON.parse(Buffer.from(command.input.Payload).toString('utf8')), event);
  assert.equal(ASYNC_INVOKE_ACCEPTED, 202);

  // And backend/package.json depends on "@aws-sdk/client-lambda" "3.1146.0"
  const pkg = JSON.parse(readFileSync(join(__dirname, '../../package.json'), 'utf8'));
  assert.equal(pkg.dependencies['@aws-sdk/client-lambda'], '3.1146.0');
});

const rejections = [
  {
    name: 'answers StatusCode 500',
    outcome: { kind: 'resolve', value: { StatusCode: 500 } },
  },
  {
    name: 'rejects on send',
    outcome: { kind: 'reject', value: new Error('send failed') },
  },
];

for (const { name, outcome } of rejections) {
  test(`Scenario Outline: Invoke rejected -- the Lambda client ${name}`, async () => {
    // Given the Lambda client <behaviour>
    const client = new FakeLambdaClient();
    client.outcome = outcome;
    const invoker = createLambdaHasherInvoker({ client, functionName: 'hasher' });

    // When invoke runs
    // Then it rejects
    await assert.rejects(invoker.invoke({ applicationId: 'app-1', url: 'https://x', hashRunId: 'r1' }));
  });
}

test('Unit: a response with no StatusCode at all rejects', async () => {
  const client = new FakeLambdaClient();
  client.outcome = { kind: 'resolve', value: {} };
  const invoker = createLambdaHasherInvoker({ client, functionName: 'hasher' });

  await assert.rejects(invoker.invoke({ applicationId: 'app-1', url: 'https://x', hashRunId: 'r1' }));
});
