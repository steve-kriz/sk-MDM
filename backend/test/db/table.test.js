/**
 * E2E and unit tests for the DynamoDB table client wrapper in db/table.ts.
 * Tests use a recording fake documentClient with no AWS SDK or network calls.
 */

import test from 'node:test';
import assert from 'node:assert';
import {
  createTableClient,
  encodeCursor,
  decodeCursor,
  PUT_IF_ABSENT_CONDITION,
  CONDITIONAL_CHECK_FAILED,
} from '../../dist/db/table.js';
import { deviceProfile, deviceCommand, nonce } from '../../dist/db/keys.js';

/**
 * A fake document client that records all sends for inspection.
 * Allows tests to verify TableName injection and control responses.
 */
class FakeDocumentClient {
  constructor() {
    this.sends = [];
    this.responsesToSend = [];
    this.errorToThrow = null;
  }

  async send(command) {
    this.sends.push(command);

    if (this.errorToThrow) {
      throw this.errorToThrow;
    }

    if (this.responsesToSend.length > 0) {
      return this.responsesToSend.shift();
    }

    return {};
  }

  recordResponse(response) {
    this.responsesToSend.push(response);
  }

  recordError(error) {
    this.errorToThrow = error;
  }

  getSends() {
    return this.sends;
  }

  clearSends() {
    this.sends = [];
  }
}

test('Unit: encodeCursor encodes a LastEvaluatedKey to base64 JSON', () => {
  const key = { pk: 'DEVICE#d1', sk: 'PROFILE' };
  const cursor = encodeCursor(key);

  // Verify it's base64 decodable and contains the JSON
  const decoded = Buffer.from(cursor, 'base64').toString('utf8');
  const parsed = JSON.parse(decoded);
  assert.deepStrictEqual(parsed, key);
});

test('Unit: decodeCursor decodes a valid cursor back to the key', () => {
  const key = { pk: 'DEVICE#d1', sk: 'PROFILE' };
  const cursor = encodeCursor(key);
  const decoded = decodeCursor(cursor);
  assert.deepStrictEqual(decoded, key);
});

test('Unit: decodeCursor rejects malformed base64', () => {
  assert.throws(
    () => decodeCursor('!!!not-base64!!!'),
    (err) => {
      assert.strictEqual(err.message, 'invalid cursor');
      return true;
    }
  );
});

test('Unit: decodeCursor rejects empty string', () => {
  assert.throws(
    () => decodeCursor(''),
    (err) => {
      assert.strictEqual(err.message, 'invalid cursor');
      return true;
    }
  );
});

test('Unit: decodeCursor rejects non-object JSON', () => {
  const arrayJson = Buffer.from(JSON.stringify([1, 2, 3]), 'utf8').toString('base64');
  assert.throws(
    () => decodeCursor(arrayJson),
    (err) => {
      assert.strictEqual(err.message, 'invalid cursor');
      return true;
    }
  );
});

test('Unit: createTableClient returns a TableClient with all methods', () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });

  assert.ok(typeof client.get === 'function');
  assert.ok(typeof client.put === 'function');
  assert.ok(typeof client.putIfAbsent === 'function');
  assert.ok(typeof client.update === 'function');
  assert.ok(typeof client.query === 'function');
  assert.ok(typeof client.delete === 'function');
});

test('Unit: get sends Get command and returns Item', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });
  const item = { pk: 'DEVICE#d1', sk: 'PROFILE', name: 'Device 1' };
  fake.recordResponse({ Item: item });

  const result = await client.get(deviceProfile('d1'));

  assert.deepStrictEqual(result, item);
  const sends = fake.getSends();
  assert.strictEqual(sends.length, 1);
  assert.strictEqual(sends[0].operation, 'Get');
  assert.deepStrictEqual(sends[0].input.Key, deviceProfile('d1'));
});

test('Unit: get returns undefined when item does not exist', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });
  fake.recordResponse({});

  const result = await client.get(deviceProfile('d1'));

  assert.strictEqual(result, undefined);
});

test('Unit: put sends Put command with Item', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });
  const item = { pk: 'DEVICE#d1', sk: 'PROFILE', name: 'Device 1' };

  await client.put(item);

  const sends = fake.getSends();
  assert.strictEqual(sends.length, 1);
  assert.strictEqual(sends[0].operation, 'Put');
  assert.deepStrictEqual(sends[0].input.Item, item);
});

test('Unit: putIfAbsent includes ConditionExpression', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });
  const item = { pk: 'DEVICE#d1', sk: 'PROFILE' };

  await client.putIfAbsent(item);

  const sends = fake.getSends();
  assert.strictEqual(sends[0].input.ConditionExpression, PUT_IF_ABSENT_CONDITION);
});

test('E2E Scenario: putIfAbsent resolves to {written:true} on success', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });
  const item = { pk: 'DEVICE#d1', sk: 'PROFILE' };

  const result = await client.putIfAbsent(item);

  assert.deepStrictEqual(result, { written: true });
});

test('E2E Scenario: putIfAbsent resolves to {written:false} on ConditionalCheckFailedException', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });
  const item = { pk: 'DEVICE#d1', sk: 'PROFILE' };

  const error = new Error('Condition failed');
  error.name = CONDITIONAL_CHECK_FAILED;
  fake.recordError(error);

  const result = await client.putIfAbsent(item);

  assert.deepStrictEqual(result, { written: false });
});

test('Unit: putIfAbsent rethrows non-conditional errors', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });
  const item = { pk: 'DEVICE#d1', sk: 'PROFILE' };

  const error = new Error('Some other error');
  error.name = 'ValidationException';
  fake.recordError(error);

  assert.rejects(
    () => client.putIfAbsent(item),
    (err) => err.message === 'Some other error'
  );
});

test('Unit: update returns Attributes with ALL_NEW by default', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });
  const updatedAttrs = { pk: 'DEVICE#d1', sk: 'PROFILE', updated: true };
  fake.recordResponse({ Attributes: updatedAttrs });

  const result = await client.update(deviceProfile('d1'), {
    UpdateExpression: 'SET #u = :v',
    ExpressionAttributeNames: { '#u': 'updated' },
    ExpressionAttributeValues: { ':v': true },
  });

  assert.deepStrictEqual(result, updatedAttrs);
  const sends = fake.getSends();
  assert.strictEqual(sends[0].input.ReturnValues, 'ALL_NEW');
});

test('Unit: delete sends Delete command', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });

  await client.delete(deviceProfile('d1'));

  const sends = fake.getSends();
  assert.strictEqual(sends.length, 1);
  assert.strictEqual(sends[0].operation, 'Delete');
  assert.deepStrictEqual(sends[0].input.Key, deviceProfile('d1'));
});

test('E2E Scenario: query returns {items, cursor} with no pagination', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });
  const items = [
    { pk: 'DEVICE#d1', sk: 'PROFILE' },
    { pk: 'DEVICE#d2', sk: 'PROFILE' },
  ];
  fake.recordResponse({ Items: items });

  const result = await client.query({
    IndexName: 'gsi1',
    KeyConditionExpression: '#p = :p',
    ExpressionAttributeNames: { '#p': 'gsi1pk' },
    ExpressionAttributeValues: { ':p': 'DEVICE' },
  });

  assert.deepStrictEqual(result.items, items);
  assert.strictEqual(result.cursor, null);
});

test('E2E Scenario: query returns cursor when LastEvaluatedKey is present', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });
  const items = [
    { pk: 'DEVICE#d1', sk: 'PROFILE' },
    { pk: 'DEVICE#d2', sk: 'PROFILE' },
  ];
  const lastKey = { pk: 'DEVICE#d2', sk: 'PROFILE', gsi1pk: 'DEVICE', gsi1sk: '2026-10-02T12:00:00Z' };
  fake.recordResponse({ Items: items, LastEvaluatedKey: lastKey });

  const result = await client.query({
    IndexName: 'gsi1',
    KeyConditionExpression: '#p = :p',
    limit: 2,
    ExpressionAttributeNames: { '#p': 'gsi1pk' },
    ExpressionAttributeValues: { ':p': 'DEVICE' },
  });

  assert.deepStrictEqual(result.items, items);
  assert.strictEqual(typeof result.cursor, 'string');

  // Verify the cursor can be decoded back to the original key
  const decodedKey = decodeCursor(result.cursor);
  assert.deepStrictEqual(decodedKey, lastKey);
});

test('E2E Scenario: query with cursor sends ExclusiveStartKey', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });
  const lastKey = { pk: 'DEVICE#d2', sk: 'PROFILE' };
  const cursor = encodeCursor(lastKey);
  const items = [{ pk: 'DEVICE#d3', sk: 'PROFILE' }];
  fake.recordResponse({ Items: items });

  await client.query({
    IndexName: 'gsi1',
    KeyConditionExpression: '#p = :p',
    cursor,
    ExpressionAttributeNames: { '#p': 'gsi1pk' },
    ExpressionAttributeValues: { ':p': 'DEVICE' },
  });

  const sends = fake.getSends();
  assert.deepStrictEqual(sends[0].input.ExclusiveStartKey, lastKey);
});

test('Unit: query includes Limit when provided', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });
  fake.recordResponse({ Items: [] });

  await client.query({ limit: 25 });

  const sends = fake.getSends();
  assert.strictEqual(sends[0].input.Limit, 25);
});

test('E2E Scenario: Malformed cursor is rejected', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });

  assert.rejects(
    () => client.query({ cursor: '!!!not-base64!!!' }),
    (err) => err.message === 'invalid cursor'
  );
});

test('E2E Scenario: Table name is injected on every call', async () => {
  const fake = new FakeDocumentClient();
  const tableName = 'test-mdm-table';
  const client = createTableClient({ documentClient: fake, tableName });

  fake.recordResponse({ Item: { pk: 'DEVICE#d1', sk: 'PROFILE' } });
  await client.get(deviceProfile('d1'));
  fake.clearSends();

  fake.recordResponse({});
  await client.put({ pk: 'DEVICE#d1', sk: 'PROFILE' });
  fake.clearSends();

  fake.recordResponse({});
  await client.putIfAbsent({ pk: 'DEVICE#d1', sk: 'PROFILE' });
  fake.clearSends();

  fake.recordResponse({ Attributes: { pk: 'DEVICE#d1' } });
  await client.update(deviceProfile('d1'), { UpdateExpression: 'SET #a = :v', ExpressionAttributeNames: { '#a': 'attr' }, ExpressionAttributeValues: { ':v': 'val' } });
  fake.clearSends();

  fake.recordResponse({ Items: [] });
  await client.query({});
  fake.clearSends();

  fake.recordResponse({});
  await client.delete(deviceProfile('d1'));

  const sends = fake.getSends();
  for (const send of sends) {
    assert.strictEqual(send.input.TableName, tableName, `TableName should be ${tableName} in ${send.operation}`);
  }
});

test('Unit: query with empty response returns empty items array', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });
  fake.recordResponse({});

  const result = await client.query({});

  assert.deepStrictEqual(result.items, []);
  assert.strictEqual(result.cursor, null);
});

test('Unit: get with additional fields merges them into the request', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });
  fake.recordResponse({ Item: {} });

  await client.get(deviceProfile('d1'), {
    ConsistentRead: true,
    ProjectionExpression: 'pk, sk',
  });

  const sends = fake.getSends();
  assert.strictEqual(sends[0].input.ConsistentRead, true);
  assert.strictEqual(sends[0].input.ProjectionExpression, 'pk, sk');
});

test('Unit: put with additional fields merges them into the request', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });

  await client.put(
    { pk: 'DEVICE#d1', sk: 'PROFILE' },
    { ReturnConsumedCapacity: 'TOTAL' }
  );

  const sends = fake.getSends();
  assert.strictEqual(sends[0].input.ReturnConsumedCapacity, 'TOTAL');
});

test('Unit: update with custom ReturnValues overrides the default', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });
  fake.recordResponse({ Attributes: {} });

  await client.update(deviceProfile('d1'), {
    UpdateExpression: 'SET #a = :v',
    ExpressionAttributeNames: { '#a': 'attr' },
    ExpressionAttributeValues: { ':v': 'val' },
    ReturnValues: 'NONE',
  });

  const sends = fake.getSends();
  assert.strictEqual(sends[0].input.ReturnValues, 'NONE');
});

test('Unit: Consecutive puts record multiple sends', async () => {
  const fake = new FakeDocumentClient();
  const client = createTableClient({ documentClient: fake, tableName: 'mdm' });

  await client.put({ pk: 'A', sk: '1' });
  await client.put({ pk: 'B', sk: '2' });

  const sends = fake.getSends();
  assert.strictEqual(sends.length, 2);
  assert.strictEqual(sends[0].input.Item.pk, 'A');
  assert.strictEqual(sends[1].input.Item.pk, 'B');
});
