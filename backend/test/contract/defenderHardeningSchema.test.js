/**
 * E2E test for TASK-060 AC123: the DefenderHardening schema in
 * contract/openapi.yaml and the checkin-request-with-defender-hardening.json
 * fixture. Modelled on the hand-rolled validateAgainstSchema/resolveSchemaRef
 * helpers in backend/test/contract/messages.test.js. No database is touched.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import YAML from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const openapi = YAML.parse(readFileSync(join(__dirname, '../../../contract/openapi.yaml'), 'utf-8'));
const messagesDir = join(__dirname, '../../../contract/testdata/messages');

function resolveSchemaRef(ref) {
  const name = ref.split('/').pop();
  const schema = openapi.components.schemas[name];
  assert.ok(schema, `unknown schema ref ${ref}`);
  return schema;
}

function validateAgainstSchema(value, schema, path = '$') {
  if (schema.$ref) {
    validateAgainstSchema(value, resolveSchemaRef(schema.$ref), path);
    return;
  }
  if (value === null) {
    assert.ok(schema.nullable === true, `${path} is null but schema is not nullable`);
    return;
  }
  if (schema.enum) {
    assert.ok(schema.enum.includes(value), `${path} = ${JSON.stringify(value)} is not one of ${JSON.stringify(schema.enum)}`);
  }
  if (schema.type === 'object' || (schema.properties && schema.type === undefined)) {
    assert.ok(value !== null && typeof value === 'object' && !Array.isArray(value), `${path} should be an object`);
    const properties = schema.properties ?? {};
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        assert.ok(key in properties, `${path}.${key} is not a documented property (additionalProperties: false)`);
      }
    }
    for (const required of schema.required ?? []) {
      assert.ok(required in value, `${path} is missing required property ${required}`);
    }
    for (const [key, propSchema] of Object.entries(properties)) {
      if (value[key] !== undefined) {
        validateAgainstSchema(value[key], propSchema, `${path}.${key}`);
      }
    }
    return;
  }
  if (schema.type === 'array') {
    assert.ok(Array.isArray(value), `${path} should be an array`);
    if (typeof schema.maxItems === 'number') {
      assert.ok(value.length <= schema.maxItems, `${path} has ${value.length} items, more than maxItems ${schema.maxItems}`);
    }
    if (schema.items) {
      value.forEach((item, index) => validateAgainstSchema(item, schema.items, `${path}[${index}]`));
    }
    return;
  }
  if (schema.type === 'string') {
    assert.strictEqual(typeof value, 'string', `${path} should be a string`);
    if (typeof schema.maxLength === 'number') {
      assert.ok(value.length <= schema.maxLength, `${path} is longer than maxLength ${schema.maxLength}`);
    }
    return;
  }
  if (schema.type === 'boolean') {
    assert.strictEqual(typeof value, 'boolean', `${path} should be a boolean`);
    return;
  }
}

test('Scenario: Contract fixture round-trips and validates', async (t) => {
  // Given contract/testdata/messages/checkin-request-with-defender-hardening.json
  const fixture = JSON.parse(
    readFileSync(join(messagesDir, 'checkin-request-with-defender-hardening.json'), 'utf-8'),
  );

  // Then it validates against CheckInRequest in contract/openapi.yaml
  assert.doesNotThrow(() => validateAgainstSchema(fixture, openapi.components.schemas.CheckInRequest));

  // And an item "unknown" or a state "partial" fails schema validation
  const schema = openapi.components.schemas.DefenderHardening;
  const withUnknownItem = { evaluatedAt: '2026-10-11T10:00:00Z', items: [{ item: 'unknown', state: 'ok' }] };
  assert.throws(() => validateAgainstSchema(withUnknownItem, schema));

  const withBadState = { evaluatedAt: '2026-10-11T10:00:00Z', items: [{ item: 'networkProtection', state: 'partial' }] };
  assert.throws(() => validateAgainstSchema(withBadState, schema));
});

test('Scenario (edge): A valid block with every item and state validates cleanly', async (t) => {
  const schema = openapi.components.schemas.DefenderHardening;
  const itemNames = schema.properties.items.items.properties.item.enum;
  const stateNames = schema.properties.items.items.properties.state.enum;

  assert.strictEqual(itemNames.length, 14);
  const block = {
    evaluatedAt: '2026-10-11T10:00:00Z',
    items: itemNames.map((item, i) => ({ item, state: stateNames[i % stateNames.length] })),
  };
  assert.doesNotThrow(() => validateAgainstSchema(block, schema));
});

test('Scenario (edge): more than 14 items fails maxItems', async (t) => {
  const schema = openapi.components.schemas.DefenderHardening;
  const itemNames = schema.properties.items.items.properties.item.enum;
  const block = {
    evaluatedAt: '2026-10-11T10:00:00Z',
    items: [...itemNames, itemNames[0]].map((item) => ({ item, state: 'ok' })),
  };
  assert.throws(() => validateAgainstSchema(block, schema));
});
