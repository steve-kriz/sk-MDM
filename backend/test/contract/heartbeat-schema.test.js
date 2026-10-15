/**
 * E2E cucumber-style tests for TASK-044's OpenAPI schema additions (AC1, AC2):
 * CheckInResponse.heartbeatIntervalSeconds, and the new HeartbeatRequest /
 * HeartbeatResponse schemas on POST /api/v1/devices/{deviceId}/heartbeat.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import YAML from 'yaml';

const __dirname = dirname(fileURLToPath(import.meta.url));
const openapi = YAML.parse(readFileSync(join(__dirname, '../../../contract/openapi.yaml'), 'utf-8'));

// ============================================================================
// Scenario: OpenAPI declares the optional check-in heartbeat interval (AC1)
// ============================================================================

test('Scenario: CheckInResponse.heartbeatIntervalSeconds is a pinned optional integer enum', () => {
  const schema = openapi.components.schemas.CheckInResponse;
  const property = schema.properties.heartbeatIntervalSeconds;

  assert.strictEqual(property.type, 'integer');
  assert.deepStrictEqual(property.enum, [60, 300, 900, 1800, 3600]);
  assert.ok(typeof property.description === 'string' && property.description.length > 0);
  assert.match(property.description, /only when.*heartbeat.*on/i);

  assert.ok(!schema.required.includes('heartbeatIntervalSeconds'));
  assert.strictEqual(schema.additionalProperties, false);
});

// ============================================================================
// Scenario: OpenAPI declares the heartbeat endpoint and schemas (AC2)
// ============================================================================

test('Scenario: POST /api/v1/devices/{deviceId}/heartbeat is declared', () => {
  const path = openapi.paths['/api/v1/devices/{deviceId}/heartbeat'];
  assert.ok(path, 'path should exist');
  assert.ok(path.post, 'post operation should exist');
});

test('Scenario: HeartbeatRequest requires collectedAt and performance, refs AnalyticsPerformance', () => {
  const schema = openapi.components.schemas.HeartbeatRequest;
  assert.ok(schema, 'HeartbeatRequest schema should exist');
  assert.deepStrictEqual([...schema.required].sort(), ['collectedAt', 'performance'].sort());
  assert.strictEqual(schema.properties.collectedAt.type, 'string');
  assert.strictEqual(schema.properties.collectedAt.format, 'date-time');
  assert.strictEqual(schema.properties.performance.$ref, '#/components/schemas/AnalyticsPerformance');
  assert.strictEqual(schema.properties.warnings.type, 'array');
  assert.strictEqual(schema.properties.warnings.items.type, 'string');
  assert.strictEqual(schema.additionalProperties, false);
});

test('Scenario: HeartbeatResponse requires heartbeatIntervalSeconds with the off-inclusive enum', () => {
  const schema = openapi.components.schemas.HeartbeatResponse;
  assert.ok(schema, 'HeartbeatResponse schema should exist');
  assert.deepStrictEqual(schema.required, ['heartbeatIntervalSeconds']);
  const property = schema.properties.heartbeatIntervalSeconds;
  assert.strictEqual(property.type, 'integer');
  assert.deepStrictEqual(property.enum, [0, 60, 300, 900, 1800, 3600]);
  assert.strictEqual(schema.additionalProperties, false);
});

test('Scenario: HeartbeatRequest.network is an optional array of HeartbeatNetworkAdapter', () => {
  const schema = openapi.components.schemas.HeartbeatRequest;
  assert.ok(!schema.required.includes('network'));
  assert.strictEqual(schema.properties.network.type, 'array');
  assert.strictEqual(schema.properties.network.maxItems, 8);
  assert.strictEqual(schema.properties.network.items.$ref, '#/components/schemas/HeartbeatNetworkAdapter');

  const adapter = openapi.components.schemas.HeartbeatNetworkAdapter;
  assert.strictEqual(adapter.additionalProperties, false);
  const fixture = JSON.parse(
    readFileSync(join(__dirname, '../../../contract/testdata/messages/heartbeat-request-with-network.json'), 'utf-8'),
  );
  for (const entry of fixture.network) {
    assert.deepStrictEqual(Object.keys(entry).sort(), [...adapter.required].sort());
    assert.deepStrictEqual(Object.keys(adapter.properties).sort(), [...adapter.required].sort());
  }
});
