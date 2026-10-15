/**
 * E2E cucumber-style tests for TASK-044's bootstrap wiring of the heartbeat
 * CloudWatch Logs store: `backend/src/bootstrap.ts` builds it from the
 * injected `createLogsClient` only when `HEARTBEAT_LOG_GROUP` is set and
 * non-empty, and passes it to both the device heartbeat route and the admin
 * routes.
 *
 * All AWS clients are stubbed in-process; no real connection of any kind is
 * made.
 */

import test from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { bootstrap, REQUIRED_ENV } from '../dist/bootstrap.js';
import { resolveHeartbeatDependencies } from '../dist/routes/heartbeat.js';
import { resolveAdminDependencies } from '../dist/admin/router.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ============================================================================
// Scenario: The CloudWatch Logs SDK is pinned (AC8)
// ============================================================================

test('Scenario: backend/package.json pins @aws-sdk/client-cloudwatch-logs at 3.1146.0', () => {
  const pkg = JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf8'));
  assert.strictEqual(pkg.dependencies['@aws-sdk/client-cloudwatch-logs'], '3.1146.0');
});

function completeEnv(overrides = {}) {
  return {
    TABLE_NAME: 'mdm-table',
    PEPPER_SECRET_ARN: 'arn:secret',
    ENTRA_TENANT_ID: 'tenant',
    ENTRA_CLIENT_ID: 'client',
    ...overrides,
  };
}

function fakeFactories() {
  return {
    createDocumentClient: () => ({ send: async () => ({}) }),
    createSecretsClient: () => ({ send: async () => ({ SecretString: 'pepper' }) }),
    fetchImpl: async () => ({ status: 200, json: async () => ({ keys: [] }) }),
  };
}

// ============================================================================
// Scenario Outline: Bootstrap wires the heartbeat log only when configured (AC11)
// ============================================================================

const cases = [
  { label: '"/sk-mdm/heartbeats"', env: { HEARTBEAT_LOG_GROUP: '/sk-mdm/heartbeats' }, times: 1, present: true },
  { label: 'absent', env: {}, times: 0, present: false },
  { label: '""', env: { HEARTBEAT_LOG_GROUP: '' }, times: 0, present: false },
];

for (const tc of cases) {
  test(`Scenario Outline: Bootstrap wires the heartbeat log only when configured (${tc.label})`, async () => {
    let createLogsClientCalls = 0;
    const result = await bootstrap({
      env: completeEnv(tc.env),
      ...fakeFactories(),
      createLogsClient: () => {
        createLogsClientCalls += 1;
        return { send: async () => ({}) };
      },
    }).catch((error) => error);

    assert.ok(!(result instanceof Error), `bootstrap should not throw: ${result?.message}`);
    assert.strictEqual(createLogsClientCalls, tc.times);

    const heartbeatDeps = resolveHeartbeatDependencies();
    const adminDeps = resolveAdminDependencies();
    if (tc.present) {
      assert.ok(heartbeatDeps.heartbeatLog !== undefined, 'heartbeat route received heartbeatLog');
      assert.ok(adminDeps.heartbeatLog !== undefined, 'admin routes received heartbeatLog');
    } else {
      assert.strictEqual(heartbeatDeps.heartbeatLog, undefined);
      assert.strictEqual(adminDeps.heartbeatLog, undefined);
    }
  });
}

test('Scenario: Bootstrap with no createLogsClient option defaults without throwing when unconfigured', async () => {
  const result = await bootstrap({ env: completeEnv(), ...fakeFactories() }).catch((error) => error);
  assert.ok(!(result instanceof Error), `bootstrap should not throw: ${result?.message}`);
  assert.strictEqual(resolveHeartbeatDependencies().heartbeatLog, undefined);
});

test('Scenario: REQUIRED_ENV is unchanged by the heartbeat wiring', () => {
  assert.deepStrictEqual([...REQUIRED_ENV], ['TABLE_NAME', 'PEPPER_SECRET_ARN', 'ENTRA_TENANT_ID', 'ENTRA_CLIENT_ID']);
});
