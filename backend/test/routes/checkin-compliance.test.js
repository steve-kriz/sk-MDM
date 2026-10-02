/**
 * E2E and unit tests for compliance state computation during check-in (TASK-012).
 * Tests the Gherkin scenarios for policy compliance reporting and state calculation.
 * Mock all database calls — no real DB connections.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const {
  createCheckInHandler,
} = await import(
  `file://${join(__dirname, '../../dist/routes/checkin.js')}`
);

const { deviceProfile, deviceCompliance } = await import(
  `file://${join(__dirname, '../../dist/db/keys.js')}`
);

const {
  computeComplianceState,
  COMPLIANT_STATE,
  NONCOMPLIANT_STATE,
  UNKNOWN_STATE,
} = await import(
  `file://${join(__dirname, '../../dist/policies/resolve.js')}`
);

// ============================================================================
// Mock Table Client
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
    this.queryResponses = [];
  }

  keyStr(key) {
    return JSON.stringify({ pk: key.pk, sk: key.sk });
  }

  async get(key) {
    return this.items.get(this.keyStr(key));
  }

  async put(item) {
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  async putIfAbsent(item) {
    const keyStr = this.keyStr({ pk: item.pk, sk: item.sk });
    if (this.items.has(keyStr)) {
      return { written: false };
    }
    this.items.set(keyStr, { ...item });
    return { written: true };
  }

  async update(key, fields) {
    const existing = this.items.get(this.keyStr(key)) || {};
    const updated = { ...existing, ...key };
    this.items.set(this.keyStr(key), updated);
    return updated;
  }

  async query(request) {
    if (this.queryResponses.length > 0) {
      return this.queryResponses.shift();
    }
    return { items: [], cursor: null };
  }

  seedItem(item) {
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  seedQueryResponses(responses) {
    this.queryResponses = [...responses];
  }
}

function createFakeVerifier(deviceIdToReturn = 'test-device-id', authOk = true) {
  return async (req, options) => {
    if (!authOk) {
      return { ok: false, status: 401, body: { error: 'bad_signature' } };
    }
    return { ok: true, deviceId: deviceIdToReturn };
  };
}

function createCheckInRequest(deviceId = 'test-device-id', policyCompliance = []) {
  return {
    method: 'POST',
    path: `/api/v1/devices/${deviceId}/checkin`,
    query: {},
    headers: {
      'x-mdm-device-id': deviceId,
      'x-mdm-timestamp': Math.floor(Date.now() / 1000).toString(),
      'x-mdm-nonce': 'test-nonce-value',
      'x-mdm-signature': 'test-signature-value',
    },
    params: { deviceId },
    body: JSON.stringify({
      collectedAt: '2026-10-02T11:00:00Z',
      inventory: {
        hardware: {
          manufacturer: 'Dell',
          model: 'Test',
          serialNumber: 'SN123',
          cpu: 'Intel',
          ramBytes: 16000000000,
          diskBytes: 500000000000,
        },
        os: { name: 'Windows', version: '11', build: '22621', architecture: 'x86_64' },
        software: [],
        warnings: [],
      },
      posture: {
        diskEncryption: { enabled: true, method: 'bitlocker' },
        firewall: { enabled: true },
        antivirus: { name: 'Windows Defender', enabled: true, definitionsAgeDays: 1 },
        osUpdate: { lastCheckedAt: '2026-10-02T10:00:00Z', pendingCount: 0, rebootRequired: false },
        localAdmins: [],
        warnings: [],
      },
      policyCompliance,
    }),
  };
}

// ============================================================================
// Unit Tests for computeComplianceState
// ============================================================================

test('Unit: Scenario: Compliance report flips device state to noncompliant', (t) => {
  const assignedPolicies = ['p1'];
  const results = [{ policyId: 'p1', compliant: false }];
  const state = computeComplianceState(assignedPolicies, results);
  assert.strictEqual(state, NONCOMPLIANT_STATE);
});

test('Unit: Scenario: All-compliant report sets compliant', (t) => {
  const assignedPolicies = ['p1', 'p2'];
  const results = [
    { policyId: 'p1', compliant: true },
    { policyId: 'p2', compliant: true },
  ];
  const state = computeComplianceState(assignedPolicies, results);
  assert.strictEqual(state, COMPLIANT_STATE);
});

test('Unit: Scenario: Omitting an assigned policy is not compliant', (t) => {
  const assignedPolicies = ['p1', 'p2'];
  const results = [{ policyId: 'p1', compliant: true }];
  const state = computeComplianceState(assignedPolicies, results);
  assert.strictEqual(state, NONCOMPLIANT_STATE);
});

test('Unit: Scenario: A device that has never reported is unknown', (t) => {
  const assignedPolicies = ['p1'];
  const results = [];
  const state = computeComplianceState(assignedPolicies, results);
  assert.strictEqual(state, UNKNOWN_STATE);
});

test('Unit: Scenario: A device with no assigned policy is unknown', (t) => {
  const assignedPolicies = [];
  const results = [];
  const state = computeComplianceState(assignedPolicies, results);
  assert.strictEqual(state, UNKNOWN_STATE);
});

test('Unit: Scenario: Unassigned policy result is ignored', (t) => {
  const assignedPolicies = ['p1'];
  const results = [
    { policyId: 'p1', compliant: true },
    { policyId: 'p9', compliant: false },
  ];
  const state = computeComplianceState(assignedPolicies, results);
  assert.strictEqual(state, COMPLIANT_STATE);
});

test('Unit: Compliance state with one false result among compliant', (t) => {
  const assignedPolicies = ['p1', 'p2', 'p3'];
  const results = [
    { policyId: 'p1', compliant: true },
    { policyId: 'p2', compliant: false },
    { policyId: 'p3', compliant: true },
  ];
  const state = computeComplianceState(assignedPolicies, results);
  assert.strictEqual(state, NONCOMPLIANT_STATE);
});

test('Unit: Partial results with all compliant entries is noncompliant', (t) => {
  const assignedPolicies = ['p1', 'p2', 'p3'];
  const results = [
    { policyId: 'p1', compliant: true },
    { policyId: 'p2', compliant: true },
  ];
  const state = computeComplianceState(assignedPolicies, results);
  assert.strictEqual(state, NONCOMPLIANT_STATE);
});

// ============================================================================
// E2E Tests for Check-in with Compliance
// ============================================================================

test('Scenario: Check-in accepts policyCompliance array without error', async (t) => {
  const table = new FakeTable();
  const deviceId = 'test-device-id';

  const profileKey = deviceProfile(deviceId);
  table.seedItem({
    ...profileKey,
    deviceId,
    hostname: 'test-host',
    complianceState: UNKNOWN_STATE,
  });

  table.seedQueryResponses([
    { items: [], cursor: null },
  ]);

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const request = createCheckInRequest(deviceId, [
    { policyId: 'p1', version: 1, compliant: false, violations: ['firewall_disabled'] },
  ]);

  const result = await handler(request);
  assert.strictEqual(result.statusCode, 200);
});

test('Scenario: Check-in with empty policyCompliance array is accepted', async (t) => {
  const table = new FakeTable();
  const deviceId = 'test-device-id';

  const profileKey = deviceProfile(deviceId);
  table.seedItem({
    ...profileKey,
    deviceId,
    hostname: 'test-host',
    complianceState: UNKNOWN_STATE,
  });

  table.seedQueryResponses([
    { items: [], cursor: null },
  ]);

  const handler = createCheckInHandler({
    table,
    pepper: 'a'.repeat(64),
    now: () => new Date('2026-10-02T12:00:00Z'),
    verifyDevice: createFakeVerifier(deviceId, true),
  });

  const request = createCheckInRequest(deviceId, []);
  const result = await handler(request);

  assert.strictEqual(result.statusCode, 200);
});
