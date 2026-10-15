/**
 * TASK-041: Tests for AC11-AC15: device disable/enable and credential section.
 * Device credentials can be disabled (status = 'revoked') and re-enabled.
 * The device detail shows the credential status and enrollment token info.
 *
 * The table is an in-memory fake; nothing reaches DynamoDB.
 */

import test from 'node:test';
import assert from 'node:assert';
import { handleDeviceDisable, handleDeviceEnable, handleDeviceDetail } from '../../dist/admin/devices.js';
import { deviceProfile, enrollmentToken } from '../../dist/db/keys.js';
import { isoUtc } from '../../dist/audit.js';

class FakeTable {
  constructor(items = []) {
    this.items = new Map();
    this.audits = [];
    for (const item of items) {
      this.items.set(`${item.pk}|${item.sk}`, { ...item });
      if (String(item.pk).startsWith('AUDIT#')) {
        this.audits.push(item);
      }
    }
  }

  async get(key) {
    return this.items.get(`${key.pk}|${key.sk}`);
  }

  async update(key, fields) {
    const keyStr = `${key.pk}|${key.sk}`;
    const existing = this.items.get(keyStr) || { pk: key.pk, sk: key.sk };
    const updated = { ...existing };

    // Handle SET operations for disable
    if (fields?.UpdateExpression?.includes('SET')) {
      const values = fields.ExpressionAttributeValues || {};
      if (values[':status'] !== undefined) {
        updated.status = values[':status'];
      }
      if (values[':disabledAt'] !== undefined) {
        updated.disabledAt = values[':disabledAt'];
      }
      if (values[':disabledBy'] !== undefined) {
        updated.disabledBy = values[':disabledBy'];
      }
    }

    // Handle REMOVE operations for enable
    if (fields?.UpdateExpression?.includes('REMOVE')) {
      delete updated.status;
      delete updated.disabledAt;
      delete updated.disabledBy;
    }

    this.items.set(keyStr, updated);
    return updated;
  }

  async put(item) {
    this.items.set(`${item.pk}|${item.sk}`, { ...item });
    if (String(item.pk).startsWith('AUDIT#')) {
      this.audits.push(item);
    }
  }

  async query(request) {
    return { items: [], cursor: null };
  }
}

// ============================================================================
// AC11: Disable device endpoint
// ============================================================================

test('AC11 E2E: Disable device returns 200 with credential.status disabled', async () => {
  const table = new FakeTable([
    { ...deviceProfile('dev-1'), deviceId: 'dev-1', hostname: 'host-1' },
  ]);

  const now = new Date('2026-10-02T12:00:00Z');
  const result = await handleDeviceDisable(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {}, claims: { preferred_username: 'admin@contoso.com' } },
    { table, now: () => now }
  );

  assert.strictEqual(result.statusCode, 200);
  const body = result.body;
  assert.strictEqual(body.deviceId, 'dev-1');
  assert(body.credential);
  assert.strictEqual(body.credential.status, 'disabled');
});

test('AC11 Unit: Disable sets status revoked and disabledAt/disabledBy in one update', async () => {
  const table = new FakeTable([
    { ...deviceProfile('dev-1'), deviceId: 'dev-1', hostname: 'host-1' },
  ]);

  const now = new Date('2026-10-02T12:00:00Z');
  await handleDeviceDisable(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {}, claims: { preferred_username: 'admin@contoso.com' } },
    { table, now: () => now }
  );

  const profile = await table.get(deviceProfile('dev-1'));
  assert.strictEqual(profile.status, 'revoked');
  assert(profile.disabledAt);
  assert.strictEqual(profile.disabledBy, 'admin@contoso.com');
});

test('AC11 AC10 Unit: Disable appends audit device.disabled with source admin', async () => {
  const table = new FakeTable([
    { ...deviceProfile('dev-1'), deviceId: 'dev-1', hostname: 'host-1' },
  ]);

  const now = new Date('2026-10-02T12:00:00Z');
  await handleDeviceDisable(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {}, claims: { preferred_username: 'admin@contoso.com' } },
    { table, now: () => now }
  );

  const audits = table.audits;
  const disableAudit = audits.find((a) => a.action === 'device.disabled');
  assert(disableAudit, 'device.disabled audit should be written');
  assert.strictEqual(disableAudit.target, 'dev-1');
  assert.deepStrictEqual(disableAudit.detail, { source: 'admin' });
});

// ============================================================================
// AC12: Enable device endpoint
// ============================================================================

test('AC12 E2E: Enable device returns 200 with credential.status active', async () => {
  const now = new Date('2026-10-02T12:00:00Z');
  const table = new FakeTable([
    {
      ...deviceProfile('dev-1'),
      deviceId: 'dev-1',
      hostname: 'host-1',
      status: 'revoked',
      disabledAt: '2026-10-01T12:00:00Z',
      disabledBy: 'admin-user',
    },
  ]);

  const result = await handleDeviceEnable(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {}, claims: { preferred_username: 'admin@contoso.com' } },
    { table, now: () => now }
  );

  assert.strictEqual(result.statusCode, 200);
  const body = result.body;
  assert.strictEqual(body.deviceId, 'dev-1');
  assert(body.credential);
  assert.strictEqual(body.credential.status, 'active');
});

test('AC12 Unit: Enable removes status, disabledAt, disabledBy', async () => {
  const now = new Date('2026-10-02T12:00:00Z');
  const table = new FakeTable([
    {
      ...deviceProfile('dev-1'),
      deviceId: 'dev-1',
      hostname: 'host-1',
      status: 'revoked',
      disabledAt: '2026-10-01T12:00:00Z',
      disabledBy: 'admin-user',
    },
  ]);

  await handleDeviceEnable(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {}, claims: { preferred_username: 'admin@contoso.com' } },
    { table, now: () => now }
  );

  const profile = await table.get(deviceProfile('dev-1'));
  assert.strictEqual(profile.status, undefined);
  assert.strictEqual(profile.disabledAt, undefined);
  assert.strictEqual(profile.disabledBy, undefined);
});

test('AC12 Unit: Enable does not read or write token record', async () => {
  const now = new Date('2026-10-02T12:00:00Z');
  const table = new FakeTable([
    {
      ...deviceProfile('dev-1'),
      deviceId: 'dev-1',
      hostname: 'host-1',
      status: 'revoked',
      disabledAt: '2026-10-01T12:00:00Z',
      disabledBy: 'admin-user',
      enrollmentTokenId: 'token-123',
    },
    {
      ...enrollmentToken('token-123'),
      tokenId: 'token-123',
      label: 'test-token',
      useCount: 1,
    },
  ]);

  await handleDeviceEnable(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {}, claims: { preferred_username: 'admin@contoso.com' } },
    { table, now: () => now }
  );

  // Token record should be unchanged
  const token = await table.get(enrollmentToken('token-123'));
  assert.strictEqual(token.useCount, 1, 'token record should not be modified');
});

// ============================================================================
// AC13: Error cases for disable/enable
// ============================================================================

test('AC13 Edge: Disable already-disabled device returns 409 already_disabled', async () => {
  const table = new FakeTable([
    {
      ...deviceProfile('dev-1'),
      deviceId: 'dev-1',
      hostname: 'host-1',
      status: 'revoked',
      disabledAt: '2026-10-01T12:00:00Z',
      disabledBy: 'admin-user',
    },
  ]);

  const now = new Date('2026-10-02T12:00:00Z');
  const result = await handleDeviceDisable(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {}, claims: { preferred_username: 'admin@contoso.com' } },
    { table, now: () => now }
  );

  assert.strictEqual(result.statusCode, 409);
  const body = result.body;
  assert.strictEqual(body.error, 'already_disabled');
});

test('AC13 Edge: Enable active device returns 409 not_disabled', async () => {
  const table = new FakeTable([
    { ...deviceProfile('dev-1'), deviceId: 'dev-1', hostname: 'host-1' },
  ]);

  const now = new Date('2026-10-02T12:00:00Z');
  const result = await handleDeviceEnable(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {}, claims: { preferred_username: 'admin@contoso.com' } },
    { table, now: () => now }
  );

  assert.strictEqual(result.statusCode, 409);
  const body = result.body;
  assert.strictEqual(body.error, 'not_disabled');
});

test('AC13 Edge: Disable unknown device returns 404', async () => {
  const table = new FakeTable([]);

  const now = new Date('2026-10-02T12:00:00Z');
  const result = await handleDeviceDisable(
    { params: { deviceId: 'unknown-dev' }, query: {}, headers: {}, claims: { preferred_username: 'admin@contoso.com' } },
    { table, now: () => now }
  );

  assert.strictEqual(result.statusCode, 404);
  const body = result.body;
  assert.strictEqual(body.error, 'not_found');
});

test('AC13 Edge: Enable unknown device returns 404', async () => {
  const table = new FakeTable([]);

  const now = new Date('2026-10-02T12:00:00Z');
  const result = await handleDeviceEnable(
    { params: { deviceId: 'unknown-dev' }, query: {}, headers: {}, claims: { preferred_username: 'admin@contoso.com' } },
    { table, now: () => now }
  );

  assert.strictEqual(result.statusCode, 404);
  const body = result.body;
  assert.strictEqual(body.error, 'not_found');
});

// ============================================================================
// AC15: Device detail credential section
// ============================================================================

test('AC15 E2E: Device detail includes credential section with status and token info', async () => {
  const now = new Date('2026-10-02T12:00:00Z');
  const table = new FakeTable([
    {
      ...deviceProfile('dev-1'),
      deviceId: 'dev-1',
      hostname: 'host-1',
      enrollmentTokenId: 'token-123',
      enrolledAt: '2026-10-01T10:00:00Z',
    },
    {
      ...enrollmentToken('token-123'),
      tokenId: 'token-123',
      label: 'sign-in a@x',
      createdBy: 'amy@contoso.com',
      createdAt: '2026-10-01T10:00:00Z',
      maxUses: 1,
      useCount: 1,
      expiresAt: '2026-10-31T11:00:00Z', // Future expiry
    },
  ]);

  const result = await handleDeviceDetail(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {} },
    { table, now: () => now }
  );

  assert.strictEqual(result.statusCode, 200);
  const body = result.body;
  assert(body.credential);
  assert.strictEqual(body.credential.status, 'active');
  assert(body.credential.enrollmentToken);
  assert.strictEqual(body.credential.enrollmentToken.tokenId, 'token-123');
  assert.strictEqual(body.credential.enrollmentToken.label, 'sign-in a@x');
  assert.strictEqual(body.credential.enrollmentToken.status, 'used');
});

test('AC15 E2E: Device detail shows disabled device with empty token fields', async () => {
  const table = new FakeTable([
    {
      ...deviceProfile('dev-1'),
      deviceId: 'dev-1',
      hostname: 'host-1',
      status: 'revoked',
      disabledAt: '2026-10-01T12:00:00Z',
      disabledBy: 'admin-user',
    },
  ]);

  const result = await handleDeviceDetail(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {} },
    { table }
  );

  assert.strictEqual(result.statusCode, 200);
  const body = result.body;
  assert(body.credential);
  assert.strictEqual(body.credential.status, 'disabled');
  assert.strictEqual(body.credential.disabledAt, '2026-10-01T12:00:00Z');
  assert.strictEqual(body.credential.disabledBy, 'admin-user');
  assert.strictEqual(body.credential.enrollmentToken, null);
});

test('AC15 Edge: Device without enrollmentTokenId shows credential with null token', async () => {
  const table = new FakeTable([
    { ...deviceProfile('dev-1'), deviceId: 'dev-1', hostname: 'host-1' },
  ]);

  const result = await handleDeviceDetail(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {} },
    { table }
  );

  assert.strictEqual(result.statusCode, 200);
  const body = result.body;
  assert(body.credential);
  assert.strictEqual(body.credential.status, 'active');
  assert.strictEqual(body.credential.enrollmentToken, null);
});

test('AC15 Edge: Missing token record shows credential with null token', async () => {
  const table = new FakeTable([
    {
      ...deviceProfile('dev-1'),
      deviceId: 'dev-1',
      hostname: 'host-1',
      enrollmentTokenId: 'missing-token',
    },
  ]);

  const result = await handleDeviceDetail(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {} },
    { table }
  );

  assert.strictEqual(result.statusCode, 200);
  const body = result.body;
  assert(body.credential);
  assert.strictEqual(body.credential.enrollmentToken, null);
});

test('AC15 Unit: Device detail response contains no secret/hash/pepper keys', async () => {
  const table = new FakeTable([
    {
      ...deviceProfile('dev-1'),
      deviceId: 'dev-1',
      hostname: 'host-1',
      secretEnc: 'should-not-appear',
      tokenHash: 'should-not-appear',
      pepper: 'should-not-appear',
    },
  ]);

  const result = await handleDeviceDetail(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {} },
    { table }
  );

  assert.strictEqual(result.statusCode, 200);
  const body = JSON.stringify(result.body);
  assert(!body.includes('secret'), 'response should not contain "secret"');
  assert(!body.includes('hash'), 'response should not contain "hash"');
  assert(!body.includes('pepper'), 'response should not contain "pepper"');
});
