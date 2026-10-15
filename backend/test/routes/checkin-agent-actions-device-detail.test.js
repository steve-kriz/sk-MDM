/**
 * E2E test for TASK-070 AC20: an agent action accepted on check-in shows up
 * in the device detail's `deviceEvents` and renders as a History row. All
 * database calls are mocked; no real DB connection is ever made.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

const { createCheckInHandler } = await import(`file://${join(__dirname, '../../dist/routes/checkin.js')}`);
const { handleDeviceDetail } = await import(`file://${join(__dirname, '../../dist/admin/devices.js')}`);
const { deviceProfile } = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);
const { render } = await import(`file://${join(__dirname, '../../dist/ui/views/deviceDetail.js')}`);
const { FakeTable } = await import('../helpers/fakeTable.js');

const randomHex = (bytes = 32) => randomBytes(bytes).toString('hex');

const fullBody = {
  collectedAt: '2026-10-12T01:00:00Z',
  agentVersion: '1.4.0',
  inventory: {
    hardware: { manufacturer: 'Dell', model: 'OptiPlex', serialNumber: 'S1', cpu: 'i7', ramBytes: 1, diskBytes: 1 },
    os: { name: 'Windows', version: '11', build: '22621', architecture: 'x86_64' },
    software: [],
    warnings: [],
  },
  posture: {
    diskEncryption: { enabled: true, method: 'bitlocker' },
    firewall: { enabled: true },
    antivirus: { name: 'Microsoft Defender', enabled: true, definitionsAgeDays: 1 },
    screenLock: { enabled: true, timeoutSeconds: 300 },
    osUpdates: { pendingCount: 0, lastInstalledAt: null },
    warnings: [],
  },
  agentActions: [{ type: 'enforce.firewall_enabled', occurredAt: '2026-10-12T00:59:00Z', details: {} }],
};

function checkInRequest(deviceId, body) {
  return {
    method: 'POST',
    path: `/api/v1/devices/${deviceId}/checkin`,
    query: {},
    headers: {
      'x-mdm-device-id': deviceId,
      'x-mdm-timestamp': Math.floor(Date.now() / 1000).toString(),
      'x-mdm-nonce': randomHex(16),
      'x-mdm-signature': randomHex(32),
    },
    params: { deviceId },
    body: JSON.stringify(body),
  };
}

// ============================================================================
// Scenario: The action shows in the device detail and History (AC20)
// ============================================================================

test('Scenario: The action shows in the device detail and History (AC20)', async () => {
  const table = new FakeTable();
  table.seed({ ...deviceProfile('dev-1'), deviceId: 'dev-1', platform: 'windows' });
  const now = new Date('2026-10-12T01:00:00Z');

  // Given a check-in with one "enforce.firewall_enabled" action was accepted
  // for "dev-1"
  const checkinHandler = createCheckInHandler({
    table,
    pepper: randomHex(32),
    now: () => now,
    verifyDevice: async (req) => ({ ok: true, deviceId: req.params.deviceId }),
  });
  const checkinResult = await checkinHandler(checkInRequest('dev-1', fullBody));
  assert.strictEqual(checkinResult.statusCode, 200, JSON.stringify(checkinResult.body));

  // When GET /admin/api/v1/devices/dev-1 is called
  const detailResult = await handleDeviceDetail(
    { params: { deviceId: 'dev-1' }, query: {}, headers: {} },
    { table, now: () => now },
  );
  assert.strictEqual(detailResult.statusCode, 200, JSON.stringify(detailResult.body));

  // Then deviceEvents holds that event with source "agent", summary "Firewall
  // turned on by policy", details {} and actor null
  const { deviceEvents } = detailResult.body;
  const event = deviceEvents.find((e) => e.type === 'enforce.firewall_enabled');
  assert.ok(event, `expected a firewall_enabled event, got ${JSON.stringify(deviceEvents)}`);
  assert.strictEqual(event.source, 'agent');
  assert.strictEqual(event.summary, 'Firewall turned on by policy');
  assert.deepStrictEqual(event.details, {});
  assert.strictEqual(event.actor, null);
  assert.strictEqual(event.occurredAt, '2026-10-12T00:59:00Z');

  // And the rendered History has a "device-event" row with Source "agent" and
  // Action "Firewall turned on by policy"
  const html = render({
    profile: { deviceId: 'dev-1', timeZone: 'Australia/Sydney' },
    deviceEvents,
    commands: [],
  });
  const historySection = html.match(/<section class="panel" id="detail-commands">[\s\S]*?<\/section>/)[0];
  assert.ok(historySection.includes('class="device-event"'), 'expected a device-event row');
  assert.ok(historySection.includes('>agent<'), 'expected the Source cell to read "agent"');
  assert.ok(historySection.includes('Firewall turned on by policy'), 'expected the Action cell to read the summary');
});
