/**
 * Installer sign-in enrollment: ownership and "enrolled by" in the admin
 * device list and detail views, and the ownership filter.
 *
 * Spec: docs/superpowers/specs/2026-10-09-installer-signin-enrollment-design.md
 * section 2.2. The table is an in-memory fake; nothing reaches DynamoDB.
 */

import test from 'node:test';
import assert from 'node:assert';
import {
  deviceSummary,
  handleDeviceList,
  handleDeviceDetail,
  DEFAULT_OWNERSHIP,
} from '../../dist/admin/devices.js';
import { deviceProfile, deviceListIndex } from '../../dist/db/keys.js';

const devicesView = await import('../../dist/ui/views/devices.js');
const deviceDetailView = await import('../../dist/ui/views/deviceDetail.js');

/** A fake table answering the fleet query and point reads. */
class FakeTable {
  constructor(profiles = []) {
    this.items = new Map();
    for (const profile of profiles) {
      this.put(profile);
    }
  }
  put(item) {
    this.items.set(`${item.pk}|${item.sk}`, { ...item });
  }
  async get(key) {
    return this.items.get(`${key.pk}|${key.sk}`);
  }
  async query(request) {
    const values = request.ExpressionAttributeValues ?? {};
    const items = [...this.items.values()].filter((item) =>
      values[':gsi1pk'] !== undefined ? item.gsi1pk === values[':gsi1pk'] : item.pk === values[':pk'],
    );
    return { items, cursor: null };
  }
}

function profile(deviceId, lastSeenAt, extra = {}) {
  return {
    ...deviceProfile(deviceId),
    ...deviceListIndex(lastSeenAt),
    deviceId,
    hostname: `host-${deviceId}`,
    platform: 'windows',
    osVersion: '10.0',
    agentVersion: '1.0.0',
    lastSeenAt,
    secretEnc: 'should-never-leave',
    ...extra,
  };
}

function fleet() {
  return new FakeTable([
    profile('d-old', '2026-10-09T10:00:00Z'),
    profile('d-office', '2026-10-09T11:00:00Z', {
      ownership: 'officehq',
      enrolledBy: { oid: 'o-1', upn: 'amy@contoso.com', name: 'Amy' },
    }),
    profile('d-byoc', '2026-10-09T12:00:00Z', {
      ownership: 'byoc',
      enrolledBy: { oid: 'o-2', upn: 'bob@contoso.com', name: 'Bob' },
    }),
  ]);
}

async function list(table, query = {}) {
  return handleDeviceList({ method: 'GET', path: '/devices', query, headers: {}, params: {} }, { table });
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

test('Summary: ownership and enrolledBy upn are returned', () => {
  const summary = deviceSummary(
    profile('d1', '2026-10-09T10:00:00Z', {
      ownership: 'byoc',
      enrolledBy: { oid: 'o-1', upn: 'amy@contoso.com', name: 'Amy' },
    }),
  );
  assert.strictEqual(summary.ownership, 'byoc');
  assert.deepStrictEqual(summary.enrolledBy, { upn: 'amy@contoso.com' });
  assert.ok(!('oid' in summary.enrolledBy), 'only the upn reaches the list');
});

test('Summary: a device enrolled before ownership existed reads as officehq with no enrolledBy', () => {
  assert.strictEqual(DEFAULT_OWNERSHIP, 'officehq');
  const summary = deviceSummary(profile('d1', '2026-10-09T10:00:00Z'));
  assert.strictEqual(summary.ownership, 'officehq');
  assert.strictEqual(summary.enrolledBy, null);
});

test('Summary: an unrecognised stored ownership reads as officehq', () => {
  const summary = deviceSummary(profile('d1', '2026-10-09T10:00:00Z', { ownership: 'weird' }));
  assert.strictEqual(summary.ownership, 'officehq');
});

test('Summary: an enrolledBy without a upn reads as null', () => {
  const summary = deviceSummary(profile('d1', '2026-10-09T10:00:00Z', { enrolledBy: { oid: 'o-1', upn: null } }));
  assert.strictEqual(summary.enrolledBy, null);
});

test('List: every item carries ownership; old devices read officehq', async () => {
  const result = await list(fleet());
  assert.strictEqual(result.statusCode, 200);
  const byId = Object.fromEntries(result.body.items.map((item) => [item.deviceId, item]));
  assert.strictEqual(byId['d-old'].ownership, 'officehq');
  assert.strictEqual(byId['d-office'].ownership, 'officehq');
  assert.strictEqual(byId['d-byoc'].ownership, 'byoc');
  assert.deepStrictEqual(byId['d-byoc'].enrolledBy, { upn: 'bob@contoso.com' });
  assert.ok(!JSON.stringify(result.body).includes('should-never-leave'));
});

test('List filter: ownership=byoc returns only BYOC devices', async () => {
  const result = await list(fleet(), { ownership: 'byoc' });
  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(
    result.body.items.map((item) => item.deviceId),
    ['d-byoc'],
  );
});

test('List filter: ownership=officehq includes devices enrolled before ownership existed', async () => {
  const result = await list(fleet(), { ownership: 'officehq' });
  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(
    result.body.items.map((item) => item.deviceId),
    ['d-office', 'd-old'],
  );
});

test('List filter: an empty ownership is no filter', async () => {
  const result = await list(fleet(), { ownership: '' });
  assert.strictEqual(result.body.items.length, 3);
});

test('List filter: an unknown ownership is 400 invalid_request', async () => {
  const result = await list(fleet(), { ownership: 'personal' });
  assert.strictEqual(result.statusCode, 400);
  assert.strictEqual(result.body.error, 'invalid_request');
});

test('Detail: profile carries ownership (defaulted) and enrolledBy', async () => {
  const table = fleet();
  const old = await handleDeviceDetail({ params: { deviceId: 'd-old' }, query: {}, headers: {} }, { table });
  assert.strictEqual(old.statusCode, 200);
  assert.strictEqual(old.body.profile.ownership, 'officehq');
  assert.ok(!('secretEnc' in old.body.profile));

  const byoc = await handleDeviceDetail({ params: { deviceId: 'd-byoc' }, query: {}, headers: {} }, { table });
  assert.strictEqual(byoc.body.profile.ownership, 'byoc');
  assert.deepStrictEqual(byoc.body.profile.enrolledBy, { oid: 'o-2', upn: 'bob@contoso.com', name: 'Bob' });
});

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

test('UI list: an Ownership column shows OfficeHQ / BYOC', () => {
  assert.ok(devicesView.COLUMNS.includes('ownership'));
  const html = devicesView.render({
    items: [
      { deviceId: 'd1', hostname: 'A', ownership: 'officehq' },
      { deviceId: 'd2', hostname: 'B', ownership: 'byoc' },
      { deviceId: 'd3', hostname: 'C' },
    ],
    cursor: null,
  });
  assert.ok(html.includes('<th>Ownership</th>'), 'the column is headed Ownership');
  assert.ok(html.includes('<td class="col-ownership">OfficeHQ</td>'));
  assert.ok(html.includes('<td class="col-ownership">BYOC</td>'));
  // A missing value is an old device: OfficeHQ.
  assert.strictEqual(html.split('<td class="col-ownership">OfficeHQ</td>').length - 1, 2);
});

test('UI list: an ownership filter offers All / OfficeHQ / BYOC with the current one selected', () => {
  const html = devicesView.render({ items: [], cursor: null, ownership: 'byoc' });
  assert.ok(html.includes('class="ownership-filter"'));
  assert.ok(html.includes('<option value="">All</option>'));
  assert.ok(html.includes('<option value="officehq">OfficeHQ</option>'));
  assert.ok(html.includes('<option value="byoc" selected>BYOC</option>'));

  const all = devicesView.render({ items: [], cursor: null });
  assert.ok(all.includes('<option value="" selected>All</option>'));
});

test('UI list: OWNERSHIP_LABELS maps the stored values', () => {
  assert.deepStrictEqual(devicesView.OWNERSHIP_LABELS, { officehq: 'OfficeHQ', byoc: 'BYOC' });
});

test('UI detail: Ownership and Enrolled by are shown', () => {
  const html = deviceDetailView.render({
    profile: {
      deviceId: 'd1',
      ownership: 'byoc',
      enrolledBy: { oid: 'o-1', upn: 'amy@contoso.com', name: 'Amy' },
    },
  });
  assert.ok(html.includes('<span class="label">Ownership</span><span class="value">BYOC</span>'));
  assert.ok(html.includes('<span class="label">Enrolled by</span><span class="value">amy@contoso.com</span>'));
});

test('UI detail: an old device reads OfficeHQ and an em dash for Enrolled by', () => {
  const html = deviceDetailView.render({ profile: { deviceId: 'd1' } });
  assert.ok(html.includes('<span class="label">Ownership</span><span class="value">OfficeHQ</span>'));
  assert.ok(html.includes('<span class="label">Enrolled by</span><span class="value">&mdash;</span>'));
});

test('UI detail: the enrolling upn is escaped', () => {
  const html = deviceDetailView.render({ profile: { deviceId: 'd1', enrolledBy: { upn: '<b>x</b>' } } });
  assert.ok(html.includes('&lt;b&gt;x&lt;/b&gt;'));
  assert.ok(!html.includes('<b>x</b>'));
});
