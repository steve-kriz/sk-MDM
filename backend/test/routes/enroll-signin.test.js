/**
 * Installer sign-in enrollment after spec Amendment B: `POST /api/v1/enroll`
 * accepts the enrollment token only. A token minted by the agent sign-in
 * carries `enrolledBy`, which is copied onto the device profile and named in
 * the audit entry. An `Authorization` header is ignored.
 *
 * Spec: docs/superpowers/specs/2026-10-09-installer-signin-enrollment-design.md
 * sections 2.1, B.2. The table is an in-memory fake; no real DB is touched.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const { createEnrollHandler, ENROLLMENT_TOKEN_HEADER } = await import(
  `file://${join(__dirname, '../../dist/routes/enroll.js')}`
);
const { deviceProfile, deviceByHardware, enrollmentToken } = await import(
  `file://${join(__dirname, '../../dist/db/keys.js')}`
);

const NOW = new Date('2026-10-09T12:00:00Z');
const PEPPER = randomBytes(32).toString('hex');
const BEARER = 'eyJhbGciOiJSUzI1NiJ9.user-token-body.signature';
const AMY = { oid: 'oid-amy', upn: 'amy@contoso.com', name: 'Amy Pond' };

/** An in-memory table recording every call. */
class FakeTable {
  constructor() {
    this.items = new Map();
    this.calls = [];
  }
  keyOf(key) {
    return `${key.pk}|${key.sk}`;
  }
  seed(item) {
    this.items.set(this.keyOf(item), { ...item });
  }
  peek(key) {
    return this.items.get(this.keyOf(key));
  }
  async get(key) {
    this.calls.push({ operation: 'get', key: { ...key } });
    const item = this.items.get(this.keyOf(key));
    return item === undefined ? undefined : { ...item };
  }
  async put(item) {
    this.calls.push({ operation: 'put', item: { ...item } });
    this.items.set(this.keyOf(item), { ...item });
  }
  async putIfAbsent(item) {
    this.calls.push({ operation: 'putIfAbsent', item: { ...item } });
    if (this.items.has(this.keyOf(item))) {
      return { written: false };
    }
    this.items.set(this.keyOf(item), { ...item });
    return { written: true };
  }
  async update(key, fields) {
    this.calls.push({ operation: 'update', key: { ...key }, fields });
    const existing = this.items.get(this.keyOf(key)) ?? { ...key };
    const updated = { ...existing };

    // Detect if this is a claim update (has ':zero' in ExpressionAttributeValues)
    if (fields?.ExpressionAttributeValues?.[':zero'] !== undefined) {
      // This is the use-count claim update
      updated.useCount = (existing.useCount ?? 0) + 1;
    } else if (fields?.UpdateExpression?.includes('list_append')) {
      // This is the deviceIds list_append update
      const deviceIdList = fields?.ExpressionAttributeValues?.[':deviceIdList'];
      if (deviceIdList && Array.isArray(deviceIdList)) {
        const existing_deviceIds = existing.deviceIds || [];
        updated.deviceIds = [...existing_deviceIds, ...deviceIdList];
      }
    }

    this.items.set(this.keyOf(key), updated);
    return updated;
  }
  audits() {
    return this.calls.filter((c) => c.operation === 'put' && String(c.item.pk).startsWith('AUDIT#')).map((c) => c.item);
  }
}

function body(overrides = {}) {
  return {
    hostname: 'LAT-7440',
    platform: 'windows',
    osVersion: '10.0.22631',
    hardwareUuid: 'HW-SIGNIN-001',
    agentVersion: '1.2.3',
    ...overrides,
  };
}

/** Seed a token record; `extra` adds e.g. `enrolledBy`. */
function seedToken(table, extra = {}) {
  const tokenId = randomBytes(8).toString('hex');
  const secret = randomBytes(32).toString('hex');
  const presented = `${tokenId}.${secret}`;
  const tokenHash = createHash('sha256').update(presented, 'utf8').digest('hex');
  table.seed({
    ...enrollmentToken(tokenId),
    tokenId,
    tokenHash,
    maxUses: 1,
    useCount: 0,
    expiresAt: '2026-10-09T13:00:00.000Z',
    ...extra,
  });
  return { tokenId, presented };
}

function request(headers, payload) {
  return { method: 'POST', path: '/api/v1/enroll', query: {}, headers, body: JSON.stringify(payload) };
}

function tokenRequest(presented, payload) {
  return request({ [ENROLLMENT_TOKEN_HEADER]: presented }, payload);
}

function handlerFor(table, extra = {}) {
  return createEnrollHandler({ table, pepper: PEPPER, now: () => NOW, randomBytes, ...extra });
}

// ---------------------------------------------------------------------------
// enrolledBy carried by a sign-in token
// ---------------------------------------------------------------------------

test('Sign-in token: enrolledBy on the token record is copied onto the device profile', async () => {
  const table = new FakeTable();
  const token = seedToken(table, { enrolledBy: AMY });
  const result = await handlerFor(table)(tokenRequest(token.presented, body({ ownership: 'byoc' })));

  assert.equal(result.statusCode, 200);
  const profile = table.peek(deviceProfile(result.body.deviceId));
  assert.deepEqual(profile.enrolledBy, AMY);
  assert.equal(profile.ownership, 'byoc');
  assert.equal(table.peek(enrollmentToken(token.tokenId)).useCount, 1, 'one use is claimed');
});

test('Sign-in token: the audit entry carries enrolledByUpn and ownership, never the token', async () => {
  const table = new FakeTable();
  const token = seedToken(table, { enrolledBy: AMY });
  const result = await handlerFor(table)(tokenRequest(token.presented, body()));
  assert.equal(result.statusCode, 200);

  const audits = table.audits();
  assert.equal(audits.length, 1);
  assert.equal(audits[0].action, 'device.enrolled');
  assert.equal(audits[0].detail.enrolledByUpn, 'amy@contoso.com');
  assert.equal(audits[0].detail.ownership, 'officehq');

  const everything = JSON.stringify([...table.items.values()]);
  assert.ok(!everything.includes(token.presented), 'the token is never stored or audited');
  assert.ok(!everything.includes(result.body.deviceSecret), 'the device secret is never stored in plaintext');
});

test('Sign-in token: an enrolledBy without a upn is copied with nulls and adds no enrolledByUpn', async () => {
  const table = new FakeTable();
  const token = seedToken(table, { enrolledBy: { oid: 'oid-x', upn: null, name: null } });
  const result = await handlerFor(table)(tokenRequest(token.presented, body()));
  assert.equal(result.statusCode, 200);
  assert.deepEqual(table.peek(deviceProfile(result.body.deviceId)).enrolledBy, { oid: 'oid-x', upn: null, name: null });
  assert.equal('enrolledByUpn' in table.audits()[0].detail, false);
});

test('Sign-in token: only oid, upn and name are copied from the record', async () => {
  const table = new FakeTable();
  const token = seedToken(table, { enrolledBy: { ...AMY, extra: 'x', tid: 't' } });
  const result = await handlerFor(table)(tokenRequest(token.presented, body()));
  assert.deepEqual(table.peek(deviceProfile(result.body.deviceId)).enrolledBy, AMY);
});

test('Sign-in token: a re-bind overwrites enrolledBy and ownership with the new enrollment', async () => {
  const table = new FakeTable();
  const token = seedToken(table, { enrolledBy: AMY });
  table.seed({ ...deviceByHardware('HW-SIGNIN-001'), deviceId: 'dev-existing' });
  table.seed({
    ...deviceProfile('dev-existing'),
    deviceId: 'dev-existing',
    groupId: 'g-1',
    ownership: 'officehq',
    enrolledBy: { oid: 'oid-old', upn: 'old@contoso.com', name: 'Old' },
    enrolledAt: '2026-01-01T00:00:00Z',
  });

  const result = await handlerFor(table)(tokenRequest(token.presented, body({ ownership: 'byoc' })));
  assert.equal(result.statusCode, 200);
  assert.equal(result.body.deviceId, 'dev-existing');
  const profile = table.peek(deviceProfile('dev-existing'));
  assert.deepEqual(profile.enrolledBy, AMY);
  assert.equal(profile.ownership, 'byoc');
  assert.equal(profile.groupId, 'g-1', 'other attributes survive a re-bind');
  assert.equal(profile.enrolledAt, '2026-01-01T00:00:00Z');
});

// ---------------------------------------------------------------------------
// Admin-minted (legacy) tokens
// ---------------------------------------------------------------------------

test('Admin token: no enrolledBy on the record stores none and audits no enrolledByUpn', async () => {
  const table = new FakeTable();
  const token = seedToken(table, { maxUses: 2 });
  const result = await handlerFor(table)(tokenRequest(token.presented, body({ ownership: 'byoc' })));
  assert.equal(result.statusCode, 200);
  const profile = table.peek(deviceProfile(result.body.deviceId));
  assert.equal('enrolledBy' in profile, false);
  assert.equal(profile.ownership, 'byoc');
  const detail = table.audits()[0].detail;
  assert.equal(detail.ownership, 'byoc');
  assert.equal('enrolledByUpn' in detail, false);
});

test('Admin token: a re-bind keeps the enrolledBy the profile carried', async () => {
  const table = new FakeTable();
  const token = seedToken(table, { maxUses: 2 });
  table.seed({ ...deviceByHardware('HW-SIGNIN-001'), deviceId: 'dev-carried' });
  table.seed({ ...deviceProfile('dev-carried'), deviceId: 'dev-carried', ownership: 'byoc', enrolledBy: AMY });
  const result = await handlerFor(table)(tokenRequest(token.presented, body()));
  assert.equal(result.statusCode, 200);
  const profile = table.peek(deviceProfile('dev-carried'));
  assert.equal(profile.ownership, 'officehq', 'ownership is always the new enrollment value');
  assert.deepEqual(profile.enrolledBy, AMY);
});

// ---------------------------------------------------------------------------
// The bearer branch is gone
// ---------------------------------------------------------------------------

test('Bearer only: an Authorization header alone answers 401 invalid_enrollment_token and reads nothing', async () => {
  const table = new FakeTable();
  const verifier = { seen: [], async verify(t) { this.seen.push(t); return { oid: 'o' }; } };
  const result = await handlerFor(table, { userVerifier: verifier })(
    request({ Authorization: `Bearer ${BEARER}` }, body()),
  );
  assert.equal(result.statusCode, 401);
  assert.deepEqual(result.body, { error: 'invalid_enrollment_token' });
  assert.deepEqual(table.calls, []);
  assert.deepEqual(verifier.seen, [], 'no verifier is consulted');
  assert.ok(!JSON.stringify(result.body).includes(BEARER));
});

test('Bearer ignored: a bearer alongside a valid token enrolls through the token and claims a use', async () => {
  const table = new FakeTable();
  const token = seedToken(table);
  const result = await handlerFor(table)(
    request({ Authorization: `Bearer ${BEARER}`, [ENROLLMENT_TOKEN_HEADER]: token.presented }, body()),
  );
  assert.equal(result.statusCode, 200);
  assert.equal(table.peek(enrollmentToken(token.tokenId)).useCount, 1);
  assert.equal('enrolledBy' in table.peek(deviceProfile(result.body.deviceId)), false);
  assert.ok(!JSON.stringify([...table.items.values()]).includes(BEARER));
});

test('Neither credential answers 401 invalid_enrollment_token', async () => {
  const table = new FakeTable();
  const result = await handlerFor(table)(request({}, body()));
  assert.equal(result.statusCode, 401);
  assert.deepEqual(result.body, { error: 'invalid_enrollment_token' });
});

// ---------------------------------------------------------------------------
// ownership validation (unchanged)
// ---------------------------------------------------------------------------

test('Ownership: absent reads as officehq', async () => {
  const table = new FakeTable();
  const token = seedToken(table);
  const result = await handlerFor(table)(tokenRequest(token.presented, body()));
  assert.equal(result.statusCode, 200);
  assert.equal(table.peek(deviceProfile(result.body.deviceId)).ownership, 'officehq');
  assert.equal(table.audits()[0].detail.ownership, 'officehq');
});

for (const bad of ['BYOC', 'personal', '', 1, null, true, ['byoc']]) {
  test(`Ownership: ${JSON.stringify(bad)} is rejected with 400 naming ownership and no use is claimed`, async () => {
    const table = new FakeTable();
    const token = seedToken(table);
    const result = await handlerFor(table)(tokenRequest(token.presented, body({ ownership: bad })));
    assert.equal(result.statusCode, 400);
    assert.equal(result.body.error, 'invalid_request');
    assert.deepEqual(result.body.fields, ['ownership']);
    assert.equal(table.peek(enrollmentToken(token.tokenId)).useCount, 0);
  });
}

test('Ownership: a bad ownership is reported alongside other bad fields', async () => {
  const table = new FakeTable();
  const token = seedToken(table);
  const result = await handlerFor(table)(tokenRequest(token.presented, body({ platform: 'linux', ownership: 'x' })));
  assert.equal(result.statusCode, 400);
  assert.deepEqual(result.body.fields, ['platform', 'ownership']);
});

test('Expired sign-in token: answers 403 enrollment_token_expired', async () => {
  const table = new FakeTable();
  const token = seedToken(table, { enrolledBy: AMY, expiresAt: '2026-10-09T11:00:00.000Z' });
  const result = await handlerFor(table)(tokenRequest(token.presented, body()));
  assert.equal(result.statusCode, 403);
  assert.deepEqual(result.body, { error: 'enrollment_token_expired' });
});

test('Used sign-in token: a second enrollment answers 403 enrollment_token_exhausted', async () => {
  const table = new FakeTable();
  const token = seedToken(table, { enrolledBy: AMY });
  const first = await handlerFor(table)(tokenRequest(token.presented, body()));
  assert.equal(first.statusCode, 200);
  const second = await handlerFor(table)(tokenRequest(token.presented, body()));
  assert.equal(second.statusCode, 403);
  assert.deepEqual(second.body, { error: 'enrollment_token_exhausted' });
});
