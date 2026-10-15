/**
 * Spec Amendment B (B.2): the admin device detail returns
 * `signedInUser: {username, reportedAt} | null`, read from the device's
 * `SIGNEDINUSER` item, and the console shows it as "Signed-in user".
 *
 * The table is an in-memory fake; nothing reaches DynamoDB.
 */

import test from 'node:test';
import assert from 'node:assert';
import { handleDeviceDetail } from '../../dist/admin/devices.js';
import { deviceProfile, deviceSignedInUser, deviceLoginUser, LOGIN_USER_SK_PREFIX } from '../../dist/db/keys.js';

const deviceDetailView = await import('../../dist/ui/views/deviceDetail.js');

class FakeTable {
  constructor(items = []) {
    this.items = new Map();
    for (const item of items) {
      this.items.set(`${item.pk}|${item.sk}`, { ...item });
    }
  }
  async get(key) {
    return this.items.get(`${key.pk}|${key.sk}`);
  }
  async query(request) {
    if (!request) {
      return { items: [], cursor: null };
    }
    const { KeyConditionExpression, ExpressionAttributeValues } = request;
    const pk = ExpressionAttributeValues?.[':pk'];
    const prefix = ExpressionAttributeValues?.[':loginPrefix'];

    if (!pk || !prefix) {
      return { items: [], cursor: null };
    }

    const items = Array.from(this.items.values()).filter(item => {
      return item.pk === pk && typeof item.sk === 'string' && item.sk.startsWith(prefix);
    });

    return { items, cursor: null };
  }
}

const PROFILE = { ...deviceProfile('d1'), deviceId: 'd1', hostname: 'h1', secretEnc: 'never' };

async function detail(items) {
  return handleDeviceDetail({ params: { deviceId: 'd1' }, query: {}, headers: {} }, { table: new FakeTable(items) });
}

test('Detail: signedInUser is {username, reportedAt} from the SIGNEDINUSER item', async () => {
  const result = await detail([
    PROFILE,
    {
      ...deviceSignedInUser('d1'),
      deviceId: 'd1',
      username: 'CONTOSO\\amy',
      source: 'os',
      reportedAt: '2026-10-09T12:00:00.000Z',
    },
  ]);
  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body.signedInUser, {
    username: 'CONTOSO\\amy',
    reportedAt: '2026-10-09T12:00:00.000Z',
  });
});

test('Detail: a reported null username reads as {username: null, reportedAt}', async () => {
  const result = await detail([
    PROFILE,
    { ...deviceSignedInUser('d1'), deviceId: 'd1', username: null, source: 'os', reportedAt: '2026-10-09T12:00:00.000Z' },
  ]);
  assert.deepStrictEqual(result.body.signedInUser, { username: null, reportedAt: '2026-10-09T12:00:00.000Z' });
});

test('Detail: no SIGNEDINUSER item reads as null', async () => {
  const result = await detail([PROFILE]);
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(result.body.signedInUser, null);
});

test('Detail: a token-era SIGNEDINUSER item (no reportedAt) reads as null', async () => {
  const result = await detail([
    PROFILE,
    {
      ...deviceSignedInUser('d1'),
      deviceId: 'd1',
      oid: 'o-1',
      upn: 'amy@contoso.com',
      verifiedAt: '2026-10-01T00:00:00.000Z',
    },
  ]);
  assert.strictEqual(result.body.signedInUser, null);
});

test('UI detail: "Signed-in user" shows the reported username', () => {
  const html = deviceDetailView.render({
    profile: { deviceId: 'd1' },
    signedInUser: { username: 'amy', reportedAt: '2026-10-09T12:00:00.000Z' },
  });
  assert.ok(html.includes('<span class="label">Signed-in user</span><span class="value">amy</span>'));
});

test('UI detail: no signed-in user shows an em dash', () => {
  for (const signedInUser of [null, undefined, { username: null, reportedAt: '2026-10-09T12:00:00.000Z' }]) {
    const html = deviceDetailView.render({ profile: { deviceId: 'd1' }, signedInUser });
    assert.ok(html.includes('<span class="label">Signed-in user</span><span class="value">&mdash;</span>'));
  }
});

test('UI detail: the username is escaped', () => {
  const html = deviceDetailView.render({
    profile: { deviceId: 'd1' },
    signedInUser: { username: '<b>x</b>', reportedAt: '2026-10-09T12:00:00.000Z' },
  });
  assert.ok(!html.includes('<b>x</b>'));
  assert.ok(html.includes('&lt;b&gt;x&lt;/b&gt;'));
});

// ============================================================================
// Login history (TASK-039)
// ============================================================================

test('Detail: loginHistory returns array with login records', async () => {
  const result = await detail([
    PROFILE,
    {
      ...deviceLoginUser('d1', 'a'.repeat(64)),
      deviceId: 'd1',
      username: 'amy',
      firstSeenAt: '2026-10-09T11:00:00.000Z',
      lastSeenAt: '2026-10-09T12:00:00.000Z',
      loginCount: 2,
    },
  ]);
  assert.strictEqual(result.statusCode, 200);
  assert.ok(Array.isArray(result.body.loginHistory));
  assert.strictEqual(result.body.loginHistory.length, 1);
  assert.deepStrictEqual(result.body.loginHistory[0], {
    username: 'amy',
    firstSeenAt: '2026-10-09T11:00:00.000Z',
    lastSeenAt: '2026-10-09T12:00:00.000Z',
    loginCount: 2,
  });
});

test('Detail: loginHistory is sorted by lastSeenAt descending then username ascending', async () => {
  const result = await detail([
    PROFILE,
    {
      ...deviceLoginUser('d1', 'a'.repeat(64)),
      deviceId: 'd1',
      username: 'bob',
      lastSeenAt: '2026-10-09T12:00:00.000Z',
      loginCount: 1,
    },
    {
      ...deviceLoginUser('d1', 'b'.repeat(64)),
      deviceId: 'd1',
      username: 'amy',
      lastSeenAt: '2026-10-09T12:00:00.000Z',
      loginCount: 1,
    },
    {
      ...deviceLoginUser('d1', 'c'.repeat(64)),
      deviceId: 'd1',
      username: 'cat',
      lastSeenAt: '2026-10-09T11:00:00.000Z',
      loginCount: 1,
    },
  ]);
  assert.strictEqual(result.statusCode, 200);
  const usernames = result.body.loginHistory.map(u => u.username);
  // Sorted by lastSeenAt descending (both '12:00' before '11:00'), then username ascending (amy < bob)
  assert.deepStrictEqual(usernames, ['amy', 'bob', 'cat']);
});

test('Detail: loginHistory filters out records without string username or lastSeenAt', async () => {
  const result = await detail([
    PROFILE,
    {
      ...deviceLoginUser('d1', 'a'.repeat(64)),
      deviceId: 'd1',
      username: 'amy',
      lastSeenAt: '2026-10-09T12:00:00.000Z',
      loginCount: 1,
    },
    {
      ...deviceLoginUser('d1', 'b'.repeat(64)),
      deviceId: 'd1',
      username: null,
      lastSeenAt: '2026-10-09T11:00:00.000Z',
      loginCount: 1,
    },
    {
      ...deviceLoginUser('d1', 'c'.repeat(64)),
      deviceId: 'd1',
      username: 'cat',
      lastSeenAt: null,
      loginCount: 1,
    },
  ]);
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(result.body.loginHistory.length, 1);
  assert.deepStrictEqual(result.body.loginHistory[0].username, 'amy');
});

test('Detail: loginHistory maps missing/invalid firstSeenAt to null', async () => {
  const result = await detail([
    PROFILE,
    {
      ...deviceLoginUser('d1', 'a'.repeat(64)),
      deviceId: 'd1',
      username: 'amy',
      firstSeenAt: '2026-10-09T10:00:00.000Z',
      lastSeenAt: '2026-10-09T12:00:00.000Z',
      loginCount: 1,
    },
    {
      ...deviceLoginUser('d1', 'b'.repeat(64)),
      deviceId: 'd1',
      username: 'bob',
      firstSeenAt: null,
      lastSeenAt: '2026-10-09T11:00:00.000Z',
      loginCount: 1,
    },
  ]);
  assert.strictEqual(result.statusCode, 200);
  const amyRecord = result.body.loginHistory.find(u => u.username === 'amy');
  const bobRecord = result.body.loginHistory.find(u => u.username === 'bob');
  assert.strictEqual(amyRecord.firstSeenAt, '2026-10-09T10:00:00.000Z');
  assert.strictEqual(bobRecord.firstSeenAt, null);
});

test('Detail: loginHistory maps invalid loginCount to null', async () => {
  const result = await detail([
    PROFILE,
    {
      ...deviceLoginUser('d1', 'a'.repeat(64)),
      deviceId: 'd1',
      username: 'amy',
      lastSeenAt: '2026-10-09T12:00:00.000Z',
      loginCount: 'invalid',
    },
  ]);
  assert.strictEqual(result.statusCode, 200);
  assert.strictEqual(result.body.loginHistory[0].loginCount, null);
});

test('Detail: loginHistory is empty array when no records exist', async () => {
  const result = await detail([PROFILE]);
  assert.strictEqual(result.statusCode, 200);
  assert.deepStrictEqual(result.body.loginHistory, []);
});

test('UI detail: login history section shows table with data', () => {
  const html = deviceDetailView.render({
    profile: { deviceId: 'd1' },
    loginHistory: [
      { username: 'amy', firstSeenAt: '2026-10-09T11:00:00.000Z', lastSeenAt: '2026-10-09T12:00:00.000Z', loginCount: 2 },
    ],
  });
  assert.ok(html.includes('id="detail-login-history"'));
  assert.ok(html.includes('class="grid login-history"'));
  assert.ok(html.includes('<th>username</th>'));
  assert.ok(html.includes('amy'));
});

test('UI detail: login history HTML-escapes usernames', () => {
  const html = deviceDetailView.render({
    profile: { deviceId: 'd1' },
    loginHistory: [
      { username: '<b>x</b>', firstSeenAt: '2026-10-09T11:00:00.000Z', lastSeenAt: '2026-10-09T12:00:00.000Z', loginCount: 1 },
    ],
  });
  assert.ok(!html.includes('<b>x</b>'));
  assert.ok(html.includes('&lt;b&gt;x&lt;/b&gt;'));
});

test('UI detail: empty login history shows "No logins recorded"', () => {
  const html = deviceDetailView.render({
    profile: { deviceId: 'd1' },
    loginHistory: [],
  });
  assert.ok(html.includes('id="detail-login-history"'));
  assert.ok(html.includes('No logins recorded'));
  assert.ok(!html.includes('class="grid login-history"'));
});

test('UI detail: undefined loginHistory shows "No logins recorded"', () => {
  const html = deviceDetailView.render({
    profile: { deviceId: 'd1' },
    loginHistory: undefined,
  });
  assert.ok(html.includes('No logins recorded'));
});

test('UI detail: non-array loginHistory shows "No logins recorded"', () => {
  const html = deviceDetailView.render({
    profile: { deviceId: 'd1' },
    loginHistory: 'bogus',
  });
  assert.ok(html.includes('No logins recorded'));
});
