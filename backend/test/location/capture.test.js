/**
 * Unit tests for TASK-056: IP-based device location (`src/location/capture.ts`).
 *
 * Pure-function unit tests for the parsing/folding rules, plus a handful of
 * unit tests for `locationTrackingEnabled`/`captureLocation` against a
 * minimal in-memory fake table. No real database connection is ever opened.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const {
  MAX_LOCATION_HISTORY,
  MAX_LOCATION_TEXT_LENGTH,
  LOCATION_CAPTURE_INTERVAL_SECONDS,
  IP_LOCATION_SOURCE,
  parseViewerLocation,
  storedCapture,
  storedHistory,
  foldLocation,
  isCaptureCurrent,
  trackingFromPolicies,
  locationTrackingEnabled,
  captureLocation,
  locationView,
} = await import(`file://${join(__dirname, '../../dist/location/capture.js')}`);

const { deviceLocation } = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);

// ============================================================================
// A minimal in-memory fake table: get/put/query. No real DB connection.
// ============================================================================

class FakeTable {
  constructor() {
    this.items = new Map();
    this.queryResponses = [];
    this.calls = [];
    this.throwOnPut = false;
  }

  keyStr(key) {
    return JSON.stringify({ pk: key.pk, sk: key.sk });
  }

  async get(key) {
    this.calls.push({ op: 'get', key });
    return this.items.get(this.keyStr(key));
  }

  async put(item) {
    this.calls.push({ op: 'put', item });
    if (this.throwOnPut) {
      throw new Error('simulated write failure');
    }
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  async query(request) {
    this.calls.push({ op: 'query', request });
    if (this.queryResponses.length > 0) {
      return this.queryResponses.shift();
    }
    return { items: [], cursor: null };
  }

  seedItem(item) {
    this.items.set(this.keyStr({ pk: item.pk, sk: item.sk }), { ...item });
  }

  getStoredItem(key) {
    return this.items.get(this.keyStr(key));
  }

  seedQueryResponses(responses) {
    this.queryResponses = [...responses];
  }
}

function headers(obj) {
  return { ...obj };
}

// ============================================================================
// Unit: parseViewerLocation
// ============================================================================

test('Unit: parseViewerLocation reads a full set of valid headers', () => {
  const at = new Date('2026-10-11T00:00:00Z');
  const capture = parseViewerLocation(
    headers({
      'CloudFront-Viewer-Latitude': '-33.8688',
      'CloudFront-Viewer-Longitude': '151.2093',
      'CloudFront-Viewer-City': 'Sydney',
      'CloudFront-Viewer-Country-Region-Name': 'New South Wales',
      'CloudFront-Viewer-Country': 'AU',
    }),
    at,
  );
  assert.deepStrictEqual(capture, {
    latitude: -33.8688,
    longitude: 151.2093,
    city: 'Sydney',
    region: 'New South Wales',
    country: 'AU',
    source: IP_LOCATION_SOURCE,
    accuracyMeters: null,
    capturedAt: '2026-10-11T00:00:00Z',
  });
});

test('Unit: parseViewerLocation reads headers case-insensitively', () => {
  const at = new Date('2026-10-11T00:00:00Z');
  const capture = parseViewerLocation(
    headers({ 'cloudfront-viewer-latitude': '10', 'cloudfront-viewer-longitude': '20' }),
    at,
  );
  assert.strictEqual(capture.latitude, 10);
  assert.strictEqual(capture.longitude, 20);
});

test('Unit: parseViewerLocation returns null when latitude is missing', () => {
  const at = new Date('2026-10-11T00:00:00Z');
  const capture = parseViewerLocation(headers({ 'CloudFront-Viewer-Longitude': '151.2' }), at);
  assert.strictEqual(capture, null);
});

test('Unit: parseViewerLocation returns null when longitude is missing', () => {
  const at = new Date('2026-10-11T00:00:00Z');
  const capture = parseViewerLocation(headers({ 'CloudFront-Viewer-Latitude': '-33.8' }), at);
  assert.strictEqual(capture, null);
});

test('Unit: parseViewerLocation returns null for a non-numeric latitude', () => {
  const at = new Date('2026-10-11T00:00:00Z');
  const capture = parseViewerLocation(
    headers({ 'CloudFront-Viewer-Latitude': 'abc', 'CloudFront-Viewer-Longitude': '151.2' }),
    at,
  );
  assert.strictEqual(capture, null);
});

test('Unit: parseViewerLocation returns null for latitude out of range (91)', () => {
  const at = new Date('2026-10-11T00:00:00Z');
  const capture = parseViewerLocation(
    headers({ 'CloudFront-Viewer-Latitude': '91', 'CloudFront-Viewer-Longitude': '151.2' }),
    at,
  );
  assert.strictEqual(capture, null);
});

test('Unit: parseViewerLocation returns null for longitude out of range (-181)', () => {
  const at = new Date('2026-10-11T00:00:00Z');
  const capture = parseViewerLocation(
    headers({ 'CloudFront-Viewer-Latitude': '-33.8', 'CloudFront-Viewer-Longitude': '-181' }),
    at,
  );
  assert.strictEqual(capture, null);
});

test('Unit: parseViewerLocation on no headers at all returns null and writes nothing', () => {
  const at = new Date('2026-10-11T00:00:00Z');
  assert.strictEqual(parseViewerLocation(undefined, at), null);
  assert.strictEqual(parseViewerLocation({}, at), null);
});

test('Unit: an invalid country is stored null, a long city/region is cut to 128, empty reads as null', () => {
  const at = new Date('2026-10-11T00:00:00Z');
  const longCity = 'x'.repeat(200);
  const capture = parseViewerLocation(
    headers({
      'CloudFront-Viewer-Latitude': '1',
      'CloudFront-Viewer-Longitude': '2',
      'CloudFront-Viewer-City': longCity,
      'CloudFront-Viewer-Country-Region-Name': '   ',
      'CloudFront-Viewer-Country': 'usa',
    }),
    at,
  );
  assert.strictEqual(capture.country, null);
  assert.strictEqual(capture.region, null);
  assert.strictEqual(capture.city, longCity.slice(0, MAX_LOCATION_TEXT_LENGTH));
  assert.strictEqual(capture.city.length, 128);
});

test('Unit: a two-character lower-case or mixed-case country header is rejected (must be [A-Z]{2})', () => {
  const at = new Date('2026-10-11T00:00:00Z');
  const capture = parseViewerLocation(
    headers({ 'CloudFront-Viewer-Latitude': '1', 'CloudFront-Viewer-Longitude': '2', 'CloudFront-Viewer-Country': 'U1' }),
    at,
  );
  assert.strictEqual(capture.country, null);
});

// ============================================================================
// Unit: storedCapture / storedHistory
// ============================================================================

test('Unit: storedCapture returns null for a non-object, and for out-of-range stored coordinates', () => {
  assert.strictEqual(storedCapture(null), null);
  assert.strictEqual(storedCapture('nope'), null);
  assert.strictEqual(storedCapture({ latitude: 91, longitude: 1, capturedAt: '2026-10-11T00:00:00Z' }), null);
  assert.strictEqual(storedCapture({ latitude: 1, longitude: 1, capturedAt: 'not-a-date' }), null);
});

test('Unit: storedHistory drops malformed entries and keeps valid ones', () => {
  const history = storedHistory({
    history: [
      { latitude: 1, longitude: 2, capturedAt: '2026-10-10T00:00:00Z' },
      { latitude: 'bad', longitude: 2, capturedAt: '2026-10-09T00:00:00Z' },
      null,
      'not-an-object',
      { latitude: 3, longitude: 4, capturedAt: '2026-10-08T00:00:00Z' },
    ],
  });
  assert.strictEqual(history.length, 2);
  assert.strictEqual(history[0].latitude, 1);
  assert.strictEqual(history[1].latitude, 3);
});

test('Unit: storedHistory on an item with no history array returns []', () => {
  assert.deepStrictEqual(storedHistory({}), []);
  assert.deepStrictEqual(storedHistory(undefined), []);
  assert.deepStrictEqual(storedHistory(null), []);
});

// ============================================================================
// Unit: foldLocation
// ============================================================================

test('Unit: foldLocation prepends the new capture and keeps the device key shape', () => {
  const capture = {
    latitude: 1,
    longitude: 2,
    city: null,
    region: null,
    country: null,
    source: 'ip',
    accuracyMeters: null,
    capturedAt: '2026-10-11T00:00:00Z',
  };
  const existing = {
    ...deviceLocation('dev-1'),
    history: [
      { latitude: 9, longitude: 9, city: null, region: null, country: null, source: 'ip', accuracyMeters: null, capturedAt: '2026-10-10T00:00:00Z' },
    ],
  };
  const folded = foldLocation('dev-1', existing, capture);
  assert.strictEqual(folded.pk, 'DEVICE#dev-1');
  assert.strictEqual(folded.sk, 'LOCATION');
  assert.strictEqual(folded.deviceId, 'dev-1');
  assert.strictEqual(folded.latitude, 1);
  assert.strictEqual(folded.history.length, 2);
  assert.strictEqual(folded.history[0].latitude, 1);
  assert.strictEqual(folded.history[1].latitude, 9);
});

test('Unit: foldLocation on no existing item starts a 1-entry history', () => {
  const capture = {
    latitude: 1,
    longitude: 2,
    city: null,
    region: null,
    country: null,
    source: 'ip',
    accuracyMeters: null,
    capturedAt: '2026-10-11T00:00:00Z',
  };
  const folded = foldLocation('dev-1', undefined, capture);
  assert.strictEqual(folded.history.length, 1);
});

test('Unit: foldLocation caps history at MAX_LOCATION_HISTORY (30), dropping the oldest', () => {
  const oldHistory = Array.from({ length: 30 }, (_, i) => ({
    latitude: i,
    longitude: i,
    city: null,
    region: null,
    country: null,
    source: 'ip',
    accuracyMeters: null,
    capturedAt: `2026-09-${String(i + 1).padStart(2, '0')}T00:00:00Z`,
  }));
  const existing = { ...deviceLocation('dev-1'), history: oldHistory };
  const newCapture = {
    latitude: 999,
    longitude: 999,
    city: null,
    region: null,
    country: null,
    source: 'ip',
    accuracyMeters: null,
    capturedAt: '2026-10-11T00:00:00Z',
  };
  const folded = foldLocation('dev-1', existing, newCapture);
  assert.strictEqual(folded.history.length, MAX_LOCATION_HISTORY);
  assert.strictEqual(folded.history[0].latitude, 999);
  // The previous oldest (i=29) must be gone; 29 entries from oldHistory remain (i=0..28).
  assert.ok(!folded.history.some((entry) => entry.latitude === 29));
});

test('Unit: foldLocation drops malformed stored history entries while folding', () => {
  const existing = {
    ...deviceLocation('dev-1'),
    history: [{ latitude: 'bad', longitude: 1, capturedAt: '2026-10-10T00:00:00Z' }],
  };
  const capture = {
    latitude: 1,
    longitude: 2,
    city: null,
    region: null,
    country: null,
    source: 'ip',
    accuracyMeters: null,
    capturedAt: '2026-10-11T00:00:00Z',
  };
  const folded = foldLocation('dev-1', existing, capture);
  assert.strictEqual(folded.history.length, 1);
});

// ============================================================================
// Unit: isCaptureCurrent (the 86400s boundary)
// ============================================================================

test('Unit: isCaptureCurrent is true at 86399 seconds before now', () => {
  const existing = { capturedAt: '2026-10-10T00:00:01Z' };
  const at = new Date('2026-10-11T00:00:00Z');
  assert.strictEqual(isCaptureCurrent(existing, at), true);
});

test('Unit: isCaptureCurrent is false at exactly 86400 seconds before now', () => {
  const existing = { capturedAt: '2026-10-10T00:00:00Z' };
  const at = new Date('2026-10-11T00:00:00Z');
  assert.strictEqual(isCaptureCurrent(existing, at), false);
});

test('Unit: isCaptureCurrent is false with no stored item', () => {
  assert.strictEqual(isCaptureCurrent(undefined, new Date()), false);
  assert.strictEqual(isCaptureCurrent(null, new Date()), false);
  assert.strictEqual(isCaptureCurrent({}, new Date()), false);
});

// ============================================================================
// Unit: trackingFromPolicies (smallest policyId wins)
// ============================================================================

test('Unit: trackingFromPolicies is true only when the merged value is exactly true', () => {
  assert.strictEqual(trackingFromPolicies([]), false);
  assert.strictEqual(
    trackingFromPolicies([{ policyId: 'pol-a', version: 1, settings: { locationTracking: true } }]),
    true,
  );
  assert.strictEqual(
    trackingFromPolicies([{ policyId: 'pol-a', version: 1, settings: { locationTracking: 'true' } }]),
    false,
  );
});

test('Unit: trackingFromPolicies resolves conflicting policies by smallest policyId', () => {
  const policies = [
    { policyId: 'pol-b', version: 1, settings: { locationTracking: true } },
    { policyId: 'pol-a', version: 1, settings: { locationTracking: false } },
  ];
  // pol-a < pol-b lexicographically, so pol-a's false wins.
  assert.strictEqual(trackingFromPolicies(policies), false);
});

// ============================================================================
// Unit: locationTrackingEnabled reusing already-resolved ids (no readAssignedPolicies query)
// ============================================================================

test('Unit: locationTrackingEnabled with assignedPolicyIds does one get per id and no query', async () => {
  const table = new FakeTable();
  const { policy } = await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);
  table.seedItem({ ...policy('pol-a'), policyId: 'pol-a', version: 1, settings: { locationTracking: true } });

  const enabled = await locationTrackingEnabled(table, 'dev-1', ['pol-a']);
  assert.strictEqual(enabled, true);
  assert.strictEqual(table.calls.filter((c) => c.op === 'query').length, 0);
  assert.strictEqual(table.calls.filter((c) => c.op === 'get').length, 1);
});

test('Unit: locationTrackingEnabled skips a resolved id whose policy record is gone', async () => {
  const table = new FakeTable();
  const enabled = await locationTrackingEnabled(table, 'dev-1', ['pol-missing']);
  assert.strictEqual(enabled, false);
});

// ============================================================================
// Unit: captureLocation call order and short-circuiting
// ============================================================================

test('Unit: captureLocation writes nothing and makes no table call when headers are unusable', async () => {
  const table = new FakeTable();
  const wrote = await captureLocation(table, 'dev-1', {}, new Date('2026-10-11T00:00:00Z'));
  assert.strictEqual(wrote, false);
  assert.strictEqual(table.calls.length, 0);
});

test('Unit: captureLocation stops before resolving tracking when an unforced capture is current', async () => {
  const table = new FakeTable();
  table.seedItem({ ...deviceLocation('dev-1'), capturedAt: '2026-10-10T12:00:00Z' });
  const at = new Date('2026-10-11T00:00:00Z'); // 12h old: current
  const wrote = await captureLocation(
    table,
    'dev-1',
    { 'cloudfront-viewer-latitude': '1', 'cloudfront-viewer-longitude': '2' },
    at,
  );
  assert.strictEqual(wrote, false);
  // Only the initial get(LOCATION); no policy resolution (no query, no further get).
  assert.deepStrictEqual(table.calls.map((c) => c.op), ['get']);
});

test('Unit: captureLocation with force=true re-captures even when the stored one is current', async () => {
  const table = new FakeTable();
  const { policy, group, groupListIndex, groupMember, groupIndex, policyAssignment, policyAssignmentIndex } =
    await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);
  table.seedItem({ ...deviceLocation('dev-1'), capturedAt: '2026-10-10T23:00:00Z', history: [{ latitude: 9, longitude: 9, city: null, region: null, country: null, source: 'ip', accuracyMeters: null, capturedAt: '2026-10-10T23:00:00Z' }] });
  table.seedItem({ ...group('grp-1'), ...groupListIndex('Group 1'), groupId: 'grp-1', name: 'Group 1' });
  table.seedItem({ ...groupMember('grp-1', 'dev-1'), ...groupIndex('grp-1', 'dev-1'), groupId: 'grp-1', deviceId: 'dev-1' });
  table.seedItem({
    ...policyAssignment('pol-1', 'grp-1'),
    ...policyAssignmentIndex('grp-1', 'pol-1'),
    policyId: 'pol-1',
    groupId: 'grp-1',
  });
  table.seedItem({ ...policy('pol-1'), policyId: 'pol-1', version: 1, settings: { locationTracking: true } });
  table.seedQueryResponses([
    { items: [{ ...group('grp-1'), ...groupListIndex('Group 1'), groupId: 'grp-1', gsi1pk: 'GROUP' }], cursor: null },
    {
      items: [
        { ...policyAssignment('pol-1', 'grp-1'), ...policyAssignmentIndex('grp-1', 'pol-1'), policyId: 'pol-1', gsi1pk: `GROUP#grp-1`, gsi1sk: 'POLICY#pol-1' },
      ],
      cursor: null,
    },
  ]);

  const at = new Date('2026-10-11T00:00:00Z');
  const wrote = await captureLocation(
    table,
    'dev-1',
    { 'cloudfront-viewer-latitude': '-37', 'cloudfront-viewer-longitude': '144' },
    at,
    { force: true },
  );
  assert.strictEqual(wrote, true);
  const stored = table.getStoredItem(deviceLocation('dev-1'));
  assert.strictEqual(stored.latitude, -37);
  assert.strictEqual(stored.history.length, 2);
  assert.strictEqual(stored.history[0].latitude, -37);
});

test('Unit: captureLocation errors propagate to the caller', async () => {
  const table = new FakeTable();
  table.throwOnPut = true;
  // Tracking enabled via no assigned policies would stop before put; force a
  // write attempt by seeding a policy that enables tracking.
  const { policy, group, groupListIndex, groupMember, groupIndex, policyAssignment, policyAssignmentIndex } =
    await import(`file://${join(__dirname, '../../dist/db/keys.js')}`);
  table.seedItem({ ...policy('pol-1'), policyId: 'pol-1', version: 1, settings: { locationTracking: true } });
  table.seedQueryResponses([
    { items: [{ ...group('grp-1'), ...groupListIndex('Group 1'), groupId: 'grp-1', gsi1pk: 'GROUP' }], cursor: null },
    {
      items: [
        { ...policyAssignment('pol-1', 'grp-1'), ...policyAssignmentIndex('grp-1', 'pol-1'), policyId: 'pol-1', gsi1pk: 'GROUP#grp-1', gsi1sk: 'POLICY#pol-1' },
      ],
      cursor: null,
    },
  ]);
  table.seedItem({ ...groupMember('grp-1', 'dev-1'), ...groupIndex('grp-1', 'dev-1'), groupId: 'grp-1', deviceId: 'dev-1' });

  await assert.rejects(
    captureLocation(table, 'dev-1', { 'cloudfront-viewer-latitude': '1', 'cloudfront-viewer-longitude': '2' }, new Date()),
    /simulated write failure/,
  );
});

// ============================================================================
// Unit: locationView
// ============================================================================

test('Unit: locationView is {latest: null, history: []} when no item exists', () => {
  assert.deepStrictEqual(locationView(undefined), { latest: null, history: [] });
  assert.deepStrictEqual(locationView(null), { latest: null, history: [] });
});

test('Unit: locationView reflects the stored latest fields and history', () => {
  const item = {
    ...deviceLocation('dev-1'),
    deviceId: 'dev-1',
    latitude: 1,
    longitude: 2,
    city: 'X',
    region: 'Y',
    country: 'AU',
    source: 'ip',
    accuracyMeters: null,
    capturedAt: '2026-10-11T00:00:00Z',
    history: [
      { latitude: 1, longitude: 2, city: 'X', region: 'Y', country: 'AU', source: 'ip', accuracyMeters: null, capturedAt: '2026-10-11T00:00:00Z' },
    ],
  };
  const view = locationView(item);
  assert.strictEqual(view.latest.latitude, 1);
  assert.strictEqual(view.history.length, 1);
});
