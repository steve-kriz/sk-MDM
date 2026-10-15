/**
 * Unit tests for the analytics view module (TASK-036).
 *
 * Tests for formatters and render function that outputs the fleet analytics screen
 * and the analytics section in the device detail view.
 */

import test from 'node:test';
import assert from 'node:assert';

const analyticsModule = await import('../../dist/ui/views/analytics.js');
const deviceDetailModule = await import('../../dist/ui/views/deviceDetail.js');

// ============================================================================
// Formatter Tests
// ============================================================================

test('Formatter: formatSeconds produces pinned text', async () => {
  assert.strictEqual(analyticsModule.formatSeconds(38.4), '38.4 s');
  assert.strictEqual(analyticsModule.formatSeconds(40), '40 s');
  assert.strictEqual(analyticsModule.formatSeconds(0), '0 s');
  assert.strictEqual(analyticsModule.formatSeconds(0.1), '0.1 s');
});

test('Formatter: formatSeconds returns null for non-finite values', async () => {
  assert.strictEqual(analyticsModule.formatSeconds(null), null);
  assert.strictEqual(analyticsModule.formatSeconds(undefined), null);
  assert.strictEqual(analyticsModule.formatSeconds(NaN), null);
  assert.strictEqual(analyticsModule.formatSeconds(Infinity), null);
  assert.strictEqual(analyticsModule.formatSeconds('40'), null);
});

test('Formatter: formatUptime produces pinned text', async () => {
  assert.strictEqual(analyticsModule.formatUptime(2031), '0d 0h 33m');
  assert.strictEqual(analyticsModule.formatUptime(90061), '1d 1h 1m');
  assert.strictEqual(analyticsModule.formatUptime(0), '0d 0h 0m');
  assert.strictEqual(analyticsModule.formatUptime(86400), '1d 0h 0m');
  assert.strictEqual(analyticsModule.formatUptime(3661), '0d 1h 1m');
});

test('Formatter: formatUptime returns null for non-finite values', async () => {
  assert.strictEqual(analyticsModule.formatUptime(null), null);
  assert.strictEqual(analyticsModule.formatUptime(undefined), null);
  assert.strictEqual(analyticsModule.formatUptime(NaN), null);
});

test('Formatter: formatPercent produces pinned text with one decimal', async () => {
  assert.strictEqual(analyticsModule.formatPercent(12.5), '12.5%');
  assert.strictEqual(analyticsModule.formatPercent(0), '0.0%');
  assert.strictEqual(analyticsModule.formatPercent(100), '100.0%');
  assert.strictEqual(analyticsModule.formatPercent(33.33333), '33.3%');
});

test('Formatter: formatPercent returns null for non-finite values', async () => {
  assert.strictEqual(analyticsModule.formatPercent(null), null);
  assert.strictEqual(analyticsModule.formatPercent(undefined), null);
  assert.strictEqual(analyticsModule.formatPercent(NaN), null);
});

test('Formatter: memoryText produces pinned text', async () => {
  assert.strictEqual(
    analyticsModule.memoryText({ memoryUsedBytes: 9663676416, memoryTotalBytes: 34359738368 }),
    '9.0 / 32.0 GiB (28.1% used)'
  );
});

test('Formatter: memoryText returns null for missing or invalid values', async () => {
  assert.strictEqual(analyticsModule.memoryText(null), null);
  assert.strictEqual(analyticsModule.memoryText({}), null);
  assert.strictEqual(analyticsModule.memoryText({ memoryUsedBytes: null, memoryTotalBytes: 1000 }), null);
  assert.strictEqual(analyticsModule.memoryText({ memoryUsedBytes: 100, memoryTotalBytes: null }), null);
  assert.strictEqual(analyticsModule.memoryText({ memoryUsedBytes: 100, memoryTotalBytes: 0 }), null);
});

test('Formatter: diskText produces pinned text', async () => {
  assert.strictEqual(
    analyticsModule.diskText({ systemDiskFreeBytes: 210453397504, systemDiskTotalBytes: 1023741952000 }),
    '196.0 GiB free of 953.4 GiB (20.6% free)'
  );
});

test('Formatter: diskText returns null for missing or invalid values', async () => {
  assert.strictEqual(analyticsModule.diskText(null), null);
  assert.strictEqual(analyticsModule.diskText({}), null);
  assert.strictEqual(analyticsModule.diskText({ systemDiskFreeBytes: null, systemDiskTotalBytes: 1000 }), null);
  assert.strictEqual(analyticsModule.diskText({ systemDiskFreeBytes: 100, systemDiskTotalBytes: null }), null);
  assert.strictEqual(analyticsModule.diskText({ systemDiskFreeBytes: 100, systemDiskTotalBytes: 0 }), null);
});

// ============================================================================
// Analytics View Render Tests
// ============================================================================

test('Render: Fleet view shell has correct structure', async () => {
  const html = analyticsModule.render({ windowDays: 7 });

  assert.ok(typeof html === 'string');
  assert.ok(html.includes('id="screen-analytics"'));
  assert.ok(html.includes('<h2>Analytics</h2>'));
  assert.ok(html.includes('class="analytics-window"'));
  assert.ok(html.includes('name="days"'));
});

test('Render: Window picker shows correct options', async () => {
  const html = analyticsModule.render({ windowDays: 7 });

  assert.ok(html.includes('<option value="1">Last 24 hours</option>'));
  assert.ok(html.includes('<option value="7" selected>Last 7 days</option>'));
  assert.ok(html.includes('<option value="30">Last 30 days</option>'));
});

test('Render: Window picker defaults to 30 when unknown', async () => {
  const html = analyticsModule.render({ windowDays: 5 });

  assert.ok(html.includes('<option value="30" selected>Last 30 days</option>'));
});

test('Render: Fleet view lists appear in correct order', async () => {
  const html = analyticsModule.render({
    slowestBoots: [],
    mostCrashes: [],
    topApps: [],
    resourcePressure: [],
  });

  const slowestIdx = html.indexOf('id="analytics-slowest-boots"');
  const crashesIdx = html.indexOf('id="analytics-most-crashes"');
  const appsIdx = html.indexOf('id="analytics-top-apps"');
  const pressureIdx = html.indexOf('id="analytics-resource-pressure"');

  assert.ok(slowestIdx < crashesIdx);
  assert.ok(crashesIdx < appsIdx);
  assert.ok(appsIdx < pressureIdx);
});

test('Render: Empty lists show correct empty messages', async () => {
  const html = analyticsModule.render({});

  assert.ok(html.includes('No boot data reported'));
  assert.ok(html.includes('No crashes or hangs in this window'));
  assert.ok(html.includes('No crashing applications in this window'));
  assert.ok(html.includes('No devices under resource pressure'));
});

test('Render: Slowest boots table shows device rows', async () => {
  const html = analyticsModule.render({
    slowestBoots: [
      { deviceId: 'd1', hostname: 'laptop-1', lastBootAt: '2026-10-09T06:00:00Z', bootDurationSeconds: 40 },
      { deviceId: 'd2', hostname: null, lastBootAt: '2026-10-09T07:00:00Z', bootDurationSeconds: 30 },
    ],
  });

  assert.ok(html.includes('data-device-id="d1"'));
  assert.ok(html.includes('laptop-1'));
  assert.ok(html.includes('data-device-id="d2"'));
  assert.ok(html.includes('2026-10-09T06:00:00Z'));
  assert.ok(html.includes('40 s'));
  assert.ok(html.includes('30 s'));
});

test('Render: Most crashes table shows device stats', async () => {
  const html = analyticsModule.render({
    mostCrashes: [
      {
        deviceId: 'd1',
        hostname: 'pc-1',
        crashCount: 2,
        hangCount: 1,
        eventCount: 3,
        lastOccurredAt: '2026-10-09T10:00:00Z',
      },
    ],
  });

  assert.ok(html.includes('data-device-id="d1"'));
  assert.ok(html.includes('pc-1'));
  assert.ok(html.includes('>2<')); // crashCount
  assert.ok(html.includes('>1<')); // hangCount
  assert.ok(html.includes('>3<')); // eventCount
});

test('Render: Top apps table shows app rows', async () => {
  const html = analyticsModule.render({
    topApps: [
      { appName: 'Teams', crashCount: 5, hangCount: 2, eventCount: 7, deviceCount: 3, lastOccurredAt: '2026-10-09T10:00:00Z' },
    ],
  });

  assert.ok(html.includes('class="app"'));
  assert.ok(html.includes('Teams'));
  assert.ok(html.includes('>5<')); // crashes
  assert.ok(html.includes('>2<')); // hangs
  assert.ok(html.includes('>7<')); // total
  assert.ok(html.includes('>3<')); // devices
});

test('Render: Resource pressure table shows reasons', async () => {
  const html = analyticsModule.render({
    resourcePressure: [
      {
        deviceId: 'd1',
        hostname: 'pc-1',
        diskFreePercent: 5.0,
        memoryUsedPercent: null,
        reasons: ['low_disk'],
      },
      {
        deviceId: 'd2',
        hostname: 'pc-2',
        diskFreePercent: 8.0,
        memoryUsedPercent: 95.0,
        reasons: ['low_disk', 'high_memory'],
      },
    ],
  });

  assert.ok(html.includes('Low disk'));
  assert.ok(html.includes('Low disk, High memory'));
  assert.ok(html.includes('5.0%'));
  assert.ok(html.includes('95.0%'));
});

test('Render: Truncation warning appears when truncated is true', async () => {
  const html = analyticsModule.render({ truncated: true });

  assert.ok(html.includes('Partial results'));
  assert.ok(html.includes('more analytics data exists'));
});

test('Render: No truncation warning when truncated is false', async () => {
  const html = analyticsModule.render({ truncated: false });

  assert.ok(!html.includes('Partial results'));
});

test('Render: HTML is escaped in app names', async () => {
  const html = analyticsModule.render({
    topApps: [{ appName: '<img src=x>', crashCount: 1, hangCount: 0, eventCount: 1, deviceCount: 1, lastOccurredAt: '2026-10-09T00:00:00Z' }],
  });

  assert.ok(!html.includes('<img src=x>'));
  assert.ok(html.includes('&lt;img src=x&gt;'));
});

test('Render: HTML is escaped in hostnames', async () => {
  const html = analyticsModule.render({
    slowestBoots: [
      { deviceId: 'd1', hostname: '<script>x</script>', lastBootAt: '2026-10-09T06:00:00Z', bootDurationSeconds: 40 },
    ],
  });

  assert.ok(!html.includes('<script>x</script>'));
  assert.ok(html.includes('&lt;script&gt;'));
});

// ============================================================================
// Device Detail Analytics Section Tests
// ============================================================================

test('Device detail: Analytics section shows formatted snapshot data', async () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    analytics: {
      snapshot: {
        deviceId: 'd1',
        boot: { lastBootAt: '2026-10-02T06:41:09Z', bootDurationSeconds: 38.4, uptimeSeconds: 2031 },
        performance: {
          cpuPercent: 12.5,
          memoryUsedBytes: 9663676416,
          memoryTotalBytes: 34359738368,
          systemDiskFreeBytes: 210453397504,
          systemDiskTotalBytes: 1023741952000,
        },
        receivedAt: '2026-10-10T11:00:00Z',
      },
      bootHistory: [],
      crashes: [],
    },
  });

  assert.ok(html.includes('id="detail-analytics"'));
  assert.ok(html.includes('2026-10-02 06:41:09'));
  assert.ok(html.includes('38.4 s'));
  assert.ok(html.includes('0d 0h 33m'));
  assert.ok(html.includes('12.5%'));
  assert.ok(html.includes('9.0 / 32.0 GiB (28.1% used)'));
  assert.ok(html.includes('196.0 GiB free of 953.4 GiB (20.6% free)'));
  assert.ok(html.includes('2026-10-10 11:00:00'));
});

test('Device detail: Analytics section appears after antivirus findings', async () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    analytics: { snapshot: null, bootHistory: [], crashes: [] },
  });

  const antivirusIdx = html.indexOf('id="detail-antivirus-findings"');
  const analyticsIdx = html.indexOf('id="detail-analytics"');

  assert.ok(antivirusIdx > -1);
  assert.ok(analyticsIdx > -1);
  assert.ok(antivirusIdx < analyticsIdx);
});

test('Device detail: Null analytics fields show em dashes', async () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    analytics: {
      snapshot: {
        deviceId: 'd1',
        boot: { lastBootAt: null, bootDurationSeconds: null, uptimeSeconds: null },
        performance: {
          cpuPercent: null,
          memoryUsedBytes: null,
          memoryTotalBytes: null,
          systemDiskFreeBytes: null,
          systemDiskTotalBytes: null,
        },
        receivedAt: '2026-10-10T11:00:00Z',
      },
      bootHistory: [],
      crashes: [],
    },
  });

  assert.ok(html.includes('&mdash;'));
});

test('Device detail: Empty snapshot shows no analytics reported', async () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    analytics: { snapshot: null, bootHistory: [], crashes: [] },
  });

  assert.ok(html.includes('No analytics reported'));
});

test('Device detail: Empty boot history shows no boots recorded', async () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    analytics: { snapshot: null, bootHistory: [], crashes: [] },
  });

  assert.ok(html.includes('No boots recorded'));
});

test('Device detail: Empty crashes shows no crashes in 30 days', async () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    analytics: { snapshot: null, bootHistory: [], crashes: [] },
  });

  assert.ok(html.includes('No crashes or hangs in the last 30 days'));
});

test('Device detail: Boot history table shows entries', async () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    analytics: {
      snapshot: null,
      bootHistory: [
        { bootAt: '2026-10-09T06:00:00Z', bootDurationSeconds: 30 },
        { bootAt: '2026-10-08T06:00:00Z', bootDurationSeconds: null },
      ],
      crashes: [],
    },
  });

  assert.ok(html.includes('class="boot"'));
  assert.ok(html.includes('2026-10-09 06:00:00'));
  assert.ok(html.includes('30 s'));
  assert.ok(html.includes('2026-10-08 06:00:00'));
  assert.ok(html.includes('&mdash;'));
});

test('Device detail: Crash table shows entries with all fields', async () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    analytics: {
      snapshot: null,
      bootHistory: [],
      crashes: [
        { eventId: 'e1', appName: 'Teams', appVersion: '1.0.0', occurredAt: '2026-10-09T10:00:00Z', kind: 'crash' },
        { eventId: 'e2', appName: 'Outlook', appVersion: null, occurredAt: '2026-10-09T11:00:00Z', kind: 'hang' },
      ],
    },
  });

  assert.ok(html.includes('class="app-crash"'));
  assert.ok(html.includes('Teams'));
  assert.ok(html.includes('Outlook'));
  assert.ok(html.includes('1.0.0'));
  assert.ok(html.includes('2026-10-09 10:00:00'));
  assert.ok(html.includes('2026-10-09 11:00:00'));
  assert.ok(html.includes('crash'));
  assert.ok(html.includes('hang'));
});

test('Device detail: HTML in app names is escaped', async () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    analytics: {
      snapshot: null,
      bootHistory: [],
      crashes: [{ eventId: 'e1', appName: '<script>x</script>', appVersion: null, occurredAt: '2026-10-09T10:00:00Z', kind: 'crash' }],
    },
  });

  assert.ok(!html.includes('<script>x</script>'));
  assert.ok(html.includes('&lt;script&gt;'));
});

test('Device detail: Render without analytics handles missing state', async () => {
  const html = deviceDetailModule.render({ profile: { deviceId: 'd1' } });

  assert.ok(typeof html === 'string');
  assert.ok(html.includes('id="screen-device-detail"'));
  assert.ok(html.includes('No analytics reported'));
});

// ============================================================================
// Analytics Collection Toggle Tests (TASK-040)
// ============================================================================

test('Device detail: Collection field shows "On" by default', async () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    analytics: { snapshot: null, bootHistory: [], crashes: [] },
  });

  assert.ok(html.includes('id="detail-analytics"'));
  assert.ok(html.includes('Collection'));
  assert.ok(html.includes('On'));
  assert.ok(html.includes('analytics-collection-toggle'));
  assert.ok(html.includes('data-enabled="false"'));
  assert.ok(html.includes('Turn analytics off'));
});

test('Device detail: Collection field shows "On" when analyticsCollection absent', async () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    analytics: { snapshot: null, bootHistory: [], crashes: [] },
    analyticsCollection: undefined,
  });

  assert.ok(html.includes('Collection'));
  assert.ok(html.includes('On'));
  assert.ok(html.includes('data-enabled="false"'));
});

test('Device detail: Collection field shows "On" when enabled is true', async () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    analytics: { snapshot: null, bootHistory: [], crashes: [] },
    analyticsCollection: { enabled: true, updatedAt: null, updatedBy: null },
  });

  assert.ok(html.includes('Collection'));
  assert.ok(html.includes('On'));
  assert.ok(html.includes('data-enabled="false"'));
  assert.ok(html.includes('Turn analytics off'));
});

test('Device detail: Collection field shows "Off" with warning and turn-on button', async () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    analytics: {
      snapshot: {
        deviceId: 'd1',
        boot: { lastBootAt: '2026-10-02T06:41:09Z', bootDurationSeconds: 38.4, uptimeSeconds: 2031 },
        performance: {
          cpuPercent: 12.5,
          memoryUsedBytes: 9663676416,
          memoryTotalBytes: 34359738368,
          systemDiskFreeBytes: 210453397504,
          systemDiskTotalBytes: 1023741952000,
        },
        receivedAt: '2026-10-10T11:00:00Z',
      },
      bootHistory: [],
      crashes: [],
    },
    analyticsCollection: {
      enabled: false,
      updatedAt: '2026-10-10T11:00:00Z',
      updatedBy: 'admin@x',
    },
  });

  assert.ok(html.includes('Collection'));
  assert.ok(html.includes('Off'));
  assert.ok(html.includes('data-enabled="true"'));
  assert.ok(html.includes('Turn analytics on'));
  assert.ok(html.includes('Analytics collection is off'));
  assert.ok(html.includes('data below was last reported before it was turned off'));
  // Verify snapshot still renders
  assert.ok(html.includes('2026-10-02 06:41:09'));
  assert.ok(html.includes('38.4 s'));
});

test('Device detail: Collection toggle button has correct device ID', async () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    analytics: { snapshot: null, bootHistory: [], crashes: [] },
  });

  assert.ok(html.includes('data-device-id="d1"'));
});

test('Device detail: Collection toggle button HTML escapes device ID', async () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: '<script>d1</script>' },
    analytics: { snapshot: null, bootHistory: [], crashes: [] },
  });

  assert.ok(!html.includes('<script>d1</script>'));
  assert.ok(html.includes('&lt;script&gt;'));
});
