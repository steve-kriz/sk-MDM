/**
 * Unit tests for TASK-044's heartbeat panel of the device detail view
 * (`backend/src/ui/views/deviceDetail.js`): the on/off field, the frequency
 * form and the "Analytics history" expander.
 */

import test from 'node:test';
import assert from 'node:assert';

const deviceDetailModule = await import('../../dist/ui/views/deviceDetail.js');

// ============================================================================
// Scenario: Heartbeat off by default with a frequency picker (AC28)
// ============================================================================

test('Scenario: Heartbeat off by default with a frequency picker', () => {
  const html = deviceDetailModule.render({ profile: { deviceId: 'd1' } });

  const analyticsStart = html.indexOf('id="detail-analytics"');
  assert.ok(analyticsStart > -1);
  const section = html.slice(analyticsStart);

  assert.match(section, /Heartbeat<\/[^>]*>\s*<[^>]*>Off/);
  assert.ok(section.includes('class="heartbeat-form"'));
  assert.ok(section.includes('<input type="hidden" name="deviceId" value="d1">'));

  // The select offers exactly five options, 60..3600, labelled correctly.
  const selectMatch = /<select name="intervalSeconds">(.*?)<\/select>/s.exec(section);
  assert.ok(selectMatch);
  const options = [...selectMatch[1].matchAll(/<option value="(\d+)"( selected)?>([^<]*)<\/option>/g)];
  assert.strictEqual(options.length, 5);
  assert.deepStrictEqual(
    options.map((m) => m[1]),
    ['60', '300', '900', '1800', '3600'],
  );
  assert.deepStrictEqual(
    options.map((m) => m[3]),
    ['1 minute', '5 minutes', '15 minutes', '30 minutes', '1 hour'],
  );
  // 300 is preselected when heartbeat is absent.
  const selected = options.filter((m) => m[2] !== undefined);
  assert.strictEqual(selected.length, 1);
  assert.strictEqual(selected[0][1], '300');

  assert.ok(section.includes('class="heartbeat-toggle" data-enabled="true">Turn heartbeat on</button>'));
  assert.ok(!section.includes('heartbeat-save'));

  // The Collection field and its toggle still render.
  assert.ok(section.includes('class="analytics-collection-toggle"'));
});

test('Scenario: heartbeat.enabled === false behaves the same as absent', () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    heartbeat: { enabled: false, intervalSeconds: 900 },
  });
  const section = html.slice(html.indexOf('id="detail-analytics"'));
  assert.match(section, /Heartbeat<\/[^>]*>\s*<[^>]*>Off/);
  assert.ok(section.includes('data-enabled="true">Turn heartbeat on</button>'));
  assert.ok(!section.includes('heartbeat-save'));
  // Its own stored interval is still preselected even while off.
  assert.ok(/<option value="900" selected>/.test(section));
});

// ============================================================================
// Scenario: Heartbeat on shows turn-off and save buttons (AC29)
// ============================================================================

test('Scenario: Heartbeat on shows turn-off and save buttons', () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    heartbeat: { enabled: true, intervalSeconds: 900 },
  });
  const section = html.slice(html.indexOf('id="detail-analytics"'));

  assert.match(section, /Heartbeat<\/[^>]*>\s*<[^>]*>On/);
  assert.ok(/<option value="900" selected>/.test(section));
  assert.ok(section.includes('class="heartbeat-toggle" data-enabled="false">Turn heartbeat off</button>'));

  const formStart = section.indexOf('class="heartbeat-form"');
  const formEnd = section.indexOf('</form>', formStart);
  const form = section.slice(formStart, formEnd);
  assert.ok(form.includes('class="heartbeat-save">Save frequency</button>'));
});

// ============================================================================
// Scenario Outline: The analytics history expander (AC30)
// ============================================================================

test('Scenario Outline: The analytics history expander - absent history', () => {
  const html = deviceDetailModule.render({ profile: { deviceId: 'd1' } });
  const section = html.slice(html.indexOf('id="detail-analytics"'));

  const detailsMatch = /<details class="expandable heartbeat-history" data-device-id="d1"([^>]*)>(.*?)<\/details>/s.exec(
    section,
  );
  assert.ok(detailsMatch, 'the expander is always present');
  assert.ok(!detailsMatch[1].includes('open'), 'no open attribute');
  assert.ok(detailsMatch[2].includes('<summary data-device-id="d1">Analytics history</summary>'));
  assert.ok(!detailsMatch[2].includes('table.heartbeats'));
  assert.ok(!detailsMatch[2].includes('class="grid heartbeats"'));
});

test('Scenario Outline: The analytics history expander - open with items', () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    heartbeatHistory: {
      open: true,
      items: [
        {
          receivedAt: '2026-10-11T12:00:00Z',
          collectedAt: '2026-10-11T11:59:58Z',
          performance: { cpuPercent: 12.5, memoryUsedBytes: 1, memoryTotalBytes: 2, systemDiskFreeBytes: 1, systemDiskTotalBytes: 2 },
        },
        {
          receivedAt: '2026-10-11T11:55:00Z',
          collectedAt: '2026-10-11T11:54:58Z',
          performance: null,
        },
      ],
    },
  });
  const section = html.slice(html.indexOf('id="detail-analytics"'));

  const detailsMatch = /<details class="expandable heartbeat-history" data-device-id="d1"([^>]*)>(.*?)<\/details>/s.exec(
    section,
  );
  assert.ok(detailsMatch);
  assert.ok(detailsMatch[1].includes('open'));
  assert.ok(detailsMatch[2].includes('<table class="grid heartbeats">'));

  const headings = [...detailsMatch[2].matchAll(/<th>([^<]*)<\/th>/g)].map((m) => m[1]);
  assert.deepStrictEqual(headings, ['receivedAt', 'collectedAt', 'CPU', 'Memory', 'System disk', 'Network']);

  const rowCount = (detailsMatch[2].match(/<tr class="heartbeat">/g) ?? []).length;
  assert.strictEqual(rowCount, 2);
  assert.ok(detailsMatch[2].includes('2026-10-11 12:00:00'));
  assert.ok(detailsMatch[2].includes('2026-10-11 11:59:58'));
});

test('Scenario Outline: The analytics history expander - open with no items', () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    heartbeatHistory: { open: true, items: [] },
  });
  const section = html.slice(html.indexOf('id="detail-analytics"'));
  assert.ok(section.includes('<p class="empty">No heartbeats recorded</p>'));
});

test('Scenario Outline: The analytics history expander - error', () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    heartbeatHistory: { open: true, error: 'heartbeat_store_unavailable' },
  });
  const section = html.slice(html.indexOf('id="detail-analytics"'));
  assert.ok(section.includes('<p class="error">heartbeat_store_unavailable</p>'));
});

test('Scenario: The analytics history shows each network adapter on its own line', () => {
  const html = deviceDetailModule.render({
    profile: { deviceId: 'd1' },
    heartbeatHistory: {
      open: true,
      items: [
        {
          receivedAt: '2026-10-14T12:00:00Z',
          collectedAt: '2026-10-14T11:59:58Z',
          performance: null,
          network: [
            {
              name: 'Ethernet',
              linkSpeedBitsPerSecond: 1000000000,
              receiveBitsPerSecond: 200000000,
              sendBitsPerSecond: 20000000,
              utilizationPercent: 20,
              packetsReceivedPerSecond: 20000,
              packetsSentPerSecond: 5000,
              receiveErrors: 0,
              sendErrors: 405,
              receiveDiscards: 12,
              sendDiscards: 0,
            },
            {
              name: '<Wi-Fi>',
              linkSpeedBitsPerSecond: null,
              receiveBitsPerSecond: 1200000,
              sendBitsPerSecond: 800,
              utilizationPercent: null,
              packetsReceivedPerSecond: 100,
              packetsSentPerSecond: 50,
              receiveErrors: 0,
              sendErrors: 0,
              receiveDiscards: 0,
              sendDiscards: null,
            },
          ],
        },
        { receivedAt: '2026-10-14T11:55:00Z', collectedAt: '2026-10-14T11:54:58Z', performance: null },
      ],
    },
  });
  const cells = [...html.matchAll(/<td class="col-network">(.*?)<\/td>/g)].map((m) => m[1]);
  assert.strictEqual(cells.length, 2);
  assert.strictEqual(
    cells[0],
    'Ethernet: 20.0% of 1.0 Gb/s · in 200.0 Mb/s, out 20.0 Mb/s · 20000/5000 pkt/s · errors 0/405 · discards 12/0<br>' +
      '&lt;Wi-Fi&gt;: link speed unknown · in 1.2 Mb/s, out 800 b/s · 100/50 pkt/s · errors 0/0 · discards 0/?',
  );
  assert.strictEqual(cells[1], '&mdash;');
});
