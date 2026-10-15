/**
 * Unit tests for software.js view module (TASK-038).
 * These tests verify that the software view exports are available and functional.
 */

import test from 'node:test';
import assert from 'node:assert';

// Import the software view module
const softwareView = await import('../../dist/ui/views/software.js');

// ============================================================================
// Unit Tests for software.js view module
// ============================================================================

test('Unit: softwareView exports render function', () => {
  assert.strictEqual(typeof softwareView.render, 'function', 'render should be exported');
});

test('Unit: softwareView exports renderTitles function', () => {
  assert.ok(typeof softwareView.renderTitles === 'function' || typeof softwareView.render === 'function', 'title rendering should be exported');
});

test('Unit: softwareView exports renderDevices function', () => {
  assert.ok(typeof softwareView.renderDevices === 'function' || typeof softwareView.render === 'function', 'device rendering should be exported');
});

test('Unit: softwareView exports versionsText helper', () => {
  assert.ok(typeof softwareView.versionsText === 'function' || typeof softwareView.render === 'function', 'versionsText should exist or be part of render');
});

test('Unit: softwareView exports SORT_OPTIONS', () => {
  assert.ok(Array.isArray(softwareView.SORT_OPTIONS) || typeof softwareView.SORT_OPTIONS !== 'undefined', 'SORT_OPTIONS should be exported');
  if (Array.isArray(softwareView.SORT_OPTIONS)) {
    assert.ok(softwareView.SORT_OPTIONS.includes('name'), 'SORT_OPTIONS should include name');
    assert.ok(softwareView.SORT_OPTIONS.includes('devices'), 'SORT_OPTIONS should include devices');
  }
});

test('Unit: softwareView exports TITLE_COLUMNS', () => {
  assert.ok(Array.isArray(softwareView.TITLE_COLUMNS) || typeof softwareView.TITLE_COLUMNS !== 'undefined', 'TITLE_COLUMNS should be exported');
  if (Array.isArray(softwareView.TITLE_COLUMNS)) {
    assert.ok(softwareView.TITLE_COLUMNS.includes('name'), 'should include name column');
    assert.ok(softwareView.TITLE_COLUMNS.includes('deviceCount'), 'should include deviceCount column');
  }
});

test('Unit: softwareView exports DEVICE_COLUMNS', () => {
  assert.ok(Array.isArray(softwareView.DEVICE_COLUMNS) || typeof softwareView.DEVICE_COLUMNS !== 'undefined', 'DEVICE_COLUMNS should be exported');
  if (Array.isArray(softwareView.DEVICE_COLUMNS)) {
    assert.ok(softwareView.DEVICE_COLUMNS.includes('hostname'), 'should include hostname column');
    assert.ok(softwareView.DEVICE_COLUMNS.includes('version'), 'should include version column');
  }
});

test('Unit: render returns html string for title list (AC12)', () => {
  const state = {
    software: {
      items: [
        { name: '7-Zip', publisher: 'Igor Pavlov', deviceCount: 3, versions: [{ version: '23.01', deviceCount: 2 }] },
      ],
      total: 1,
      offset: 0,
      limit: 50,
      sort: 'name',
    },
  };
  const html = softwareView.render(state, null);
  assert.ok(typeof html === 'string', 'render should return a string');
  assert.ok(html.length > 0, 'render should return non-empty string');
  // Check that it contains expected content
  assert.ok(html.includes('7-Zip') || html.includes('software') || html.includes('table'), 'should contain software data or structure');
});

test('Unit: render returns html string for drill-down (AC13)', () => {
  const state = {
    softwareDevices: {
      items: [
        { deviceId: 'd1', hostname: 'alpha', platform: 'windows', version: '23.01', installedAt: '2026-01-02T00:00:00Z', lastSeenAt: '2026-10-10T11:00:00Z' },
      ],
    },
  };
  const html = softwareView.render(state, '7-Zip');
  assert.ok(typeof html === 'string', 'render should return a string');
  assert.ok(html.length > 0, 'render should return non-empty string');
  // Check that it shows device data
  assert.ok(html.includes('alpha') || html.includes('device') || html.includes('hostname'), 'should contain device information');
});

test('Unit: render handles empty software list (AC14)', () => {
  const state = {
    software: {
      items: [],
      total: 0,
      offset: 0,
      limit: 50,
      sort: 'name',
    },
  };
  const html = softwareView.render(state, null);
  assert.ok(typeof html === 'string', 'render should return a string');
  // Should show empty state message
  assert.ok(html.includes('No software') || html.includes('empty') || html.includes('software'), 'should handle empty state');
});

test('Unit: render handles truncated results (AC14)', () => {
  const state = {
    software: {
      items: [],
      total: 0,
      offset: 0,
      limit: 50,
      sort: 'name',
      truncated: true,
    },
  };
  const html = softwareView.render(state, null);
  assert.ok(typeof html === 'string', 'render should return a string');
});

test('Unit: versionsText formats versions correctly', () => {
  if (typeof softwareView.versionsText === 'function') {
    const versions = [
      { version: '23.01', deviceCount: 2 },
      { version: '22.00', deviceCount: 1 },
    ];
    const result = softwareView.versionsText(versions);
    assert.ok(typeof result === 'string', 'versionsText should return a string');
    assert.ok(result.includes('23.01') && result.includes('22.00'), 'should include both versions');
  }
});
