/**
 * The fleet analytics screen: what `GET /admin/api/v1/analytics` answers with.
 *
 *   render({windowDays, slowestBoots, mostCrashes, topApps, resourcePressure, truncated})
 *
 * A pure function of state, like every view: it reads no global, touches no
 * DOM and returns a string. Device rows are `tr.device`, so the console's
 * existing click handler opens the device detail screen.
 *
 * The formatters the device detail screen's Analytics section uses live here
 * too, so both screens show a duration, a percentage or a byte count the same
 * way. Each returns `null` for a value it cannot format, which the views show
 * as an em dash.
 */
import { cell, escapeHtml } from '../public/html.js';

/** The window picker's choices, in order. */
export const WINDOW_OPTIONS = [
  { value: 1, label: 'Last 24 hours' },
  { value: 7, label: 'Last 7 days' },
  { value: 30, label: 'Last 30 days' },
];

/** The window selected when the state names none, or one the picker does not offer. */
export const DEFAULT_WINDOW_DAYS = 30;

/** Bytes in a GiB. */
const GIB = 1024 * 1024 * 1024;

/** How each resource pressure reason is shown. */
const REASON_LABELS = { low_disk: 'Low disk', high_memory: 'High memory' };

/** The partial-results warning, shown when the API stopped reading early. */
export const TRUNCATED_WARNING =
  '<p class="warning">Partial results: more analytics data exists than one request reads</p>';

/** True for a finite number. */
function isNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

/** One decimal place, always shown. */
function oneDecimal(value) {
  return (Math.round(value * 10) / 10).toFixed(1);
}

/** `38.4 s`, `40 s`; `null` when there is no duration. */
export function formatSeconds(seconds) {
  if (!isNumber(seconds)) {
    return null;
  }
  return `${Math.round(seconds * 10) / 10} s`;
}

/** `1d 1h 1m`; `null` when there is no uptime. */
export function formatUptime(seconds) {
  if (!isNumber(seconds)) {
    return null;
  }
  const total = Math.max(0, Math.floor(seconds));
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  return `${days}d ${hours}h ${minutes}m`;
}

/** `12.5%`, `0.0%`; `null` when there is no percentage. */
export function formatPercent(percent) {
  if (!isNumber(percent)) {
    return null;
  }
  return `${oneDecimal(percent)}%`;
}

/** `9.0 / 32.0 GiB (28.1% used)`; `null` when either value is missing or the total is not positive. */
export function memoryText(performance) {
  const used = performance?.memoryUsedBytes;
  const total = performance?.memoryTotalBytes;
  if (!isNumber(used) || !isNumber(total) || !(total > 0)) {
    return null;
  }
  return `${oneDecimal(used / GIB)} / ${oneDecimal(total / GIB)} GiB (${oneDecimal((used / total) * 100)}% used)`;
}

/** `196.0 GiB free of 953.4 GiB (20.6% free)`; `null` when either value is missing or the total is not positive. */
export function diskText(performance) {
  const free = performance?.systemDiskFreeBytes;
  const total = performance?.systemDiskTotalBytes;
  if (!isNumber(free) || !isNumber(total) || !(total > 0)) {
    return null;
  }
  return `${oneDecimal(free / GIB)} GiB free of ${oneDecimal(total / GIB)} GiB (${oneDecimal((free / total) * 100)}% free)`;
}

/** `200 Mb/s`, `1.2 Gb/s`, `80 kb/s`; `?` when there is no rate. */
function formatBitRate(bits) {
  if (!isNumber(bits)) {
    return '?';
  }
  for (const [unit, size] of [['Gb/s', 1e9], ['Mb/s', 1e6], ['kb/s', 1e3]]) {
    if (bits >= size) {
      return `${oneDecimal(bits / size)} ${unit}`;
    }
  }
  return `${Math.round(bits)} b/s`;
}

/** A count or `?`. */
function countText(value) {
  return isNumber(value) ? String(Math.round(value)) : '?';
}

/**
 * One line per heartbeat network adapter:
 * `Ethernet: 20.0% of 1.0 Gb/s · in 200.0 Mb/s, out 20.0 Mb/s · 20000/5000 pkt/s · errors 0/405 · discards 12/0`.
 * Pairs are in/out. `[]` when there is no network block.
 */
export function networkLines(network) {
  if (!Array.isArray(network)) {
    return [];
  }
  return network
    .filter((adapter) => typeof adapter?.name === 'string')
    .map((adapter) => {
      const saturation = isNumber(adapter.linkSpeedBitsPerSecond)
        ? `${formatPercent(adapter.utilizationPercent) ?? '?'} of ${formatBitRate(adapter.linkSpeedBitsPerSecond)}`
        : 'link speed unknown';
      return [
        `${adapter.name}: ${saturation}`,
        `in ${formatBitRate(adapter.receiveBitsPerSecond)}, out ${formatBitRate(adapter.sendBitsPerSecond)}`,
        `${countText(adapter.packetsReceivedPerSecond)}/${countText(adapter.packetsSentPerSecond)} pkt/s`,
        `errors ${countText(adapter.receiveErrors)}/${countText(adapter.sendErrors)}`,
        `discards ${countText(adapter.receiveDiscards)}/${countText(adapter.sendDiscards)}`,
      ].join(' · ');
    });
}

/** The window picker; `selected` is the window currently applied. */
function windowPicker(selected) {
  const current = WINDOW_OPTIONS.some(({ value }) => value === selected) ? selected : DEFAULT_WINDOW_DAYS;
  const options = WINDOW_OPTIONS.map(
    ({ value, label }) => `<option value="${value}"${value === current ? ' selected' : ''}>${label}</option>`,
  ).join('');
  return `<label class="filter">Window <select class="analytics-window" name="days">${options}</select></label>`;
}

/** A list from the state, or `[]` when it is absent. */
function listOf(value) {
  return Array.isArray(value) ? value : [];
}

/** The row opening a device: its hostname, or its id when the hostname is unknown. */
function deviceRow(entry, cells) {
  const label = entry?.hostname ?? entry?.deviceId;
  return [
    `<tr class="device" data-device-id="${escapeHtml(entry?.deviceId)}">`,
    `<td class="col-device">${cell(label)}</td>`,
    cells.join(''),
    '</tr>',
  ].join('');
}

/** One titled section: a table when there are entries, the empty message otherwise. */
function section(id, heading, headings, rows, emptyMessage) {
  const body =
    rows.length === 0
      ? `<p class="empty">${emptyMessage}</p>`
      : [
          `<table class="grid ${id}">`,
          `<thead><tr>${headings.map((text) => `<th>${text}</th>`).join('')}</tr></thead>`,
          `<tbody>${rows.join('')}</tbody>`,
          '</table>',
        ].join('');
  return `<section class="panel" id="${id}"><h3>${heading}</h3>${body}</section>`;
}

/** A plain table cell. */
function td(value) {
  return `<td>${cell(value)}</td>`;
}

/** The fleet analytics screen. */
export function render(state = {}) {
  const current = state ?? {};

  const slowest = section(
    'analytics-slowest-boots',
    'Slowest boots',
    ['Device', 'Last boot', 'Boot duration'],
    listOf(current.slowestBoots).map((entry) =>
      deviceRow(entry, [td(entry?.lastBootAt), td(formatSeconds(entry?.bootDurationSeconds))]),
    ),
    'No boot data reported',
  );

  const crashes = section(
    'analytics-most-crashes',
    'Most crashes and hangs',
    ['Device', 'Crashes', 'Hangs', 'Total', 'Last occurred'],
    listOf(current.mostCrashes).map((entry) =>
      deviceRow(entry, [
        td(entry?.crashCount),
        td(entry?.hangCount),
        td(entry?.eventCount),
        td(entry?.lastOccurredAt),
      ]),
    ),
    'No crashes or hangs in this window',
  );

  const apps = section(
    'analytics-top-apps',
    'Top crashing applications',
    ['Application', 'Crashes', 'Hangs', 'Total', 'Devices', 'Last occurred'],
    listOf(current.topApps).map((entry) =>
      [
        '<tr class="app">',
        td(entry?.appName),
        td(entry?.crashCount),
        td(entry?.hangCount),
        td(entry?.eventCount),
        td(entry?.deviceCount),
        td(entry?.lastOccurredAt),
        '</tr>',
      ].join(''),
    ),
    'No crashing applications in this window',
  );

  const pressure = section(
    'analytics-resource-pressure',
    'Resource pressure',
    ['Device', 'Disk free', 'Memory used', 'Reasons'],
    listOf(current.resourcePressure).map((entry) =>
      deviceRow(entry, [
        td(formatPercent(entry?.diskFreePercent)),
        td(formatPercent(entry?.memoryUsedPercent)),
        td(listOf(entry?.reasons).map((reason) => REASON_LABELS[reason] ?? reason).join(', ')),
      ]),
    ),
    'No devices under resource pressure',
  );

  return [
    '<section class="screen" id="screen-analytics"><h2>Analytics</h2>',
    windowPicker(current.windowDays),
    current.truncated === true ? TRUNCATED_WARNING : '',
    slowest,
    crashes,
    apps,
    pressure,
    '</section>',
  ].join('');
}

export const renderAnalytics = render;
