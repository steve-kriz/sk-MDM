/**
 * The fleet software screens: what `GET /admin/api/v1/software` and
 * `GET /admin/api/v1/software/devices` answer with.
 *
 *   render({items, total, offset, limit, search, sort, truncated})   -> the title list
 *   render({name, items, truncated})                                  -> one title's devices
 *
 * The drill-down is chosen by a `name` in state. A pure function of state, like
 * every view: it reads no global, touches no DOM and returns a string. Title
 * rows are `tr.software-title` carrying `data-name`; device rows are
 * `tr.device`, so the console's existing click handler opens the device detail
 * screen.
 */
import { cell, escapeHtml } from '../public/html.js';

/** The title orderings the sort select offers, in order. */
export const SORT_OPTIONS = ['name', 'devices'];

/** The title list columns, in order. */
export const TITLE_COLUMNS = ['name', 'publisher', 'versions', 'deviceCount'];

/** The drill-down columns, in order. */
export const DEVICE_COLUMNS = ['hostname', 'platform', 'version', 'installedAt', 'lastSeenAt'];

/** The partial-results warning, shown when the API stopped reading early. */
export const TRUNCATED_WARNING =
  '<p class="warning truncated">Partial results: not every device inventory could be read</p>';

/** The array, or an empty one when the value is not an array. */
function listOf(value) {
  return Array.isArray(value) ? value : [];
}

/** A non-negative integer, or the fallback. */
function count(value, fallback) {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : fallback;
}

/** `"23.01 (2), 22.00 (1)"` -- a title's versions with their device counts. */
export function versionsText(versions) {
  return listOf(versions)
    .map((entry) => `${entry?.version} (${entry?.deviceCount})`)
    .join(', ');
}

/** The search form, prefilled with the current search. */
function searchForm(search) {
  return [
    '<form class="software-search">',
    '<label for="software-search">Search</label>',
    `<input id="software-search" name="search" value="${escapeHtml(search)}">`,
    '<button type="submit">Search</button>',
    '</form>',
  ].join('');
}

/** The sort select, with the current ordering selected. */
function sortSelect(sort) {
  const options = SORT_OPTIONS.map(
    (value) => `<option value="${value}"${value === sort ? ' selected' : ''}>${value}</option>`,
  ).join('');
  return `<label for="software-sort">Sort</label><select id="software-sort" class="software-sort">${options}</select>`;
}

/** One title row. */
function titleRow(item) {
  const title = item ?? {};
  const values = { ...title, versions: versionsText(title.versions) };
  const cells = TITLE_COLUMNS.map((column) => `<td class="col-${column}">${cell(values[column])}</td>`).join('');
  return `<tr class="software-title" data-name="${escapeHtml(title.name)}">${cells}</tr>`;
}

/** One device row of the drill-down. */
function deviceRow(item) {
  const device = item ?? {};
  const cells = DEVICE_COLUMNS.map((column) => `<td class="col-${column}">${cell(device[column])}</td>`).join('');
  return `<tr class="device" data-device-id="${escapeHtml(device.deviceId)}">${cells}</tr>`;
}

/** The fleet title list. */
export function renderTitles(state = {}) {
  const items = listOf(state.items);
  const offset = count(state.offset, 0);
  const limit = count(state.limit, 50);
  const total = count(state.total, items.length);
  const sort = SORT_OPTIONS.includes(state.sort) ? state.sort : 'name';
  const search = typeof state.search === 'string' ? state.search : '';

  const table =
    items.length === 0
      ? '<p class="empty">No software reported</p>'
      : [
          '<table class="grid software-titles">',
          `<thead><tr>${TITLE_COLUMNS.map((column) => `<th>${column}</th>`).join('')}</tr></thead>`,
          `<tbody>${items.map(titleRow).join('')}</tbody>`,
          '</table>',
        ].join('');

  const previous = offset > 0 ? '<button type="button" class="software-prev">Previous</button>' : '';
  const next = offset + limit < total ? '<button type="button" class="software-next">Next</button>' : '';

  return [
    '<section class="screen" id="screen-software"><h2>Software</h2>',
    searchForm(search),
    sortSelect(sort),
    state.truncated === true ? TRUNCATED_WARNING : '',
    table,
    previous || next ? `<div class="pager">${previous}${next}</div>` : '',
    '</section>',
  ].join('');
}

/** One title's devices. */
export function renderDevices(state = {}) {
  const items = listOf(state.items);
  const table =
    items.length === 0
      ? '<p class="empty">No devices have this software</p>'
      : [
          '<table class="grid software-devices">',
          `<thead><tr>${DEVICE_COLUMNS.map((column) => `<th>${column}</th>`).join('')}</tr></thead>`,
          `<tbody>${items.map(deviceRow).join('')}</tbody>`,
          '</table>',
        ].join('');
  return [
    '<section class="screen" id="screen-software-devices">',
    `<h2>${cell(state.name)}</h2>`,
    state.truncated === true ? TRUNCATED_WARNING : '',
    table,
    '</section>',
  ].join('');
}

/** The software screen: the drill-down when state names a title, else the title list. */
export function render(state = {}) {
  return typeof state.name === 'string' && state.name.length > 0 ? renderDevices(state) : renderTitles(state);
}

export const renderSoftware = render;
