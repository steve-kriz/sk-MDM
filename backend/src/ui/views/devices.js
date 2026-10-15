/**
 * The device list: the fleet, one row per machine.
 *
 *   render({items, cursor}) -> '<section ...>...</section>'
 *
 * The state is the `{items, cursor}` envelope `GET /admin/api/v1/devices`
 * answers with, handed over untouched, plus the `ownership` filter currently
 * applied (`''`, `'officehq'` or `'byoc'`). The view is a pure function of it: it
 * reads no global, touches no DOM and returns a string, so `node --test`
 * renders every screen without a browser.
 */
import { cell, escapeHtml } from '../public/html.js';

/** The columns a row shows, in order. */
export const COLUMNS = ['hostname', 'ownership', 'platform', 'osVersion', 'lastSeenAt', 'complianceState'];

/** Column headings that are not simply the field name. */
const HEADINGS = { ownership: 'Ownership', osVersion: 'OS' };

/**
 * What a device's OS reads as: the friendly name the check-in derived
 * (`osDisplay`), falling back to the enrolled kernel version.
 */
export function osLabel(item) {
  return typeof item?.osDisplay === 'string' && item.osDisplay.length > 0 ? item.osDisplay : item?.osVersion;
}

/** How each stored ownership value is shown. */
export const OWNERSHIP_LABELS = { officehq: 'OfficeHQ', byoc: 'BYOC' };

/** The ownership filter's choices, in order: `''` is no filter. */
export const OWNERSHIP_FILTER_OPTIONS = [
  { value: '', label: 'All' },
  { value: 'officehq', label: OWNERSHIP_LABELS.officehq },
  { value: 'byoc', label: OWNERSHIP_LABELS.byoc },
];

/**
 * The label for a stored ownership. A device enrolled before ownership was
 * recorded is an OfficeHQ device, which is also what the API answers for it.
 */
export function ownershipLabel(value) {
  return OWNERSHIP_LABELS[value] ?? OWNERSHIP_LABELS.officehq;
}

/** The ownership filter; `selected` is the value currently applied. */
function ownershipFilter(selected) {
  const current = typeof selected === 'string' ? selected : '';
  const options = OWNERSHIP_FILTER_OPTIONS.map(
    ({ value, label }) =>
      `<option value="${value}"${value === current ? ' selected' : ''}>${label}</option>`,
  ).join('');
  return `<label class="filter">Ownership <select class="ownership-filter" name="ownership">${options}</select></label>`;
}

/** What an empty fleet reads as. */
export const EMPTY_MESSAGE = 'No devices enrolled';

/** One row, carrying the device id the detail screen is opened with. */
function row(item) {
  const values = { ...item, ownership: ownershipLabel(item.ownership), osVersion: osLabel(item) };
  const cells = COLUMNS.map((column) => `<td class="col-${column}">${cell(values[column])}</td>`).join('');
  return `<tr class="device" data-device-id="${escapeHtml(item.deviceId)}">${cells}</tr>`;
}

/** The device list screen. */
export function render(state = {}) {
  const items = Array.isArray(state.items) ? state.items : [];
  const body =
    items.length === 0
      ? `<p class="empty">${EMPTY_MESSAGE}</p>`
      : [
          '<table class="grid devices">',
          `<thead><tr>${COLUMNS.map((column) => `<th>${HEADINGS[column] ?? column}</th>`).join('')}</tr></thead>`,
          `<tbody>${items.map(row).join('')}</tbody>`,
          '</table>',
        ].join('');

  const more =
    typeof state.cursor === 'string' && state.cursor.length > 0
      ? `<button type="button" class="more" data-cursor="${escapeHtml(state.cursor)}">Load more</button>`
      : '';

  return `<section class="screen" id="screen-devices"><h2>Devices</h2>${ownershipFilter(state.ownership)}${body}${more}</section>`;
}

export const renderDevices = render;
