/**
 * The device list: the fleet, one row per machine.
 *
 *   render({items, cursor}) -> '<section ...>...</section>'
 *
 * The state is the `{items, cursor}` envelope `GET /admin/api/v1/devices`
 * answers with, handed over untouched. The view is a pure function of it: it
 * reads no global, touches no DOM and returns a string, so `node --test`
 * renders every screen without a browser.
 */
import { cell, escapeHtml } from '../public/html.js';

/** The columns a row shows, in order. */
export const COLUMNS = ['hostname', 'primaryUser', 'platform', 'osVersion', 'lastSeenAt', 'complianceState'];

/** Re-resolves every device's Entra user through Graph, a page at a time. */
export const REFRESH_USER_LINKS_BUTTON =
  '<button type="button" class="refresh-user-links">Refresh user links</button>';

/** What an empty fleet reads as. */
export const EMPTY_MESSAGE = 'No devices enrolled';

/** One row, carrying the device id the detail screen is opened with. */
function row(item) {
  const cells = COLUMNS.map((column) => `<td class="col-${column}">${cell(item[column])}</td>`).join('');
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
          `<thead><tr>${COLUMNS.map((column) => `<th>${column}</th>`).join('')}</tr></thead>`,
          `<tbody>${items.map(row).join('')}</tbody>`,
          '</table>',
        ].join('');

  const more =
    typeof state.cursor === 'string' && state.cursor.length > 0
      ? `<button type="button" class="more" data-cursor="${escapeHtml(state.cursor)}">Load more</button>`
      : '';

  return `<section class="screen" id="screen-devices"><h2>Devices</h2>${REFRESH_USER_LINKS_BUTTON}${body}${more}</section>`;
}

export const renderDevices = render;
