/**
 * The audit trail over a date range.
 *
 *   requestFor({from, to}) -> GET /admin/api/v1/audit?from=<iso>&to=<iso>
 *   render({items, from, to})
 *
 * The API already answers newest first; the view sorts again rather than trust
 * the order of whatever it was handed, because "what happened last" is the one
 * question this screen exists to answer.
 */
import { cell, escapeHtml, join } from '../public/html.js';

/** The columns an entry shows, in order. */
export const COLUMNS = ['at', 'actor', 'action', 'target'];

/** What an empty range reads as. */
export const EMPTY_MESSAGE = 'No audit entries in this range';

/** The query for a range. */
export function requestFor(state = {}) {
  const query = {};
  if (state.from) {
    query.from = state.from;
  }
  if (state.to) {
    query.to = state.to;
  }
  return { method: 'GET', path: '/admin/api/v1/audit', query };
}

/** The entries the state carries, newest first. */
export function entriesOf(state = {}) {
  const items = Array.isArray(state.items) ? state.items : Array.isArray(state.entries) ? state.entries : [];
  return [...items].sort((left, right) => String(right.at ?? '').localeCompare(String(left.at ?? '')));
}

/** One entry. */
function row(entry) {
  const cells = COLUMNS.map((column) => `<td class="col-${column}">${cell(entry[column])}</td>`).join('');
  return `<tr class="audit-entry">${cells}</tr>`;
}

/** The audit screen. */
export function render(state = {}) {
  const entries = entriesOf(state);
  const table =
    entries.length === 0
      ? `<p class="empty">${EMPTY_MESSAGE}</p>`
      : [
          '<table class="grid audit">',
          `<thead><tr>${COLUMNS.map((column) => `<th>${column}</th>`).join('')}</tr></thead>`,
          `<tbody>${entries.map(row).join('')}</tbody>`,
          '</table>',
        ].join('');

  return join([
    '<section class="screen" id="screen-audit"><h2>Audit log</h2>',
    '<form class="audit-range">',
    '<label for="audit-from">from</label>',
    `<input id="audit-from" name="from" value="${escapeHtml(state.from)}">`,
    '<label for="audit-to">to</label>',
    `<input id="audit-to" name="to" value="${escapeHtml(state.to)}">`,
    '<button type="submit" class="load">Load</button>',
    '</form>',
    table,
    '</section>',
  ]);
}

export const renderAudit = render;
