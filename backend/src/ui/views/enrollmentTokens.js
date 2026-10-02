/**
 * Enrollment tokens: minting them, and showing one exactly once.
 *
 *   render({items, created})
 *   createRequest({label, maxUses, expiresAt}) -> POST /admin/api/v1/enrollment-tokens
 *
 * The API returns the full token in the creation response and nowhere else --
 * only its hash is stored -- so this screen is the one and only chance an
 * operator has to copy it. It is rendered once, in a copy field, under the text
 * that says so. Re-rendering from the stored records shows the record's
 * metadata and no token value, because there is none to show.
 */
import { cell, escapeHtml, join } from '../public/html.js';

/** The columns a stored token record shows, in order. */
export const COLUMNS = ['tokenId', 'label', 'maxUses', 'useCount', 'expiresAt'];

/** The warning the freshly minted token is shown under. */
export const ONCE_MESSAGE = 'This token is shown once';

/** What an empty token list reads as. */
export const EMPTY_MESSAGE = 'No enrollment tokens yet';

/** The creation request, or `null` when the form is not complete enough to send. */
export function createRequest(state = {}) {
  const label = typeof state.label === 'string' ? state.label : '';
  const maxUses = typeof state.maxUses === 'string' ? Number(state.maxUses) : state.maxUses;
  const expiresAt = typeof state.expiresAt === 'string' ? state.expiresAt : '';
  if (!Number.isInteger(maxUses) || maxUses < 1 || expiresAt.length === 0) {
    return null;
  }
  return {
    method: 'POST',
    path: '/admin/api/v1/enrollment-tokens',
    body: { label, maxUses, expiresAt },
  };
}

/** Just the creation body, or `null`. */
export function createBody(state = {}) {
  return createRequest(state)?.body ?? null;
}

/**
 * The token to show this render, or `null`.
 *
 * Read from the creation response alone -- `state.created`, or the state itself
 * when the response is handed straight in. A stored record never carries one.
 */
export function shownToken(state = {}) {
  const created = state.created ?? state;
  const token = created?.token;
  return typeof token === 'string' && token.length > 0 ? token : null;
}

/** One stored token record. */
function row(item) {
  const cells = COLUMNS.map((column) => `<td class="col-${column}">${cell(item[column])}</td>`).join('');
  return `<tr class="token" data-token-id="${escapeHtml(item.tokenId)}">${cells}</tr>`;
}

/** The enrollment tokens screen. */
export function render(state = {}) {
  const items = Array.isArray(state.items) ? state.items : [];
  const token = shownToken(state);

  const once =
    token === null
      ? ''
      : join([
          '<div class="token-once">',
          `<p class="warning">${ONCE_MESSAGE}</p>`,
          `<input id="new-token" class="copy-field" readonly value="${escapeHtml(token)}">`,
          '<button type="button" class="copy" data-copy-target="new-token">Copy</button>',
          '</div>',
        ]);

  const list =
    items.length === 0
      ? `<p class="empty">${EMPTY_MESSAGE}</p>`
      : [
          '<table class="grid tokens">',
          `<thead><tr>${COLUMNS.map((column) => `<th>${column}</th>`).join('')}</tr></thead>`,
          `<tbody>${items.map(row).join('')}</tbody>`,
          '</table>',
        ].join('');

  return join([
    '<section class="screen" id="screen-enrollment-tokens"><h2>Enrollment tokens</h2>',
    once,
    '<form class="create-token">',
    '<label for="token-label">label</label>',
    `<input id="token-label" name="label" value="${escapeHtml(state.label)}">`,
    '<label for="token-max-uses">maxUses</label>',
    `<input id="token-max-uses" name="maxUses" type="number" min="1" value="${escapeHtml(state.maxUses)}">`,
    '<label for="token-expires">expiresAt</label>',
    `<input id="token-expires" name="expiresAt" value="${escapeHtml(state.expiresAt)}">`,
    '<button type="submit" class="create">Create token</button>',
    '</form>',
    list,
    '</section>',
  ]);
}

export const renderEnrollmentTokens = render;
