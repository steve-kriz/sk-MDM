/**
 * Settings: the one value an operator needs to install an agent.
 *
 *   render({collectionUrl})
 *
 * The URL itself is decided on the server by `src/ui/settings.ts`
 * (`COLLECTION_URL`, else the Lambda's own Function URL) and handed to this
 * view as plain state, so the screen renders the same string the installers
 * are given and invents nothing.
 */
import { escapeHtml, join } from '../public/html.js';

/** What an unconfigured deployment reads as. */
export const UNKNOWN_MESSAGE = 'No collection URL is configured';

/** The URL the state carries, whichever name it arrived under. */
export function urlOf(state = {}) {
  const url = state.collectionUrl ?? state.url;
  return typeof url === 'string' && url.length > 0 ? url : null;
}

/** The settings screen. */
export function render(state = {}) {
  const url = urlOf(state);
  const value =
    url === null
      ? `<p class="empty">${UNKNOWN_MESSAGE}</p>`
      : join([
          '<div class="setting">',
          '<label for="collection-url">Collection URL</label>',
          `<input id="collection-url" class="copy-field" readonly value="${escapeHtml(url)}">`,
          '<button type="button" class="copy" data-copy-target="collection-url">Copy</button>',
          '<p class="hint">Give this URL to the installers.</p>',
          '</div>',
        ]);

  return `<section class="screen" id="screen-settings"><h2>Settings</h2>${value}</section>`;
}

export const renderSettings = render;
