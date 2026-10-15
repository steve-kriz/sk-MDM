/**
 * Settings: the one value an operator needs to install an agent, and the
 * fleet-wide command setting.
 *
 *   render({collectionUrl, onFailure})
 *   commandSettingsRequest({onFailure}) -> PUT /admin/api/v1/settings/commands {onFailure} | null
 *
 * Auto-assigning devices to groups by ownership is set on each group, on the
 * Groups screen.
 *
 * `onFailure` comes from `GET /admin/api/v1/settings/commands`: `continue`
 * (the default) leaves the rest of a machine's queue alone when a command
 * fails; `stop` skips the remaining commands.
 *
 * The URL itself is decided on the server by `src/ui/settings.ts`
 * (`COLLECTION_URL`, else the Lambda's own Function URL) and handed to this
 * view as plain state, so the screen renders the same string the installers
 * are given and invents nothing.
 */
import { escapeHtml, join } from '../public/html.js';

/** The "When a command fails" choices, in the order the select lists them. */
export const ON_FAILURE_OPTIONS = [
  { value: 'continue', label: 'Continue' },
  { value: 'stop', label: 'Stop the remaining commands' },
];

/** The command settings request, or `null` for a value the API would refuse. */
export function commandSettingsRequest(state = {}) {
  if (!ON_FAILURE_OPTIONS.some(({ value }) => value === state.onFailure)) {
    return null;
  }
  return { method: 'PUT', path: '/admin/api/v1/settings/commands', body: { onFailure: state.onFailure } };
}

/** The "When a command fails" form, preselected from the stored setting. */
function commandSettingsForm(onFailure) {
  const current = ON_FAILURE_OPTIONS.some(({ value }) => value === onFailure) ? onFailure : 'continue';
  const options = ON_FAILURE_OPTIONS.map(
    ({ value, label }) => `<option value="${value}"${value === current ? ' selected' : ''}>${escapeHtml(label)}</option>`,
  ).join('');
  return join([
    '<form class="command-settings setting">',
    '<label for="command-on-failure">When a command fails</label>',
    `<select id="command-on-failure" name="onFailure">${options}</select>`,
    '<button type="submit" class="save">Save</button>',
    '</form>',
  ]);
}

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

  return `<section class="screen" id="screen-settings"><h2>Settings</h2>${value}${commandSettingsForm(state.onFailure)}</section>`;
}

export const renderSettings = render;
