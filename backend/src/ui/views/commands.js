/**
 * The command library: saved scripts an admin queues onto devices.
 *
 *   render({items, editing, editDraft, name, interpreter, timeoutSeconds, description, script})
 *   createRequest(state)  -> {method:'POST', path, body} | null
 *   updateRequest(state)  -> {method:'PUT', path, body} | null
 *   deleteRequest({scriptId, name, typedName}) -> {method:'DELETE', path} | null
 *   fieldErrors(state)    -> the fields the API would refuse
 *   generateRequest(state) -> {method:'POST', path:GENERATE_PATH, body} | null (TASK-053)
 *   generateRefusals(state) -> the fields the generate API would refuse
 *
 * `render` reads `generating` (`'create' | 'edit' | null`): that form's
 * Generate button is disabled and reads `Generating...`.
 *
 * The rules mirror `POST /admin/api/v1/scripts` (see `src/admin/scripts.ts`),
 * so a blank name, an empty script or a timeout outside 1-3600 is refused here
 * and nothing is sent. Clicking a row opens the edit form; its Delete button
 * stays disabled until the script's name is typed exactly.
 */
import { attributes, cell, escapeHtml, join } from '../public/html.js';

/** The library's path under the admin API. */
export const SCRIPTS_PATH = '/admin/api/v1/scripts';

/** The shells a saved command may use, and the platform each runs on. */
export const SHELLS = [
  { value: 'cmd', label: 'cmd', platform: 'windows' },
  { value: 'powershell', label: 'powershell', platform: 'windows' },
  { value: 'bash', label: 'bash', platform: 'darwin' },
  { value: 'zsh', label: 'zsh', platform: 'darwin' },
];

/** The library table's columns, in order. */
export const COLUMNS = ['name', 'shell', 'platform', 'description', 'updated'];

/** What an empty library reads as. */
export const EMPTY_MESSAGE = 'No saved commands yet';

/** Accepted range of `timeoutSeconds`, both bounds inclusive. */
export const TIMEOUT_SECONDS = { min: 1, max: 3600 };

/** The timeout used when the form leaves it empty. */
export const DEFAULT_TIMEOUT_SECONDS = 300;

/** Longest accepted name and description, in characters. */
export const NAME_MAX_LENGTH = 100;
export const DESCRIPTION_MAX_LENGTH = 500;

const SHELL_VALUES = SHELLS.map((shell) => shell.value);

/** The timeout as typed: empty is the default, a whole number is itself, anything else is `NaN`. */
function timeoutOf(value) {
  if (value === undefined || value === null || value === '') {
    return DEFAULT_TIMEOUT_SECONDS;
  }
  if (typeof value === 'number') {
    return value;
  }
  const text = String(value).trim();
  return /^-?[0-9]+(\.[0-9]+)?$/.test(text) ? Number(text) : Number.NaN;
}

/** The fields the API would refuse, in the order it names them. */
export function fieldErrors(state = {}) {
  const errors = [];
  const name = typeof state.name === 'string' ? state.name : '';
  if (name.trim().length === 0 || name.length > NAME_MAX_LENGTH) {
    errors.push('name');
  }
  if (typeof state.description === 'string' && state.description.length > DESCRIPTION_MAX_LENGTH) {
    errors.push('description');
  }
  if (!SHELL_VALUES.includes(state.interpreter)) {
    errors.push('interpreter');
  }
  if (typeof state.script !== 'string' || state.script.length === 0) {
    errors.push('script');
  }
  const timeout = timeoutOf(state.timeoutSeconds);
  if (!Number.isInteger(timeout) || timeout < TIMEOUT_SECONDS.min || timeout > TIMEOUT_SECONDS.max) {
    errors.push('timeoutSeconds');
  }
  return errors;
}

/** The body a create or update sends, from a state `fieldErrors` accepts. */
function bodyOf(state) {
  const description = typeof state.description === 'string' && state.description.length > 0 ? state.description : null;
  return {
    name: state.name,
    interpreter: state.interpreter,
    script: state.script,
    timeoutSeconds: timeoutOf(state.timeoutSeconds),
    description,
  };
}

/** The create request, or `null` when a field would be refused. */
export function createRequest(state = {}) {
  if (fieldErrors(state).length > 0) {
    return null;
  }
  return { method: 'POST', path: SCRIPTS_PATH, body: bodyOf(state) };
}

/** The path one saved command lives at. */
export function scriptPath(scriptId) {
  return `${SCRIPTS_PATH}/${scriptId}`;
}

/** The update request for `state.scriptId`, or `null` when there is none or a field would be refused. */
export function updateRequest(state = {}) {
  if (typeof state.scriptId !== 'string' || state.scriptId.length === 0 || fieldErrors(state).length > 0) {
    return null;
  }
  return { method: 'PUT', path: scriptPath(state.scriptId), body: bodyOf(state) };
}

/** The delete request: only once the script's name has been typed exactly. */
export function deleteRequest(state = {}) {
  const name = typeof state.name === 'string' ? state.name : '';
  if (!state.scriptId || name.length === 0 || state.typedName !== name) {
    return null;
  }
  return { method: 'DELETE', path: scriptPath(state.scriptId) };
}

/** The AI script generator's path under the admin API (TASK-053). */
export const GENERATE_PATH = '/admin/api/v1/scripts/generate';

/** Longest accepted generate request, in characters after trimming. */
export const GENERATE_PROMPT_MAX_LENGTH = 4000;

/**
 * The fields `POST /admin/api/v1/scripts/generate` would refuse, in the order
 * it names them: the script textarea is the prompt, so an empty or over-long
 * script is `prompt`. The name is not part of a generate request.
 */
export function generateRefusals(state = {}) {
  const errors = [];
  const prompt = typeof state.script === 'string' ? state.script.trim() : '';
  if (prompt.length === 0 || prompt.length > GENERATE_PROMPT_MAX_LENGTH) {
    errors.push('prompt');
  }
  if (typeof state.description === 'string' && state.description.length > DESCRIPTION_MAX_LENGTH) {
    errors.push('description');
  }
  if (!SHELL_VALUES.includes(state.interpreter)) {
    errors.push('interpreter');
  }
  const timeout = timeoutOf(state.timeoutSeconds);
  if (!Number.isInteger(timeout) || timeout < TIMEOUT_SECONDS.min || timeout > TIMEOUT_SECONDS.max) {
    errors.push('timeoutSeconds');
  }
  return errors;
}

/** The generate request built from a form's fields, or `null` when a field would be refused. */
export function generateRequest(state = {}) {
  if (generateRefusals(state).length > 0) {
    return null;
  }
  const description = typeof state.description === 'string' && state.description.length > 0 ? state.description : null;
  return {
    method: 'POST',
    path: GENERATE_PATH,
    body: {
      prompt: state.script.trim(),
      interpreter: state.interpreter,
      timeoutSeconds: timeoutOf(state.timeoutSeconds),
      description,
    },
  };
}

/** The shell select, with `selected` marked. */
function shellSelect(id, selected) {
  const options = SHELLS.map(
    (shell) =>
      `<option value="${shell.value}"${shell.value === selected ? ' selected' : ''}>${shell.label} (${shell.platform})</option>`,
  ).join('');
  return `<select id="${id}" name="interpreter">${options}</select>`;
}

/** One named field error. */
function errorFor(errors, field, message) {
  return errors.includes(field) ? `<p class="field-error" data-field="${field}">${message}</p>` : '';
}

/** The inputs shared by the create and edit forms; `prefix` keeps their element ids apart. */
function scriptFields(shown, prefix, errors = [], generating = false) {
  const id = (name) => `${prefix}${name}`;
  const timeout = shown.timeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS;
  return join([
    `<label for="${id('name')}">name</label>`,
    `<input id="${id('name')}" name="name" maxlength="${NAME_MAX_LENGTH}" value="${escapeHtml(shown.name)}">`,
    errorFor(errors, 'name', 'name is required'),
    `<label for="${id('shell')}">shell</label>`,
    shellSelect(id('shell'), shown.interpreter),
    `<label for="${id('timeout')}">timeoutSeconds</label>`,
    `<input id="${id('timeout')}" name="timeoutSeconds" type="number" min="${TIMEOUT_SECONDS.min}" max="${TIMEOUT_SECONDS.max}" value="${escapeHtml(timeout)}">`,
    errorFor(errors, 'timeoutSeconds', `timeoutSeconds must be between ${TIMEOUT_SECONDS.min} and ${TIMEOUT_SECONDS.max}`),
    `<label for="${id('description')}">description</label>`,
    `<input id="${id('description')}" name="description" maxlength="${DESCRIPTION_MAX_LENGTH}" value="${escapeHtml(shown.description)}">`,
    `<label for="${id('script')}">script</label>`,
    `<textarea id="${id('script')}" name="script" class="script-body monospace" spellcheck="false" style="font-family: monospace">${escapeHtml(shown.script)}</textarea>` +
      generateButton(generating),
    errorFor(errors, 'script', 'script is required'),
  ]);
}

/** The Generate button that follows the script textarea; disabled while that form's generate is pending. */
function generateButton(generating) {
  return generating
    ? '<button type="button" class="generate-script" disabled>Generating...</button>'
    : '<button type="button" class="generate-script">Generate</button>';
}

/**
 * The edit panel for the script being edited: `form.edit-script`, then -- as a
 * sibling, never nested -- `form.delete-script`, whose Delete button stays
 * disabled until the script's name is typed exactly.
 */
function editPanel(editing, draft, generating = false) {
  if (editing === null || editing === undefined || !editing.scriptId) {
    return '';
  }
  const shown = draft ?? editing;
  const scriptId = escapeHtml(editing.scriptId);
  const deletable = deleteRequest({ scriptId: editing.scriptId, name: editing.name, typedName: '' }) !== null;
  return join([
    `<div class="edit-panel" data-script-id="${scriptId}">`,
    `<h3>Edit command ${cell(editing.name)}</h3>`,
    '<form class="edit-script">',
    `<input type="hidden" name="scriptId" value="${scriptId}">`,
    scriptFields(shown, 'edit-script-', [], generating),
    '<button type="submit" class="save">Save</button>',
    '</form>',
    '<form class="delete-script">',
    `<input type="hidden" name="scriptId" value="${scriptId}">`,
    '<label for="delete-script-name">Type the command name to delete it</label>',
    '<input id="delete-script-name" name="typedName" value="" autocomplete="off">',
    `<button type="submit" class="delete"${attributes({ disabled: !deletable })}>Delete</button>`,
    '</form>',
    '</div>',
  ]);
}

/** One saved command. */
function row(item) {
  return [
    `<tr class="script" data-script-id="${escapeHtml(item.scriptId)}">`,
    `<td class="col-name">${cell(item.name)}</td>`,
    `<td class="col-shell">${cell(item.interpreter)}</td>`,
    `<td class="col-platform">${cell(item.platform)}</td>`,
    `<td class="col-description">${cell(item.description)}</td>`,
    `<td class="col-updated">${cell(item.updatedAt)}</td>`,
    '</tr>',
  ].join('');
}

/** The commands screen. */
export function render(state = {}) {
  const items = Array.isArray(state.items) ? state.items : [];
  const list =
    items.length === 0
      ? `<p class="empty">${EMPTY_MESSAGE}</p>`
      : [
          '<table class="grid scripts">',
          `<thead><tr>${COLUMNS.map((column) => `<th>${column}</th>`).join('')}</tr></thead>`,
          `<tbody>${items.map(row).join('')}</tbody>`,
          '</table>',
        ].join('');

  const draft = {
    name: state.name ?? '',
    interpreter: state.interpreter ?? SHELLS[0].value,
    timeoutSeconds: state.timeoutSeconds ?? DEFAULT_TIMEOUT_SECONDS,
    description: state.description ?? '',
    script: state.script ?? '',
  };

  return join([
    '<section class="screen" id="screen-commands"><h2>Commands</h2>',
    list,
    editPanel(state.editing, state.editDraft, state.generating === 'edit'),
    '<h3>New command</h3>',
    '<form class="create-script">',
    scriptFields(draft, 'script-', [], state.generating === 'create'),
    '<button type="submit" class="create">Save command</button>',
    '</form>',
    '</section>',
  ]);
}

export const renderCommands = render;
