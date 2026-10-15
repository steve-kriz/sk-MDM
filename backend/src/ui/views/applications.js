/**
 * The application safe list: approved installers users may download and admins
 * may push to a device.
 *
 *   render({items, dialog})             -- the list, and the add/edit popup while dialog.open
 *   fileRefusal({name, size})           -- why a chosen file cannot be uploaded, or null
 *   createUrlRequest(state)             -- {method:'POST', path, body} | null
 *   updateRequest(state, existing)      -- {method:'PATCH', path, body} | null
 *   deleteRequest({applicationId})      -- {method:'DELETE', path} | null
 *   retryHashRequest({applicationId})   -- {method:'POST', path} | null
 *
 * An upload never passes through the backend: the console asks for a presigned
 * S3 PUT URL, PUTs the file straight to the bucket and then registers the
 * application (see `app.js`). The rules here mirror `src/admin/applications.ts`
 * so a disallowed or oversized file is refused before any request.
 *
 * A URL source's SHA-256 is computed by the server (TASK-050), so the form has
 * no sha256 field. Each row shows the hash status, and a URL row that is not
 * ready offers Retry.
 *
 * Adding and editing both happen in one popup (`dialog`): `{open, mode: 'create'}`
 * or `{open, mode: 'edit', applicationId}`, with an optional `error` shown
 * inside it. An edit cannot change the source or an uploaded file, so those
 * fields are not offered; a URL source's url and installerType are.
 */
import { cell, escapeHtml, join } from '../public/html.js';

/** The safe list's path under the admin API. */
export const APPLICATIONS_PATH = '/admin/api/v1/applications';

/** The path that issues a presigned upload URL. */
export const UPLOAD_URL_PATH = '/admin/api/v1/applications/upload-url';

/** Largest accepted uploaded installer, in bytes (500 MiB). */
export const UPLOAD_MAX_BYTES = 524288000;

/** The installer extensions the safe list accepts, as the file input's `accept`. */
export const ACCEPTED_EXTENSIONS = '.msi,.exe,.pkg';

/** The installer types a URL application may name. */
export const INSTALLER_TYPES = ['msi', 'exe', 'pkg'];

/** Where an application comes from. */
export const SOURCES = ['upload', 'url'];

/** The list's columns, in order. */
export const COLUMNS = ['name', 'platform', 'installerType', 'source', 'status', 'description', ''];

/** What each hash status reads as; a failure is followed by its error code. */
export const STATUS_LABELS = { pending: 'Hashing…', ready: 'Ready', failed: 'Failed' };

/** What an empty list reads as. */
export const EMPTY_MESSAGE = 'No applications yet';

const EXTENSION_PATTERN = /\.(msi|exe|pkg)$/i;

/** Why a chosen file cannot be uploaded, or `null` when it can. */
export function fileRefusal({ name, size } = {}) {
  if (typeof name !== 'string' || !EXTENSION_PATTERN.test(name)) {
    return 'file_type_not_allowed';
  }
  if (typeof size === 'number' && size > UPLOAD_MAX_BYTES) {
    return 'file_too_large';
  }
  return null;
}

/** A typed value, or `''`. */
function text(value) {
  return typeof value === 'string' ? value : '';
}

/** A typed value, or `null` when it is empty. */
function orNull(value) {
  const typed = text(value);
  return typed.length > 0 ? typed : null;
}

/** The create request for a URL application, or `null` when a required field is empty. */
export function createUrlRequest(state = {}) {
  const name = text(state.name);
  const url = text(state.url);
  const installerType = text(state.installerType);
  if (name.length === 0 || url.length === 0 || installerType.length === 0) {
    return null;
  }
  return {
    method: 'POST',
    path: APPLICATIONS_PATH,
    body: {
      source: 'url',
      name,
      description: orNull(state.description),
      url,
      installerType,
      installArgs: orNull(state.installArgs),
    },
  };
}

/** The register request for an uploaded application, once its object is in the bucket. */
export function createUploadRequest(state = {}) {
  return {
    method: 'POST',
    path: APPLICATIONS_PATH,
    body: {
      source: 'upload',
      name: text(state.name),
      description: orNull(state.description),
      uploadKey: text(state.uploadKey),
      sha256: text(state.sha256),
      installArgs: orNull(state.installArgs),
    },
  };
}

/** The delete request for one application, or `null` when there is no id. */
export function deleteRequest({ applicationId } = {}) {
  if (typeof applicationId !== 'string' || applicationId.length === 0) {
    return null;
  }
  return { method: 'DELETE', path: `${APPLICATIONS_PATH}/${encodeURIComponent(applicationId)}` };
}

/** The retry request for one URL application's hash, or `null` when there is no id. */
export function retryHashRequest({ applicationId } = {}) {
  if (typeof applicationId !== 'string' || applicationId.length === 0) {
    return null;
  }
  return { method: 'POST', path: `${APPLICATIONS_PATH}/${encodeURIComponent(applicationId)}/retry-hash` };
}

/** The status cell's text, escaped. */
function statusText(item) {
  if (item.hashStatus === 'failed') {
    return `${STATUS_LABELS.failed}: ${escapeHtml(text(item.hashError))}`;
  }
  if (item.hashStatus === 'pending' || item.hashStatus === 'ready') {
    return STATUS_LABELS[item.hashStatus];
  }
  return cell(item.hashStatus);
}

/** One application. */
function row(item) {
  const id = escapeHtml(item.applicationId);
  const retry =
    item.source === 'url' && (item.hashStatus === 'pending' || item.hashStatus === 'failed')
      ? `<button type="button" class="retry-application-hash" data-application-id="${id}">Retry</button>`
      : '';
  return [
    `<tr class="application" data-application-id="${id}">`,
    `<td class="col-name">${cell(item.name)}</td>`,
    `<td class="col-platform">${cell(item.platform)}</td>`,
    `<td class="col-installer-type">${cell(item.installerType)}</td>`,
    `<td class="col-source">${cell(item.source)}</td>`,
    `<td class="col-status">${statusText(item)}</td>`,
    `<td class="col-description">${cell(item.description)}</td>`,
    `<td>${retry}<button type="button" class="edit-application" data-application-id="${id}">Edit</button>` +
      `<button type="button" class="delete-application" data-application-id="${id}">Delete</button></td>`,
    '</tr>',
  ].join('');
}

/** A select over `values`, with `selected` chosen when it is one of them. */
function select(id, name, values, selected) {
  const options = values
    .map((value) => `<option value="${value}"${value === selected ? ' selected' : ''}>${value}</option>`)
    .join('');
  return `<select id="${id}" name="${name}">${options}</select>`;
}

/** A text input carrying `value`, escaped. */
function input(id, name, maxlength, value, type = '') {
  const typed = type === '' ? '' : ` type="${type}"`;
  return `<input id="${id}" name="${name}"${typed} maxlength="${maxlength}" value="${escapeHtml(text(value))}">`;
}

/** Shown under installArgs: an exe with no silent switch waits for input no one can give. */
export const INSTALL_ARGS_HINT =
  'exe installers need a silent switch, e.g. /S — without one the install waits for input and times out.';

/** The edit request for `existing` from the popup's typed values, or `null` when there is no id or name. */
export function updateRequest(state = {}, existing = {}) {
  const applicationId = text(existing.applicationId);
  const name = text(state.name);
  if (applicationId.length === 0 || name.length === 0) {
    return null;
  }
  const body = { name, description: orNull(state.description), installArgs: orNull(state.installArgs) };
  if (existing.source === 'url') {
    body.url = text(state.url);
    body.installerType = text(state.installerType);
  }
  return { method: 'PATCH', path: `${APPLICATIONS_PATH}/${encodeURIComponent(applicationId)}`, body };
}

/**
 * The add/edit popup, or `''` unless `dialog.open`. Create offers every
 * field; edit is pre-filled from the application and offers only what an edit
 * may change (no source, no file; url and installerType for a URL source).
 */
function applicationDialog(dialog, items) {
  if (dialog === null || typeof dialog !== 'object' || dialog.open !== true) {
    return '';
  }
  const editing = dialog.mode === 'edit' ? items.find((item) => item.applicationId === dialog.applicationId) : undefined;
  if (dialog.mode === 'edit' && editing === undefined) {
    return '';
  }
  const app = editing ?? {};
  const isUrl = editing === undefined || editing.source === 'url';
  const error =
    typeof dialog.error === 'string' && dialog.error.length > 0
      ? `<p class="error application-dialog-error">${escapeHtml(dialog.error)}</p>`
      : '';
  const title = editing === undefined ? 'New application' : `Edit ${escapeHtml(text(app.name))}`;
  const formClass = editing === undefined ? 'create-application' : 'edit-application-form';

  return join([
    '<div class="modal-backdrop application-dialog-backdrop">',
    '<div class="modal" id="application-dialog" role="dialog" aria-modal="true" aria-labelledby="application-dialog-title">',
    `<h3 id="application-dialog-title">${title}</h3>`,
    error,
    `<form class="${formClass}">`,
    editing === undefined
      ? join(['<label for="application-source">source</label>', select('application-source', 'source', SOURCES)])
      : join([
          `<input type="hidden" name="applicationId" value="${escapeHtml(text(app.applicationId))}">`,
          `<p class="application-source">source: ${cell(app.source)}${app.fileName ? ` (${escapeHtml(app.fileName)})` : ''}</p>`,
        ]),
    '<label for="application-name">name</label>',
    input('application-name', 'name', 100, app.name),
    '<label for="application-description">description</label>',
    input('application-description', 'description', 500, app.description),
    editing === undefined
      ? join([
          '<label for="application-file">file (upload)</label>',
          `<input id="application-file" name="file" type="file" accept="${ACCEPTED_EXTENSIONS}">`,
        ])
      : '',
    isUrl
      ? join([
          `<label for="application-url">url${editing === undefined ? ' (url source)' : ''}</label>`,
          input('application-url', 'url', 2048, app.url, 'url'),
          `<label for="application-installer-type">installerType${editing === undefined ? ' (url source)' : ''}</label>`,
          select('application-installer-type', 'installerType', INSTALLER_TYPES, app.installerType),
        ])
      : '',
    '<label for="application-install-args">installArgs (exe only)</label>',
    input('application-install-args', 'installArgs', 500, app.installArgs),
    `<p class="hint">${escapeHtml(INSTALL_ARGS_HINT)}</p>`,
    editing !== undefined && isUrl ? '<p class="hint">Changing the url hashes the installer again before it can be installed.</p>' : '',
    '<div class="modal-actions">',
    '<button type="button" class="cancel-application-dialog">Cancel</button>',
    editing === undefined
      ? '<button type="submit" class="create">Add application</button>'
      : '<button type="submit" class="save">Save</button>',
    '</div>',
    '</form>',
    '</div>',
    '</div>',
  ]);
}

/** The applications screen. */
export function render(state = {}) {
  const items = Array.isArray(state.items) ? state.items : [];
  const list =
    items.length === 0
      ? `<p class="empty">${EMPTY_MESSAGE}</p>`
      : [
          '<table class="grid applications">',
          `<thead><tr>${COLUMNS.map((column) => `<th>${column}</th>`).join('')}</tr></thead>`,
          `<tbody>${items.map(row).join('')}</tbody>`,
          '</table>',
        ].join('');

  return join([
    '<section class="screen" id="screen-applications"><h2>Applications</h2>',
    '<button type="button" class="open-create-application">Add application</button>',
    list,
    applicationDialog(state.dialog, items),
    '</section>',
  ]);
}

export const renderApplications = render;
