/**
 * One device in full: the sections `GET /admin/api/v1/devices/{deviceId}`
 * answers with.
 *
 *   render({profile, inventory, posture, commands, antivirusStatus, defenderHardening, antivirusFindings, antivirusScan, signedInUser,
 *           loginHistory, agentErrors, deviceEvents, analytics,
 *           heartbeat, heartbeatHistory, groups, policies, allGroups, deleteDialog, location, locationTracking,
 *           openSections})
 *   addGroupRequest({deviceId, groupId})              -> POST /admin/api/v1/groups/{groupId}/members {deviceIds: [deviceId]}
 *   removeGroupRequest({deviceId, groupId})           -> DELETE on that same path {deviceIds: [deviceId]}
 *   formatDeviceTime(value, timeZone)                 -> 'YYYY-MM-DD HH:mm:ss' in that zone, HTML-escaped
 *   deviceTimeZone(profile.timeZone)                  -> that zone when Intl accepts it, else 'UTC'
 *   updateRequest({deviceId, ownership})              -> PUT /admin/api/v1/devices/{deviceId} {ownership}
 *   deleteRequest({deviceId, hostname, typedHostname}) -> DELETE /admin/api/v1/devices/{deviceId} {confirm: true},
 *                                                         or null until the hostname (else the id) is typed
 *   queueRequest({deviceId, scriptId, hostname, typedHostname})
 *                                                      -> POST /admin/api/v1/devices/{deviceId}/scripts {scriptId, confirm: true},
 *                                                         or null until a script is chosen and the hostname typed
 *   moveRequest({deviceId, commandId, direction})     -> POST .../commands/{commandId}/move {direction}
 *   cancelRequest({deviceId, commandId})              -> POST .../commands/{commandId}/cancel
 *   installRequest({deviceId, applicationId})         -> POST /admin/api/v1/devices/{deviceId}/applications {applicationId},
 *                                                         or null until both are known (TASK-049)
 *
 * Commands are split in two (TASK-045): the Queue lists `pending` and
 * `leased` commands in run order `(seq ?? -Infinity, issuedAt)`, pending rows
 * with up, down and Cancel. History (TASK-067) is one timeline, newest first,
 * merging `deviceEvents` (admin, agent and system actions on the device) with
 * every other command, whose output stays behind a `<details>`.
 * `state.scripts` is the library for the device's platform, offered by the
 * Run a command panel.
 *
 * The Profile panel ends with a Delete device button (TASK-051). It opens a
 * confirmation popup, rendered from `deleteDialog` (`{open, typedHostname,
 * error}`) only while `open === true`, that asks for the device name -- the
 * hostname, else the id -- before `deleteRequest` lets the DELETE through. A
 * failed DELETE is shown inside the popup, not as a page banner.
 *
 * The Software section lists `inventory.software` sorted by name (lower-cased),
 * then version.
 *
 * Every date on this page is shown in the device's own time zone
 * (`profile.timeZone`, reported by the agent), or in UTC when none usable is
 * stored; the Profile panel says which (TASK-046). A device with no stored
 * zone shows `not reported`, followed by the agent's `timezone:` inventory
 * warning in brackets when it sent one (TASK-052). The Groups panel lists the
 * device's groups with add and remove through the group member routes;
 * `allGroups` is the full group list the add form offers from. The Policies
 * panel is read only: a policy reaches a device only through a group.
 *
 * Every section is rendered even when the device has never reported one, so a
 * machine that is enrolled but silent looks different from one that is
 * missing: the heading is there, with nothing under it.
 *
 * Every section but Profile sits in a `<details class="expandable
 * device-section" data-section="ID">` expander, collapsed by default
 * (TASK-062). `openSections` (an array of section ids, kept by the app outside
 * the page data) names the ones rendered open; anything else in it is ignored.
 */
import { attributes, cell, escapeHtml } from '../public/html.js';
import { diskText, formatPercent, formatSeconds, formatUptime, memoryText, networkLines } from './analytics.js';
import { OWNERSHIP_FILTER_OPTIONS, ownershipLabel } from './devices.js';

/**
 * The opening of a collapsible device section (TASK-062): the panel wrapper,
 * a `details.device-section` expander tagged with its section id, and the
 * title in the summary. `render()` adds ` open` to the ones in `openSections`.
 * `title` is trusted markup (fixed text or a number), not user data.
 */
function sectionStart(id, title) {
  return `<section class="panel" id="${id}"><details class="expandable device-section" data-section="${id}"><summary><h3>${title}</h3></summary>`;
}

/** The closing of a section opened by `sectionStart`. */
const SECTION_END = '</details></section>';

/**
 * The section expanders named in `openSections` rendered open: each string
 * entry turns its exact `data-section="ID">` tag into `data-section="ID" open>`.
 * Non-arrays, non-strings, duplicates and ids of sections not rendered change
 * nothing.
 */
function openSectionExpanders(html, openSections) {
  if (!Array.isArray(openSections)) {
    return html;
  }
  let out = html;
  for (const id of new Set(openSections.filter((entry) => typeof entry === 'string'))) {
    const tag = `<details class="expandable device-section" data-section="${escapeHtml(id)}">`;
    out = out.replace(tag, () => `<details class="expandable device-section" data-section="${escapeHtml(id)}" open>`);
  }
  return out;
}

/** The zone used for every date on the page: `timeZone` when Intl accepts it, else `'UTC'`. */
export function deviceTimeZone(timeZone) {
  if (typeof timeZone !== 'string' || timeZone.length === 0) {
    return 'UTC';
  }
  try {
    new Intl.DateTimeFormat('en-US', { timeZone });
  } catch {
    return 'UTC';
  }
  return timeZone;
}

/** An ISO-8601 date, with or without a time; anything else is shown as it is. */
const ISO_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}(T.*)?$/;

/**
 * A date as `YYYY-MM-DD HH:mm:ss` (24-hour) in `timeZone`, HTML-escaped.
 *
 * `value` is an ISO-8601 string or a finite number of epoch milliseconds. A
 * string that does not parse is shown unchanged; `null`, `undefined` and
 * `''` show as an em dash, as `cell()` does. The offset is the one in force
 * at the date shown, so daylight saving follows the date, not today.
 */
export function formatDeviceTime(value, timeZone) {
  if (value === null || value === undefined || value === '') {
    return '&mdash;';
  }
  let millis = Number.NaN;
  if (typeof value === 'number' && Number.isFinite(value)) {
    millis = value;
  } else if (typeof value === 'string' && ISO_DATE_PATTERN.test(value)) {
    millis = Date.parse(value);
  }
  const date = new Date(millis);
  if (Number.isNaN(date.getTime())) {
    return cell(value);
  }
  const parts = {};
  for (const part of new Intl.DateTimeFormat('en-US', {
    timeZone: deviceTimeZone(timeZone),
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date)) {
    parts[part.type] = part.value;
  }
  const year = String(parts.year ?? '').padStart(4, '0');
  return escapeHtml(`${year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}`);
}

/** The add-to-group request, or `null` when no device or no group is named. */
export function addGroupRequest(state = {}) {
  const deviceId = typeof state.deviceId === 'string' ? state.deviceId.trim() : '';
  const groupId = typeof state.groupId === 'string' ? state.groupId.trim() : '';
  if (deviceId.length === 0 || groupId.length === 0) {
    return null;
  }
  return { method: 'POST', path: `/admin/api/v1/groups/${groupId}/members`, body: { deviceIds: [deviceId] } };
}

/** The remove-from-group request, or `null` when no device or no group is named. */
export function removeGroupRequest(state = {}) {
  const deviceId = typeof state.deviceId === 'string' ? state.deviceId.trim() : '';
  const groupId = typeof state.groupId === 'string' ? state.groupId.trim() : '';
  if (deviceId.length === 0 || groupId.length === 0) {
    return null;
  }
  return { method: 'DELETE', path: `/admin/api/v1/groups/${groupId}/members`, body: { deviceIds: [deviceId] } };
}

/** The ownership request, or `null` when no device or ownership is named. */
export function updateRequest(state = {}) {
  const deviceId = typeof state.deviceId === 'string' ? state.deviceId.trim() : '';
  const ownership = typeof state.ownership === 'string' ? state.ownership : '';
  if (deviceId.length === 0 || ownership.length === 0) {
    return null;
  }
  return { method: 'PUT', path: `/admin/api/v1/devices/${deviceId}`, body: { ownership } };
}

/**
 * The delete request, or `null` until `typedHostname` is exactly the device's
 * hostname -- or its id, for a device that has never reported a hostname.
 * Typing it is the confirmation, as on the dispatch screen.
 */
export function deleteRequest(state = {}) {
  const deviceId = typeof state.deviceId === 'string' ? state.deviceId.trim() : '';
  const hostname = typeof state.hostname === 'string' && state.hostname.length > 0 ? state.hostname : null;
  const expected = hostname ?? deviceId;
  if (deviceId.length === 0 || state.typedHostname !== expected) {
    return null;
  }
  return { method: 'DELETE', path: `/admin/api/v1/devices/${deviceId}`, body: { confirm: true } };
}

/** The ownership form, prefilled with the device's current ownership. */
function editDeviceForm(deviceId, ownership) {
  const options = OWNERSHIP_FILTER_OPTIONS.filter(({ value }) => value !== '')
    .map(
      ({ value, label }) =>
        `<option value="${escapeHtml(value)}"${value === ownership ? ' selected' : ''}>${escapeHtml(label)}</option>`,
    )
    .join('');
  return [
    '<form class="edit-device">',
    `<input type="hidden" name="deviceId" value="${escapeHtml(deviceId)}">`,
    '<label for="edit-device-ownership">Ownership</label>',
    `<select id="edit-device-ownership" name="ownership">${options}</select>`,
    '<button type="submit" class="save">Save ownership</button>',
    '</form>',
  ].join('');
}

/**
 * The delete confirmation popup (TASK-051), rendered only while
 * `dialog.open === true`. Its Delete button stays disabled until the device
 * name -- the hostname, else the id -- is typed exactly; a failed DELETE is
 * shown inside it as `p.delete-device-error`.
 */
function deleteDeviceDialog(dialog, deviceId, hostname) {
  if (dialog === null || typeof dialog !== 'object' || dialog.open !== true) {
    return '';
  }
  const typedHostname = typeof dialog.typedHostname === 'string' ? dialog.typedHostname : '';
  const deletable = deleteRequest({ deviceId, hostname, typedHostname }) !== null;
  const name = hostname ?? deviceId;
  const prompt = hostname === null ? 'Type the device id to delete it' : 'Type the hostname to delete it';
  const error =
    typeof dialog.error === 'string' && dialog.error.length > 0
      ? `<p class="error delete-device-error">${escapeHtml(dialog.error)}</p>`
      : '';
  return [
    '<div class="modal-backdrop">',
    '<div class="modal" id="delete-device-dialog" role="dialog" aria-modal="true" aria-labelledby="delete-device-title">',
    '<h3 id="delete-device-title">Delete device</h3>',
    `<p>This permanently deletes <strong>${escapeHtml(name)}</strong>.</p>`,
    error,
    '<form class="delete-device">',
    `<input type="hidden" name="deviceId" value="${escapeHtml(deviceId)}">`,
    `<label for="delete-device-hostname">${prompt}</label>`,
    `<input id="delete-device-hostname" name="typedHostname" value="${escapeHtml(typedHostname)}" autocomplete="off">`,
    '<div class="modal-actions">',
    '<button type="button" class="cancel-delete-device">Cancel</button>',
    `<button type="submit" class="delete"${attributes({ disabled: !deletable })}>Delete device</button>`,
    '</div>',
    '</form>',
    '</div>',
    '</div>',
  ].join('');
}

/**
 * The History table's header cells, in order (TASK-067). One timeline: the
 * device's events and every command no longer queued, newest first.
 */
export const HISTORY_COLUMNS = ['When', 'Source', 'Action', 'Status', 'Details'];

/** The statuses a command is in while it is still in the device's queue. */
export const QUEUE_STATUSES = ['pending', 'leased'];

/** The queue request, or `null` until a script is chosen and the hostname typed exactly. */
export function queueRequest(state = {}) {
  const deviceId = typeof state.deviceId === 'string' ? state.deviceId.trim() : '';
  const scriptId = typeof state.scriptId === 'string' ? state.scriptId : '';
  const hostname = typeof state.hostname === 'string' && state.hostname.length > 0 ? state.hostname : null;
  if (deviceId.length === 0 || scriptId.length === 0 || hostname === null || state.typedHostname !== hostname) {
    return null;
  }
  return { method: 'POST', path: `/admin/api/v1/devices/${deviceId}/scripts`, body: { scriptId, confirm: true } };
}

/**
 * The install request for `form.install-application` (TASK-049), or `null`
 * until both the device and an application are known.
 */
export function installRequest(state = {}) {
  const deviceId = typeof state.deviceId === 'string' ? state.deviceId : '';
  const applicationId = typeof state.applicationId === 'string' ? state.applicationId : '';
  if (deviceId.length === 0 || applicationId.length === 0) {
    return null;
  }
  return { method: 'POST', path: `/admin/api/v1/devices/${deviceId}/applications`, body: { applicationId } };
}

/** Move a pending command one place `up` or `down` its device's queue. */
export function moveRequest(state = {}) {
  if (!state.deviceId || !state.commandId || (state.direction !== 'up' && state.direction !== 'down')) {
    return null;
  }
  return {
    method: 'POST',
    path: `/admin/api/v1/devices/${state.deviceId}/commands/${state.commandId}/move`,
    body: { direction: state.direction },
  };
}

/** Cancel a pending command. */
export function cancelRequest(state = {}) {
  if (!state.deviceId || !state.commandId) {
    return null;
  }
  return { method: 'POST', path: `/admin/api/v1/devices/${state.deviceId}/commands/${state.commandId}/cancel`, body: {} };
}

/** A number attribute, or `fallback`. */
function numberOr(value, fallback) {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

/** Run order: `(seq ?? -Infinity, issuedAt)` ascending, as the lease hands commands out. */
export function byRunOrder(left, right) {
  const leftSeq = numberOr(left?.seq, Number.NEGATIVE_INFINITY);
  const rightSeq = numberOr(right?.seq, Number.NEGATIVE_INFINITY);
  if (leftSeq !== rightSeq) {
    return leftSeq < rightSeq ? -1 : 1;
  }
  return numberOr(left?.issuedAt, 0) - numberOr(right?.issuedAt, 0);
}

/** The commands still in the queue, in run order. */
export function queuedCommands(commands) {
  return (Array.isArray(commands) ? commands : []).filter((command) => QUEUE_STATUSES.includes(command?.status)).sort(byRunOrder);
}

/** The commands no longer in the queue, in the order the API listed them (newest first). */
export function historyCommands(commands) {
  return (Array.isArray(commands) ? commands : []).filter((command) => !QUEUE_STATUSES.includes(command?.status));
}

/**
 * The Run a command panel: the library scripts for the device's platform, and
 * a Queue button disabled until one is chosen and the hostname typed exactly.
 */
function runCommandSection(scripts, deviceId, hostname, selected = {}) {
  const list = Array.isArray(scripts) ? scripts : [];
  const scriptId = typeof selected.scriptId === 'string' ? selected.scriptId : '';
  const typedHostname = typeof selected.typedHostname === 'string' ? selected.typedHostname : '';
  const queueable = queueRequest({ deviceId, scriptId, hostname, typedHostname }) !== null;
  const options = list
    .map(
      (script) =>
        `<option value="${escapeHtml(script.scriptId)}"${script.scriptId === scriptId ? ' selected' : ''}>${cell(script.name)}</option>`,
    )
    .join('');
  return [
    sectionStart('detail-run-command', 'Run a command'),
    list.length === 0 ? '<p class="empty">No saved commands for this platform</p>' : '',
    '<form class="queue-script">',
    `<input type="hidden" name="deviceId" value="${escapeHtml(deviceId)}">`,
    '<label for="queue-script-id">Command</label>',
    `<select id="queue-script-id" name="scriptId"><option value=""></option>${options}</select>`,
    '<label for="queue-script-hostname">Type the hostname to queue it</label>',
    `<input id="queue-script-hostname" name="typedHostname" value="${escapeHtml(typedHostname)}" autocomplete="off">`,
    `<button type="submit" class="queue"${attributes({ disabled: !queueable })}>Queue</button>`,
    '</form>',
    SECTION_END,
  ].join('');
}

/** One command in the queue: pending rows can move up, down or be cancelled; leased rows cannot. */
function queueRow(command, deviceId, timeZone) {
  const pending = command.status === 'pending';
  const data = `data-device-id="${escapeHtml(deviceId)}" data-command-id="${escapeHtml(command.commandId)}"`;
  const disabled = attributes({ disabled: !pending });
  return [
    `<tr class="queued-command" data-command-id="${escapeHtml(command.commandId)}">`,
    `<td class="col-seq">${cell(command.seq)}</td>`,
    `<td class="col-name">${cell(command.scriptName ?? command.type)}</td>`,
    `<td class="col-status">${cell(command.status)}</td>`,
    `<td class="col-issuedAt">${formatDeviceTime(command.issuedAt, timeZone)}</td>`,
    '<td class="col-actions">',
    `<button type="button" class="move-command" ${data} data-direction="up" title="Move up"${disabled}>&uarr;</button>`,
    `<button type="button" class="move-command" ${data} data-direction="down" title="Move down"${disabled}>&darr;</button>`,
    `<button type="button" class="cancel-command" ${data}${disabled}>Cancel</button>`,
    '</td>',
    '</tr>',
  ].join('');
}

/** The Queue panel: pending and leased commands, in run order. */
function queueSection(commands, deviceId, timeZone) {
  const queue = queuedCommands(commands);
  return [
    sectionStart('detail-queue', 'Queue'),
    queue.length === 0
      ? '<p class="empty">Nothing queued</p>'
      : [
          '<table class="grid queue">',
          '<thead><tr><th>seq</th><th>name</th><th>status</th><th>issuedAt</th><th></th></tr></thead>',
          `<tbody>${queue.map((command) => queueRow(command, deviceId, timeZone)).join('')}</tbody>`,
          '</table>',
        ].join(''),
    SECTION_END,
  ].join('');
}

/** A History row's time in epoch ms, or `null` when it has none parseable. */
function historyTime(entry) {
  if (entry.kind === 'event') {
    const occurred = typeof entry.item.occurredAt === 'string' ? Date.parse(entry.item.occurredAt) : Number.NaN;
    return Number.isNaN(occurred) ? null : occurred;
  }
  const issued = entry.item.issuedAt;
  return typeof issued === 'number' && Number.isFinite(issued) ? issued : null;
}

/** A History row's id: the event's `eventId` or the command's `commandId`. */
function historyId(entry) {
  const id = entry.kind === 'event' ? entry.item.eventId : entry.item.commandId;
  return typeof id === 'string' ? id : String(id ?? '');
}

/**
 * History order: time descending; at equal times events before commands, then
 * by id ascending; rows without a parseable time last.
 */
function byHistoryOrder(left, right) {
  const leftTime = historyTime(left);
  const rightTime = historyTime(right);
  if (leftTime !== rightTime) {
    if (leftTime === null) return 1;
    if (rightTime === null) return -1;
    return rightTime - leftTime;
  }
  if (left.kind !== right.kind) {
    return left.kind === 'event' ? -1 : 1;
  }
  const leftId = historyId(left);
  const rightId = historyId(right);
  return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
}

/**
 * The History panel (TASK-067): one table merging the device's events and
 * every command no longer queued, newest first; command output expandable.
 */
function historySection(deviceEvents, commands, timeZone) {
  const events = (Array.isArray(deviceEvents) ? deviceEvents : []).map((event) => ({
    kind: 'event',
    item: event !== null && typeof event === 'object' ? event : {},
  }));
  const finished = historyCommands(commands).map((command) => ({
    kind: 'command',
    item: command !== null && typeof command === 'object' ? command : {},
  }));
  const rows = [...events, ...finished].sort(byHistoryOrder);
  return [
    sectionStart('detail-commands', 'History'),
    rows.length === 0
      ? '<p class="empty">No actions recorded</p>'
      : [
          '<table class="grid history">',
          `<thead><tr>${HISTORY_COLUMNS.map((column) => `<th>${column}</th>`).join('')}</tr></thead>`,
          `<tbody>${rows
            .map((row) => (row.kind === 'event' ? deviceEventRow(row.item, timeZone) : commandRow(row.item, timeZone)))
            .join('')}</tbody>`,
          '</table>',
        ].join(''),
    SECTION_END,
  ].join('');
}

/** The antivirus finding columns a row shows, in order. */
export const FINDING_COLUMNS = [
  'detectedAt',
  'threatName',
  'severity',
  'remediated',
  'resources',
  'category',
  'status',
  'action',
  'active',
  'lastStatusChangeAt',
];

/** A nested value (`inventory.hardware.serialNumber`), or `null` when any step is missing. */
function at(source, path) {
  let value = source;
  for (const key of path) {
    if (value === null || value === undefined || typeof value !== 'object') {
      return null;
    }
    value = value[key];
  }
  return value ?? null;
}

/**
 * The Profile `Time zone` text, HTML-escaped: the stored zone when it is a
 * non-empty string, else `not reported (<w>)` with the first `timezone:`
 * inventory warning the agent sent saying why, else `not reported` (TASK-052).
 */
function timeZoneText(timeZone, inventory) {
  if (typeof timeZone === 'string' && timeZone.length > 0) {
    return escapeHtml(timeZone);
  }
  const warnings = at(inventory, ['warnings']);
  const reason = Array.isArray(warnings)
    ? warnings.find((w) => typeof w === 'string' && w.startsWith('timezone:'))
    : undefined;
  return escapeHtml(reason === undefined ? 'not reported' : `not reported (${reason})`);
}

/** `true`/`false`/unknown, as a word rather than a checkbox. */
function flag(value) {
  if (value === true) {
    return 'true';
  }
  if (value === false) {
    return 'false';
  }
  return 'unknown';
}

/** A definition row inside a section. */
function field(label, value) {
  return `<div class="field"><span class="label">${escapeHtml(label)}</span><span class="value">${value}</span></div>`;
}

/**
 * The Profile `OS` value: the friendly name the check-in derived
 * (`osDisplay`) when there is one, else the enrolled `osVersion`.
 */
function osText(profile) {
  return typeof profile.osDisplay === 'string' && profile.osDisplay.length > 0 ? profile.osDisplay : profile.osVersion;
}

/** Bytes per GiB, as the analytics view counts them. */
const GIB = 1024 * 1024 * 1024;

/** `953.4 GiB`; `null` when the value is not a finite number >= 0. */
function gibText(bytes) {
  if (typeof bytes !== 'number' || !Number.isFinite(bytes) || bytes < 0) {
    return null;
  }
  return `${(Math.round((bytes / GIB) * 10) / 10).toFixed(1)} GiB`;
}

/** How each stored firmware type is shown. */
const FIRMWARE_TYPE_LABELS = { uefi: 'UEFI', bios: 'BIOS' };

/** What a Device details group without data reads as. */
const NOT_REPORTED = '<p class="empty">Not reported</p>';

/** A list of strings, comma-joined; `null` when it holds none. */
function listText(value) {
  if (!Array.isArray(value)) {
    return null;
  }
  const strings = value.filter((entry) => typeof entry === 'string' && entry.length > 0);
  return strings.length > 0 ? strings.join(', ') : null;
}

/** The build with its update revision (`22631.4317`) when both are known. */
function buildText(os) {
  const build = at(os, ['build']);
  const ubr = at(os, ['ubr']);
  if (typeof build === 'string' && build.length > 0 && !build.includes('.') && Number.isInteger(ubr) && ubr >= 0) {
    return `${build}.${ubr}`;
  }
  return build;
}

/** The array under `key`, keeping only its object entries; empty when there is none. */
function objectsAt(inventory, key) {
  const value = at(inventory, [key]);
  return Array.isArray(value) ? value.filter((entry) => entry !== null && typeof entry === 'object') : [];
}

/** A small table: `headings` and one row of already-rendered cells per entry. */
function detailTable(className, headings, rows) {
  return [
    `<table class="grid ${className}"><thead><tr>`,
    headings.map((heading) => `<th>${escapeHtml(heading)}</th>`).join(''),
    '</tr></thead><tbody>',
    rows.map((cells) => `<tr>${cells.map((value) => `<td>${value}</td>`).join('')}</tr>`).join(''),
    '</tbody></table>',
  ].join('');
}

/**
 * The Device details panel (`id="detail-inventory"`): everything the agent
 * reported about the machine, grouped OS / Hardware / Firmware & security /
 * Storage / Network / Join state. The OS and Hardware groups always list
 * their fields; a group whose optional block an older agent never sent reads
 * `Not reported`.
 */
function deviceDetailsSection(inventory, timeZone) {
  const os = at(inventory, ['os']);
  const hardware = at(inventory, ['hardware']);
  const firmware = at(inventory, ['firmware']);
  const join = at(inventory, ['join']);
  const disks = objectsAt(inventory, 'disks');
  const physicalDisks = objectsAt(inventory, 'physicalDisks');
  const network = objectsAt(inventory, 'network');
  const isBlock = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);

  const osGroup = [
    '<h4>OS</h4>',
    field('Edition', cell(at(os, ['edition']))),
    field('Display version', cell(at(os, ['displayVersion']))),
    field('Version', cell(at(os, ['version']))),
    field('Build', cell(buildText(os))),
    field('Architecture', cell(at(os, ['architecture']))),
    field('Install date', formatDeviceTime(at(os, ['installDate']), timeZone)),
    field('Last boot', formatDeviceTime(at(os, ['lastBootAt']), timeZone)),
    field('Locale', cell(at(os, ['locale']))),
  ];

  const hardwareGroup = [
    '<h4>Hardware</h4>',
    field('Manufacturer', cell(at(hardware, ['manufacturer']))),
    field('Model', cell(at(hardware, ['model']))),
    field('System family', cell(at(hardware, ['systemFamily']))),
    field('System SKU', cell(at(hardware, ['systemSku']))),
    field('Serial number', cell(at(hardware, ['serialNumber']))),
    field('CPU', cell(at(hardware, ['cpu']))),
    field('CPU cores', cell(at(hardware, ['cpuCores']))),
    field('Logical processors', cell(at(hardware, ['cpuLogicalProcessors']))),
    field('Memory', cell(gibText(at(hardware, ['ramBytes'])))),
    field('Disk', cell(gibText(at(hardware, ['diskBytes'])))),
  ];

  const firmwareType = at(firmware, ['type']);
  const firmwareGroup = [
    // A bare "& " is valid HTML5 text, so the title is written as it reads.
    '<h4>Firmware & security</h4>',
    ...(isBlock(firmware)
      ? [
          field('Firmware type', cell(FIRMWARE_TYPE_LABELS[firmwareType] ?? firmwareType)),
          field('BIOS version', cell(at(firmware, ['biosVersion']))),
          field('BIOS release date', formatDeviceTime(at(firmware, ['biosReleaseDate']), timeZone)),
          field('Secure Boot', flag(at(firmware, ['secureBootEnabled']))),
          field('TPM present', flag(at(firmware, ['tpmPresent']))),
          field('TPM ready', flag(at(firmware, ['tpmReady']))),
          field('TPM version', cell(at(firmware, ['tpmVersion']))),
        ]
      : [NOT_REPORTED]),
  ];

  const storage = [];
  if (disks.length > 0) {
    storage.push(
      detailTable(
        'device-disks',
        ['Device', 'File system', 'Size', 'Free'],
        disks.map((disk) => [
          cell(disk.deviceId),
          cell(disk.fileSystem),
          cell(gibText(disk.sizeBytes)),
          cell(gibText(disk.freeBytes)),
        ]),
      ),
    );
  }
  if (physicalDisks.length > 0) {
    storage.push(
      detailTable(
        'device-physical-disks',
        ['Model', 'Media type', 'Size'],
        physicalDisks.map((disk) => [cell(disk.model), cell(disk.mediaType), cell(gibText(disk.sizeBytes))]),
      ),
    );
  }
  const storageGroup = ['<h4>Storage</h4>', ...(storage.length > 0 ? storage : [NOT_REPORTED])];

  const networkGroup = [
    '<h4>Network</h4>',
    network.length > 0
      ? detailTable(
          'device-network',
          ['Description', 'MAC', 'IPv4', 'IPv6', 'DHCP', 'DNS servers', 'Gateways'],
          network.map((adapter) => [
            cell(adapter.description),
            cell(adapter.macAddress),
            cell(listText(adapter.ipv4)),
            cell(listText(adapter.ipv6)),
            flag(adapter.dhcpEnabled),
            cell(listText(adapter.dnsServers)),
            cell(listText(adapter.gateways)),
          ]),
        )
      : NOT_REPORTED,
  ];

  const joinGroup = [
    '<h4>Join state</h4>',
    ...(isBlock(join)
      ? [
          field('Entra joined', flag(at(join, ['azureAdJoined']))),
          field('Domain joined', flag(at(join, ['domainJoined']))),
          field('Domain', cell(at(join, ['domain']))),
          field('Tenant name', cell(at(join, ['tenantName']))),
          field('Tenant ID', cell(at(join, ['tenantId']))),
          field('Entra device ID', cell(at(join, ['entraDeviceId']))),
        ]
      : [NOT_REPORTED]),
  ];

  return [
    sectionStart('detail-inventory', 'Device details'),
    ...osGroup,
    ...hardwareGroup,
    ...firmwareGroup,
    ...storageGroup,
    ...networkGroup,
    ...joinGroup,
    SECTION_END,
  ].join('');
}

/** True for a value a History details part shows: anything but null, undefined or ''. */
function present(value) {
  return value !== null && value !== undefined && value !== '';
}

/** The five History cells, in `HISTORY_COLUMNS` order. Every argument is already markup. */
function historyCells(when, source, action, status, details) {
  return [
    `<td class="col-when">${when}</td>`,
    `<td class="col-source">${source}</td>`,
    `<td class="col-action">${action}</td>`,
    `<td class="col-status">${status}</td>`,
    `<td class="col-details">${details}</td>`,
  ].join('');
}

/**
 * An event's Details: `by=<actor>` when the actor is a string, then each
 * details entry as `key=value`, joined by `; ` and HTML-escaped; empty when
 * there is nothing.
 */
function deviceEventDetails(event) {
  const parts = [];
  if (typeof event.actor === 'string') {
    parts.push(`by=${event.actor}`);
  }
  const details = event.details;
  if (typeof details === 'object' && details !== null && !Array.isArray(details)) {
    for (const [key, value] of Object.entries(details)) {
      parts.push(`${key}=${value}`);
    }
  }
  return escapeHtml(parts.join('; '));
}

/** One device event (TASK-067): when, who, what; events carry no status. */
function deviceEventRow(event, timeZone) {
  return [
    `<tr class="device-event" data-event-id="${escapeHtml(event.eventId ?? '')}">`,
    historyCells(
      formatDeviceTime(event.occurredAt, timeZone),
      cell(event.source),
      cell(event.summary),
      '&mdash;',
      deviceEventDetails(event),
    ),
    '</tr>',
  ].join('');
}

/** One finished command, and -- when it reported any -- its output behind a `<details>`. */
function commandRow(command, timeZone) {
  const details = [
    present(command.type) ? `type=${command.type}` : null,
    present(command.exitCode) ? `exitCode=${command.exitCode}` : null,
    present(command.issuedBy) ? `by=${command.issuedBy}` : null,
  ]
    .filter((part) => part !== null)
    .join('; ');
  const row = [
    `<tr class="command" data-command-id="${escapeHtml(command.commandId)}">`,
    historyCells(
      formatDeviceTime(command.issuedAt, timeZone),
      'admin',
      cell(present(command.scriptName) ? command.scriptName : command.type),
      cell(command.status),
      escapeHtml(details),
    ),
    '</tr>',
  ].join('');
  if (typeof command.output !== 'string' || command.output.length === 0) {
    return row;
  }
  return [
    row,
    `<tr class="command-output" data-command-id="${escapeHtml(command.commandId)}"><td colspan="${HISTORY_COLUMNS.length}">`,
    `<details class="expandable"><summary>output</summary><pre class="output">${escapeHtml(command.output)}</pre></details>`,
    '</td></tr>',
  ].join('');
}

/**
 * The device credential: whether the device is disabled, and the enrollment
 * token that enrolled it (metadata only -- never a token or secret value). An
 * active device offers one-click Disable; a disabled one offers Enable.
 */
function credentialSection(credential, deviceId, timeZone) {
  const disabled = credential?.status === 'disabled';
  const token = credential?.enrollmentToken ?? null;
  const button = disabled
    ? `<button type="button" class="enable-device" data-device-id="${escapeHtml(deviceId)}">Enable</button>`
    : `<button type="button" class="disable-device" data-device-id="${escapeHtml(deviceId)}">Disable</button>`;
  return [
    sectionStart('detail-credential', 'Device credential'),
    field('Status', disabled ? 'Disabled' : 'Active'),
    field('Disabled at', formatDeviceTime(credential?.disabledAt, timeZone)),
    field('Disabled by', cell(credential?.disabledBy)),
    field('Enrollment token', cell(token?.tokenId)),
    field('Token label', cell(token?.label)),
    field('Token status', cell(token?.status)),
    button,
    SECTION_END,
  ].join('');
}

/** How each antivirus finding `status` is shown; an unknown one is shown as sent. */
export const FINDING_STATUS_LABELS = {
  unknown: 'Unknown',
  detected: 'Detected',
  cleaned: 'Cleaned',
  quarantined: 'Quarantined',
  removed: 'Removed',
  allowed: 'Allowed',
  blocked: 'Blocked',
  quarantine_failed: 'Quarantine failed',
  remove_failed: 'Remove failed',
  allow_failed: 'Allow failed',
  abandoned: 'Abandoned',
  block_failed: 'Block failed',
};

/** How each antivirus finding `action` is shown; an unknown one is shown as sent. */
export const FINDING_ACTION_LABELS = {
  unknown: 'Unknown',
  clean: 'Clean',
  quarantine: 'Quarantine',
  remove: 'Remove',
  allow: 'Allow',
  user_defined: 'User defined',
  no_action: 'No action',
  block: 'Block',
};

/** A label from `labels` for a string value, else the value as sent. */
function labelOf(labels, value) {
  return typeof value === 'string' && Object.hasOwn(labels, value) ? labels[value] : value;
}

/**
 * One antivirus threat detection; `resources` is shown joined with `, `. A
 * finding whose threat is still active (`active === true`) is highlighted
 * with the `active-threat` class; an absent `active` shows an em dash.
 */
function findingRow(entry, timeZone) {
  const finding = entry ?? {};
  const values = {
    ...finding,
    remediated: flag(finding.remediated),
    resources: Array.isArray(finding.resources) ? finding.resources.join(', ') : finding.resources,
    status: labelOf(FINDING_STATUS_LABELS, finding.status),
    action: labelOf(FINDING_ACTION_LABELS, finding.action),
    active: typeof finding.active === 'boolean' ? flag(finding.active) : null,
  };
  const timeColumns = new Set(['detectedAt', 'lastStatusChangeAt']);
  const cells = FINDING_COLUMNS.map(
    (column) =>
      `<td class="col-${column}">${timeColumns.has(column) ? formatDeviceTime(values[column], timeZone) : cell(values[column])}</td>`,
  ).join('');
  const rowClass = finding.active === true ? 'antivirus-finding active-threat' : 'antivirus-finding';
  return `<tr class="${rowClass}">${cells}</tr>`;
}

/** The Protection table rows: label and `protection` key, in order. */
const PROTECTION_ROWS = [
  ['Antivirus service', 'amServiceEnabled'],
  ['Antivirus', 'antivirusEnabled'],
  ['Antispyware', 'antispywareEnabled'],
  ['Real-time protection', 'realTimeProtectionEnabled'],
  ['Behaviour monitoring', 'behaviorMonitorEnabled'],
  ['Downloads and attachments (IOAV)', 'ioavProtectionEnabled'],
  ['On-access protection', 'onAccessProtectionEnabled'],
  ['Network inspection', 'nisEnabled'],
  ['Tamper protection', 'tamperProtected'],
];

/** The Versions fields: label and `versions` key, in order. */
const VERSION_FIELDS = [
  ['Engine', 'engine'],
  ['Platform', 'product'],
  ['Service', 'service'],
  ['Network inspection engine', 'nisEngine'],
  ['Antivirus signatures', 'antivirusSignature'],
  ['Antispyware signatures', 'antispywareSignature'],
  ['Network inspection signatures', 'nisSignature'],
  ['XProtect definitions', 'xprotectDefinitions'],
  ['XProtect Remediator', 'xprotectRemediator'],
];

/** The Signatures fields: label prefix, update-time key and age key, in order. */
const SIGNATURE_FIELDS = [
  ['Antivirus', 'antivirusLastUpdatedAt', 'antivirusAgeDays'],
  ['Antispyware', 'antispywareLastUpdatedAt', 'antispywareAgeDays'],
  ['Network inspection', 'nisLastUpdatedAt', 'nisAgeDays'],
];

/** A signature age of this many days or more is stale. */
export const SIGNATURE_STALE_DAYS = 3;

/** A Defender quick scan older than this many days is stale. */
export const QUICK_SCAN_STALE_DAYS = 7;

/** The Defender ComputerState flags, in display order. */
const COMPUTER_STATE_FLAGS = [
  [1, 'Full scan pending'],
  [2, 'Reboot pending'],
  [4, 'Manual steps pending'],
  [8, 'Offline scan pending'],
  [16, 'Critical failure pending'],
];

/** How each Security Center product `state` is shown. */
const PRODUCT_STATE_LABELS = { on: 'On', off: 'Off', snoozed: 'Snoozed', expired: 'Expired', unknown: 'Unknown' };

/** `Yes`/`No`/`Unknown` for a boolean or anything else. */
function yesNo(value) {
  if (value === true) {
    return 'Yes';
  }
  if (value === false) {
    return 'No';
  }
  return 'Unknown';
}

/** An age in days as `<n> days`, stale-marked when `stale(n)`; `&mdash;` when not an integer. */
function ageText(value, stale) {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    return '&mdash;';
  }
  const text = `${value} days`;
  return stale(value) ? `<span class="stale">${text}</span> (stale)` : text;
}

/** The Defender ComputerState as words: `Clean` for 0, else its set flags. */
function computerStateText(value) {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    return '&mdash;';
  }
  if (value === 0) {
    return 'Clean';
  }
  const set = COMPUTER_STATE_FLAGS.filter(([bit]) => (value & bit) !== 0).map(([, label]) => label);
  return set.length === 0 ? cell(value) : escapeHtml(set.join(', '));
}

/**
 * The Antivirus status panel: the latest full antivirus status the device
 * reported (TASK-058), or `No antivirus status reported` when there is none.
 * Every device-reported string is escaped.
 */
function antivirusStatusSection(status, findings, timeZone) {
  const open = sectionStart('detail-antivirus-status', 'Antivirus status');
  if (status === null || status === undefined || typeof status !== 'object' || Array.isArray(status)) {
    return `${open}<p class="empty">No antivirus status reported</p>${SECTION_END}`;
  }
  const runningMode = typeof status.runningMode === 'string' ? status.runningMode : null;
  const activeThreats = findings.filter((finding) => finding?.active === true).length;

  const header = [
    field('Product', cell(status.product)),
    field('Reported at', formatDeviceTime(status.reportedAt, timeZone)),
    field('Microsoft Defender running', status.defenderAvailable === true ? 'Yes' : 'No'),
    field('Running mode', cell(runningMode)),
    field('Active threats', cell(activeThreats)),
  ].join('');

  const warnings = [
    runningMode !== null && runningMode.toLowerCase().includes('passive')
      ? '<p class="warning">Microsoft Defender is in passive mode; another antivirus product is the primary one.</p>'
      : '',
    status.product === 'Microsoft Defender' && status.defenderAvailable !== true
      ? '<p class="warning">Microsoft Defender is not running on this device.</p>'
      : '',
  ].join('');

  const protection = status.protection ?? {};
  const protectionValues = PROTECTION_ROWS.map(([label, key]) => [label, at(protection, [key])]);
  const protectionTable = protectionValues.every(([, value]) => typeof value !== 'boolean')
    ? ''
    : [
        '<h4>Protection</h4>',
        '<table class="grid antivirus-protection"><tbody>',
        protectionValues
          .map(([label, value]) => {
            const shown = value === true ? 'On' : value === false ? '<span class="off">Off</span>' : 'Unknown';
            return `<tr><th>${escapeHtml(label)}</th><td>${shown}</td></tr>`;
          })
          .join(''),
        '</tbody></table>',
      ].join('');

  const versionFields = VERSION_FIELDS.map(([label, key]) => {
    const value = at(status, ['versions', key]);
    return typeof value === 'string' && value.length > 0 ? field(label, cell(value)) : '';
  }).join('');
  const versions = versionFields === '' ? '' : `<h4>Versions</h4>${versionFields}`;

  const signatureStale = (days) => days >= SIGNATURE_STALE_DAYS;
  const outOfDate = at(status, ['signatures', 'outOfDate']);
  const signatures = [
    '<h4>Signatures</h4>',
    ...SIGNATURE_FIELDS.map(([prefix, updatedKey, ageKey]) =>
      [
        field(`${prefix} signatures updated`, formatDeviceTime(at(status, ['signatures', updatedKey]), timeZone)),
        field(`${prefix} signature age`, ageText(at(status, ['signatures', ageKey]), signatureStale)),
      ].join(''),
    ),
    field('Signatures out of date', outOfDate === true ? '<span class="stale">Yes</span>' : yesNo(outOfDate)),
  ].join('');

  const overdue = (value) => (value === true ? ' (overdue)' : '');
  const scans = [
    '<h4>Scans</h4>',
    field('Last quick scan (Defender)', formatDeviceTime(at(status, ['scans', 'quickEndedAt']), timeZone)),
    field(
      'Quick scan age',
      ageText(at(status, ['scans', 'quickAgeDays']), (days) => days > QUICK_SCAN_STALE_DAYS) +
        overdue(at(status, ['scans', 'quickOverdue'])),
    ),
    field('Last full scan (Defender)', formatDeviceTime(at(status, ['scans', 'fullEndedAt']), timeZone)),
    field(
      'Full scan age',
      ageText(at(status, ['scans', 'fullAgeDays']), () => false) + overdue(at(status, ['scans', 'fullOverdue'])),
    ),
    field('Full scan required', yesNo(at(status, ['scans', 'fullRequired']))),
    field('Computer state', computerStateText(status.computerState)),
    field('Reboot required', yesNo(status.rebootRequired)),
  ].join('');

  const products = Array.isArray(status.securityCenterProducts) ? status.securityCenterProducts : [];
  const productsTable =
    products.length === 0
      ? ''
      : [
          '<h4>Security Center products</h4>',
          '<table class="grid antivirus-products">',
          '<thead><tr><th>name</th><th>state</th><th>definitions</th></tr></thead>',
          '<tbody>',
          products
            .map((product) => {
              const entry = product ?? {};
              const definitions =
                entry.definitionsUpToDate === true
                  ? 'Up to date'
                  : entry.definitionsUpToDate === false
                    ? 'Out of date'
                    : 'Unknown';
              return [
                '<tr class="antivirus-product">',
                `<td class="col-name">${cell(entry.name)}</td>`,
                `<td class="col-state">${cell(PRODUCT_STATE_LABELS[entry.state] ?? 'Unknown')}</td>`,
                `<td class="col-definitions">${definitions}</td>`,
                '</tr>',
              ].join('');
            })
            .join(''),
          '</tbody></table>',
        ].join('');

  return [open, header, warnings, protectionTable, versions, signatures, scans, productsTable, SECTION_END].join('');
}

/** How each Defender protection policy item is labelled; an unknown one is shown as sent. */
export const DEFENDER_HARDENING_ITEM_LABELS = {
  realTimeMonitoring: 'Real-time protection',
  behaviorMonitoring: 'Behaviour monitoring',
  ioavProtection: 'Downloads and attachments (IOAV)',
  scriptScanning: 'Script scanning',
  mapsReporting: 'Cloud-delivered protection',
  submitSamplesConsent: 'Automatic sample submission',
  networkProtection: 'Network protection',
  controlledFolderAccess: 'Ransomware protection (Controlled folder access)',
  puaProtection: 'Potentially unwanted app blocking',
  smartScreenWindows: 'SmartScreen for Windows',
  smartScreenEdge: 'SmartScreen for Microsoft Edge',
  signatureUpdateInterval: 'Signature update interval',
  signatureScheduleDay: 'Daily signature update schedule',
  signatureUpdate: 'Protection updates',
};

/** How each Defender protection policy item `state` is shown; an unknown one is shown as sent. */
export const DEFENDER_HARDENING_STATE_LABELS = {
  ok: 'On',
  applied: 'Turned on',
  failed: 'Failed',
  tamper_blocked: 'Blocked by Tamper Protection',
  not_applicable: 'Not applicable',
  waiting: 'Waiting to retry',
};

/** The states shown as a problem. */
const DEFENDER_HARDENING_OFF_STATES = new Set(['failed', 'tamper_blocked']);

/**
 * The Defender protection policy panel: what the agent's hardener did to each
 * protection a policy requires (TASK-060). A null or absent block renders
 * nothing; an empty `items` says nothing is required. Every device-reported
 * string is escaped.
 */
function defenderHardeningSection(block, timeZone) {
  if (block === null || block === undefined || typeof block !== 'object' || Array.isArray(block)) {
    return '';
  }
  const open = sectionStart('detail-defender-hardening', 'Defender protection policy');
  const header = field('Reported at', formatDeviceTime(block.reportedAt, timeZone));
  const items = Array.isArray(block.items) ? block.items.filter((entry) => entry && typeof entry === 'object') : [];
  if (items.length === 0) {
    return `${open}${header}<p class="empty">No Defender protection settings are required by policy</p>${SECTION_END}`;
  }
  const rows = items
    .map((entry) => {
      const label = DEFENDER_HARDENING_ITEM_LABELS[entry.item] ?? entry.item;
      const stateText = escapeHtml(DEFENDER_HARDENING_STATE_LABELS[entry.state] ?? entry.state);
      const state = DEFENDER_HARDENING_OFF_STATES.has(entry.state) ? `<span class="off">${stateText}</span>` : stateText;
      const detail = typeof entry.detail === 'string' && entry.detail.length > 0 ? escapeHtml(entry.detail) : '';
      return [
        '<tr class="defender-hardening-item">',
        `<th>${escapeHtml(label)}</th>`,
        `<td class="col-state">${state}</td>`,
        `<td class="col-detail">${detail}</td>`,
        '</tr>',
      ].join('');
    })
    .join('');
  return [
    open,
    header,
    '<table class="grid defender-hardening">',
    '<thead><tr><th>protection</th><th>state</th><th>detail</th></tr></thead>',
    `<tbody>${rows}</tbody></table>`,
    SECTION_END,
  ].join('');
}

/** How each antivirus scan `result` is shown; an unknown one is shown as sent. */
export const SCAN_RESULT_LABELS = {
  clean: 'Clean',
  threats_found: 'Threats found',
  failed: 'Failed',
  timeout: 'Timed out',
  unsupported: 'Not supported on this platform',
};

/** How each antivirus scan `scanType` is shown; an unknown one is shown as sent. */
const SCAN_TYPE_LABELS = { quick: 'Quick' };

/**
 * The Antivirus scan panel: the last scheduled scan the device reported, or
 * `No antivirus scan reported` when there is none. Every value is escaped.
 */
function antivirusScanSection(scan, timeZone) {
  const body =
    scan === null || scan === undefined || typeof scan !== 'object'
      ? '<p class="empty">No antivirus scan reported</p>'
      : [
          field('Last scan', formatDeviceTime(scan.completedAt, timeZone)),
          field('Scan type', cell(SCAN_TYPE_LABELS[scan.scanType] ?? scan.scanType)),
          field('Result', cell(SCAN_RESULT_LABELS[scan.result] ?? scan.result)),
          field('Threats found', cell(scan.threatsFound)),
          typeof scan.detail === 'string' ? field('Detail', cell(scan.detail)) : '',
        ].join('');
  return [sectionStart('detail-antivirus-scan', 'Antivirus scan'), body, SECTION_END].join('');
}

/** How each location `source` is shown; an unknown one is shown as sent. */
const LOCATION_SOURCE_LABELS = { ip: 'IP-based (approximate)' };

/** The location history columns, in order. */
export const LOCATION_HISTORY_COLUMNS = ['capturedAt', 'latitude', 'longitude', 'city', 'region', 'country', 'source'];

/** True for a finite number. */
function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

/** A location's accuracy: "Approximate" when no radius is known. */
function accuracyText(accuracyMeters) {
  return isFiniteNumber(accuracyMeters) ? `${accuracyMeters} m` : 'Approximate';
}

/** The OpenStreetMap link for a capture; no embedded map (CSP). */
function mapLink(latitude, longitude) {
  if (!isFiniteNumber(latitude) || !isFiniteNumber(longitude)) {
    return '';
  }
  // Built from two finite numbers only, so nothing in it needs escaping; the
  // `&` is left literal so the href reads exactly as the map URL.
  const href = `https://www.openstreetmap.org/?mlat=${latitude}&mlon=${longitude}#map=12/${latitude}/${longitude}`;
  return `<p class="location-map"><a href="${href}" target="_blank" rel="noopener noreferrer">View on OpenStreetMap</a></p>`;
}

/** One stored location capture. */
function locationRow(entry, timeZone) {
  const capture = entry ?? {};
  const cells = LOCATION_HISTORY_COLUMNS.map((column) => {
    if (column === 'capturedAt') {
      return `<td class="col-capturedAt">${formatDeviceTime(capture.capturedAt, timeZone)}</td>`;
    }
    if (column === 'source') {
      return `<td class="col-source">${cell(LOCATION_SOURCE_LABELS[capture.source] ?? capture.source)}</td>`;
    }
    return `<td class="col-${column}">${cell(capture[column])}</td>`;
  }).join('');
  return `<tr class="location">${cells}</tr>`;
}

/**
 * The Location panel (TASK-056): the latest coarse IP-based location with an
 * OpenStreetMap link and the stored history. With nothing stored it says
 * whether a policy enables tracking; with tracking now off it still shows the
 * last stored location, with a note. Every value is escaped.
 */
function locationSection(location, locationTracking, timeZone) {
  const latest = location && typeof location.latest === 'object' ? location.latest : null;
  const history = Array.isArray(location?.history) ? location.history : [];
  const tracking = locationTracking === true;
  let body;
  if (latest === null) {
    body = tracking
      ? '<p class="empty">No location captured</p>'
      : '<p class="empty">Location tracking is not enabled by any policy</p>';
  } else {
    body = [
      tracking ? '' : '<p class="location-note">Location tracking is off; showing the last captured location</p>',
      field('Latitude', cell(latest.latitude)),
      field('Longitude', cell(latest.longitude)),
      field('City', cell(latest.city)),
      field('Region', cell(latest.region)),
      field('Country', cell(latest.country)),
      field('Source', cell(LOCATION_SOURCE_LABELS[latest.source] ?? latest.source)),
      field('Accuracy', escapeHtml(accuracyText(latest.accuracyMeters))),
      field('Captured', formatDeviceTime(latest.capturedAt, timeZone)),
      mapLink(latest.latitude, latest.longitude),
      history.length === 0
        ? ''
        : [
            '<table class="grid location-history">',
            `<thead><tr>${LOCATION_HISTORY_COLUMNS.map((column) => `<th>${column}</th>`).join('')}</tr></thead>`,
            `<tbody>${history.map((entry) => locationRow(entry, timeZone)).join('')}</tbody>`,
            '</table>',
          ].join(''),
    ].join('');
  }
  return [sectionStart('detail-location', 'Location'), body, SECTION_END].join('');
}

/** The login history columns a row shows, in order. */
export const LOGIN_HISTORY_COLUMNS = ['username', 'firstSeenAt', 'lastSeenAt', 'loginCount'];

/** One OS user ever reported as signed in on the device. */
function loginUserRow(entry, timeZone) {
  const user = entry ?? {};
  const dates = ['firstSeenAt', 'lastSeenAt'];
  const cells = LOGIN_HISTORY_COLUMNS.map(
    (column) =>
      `<td class="col-${column}">${dates.includes(column) ? formatDeviceTime(user[column], timeZone) : cell(user[column])}</td>`,
  ).join('');
  return `<tr class="login-user">${cells}</tr>`;
}

/** The agent error columns a row shows, in order, with their headings (TASK-063). */
export const AGENT_ERROR_COLUMNS = [
  { key: 'lastSeenAt', label: 'Last seen' },
  { key: 'level', label: 'Level' },
  { key: 'component', label: 'Component' },
  { key: 'message', label: 'Message' },
  { key: 'count', label: 'Count' },
  { key: 'firstSeenAt', label: 'First seen' },
  { key: 'fields', label: 'Details' },
];

/**
 * An agent error's fields as `key=value` joined by `; `, HTML-escaped; empty
 * when the fields are missing, null or not an object.
 */
function agentErrorDetails(fields) {
  if (typeof fields !== 'object' || fields === null || Array.isArray(fields)) {
    return '';
  }
  return escapeHtml(
    Object.entries(fields)
      .map(([key, value]) => `${key}=${value}`)
      .join('; '),
  );
}

/** One distinct warn/error record the device's agent reported. */
function agentErrorRow(entry, timeZone) {
  const error = entry ?? {};
  const dates = ['lastSeenAt', 'firstSeenAt'];
  const cells = AGENT_ERROR_COLUMNS.map(({ key }) => {
    let value;
    if (key === 'fields') {
      value = agentErrorDetails(error.fields);
    } else if (dates.includes(key)) {
      value = formatDeviceTime(error[key], timeZone);
    } else {
      value = cell(error[key]);
    }
    return `<td class="col-${key}">${value}</td>`;
  }).join('');
  return `<tr class="agent-error">${cells}</tr>`;
}

/**
 * The Errors section (TASK-063): the warn and error records the device's agent
 * reported in the last 30 days, newest first, as the detail endpoint returns
 * them. Collapsed by default like every other device section.
 */
function agentErrorsSection(agentErrors, timeZone) {
  const entries = Array.isArray(agentErrors) ? agentErrors : [];
  return [
    sectionStart('detail-errors', 'Errors'),
    entries.length === 0
      ? '<p class="empty">No agent errors in the last 30 days</p>'
      : [
          '<table class="grid agent-errors">',
          `<thead><tr>${AGENT_ERROR_COLUMNS.map(({ label }) => `<th>${label}</th>`).join('')}</tr></thead>`,
          `<tbody>${entries.map((entry) => agentErrorRow(entry, timeZone)).join('')}</tbody>`,
          '</table>',
        ].join(''),
    SECTION_END,
  ].join('');
}

/** The installed software columns a row shows, in order. */
export const SOFTWARE_COLUMNS = ['name', 'version', 'publisher', 'installedAt'];

/** `-1`/`0`/`1` for two strings in code-unit order, independent of locale. */
function compareCodeUnits(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

/** A software entry's field as a string, for sorting; `''` when it is not one. */
function textOf(entry, key) {
  const value = entry?.[key];
  return typeof value === 'string' ? value : '';
}

/** Name lower-cased ascending, then version ascending by code unit. */
function compareSoftware(a, b) {
  return (
    compareCodeUnits(textOf(a, 'name').toLowerCase(), textOf(b, 'name').toLowerCase()) ||
    compareCodeUnits(textOf(a, 'version'), textOf(b, 'version'))
  );
}

/** One installed software entry; a missing publisher or installedAt shows as an em dash. */
function softwareRow(entry, timeZone) {
  const software = entry ?? {};
  const cells = SOFTWARE_COLUMNS.map(
    (column) =>
      `<td class="col-${column}">${column === 'installedAt' ? formatDeviceTime(software[column], timeZone) : cell(software[column])}</td>`,
  ).join('');
  return `<tr class="software">${cells}</tr>`;
}

/**
 * The install form (TASK-049): the safe-list applications for the device's
 * platform whose hash is ready (TASK-050), and an Install button disabled
 * until one is chosen.
 */
function installApplicationForm(applications, deviceId) {
  const list = (Array.isArray(applications) ? applications : []).filter(
    (application) => application?.hashStatus === 'ready',
  );
  const options = list
    .map((application) => `<option value="${escapeHtml(application.applicationId)}">${cell(application.name)}</option>`)
    .join('');
  return [
    list.length === 0 ? '<p class="empty">No applications for this platform</p>' : '',
    '<form class="install-application">',
    `<input type="hidden" name="deviceId" value="${escapeHtml(deviceId)}">`,
    '<label for="install-application-id">Install an application</label>',
    `<select id="install-application-id" name="applicationId"><option value=""></option>${options}</select>`,
    `<button type="submit" class="install"${attributes({ disabled: true })}>Install</button>`,
    '</form>',
  ].join('');
}

/**
 * The installed software panel, sorted; the list starts collapsed behind its
 * heading. The install form sits outside that collapsed list. The whole
 * panel is itself a section expander (TASK-062) around both.
 */
function softwareSection(software, timeZone, applications, deviceId) {
  const entries = Array.isArray(software) ? software : [];
  const heading = `Software (${entries.length})`;
  return [
    sectionStart('detail-software', heading),
    entries.length === 0
      ? '<p class="empty">No software reported</p>'
      : [
          `<details class="expandable"><summary><h3>${heading}</h3></summary>`,
          '<table class="grid software">',
          `<thead><tr>${SOFTWARE_COLUMNS.map((column) => `<th>${column}</th>`).join('')}</tr></thead>`,
          `<tbody>${[...entries].sort(compareSoftware).map((entry) => softwareRow(entry, timeZone)).join('')}</tbody>`,
          '</table>',
          '</details>',
        ].join(''),
    installApplicationForm(applications, deviceId),
    SECTION_END,
  ].join('');
}

/** The crash/hang columns a row shows, in order. */
export const CRASH_COLUMNS = ['occurredAt', 'appName', 'appVersion', 'kind'];

/** One recorded boot; a missing duration shows as an em dash. */
function bootRow(entry, timeZone) {
  return [
    '<tr class="boot">',
    `<td class="col-bootAt">${formatDeviceTime(entry?.bootAt, timeZone)}</td>`,
    `<td class="col-bootDurationSeconds">${cell(formatSeconds(entry?.bootDurationSeconds))}</td>`,
    '</tr>',
  ].join('');
}

/** One application crash or hang. */
function crashRow(entry, timeZone) {
  const crash = entry ?? {};
  const cells = CRASH_COLUMNS.map(
    (column) =>
      `<td class="col-${column}">${column === 'occurredAt' ? formatDeviceTime(crash[column], timeZone) : cell(crash[column])}</td>`,
  ).join('');
  return `<tr class="app-crash">${cells}</tr>`;
}

/** The heartbeat frequencies an admin may pick, in seconds, with their labels (TASK-044). */
export const HEARTBEAT_INTERVAL_OPTIONS = [
  { value: 60, label: '1 minute' },
  { value: 300, label: '5 minutes' },
  { value: 900, label: '15 minutes' },
  { value: 1800, label: '30 minutes' },
  { value: 3600, label: '1 hour' },
];

/** The frequency preselected when the device has none stored. */
const HEARTBEAT_DEFAULT_INTERVAL = 300;

/** The heartbeat history columns, in order. */
const HEARTBEAT_HISTORY_HEADINGS = ['receivedAt', 'collectedAt', 'CPU', 'Memory', 'System disk', 'Network'];

/**
 * The heartbeat switch: its On/Off field and a form with the frequency select,
 * the on/off button and -- while on -- "Save frequency". The buttons are
 * handled by `app.js`, which posts `{enabled, intervalSeconds}`.
 */
function heartbeatForm(heartbeat, deviceId, profile, timeZone) {
  const enabled = heartbeat?.enabled === true;
  const lastHeartbeatAt = profile?.lastHeartbeatAt;
  const lastCheckInAt = profile?.lastCheckInAt;
  let status;
  if (!enabled) {
    status = 'Off: turn the heartbeat on to start receiving samples.';
  } else if (typeof lastHeartbeatAt === 'string') {
    status = `On: last heartbeat ${formatDeviceTime(lastHeartbeatAt, timeZone)}`;
  } else {
    const checkIn = typeof lastCheckInAt === 'string' ? formatDeviceTime(lastCheckInAt, timeZone) : 'never';
    status = `On: no heartbeat received yet. The device picks up this setting at its next check-in (last check-in: ${checkIn}).`;
  }
  const stored = heartbeat?.intervalSeconds;
  const selected = HEARTBEAT_INTERVAL_OPTIONS.some(({ value }) => value === stored)
    ? stored
    : HEARTBEAT_DEFAULT_INTERVAL;
  const options = HEARTBEAT_INTERVAL_OPTIONS.map(
    ({ value, label }) =>
      `<option value="${value}"${value === selected ? ' selected' : ''}>${escapeHtml(label)}</option>`,
  ).join('');
  return [
    field('Heartbeat', cell(enabled ? 'On' : 'Off')),
    `<p class="heartbeat-status">${status}</p>`,
    '<form class="heartbeat-form">',
    `<input type="hidden" name="deviceId" value="${escapeHtml(deviceId)}">`,
    `<label>Frequency <select name="intervalSeconds">${options}</select></label>`,
    enabled
      ? '<button type="button" class="heartbeat-toggle" data-enabled="false">Turn heartbeat off</button>'
      : '<button type="button" class="heartbeat-toggle" data-enabled="true">Turn heartbeat on</button>',
    enabled ? '<button type="button" class="heartbeat-save">Save frequency</button>' : '',
    '</form>',
  ].join('');
}

/** The heartbeat's network adapters, one escaped line each; a dash when there are none. */
function networkCell(network) {
  const lines = networkLines(network);
  return lines.length === 0 ? cell(null) : lines.map((line) => escapeHtml(line)).join('<br>');
}

/** One heartbeat snapshot read back from CloudWatch. */
function heartbeatRow(entry, timeZone) {
  const heartbeat = entry ?? {};
  const performance = heartbeat.performance ?? null;
  return [
    '<tr class="heartbeat">',
    `<td class="col-receivedAt">${formatDeviceTime(heartbeat.receivedAt, timeZone)}</td>`,
    `<td class="col-collectedAt">${formatDeviceTime(heartbeat.collectedAt, timeZone)}</td>`,
    `<td class="col-cpu">${cell(formatPercent(at(performance, ['cpuPercent'])))}</td>`,
    `<td class="col-memory">${cell(memoryText(performance))}</td>`,
    `<td class="col-disk">${cell(diskText(performance))}</td>`,
    `<td class="col-network">${networkCell(heartbeat.network)}</td>`,
    '</tr>',
  ].join('');
}

/**
 * The "Analytics history" expander. Closed until expanded; `app.js` fetches
 * the history on expand and repaints with `heartbeatHistory = {open, items}`
 * or `{open, error}`.
 */
function heartbeatHistorySection(heartbeatHistory, deviceId, timeZone) {
  const open = heartbeatHistory?.open === true;
  let body = '';
  if (open && typeof heartbeatHistory.error === 'string') {
    body = `<p class="error">${escapeHtml(heartbeatHistory.error)}</p>`;
  } else if (open && Array.isArray(heartbeatHistory.items)) {
    body =
      heartbeatHistory.items.length === 0
        ? '<p class="empty">No heartbeats recorded</p>'
        : [
            '<table class="grid heartbeats">',
            `<thead><tr>${HEARTBEAT_HISTORY_HEADINGS.map((heading) => `<th>${heading}</th>`).join('')}</tr></thead>`,
            `<tbody>${heartbeatHistory.items.map((entry) => heartbeatRow(entry, timeZone)).join('')}</tbody>`,
            '</table>',
          ].join('');
  }
  return [
    `<details class="expandable heartbeat-history" data-device-id="${escapeHtml(deviceId)}"${open ? ' open' : ''}>`,
    `<summary data-device-id="${escapeHtml(deviceId)}">Analytics history</summary>`,
    body,
    '</details>',
  ].join('');
}

/** The snapshot's probe warnings as one field; empty when there are none to show. */
function collectionWarningsField(warnings) {
  if (!Array.isArray(warnings) || warnings.length === 0) {
    return '';
  }
  const entries = warnings.filter((entry) => typeof entry === 'string');
  if (entries.length === 0) {
    return '';
  }
  return field('Collection warnings', escapeHtml(entries.join(', ')));
}

/**
 * Why analytics may be missing, while collection is on: no check-in yet, or
 * the last accepted check-in carried no analytics block (the snapshot is
 * absent or older than it). Empty when the snapshot is from the last check-in.
 */
function analyticsDiagnostic(snapshot, profile, timeZone) {
  const lastCheckInAt = profile?.lastCheckInAt;
  if (typeof lastCheckInAt !== 'string') {
    return snapshot === null
      ? '<p class="analytics-diagnostic">No check-in has been received from this device yet.</p>'
      : '';
  }
  const stale =
    snapshot === null || (typeof snapshot.receivedAt === 'string' && snapshot.receivedAt < lastCheckInAt);
  if (!stale) {
    return '';
  }
  const agentVersion = profile?.agentVersion;
  const version =
    typeof agentVersion === 'string' && agentVersion.length > 0 ? escapeHtml(agentVersion) : 'not reported';
  return `<p class="analytics-diagnostic">The last check-in (${formatDeviceTime(lastCheckInAt, timeZone)}) carried no analytics. Agent version: ${version}.</p>`;
}

/**
 * The endpoint analytics panel: the collection on/off switch, the latest
 * snapshot, boot history and recent crashes/hangs, then the heartbeat switch
 * and its history expander. Collection is on unless
 * `analyticsCollection.enabled` is exactly `false`; the heartbeat is on only
 * when `heartbeat.enabled` is exactly `true`.
 */
function analyticsSection(analytics, analyticsCollection, deviceId, heartbeat, heartbeatHistory, timeZone, profile) {
  const collectionEnabled = analyticsCollection?.enabled !== false;
  const collection = [
    field('Collection', cell(collectionEnabled ? 'On' : 'Off')),
    `<button type="button" class="analytics-collection-toggle" data-device-id="${escapeHtml(deviceId)}" data-enabled="${collectionEnabled ? 'false' : 'true'}">${collectionEnabled ? 'Turn analytics off' : 'Turn analytics on'}</button>`,
    collectionEnabled
      ? ''
      : '<p class="warning">Analytics collection is off; the data below was last reported before it was turned off.</p>',
  ].join('');

  const snapshot = analytics?.snapshot ?? null;
  const boots = Array.isArray(analytics?.bootHistory) ? analytics.bootHistory : [];
  const crashes = Array.isArray(analytics?.crashes) ? analytics.crashes : [];
  const performance = snapshot?.performance ?? null;

  const snapshotFields =
    snapshot === null
      ? '<p class="empty">No analytics reported</p>'
      : [
          field('Last boot', formatDeviceTime(at(snapshot, ['boot', 'lastBootAt']), timeZone)),
          field('Boot duration', cell(formatSeconds(at(snapshot, ['boot', 'bootDurationSeconds'])))),
          field('Uptime', cell(formatUptime(at(snapshot, ['boot', 'uptimeSeconds'])))),
          field('CPU', cell(formatPercent(at(performance, ['cpuPercent'])))),
          field('Memory', cell(memoryText(performance))),
          field('System disk', cell(diskText(performance))),
          field('Reported at', formatDeviceTime(snapshot.receivedAt, timeZone)),
          collectionWarningsField(snapshot.warnings),
        ].join('');

  const bootTable =
    boots.length === 0
      ? '<p class="empty">No boots recorded</p>'
      : [
          '<table class="grid boots">',
          '<thead><tr><th>bootAt</th><th>bootDurationSeconds</th></tr></thead>',
          `<tbody>${boots.map((entry) => bootRow(entry, timeZone)).join('')}</tbody>`,
          '</table>',
        ].join('');

  const crashTable =
    crashes.length === 0
      ? '<p class="empty">No crashes or hangs in the last 30 days</p>'
      : [
          '<table class="grid app-crashes">',
          `<thead><tr>${CRASH_COLUMNS.map((column) => `<th>${column}</th>`).join('')}</tr></thead>`,
          `<tbody>${crashes.map((entry) => crashRow(entry, timeZone)).join('')}</tbody>`,
          '</table>',
        ].join('');

  return [
    sectionStart('detail-analytics', 'Analytics'),
    collection,
    snapshotFields,
    collectionEnabled ? analyticsDiagnostic(snapshot, profile, timeZone) : '',
    '<h4>Boot history</h4>',
    bootTable,
    '<h4>Recent crashes and hangs</h4>',
    crashTable,
    heartbeatForm(heartbeat, deviceId, profile, timeZone),
    heartbeatHistorySection(heartbeatHistory, deviceId, timeZone),
    SECTION_END,
  ].join('');
}

/**
 * The Groups panel: the device's groups, each with a Remove button, and a form
 * adding the device to any listed group it is not in yet.
 */
function groupsSection(groups, allGroups, deviceId) {
  const memberOf = new Set(groups.map((group) => group?.groupId));
  const options = (Array.isArray(allGroups) ? allGroups : [])
    .filter((group) => !memberOf.has(group?.groupId))
    .map((group) => `<option value="${escapeHtml(group.groupId)}">${cell(group.name ?? group.groupId)}</option>`)
    .join('');
  const rows = groups
    .map((group) =>
      [
        `<tr class="device-group" data-group-id="${escapeHtml(group.groupId)}">`,
        `<td class="col-name">${cell(group.name ?? group.groupId)}</td>`,
        '<td class="col-actions">',
        `<button type="button" class="remove-device-group" data-group-id="${escapeHtml(group.groupId)}" data-device-id="${escapeHtml(deviceId)}">Remove from group</button>`,
        '</td>',
        '</tr>',
      ].join(''),
    )
    .join('');
  return [
    sectionStart('detail-groups', 'Groups'),
    groups.length === 0
      ? '<p class="empty">No groups</p>'
      : `<table class="grid device-groups"><thead><tr><th>name</th><th></th></tr></thead><tbody>${rows}</tbody></table>`,
    '<form class="add-device-group">',
    `<input type="hidden" name="deviceId" value="${escapeHtml(deviceId)}">`,
    '<label for="add-device-group-id">Group</label>',
    `<select id="add-device-group-id" name="groupId"><option value=""></option>${options}</select>`,
    '<button type="submit" class="add">Add to group</button>',
    '</form>',
    SECTION_END,
  ].join('');
}

/**
 * The Policies panel, read only: every policy reaching the device, its version
 * and the names of the device's groups it comes through. No form, no button.
 */
function policiesSection(policies, groups) {
  const names = new Map(groups.map((group) => [group?.groupId, group?.name ?? group?.groupId]));
  const rows = policies
    .map((policy) => {
      const via = (Array.isArray(policy?.viaGroups) ? policy.viaGroups : []).map((groupId) => names.get(groupId) ?? groupId);
      return [
        `<tr class="device-policy" data-policy-id="${escapeHtml(policy?.policyId)}">`,
        `<td class="col-name">${cell(policy?.name ?? policy?.policyId)}</td>`,
        `<td class="col-version">${cell(policy?.version)}</td>`,
        `<td class="col-viaGroups">${cell(via.join(', '))}</td>`,
        '</tr>',
      ].join('');
    })
    .join('');
  return [
    sectionStart('detail-policies', 'Policies'),
    policies.length === 0
      ? '<p class="empty">No policies</p>'
      : `<table class="grid device-policies"><thead><tr><th>name</th><th>version</th><th>via groups</th></tr></thead><tbody>${rows}</tbody></table>`,
    SECTION_END,
  ].join('');
}

/** The device detail screen. */
export function render(state = {}) {
  const profile = state.profile ?? {};
  const inventory = state.inventory ?? null;
  const posture = state.posture ?? null;
  const commands = Array.isArray(state.commands) ? state.commands : [];
  const findings = Array.isArray(state.antivirusFindings) ? state.antivirusFindings : [];
  const loginHistory = Array.isArray(state.loginHistory) ? state.loginHistory : [];
  const software = at(inventory, ['software']);
  const groups = Array.isArray(state.groups) ? state.groups : [];
  const policies = Array.isArray(state.policies) ? state.policies : [];
  // Every date on the page is shown in this one zone.
  const timeZone = deviceTimeZone(profile.timeZone);
  const deviceId = profile.deviceId ?? state.deviceId ?? '';
  const hostname = typeof profile.hostname === 'string' && profile.hostname.length > 0 ? profile.hostname : null;

  const profileSection = [
    '<section class="panel" id="detail-profile"><h3>Profile</h3>',
    field('hostname', cell(profile.hostname)),
    field('platform', cell(profile.platform)),
    field('OS', cell(osText(profile))),
    field('lastSeenAt', formatDeviceTime(profile.lastSeenAt, timeZone)),
    field('complianceState', cell(profile.complianceState)),
    field('Ownership', cell(ownershipLabel(profile.ownership))),
    field('Enrolled by', cell(at(profile, ['enrolledBy', 'upn']))),
    field('Signed-in user', cell(at(state.signedInUser, ['username']))),
    field('Agent version', cell(profile.agentVersion)),
    field('Time zone', timeZoneText(profile.timeZone, inventory)),
    `<p class="time-zone-note">Times shown in ${escapeHtml(timeZone)}</p>`,
    '<div class="profile-actions">',
    // Refresh re-fetches the page's stored data; it never contacts the device (TASK-057).
    state.refreshing === true
      ? `<button type="button" class="refresh-device" data-device-id="${escapeHtml(deviceId)}" disabled>Refreshing...</button>`
      : `<button type="button" class="refresh-device" data-device-id="${escapeHtml(deviceId)}">Refresh</button>`,
    `<button type="button" class="open-delete-device" data-device-id="${escapeHtml(deviceId)}">Delete device</button>`,
    '</div>',
    '</section>',
  ].join('');

  const ownership = OWNERSHIP_FILTER_OPTIONS.some(({ value }) => value !== '' && value === profile.ownership)
    ? profile.ownership
    : 'officehq';
  const manageSection = [
    sectionStart('detail-manage', 'Manage'),
    editDeviceForm(deviceId, ownership),
    SECTION_END,
  ].join('');

  const inventorySection = deviceDetailsSection(inventory, timeZone);

  const postureSection = [
    sectionStart('detail-posture', 'Posture'),
    field('diskEncryption.enabled', flag(at(posture, ['diskEncryption', 'enabled']))),
    field('firewall.enabled', flag(at(posture, ['firewall', 'enabled']))),
    field('antivirus.enabled', flag(at(posture, ['antivirus', 'enabled']))),
    SECTION_END,
  ].join('');

  const commandsSection = [
    runCommandSection(state.scripts, deviceId, hostname, state.runCommand),
    queueSection(commands, deviceId, timeZone),
    historySection(state.deviceEvents, commands, timeZone),
  ].join('');

  const findingsSection = [
    sectionStart('detail-antivirus-findings', 'Antivirus findings'),
    findings.length === 0
      ? '<p class="empty">No antivirus findings</p>'
      : [
          '<table class="grid antivirus-findings">',
          `<thead><tr>${FINDING_COLUMNS.map((column) => `<th>${column}</th>`).join('')}</tr></thead>`,
          `<tbody>${findings.map((entry) => findingRow(entry, timeZone)).join('')}</tbody>`,
          '</table>',
        ].join(''),
    SECTION_END,
  ].join('');

  const loginHistorySection = [
    sectionStart('detail-login-history', 'Login history'),
    loginHistory.length === 0
      ? '<p class="empty">No logins recorded</p>'
      : [
          '<table class="grid login-history">',
          `<thead><tr>${LOGIN_HISTORY_COLUMNS.map((column) => `<th>${column}</th>`).join('')}</tr></thead>`,
          `<tbody>${loginHistory.map((entry) => loginUserRow(entry, timeZone)).join('')}</tbody>`,
          '</table>',
        ].join(''),
    SECTION_END,
  ].join('');

  const html = [
    `<section class="screen" id="screen-device-detail" data-device-id="${escapeHtml(profile.deviceId ?? state.deviceId)}">`,
    `<h2>${cell(profile.hostname ?? profile.deviceId ?? state.deviceId)}</h2>`,
    profileSection,
    manageSection,
    groupsSection(groups, state.allGroups, deviceId),
    policiesSection(policies, groups),
    credentialSection(state.credential, deviceId, timeZone),
    inventorySection,
    softwareSection(software, timeZone, state.applications, deviceId),
    postureSection,
    commandsSection,
    antivirusStatusSection(state.antivirusStatus, findings, timeZone),
    defenderHardeningSection(state.defenderHardening, timeZone),
    findingsSection,
    antivirusScanSection(state.antivirusScan, timeZone),
    locationSection(state.location, state.locationTracking, timeZone),
    loginHistorySection,
    agentErrorsSection(state.agentErrors, timeZone),
    analyticsSection(
      state.analytics,
      state.analyticsCollection,
      profile.deviceId ?? state.deviceId,
      state.heartbeat,
      state.heartbeatHistory,
      timeZone,
      profile,
    ),
    deleteDeviceDialog(state.deleteDialog ?? null, deviceId, hostname),
    '</section>',
  ].join('');
  // Every section starts collapsed; the ones the admin opened stay open (TASK-062).
  return openSectionExpanders(html, state.openSections);
}

export const renderDeviceDetail = render;
