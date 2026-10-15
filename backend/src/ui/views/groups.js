/**
 * Groups and their membership.
 *
 *   render({items, added, removed, groupId, typedName, devices, pending, lookup, lookupMessage, memberGroupId})
 *   matchDevices(devices, text)             -> the devices whose hostname or deviceId is exactly `text`
 *                                              (trimmed, case-insensitive)
 *   addPending({devices, pending}, text)    -> {pending, lookup, lookupMessage} after Enter in the lookup
 *   removePending(pending, deviceId)        -> the pending list without that device
 *   createRequest({name})                   -> POST /admin/api/v1/groups {name}
 *   membershipRequest({groupId, deviceIds}) -> POST /admin/api/v1/groups/{groupId}/members {deviceIds}
 *   removeMembersRequest({groupId, deviceIds}) -> DELETE on that same path {deviceIds}
 *   renameRequest({groupId, name})          -> PUT /admin/api/v1/groups/{groupId} {name}
 *   autoAssignRequest({groupId, ownership}) -> PUT /admin/api/v1/groups/{groupId}/auto-assign {ownership}
 *                                              ("" -> null)
 *   deleteRequest({groupId, name, typedName}) -> DELETE /admin/api/v1/groups/{groupId} {confirm: true},
 *                                              once typedName === name
 *
 * Groups are how a policy reaches a device and how a command reaches a fleet,
 * so the screen keeps both halves together: the list, a create form, and a
 * membership form. `added` is echoed back from the membership response --
 * adding a device twice adds nothing, and the count is what tells an operator
 * how many of the listed devices were actually new.
 *
 * The membership form picks devices with a lookup (TASK-046): `devices` is the
 * whole fleet as `{deviceId, hostname}`, offered through a datalist; Enter in
 * the lookup adds the one exactly matching device to `pending`, the list "Add
 * to group" and "Remove from group" send. `lookupMessage` says why nothing was
 * added; `memberGroupId` is the group chosen in the membership form.
 *
 * Each row's auto-assign select picks the ownership whose newly enrolled (or
 * re-owned) devices join that group automatically: None, OfficeHQ devices or
 * BYOD devices. Saving adds no device that is already enrolled.
 */
import { attributes, cell, escapeHtml, join } from '../public/html.js';

/** The columns a group row shows, in order. */
export const COLUMNS = ['groupId', 'name', 'createdAt', 'autoAssign'];

/** What an empty group list reads as. */
export const EMPTY_MESSAGE = 'No groups yet';

/** Device ids as typed: an array, or a list separated by commas, spaces or newlines. */
export function deviceIdList(value) {
  if (Array.isArray(value)) {
    return value.map((id) => String(id).trim()).filter((id) => id.length > 0);
  }
  if (typeof value !== 'string') {
    return [];
  }
  return value
    .split(/[\s,]+/)
    .map((id) => id.trim())
    .filter((id) => id.length > 0);
}

/** A device's hostname, or `null` when it has none. */
function hostnameOf(device) {
  return typeof device?.hostname === 'string' && device.hostname.length > 0 ? device.hostname : null;
}

/** How a device reads in the lookup list: `hostname (deviceId)`, or just the id. */
export function deviceLabel(device) {
  const hostname = hostnameOf(device);
  return hostname === null ? String(device?.deviceId ?? '') : `${hostname} (${device.deviceId})`;
}

/**
 * The devices whose hostname or deviceId equals `text`, trimmed and compared
 * case-insensitively. Exact only, never by substring; `[]` for blank text.
 */
export function matchDevices(devices, text) {
  const wanted = typeof text === 'string' ? text.trim().toLowerCase() : '';
  if (wanted.length === 0) {
    return [];
  }
  return (Array.isArray(devices) ? devices : []).filter((device) => {
    const hostname = hostnameOf(device);
    const deviceId = typeof device?.deviceId === 'string' ? device.deviceId : '';
    return (hostname !== null && hostname.toLowerCase() === wanted) || deviceId.toLowerCase() === wanted;
  });
}

/**
 * What Enter in the lookup leaves behind, as `{pending, lookup, lookupMessage}`.
 *
 *   blank text            -> nothing changes, no message
 *   one new match         -> appended, the lookup cleared, no message
 *   one listed match      -> unchanged, the lookup cleared, "<label> is already in the list"
 *   no match              -> unchanged, the text kept, 'No device matches "<text>"'
 *   several matches       -> unchanged, the text kept, '"<text>" matches <N> devices; enter the device id'
 */
export function addPending(state = {}, text = '') {
  const pending = Array.isArray(state.pending) ? state.pending : [];
  const typed = typeof text === 'string' ? text : '';
  const trimmed = typed.trim();
  if (trimmed.length === 0) {
    return { pending, lookup: typed, lookupMessage: null };
  }
  const matches = matchDevices(state.devices, trimmed);
  if (matches.length === 0) {
    return { pending, lookup: typed, lookupMessage: `No device matches "${trimmed}"` };
  }
  if (matches.length > 1) {
    return { pending, lookup: typed, lookupMessage: `"${trimmed}" matches ${matches.length} devices; enter the device id` };
  }
  const [device] = matches;
  if (pending.some((entry) => entry?.deviceId === device.deviceId)) {
    return { pending, lookup: '', lookupMessage: `${deviceLabel(device)} is already in the list` };
  }
  return {
    pending: [...pending, { deviceId: device.deviceId, hostname: hostnameOf(device) }],
    lookup: '',
    lookupMessage: null,
  };
}

/** The pending list without the device `deviceId`. */
export function removePending(pending, deviceId) {
  return (Array.isArray(pending) ? pending : []).filter((entry) => entry?.deviceId !== deviceId);
}

/** The ids of the pending devices, in list order. */
export function pendingIds(pending) {
  return (Array.isArray(pending) ? pending : []).map((entry) => entry?.deviceId).filter((id) => typeof id === 'string');
}

/** The lookup's datalist, the message, and the pending list (or its empty state). */
function lookupFields(state) {
  const devices = Array.isArray(state.devices) ? state.devices : [];
  const pending = Array.isArray(state.pending) ? state.pending : [];
  const options = devices
    .map((device) => `<option value="${escapeHtml(hostnameOf(device) ?? device?.deviceId)}"></option>`)
    .join('');
  const list =
    pending.length === 0
      ? '<p class="empty">No devices selected</p>'
      : `<ul class="pending-devices">${pending
          .map(
            (entry) =>
              `<li data-device-id="${escapeHtml(entry.deviceId)}">${escapeHtml(deviceLabel(entry))}` +
              `<button type="button" class="remove-pending" data-device-id="${escapeHtml(entry.deviceId)}">&times;</button></li>`,
          )
          .join('')}</ul>`;
  return join([
    '<label for="member-lookup">device</label>',
    `<input id="member-lookup" class="device-lookup" name="lookup" autocomplete="off" list="member-device-options" value="${escapeHtml(
      typeof state.lookup === 'string' ? state.lookup : '',
    )}">`,
    `<datalist id="member-device-options">${options}</datalist>`,
    typeof state.lookupMessage === 'string' && state.lookupMessage.length > 0
      ? `<p class="lookup-message">${escapeHtml(state.lookupMessage)}</p>`
      : '',
    list,
  ]);
}

/** The create request, or `null` when no name has been typed. */
export function createRequest(state = {}) {
  const name = typeof state.name === 'string' ? state.name.trim() : '';
  if (name.length === 0) {
    return null;
  }
  return { method: 'POST', path: '/admin/api/v1/groups', body: { name } };
}

/** Just the create body, or `null`. */
export function createBody(state = {}) {
  return createRequest(state)?.body ?? null;
}

/** The membership request, or `null` when no group or no device id was named. */
export function membershipRequest(state = {}) {
  const groupId = typeof state.groupId === 'string' ? state.groupId.trim() : '';
  const deviceIds = deviceIdList(state.deviceIds);
  if (groupId.length === 0 || deviceIds.length === 0) {
    return null;
  }
  return { method: 'POST', path: `/admin/api/v1/groups/${groupId}/members`, body: { deviceIds } };
}

/** Just the membership body, or `null`. */
export function membershipBody(state = {}) {
  return membershipRequest(state)?.body ?? null;
}

/** The remove-members request, or `null` when no group or no device id was named. */
export function removeMembersRequest(state = {}) {
  const groupId = typeof state.groupId === 'string' ? state.groupId.trim() : '';
  const deviceIds = deviceIdList(state.deviceIds);
  if (groupId.length === 0 || deviceIds.length === 0) {
    return null;
  }
  return { method: 'DELETE', path: `/admin/api/v1/groups/${groupId}/members`, body: { deviceIds } };
}

/** The rename request, or `null` when no group is selected or the name is blank. */
export function renameRequest(state = {}) {
  const groupId = typeof state.groupId === 'string' ? state.groupId.trim() : '';
  const name = typeof state.name === 'string' ? state.name.trim() : '';
  if (groupId.length === 0 || name.length === 0) {
    return null;
  }
  return { method: 'PUT', path: `/admin/api/v1/groups/${groupId}`, body: { name } };
}

/**
 * The delete request, or `null` until `typedName` is exactly the selected
 * group's name. Typing the name is the confirmation, as on the dispatch screen.
 */
export function deleteRequest(state = {}) {
  const groupId = typeof state.groupId === 'string' ? state.groupId.trim() : '';
  const name = typeof state.name === 'string' ? state.name : '';
  if (groupId.length === 0 || state.typedName !== name) {
    return null;
  }
  return { method: 'DELETE', path: `/admin/api/v1/groups/${groupId}`, body: { confirm: true } };
}

/**
 * The queue-on-members request (TASK-045), or `null` until a group and a
 * script are chosen and `typedName` is exactly the selected group's name.
 */
export function queueScriptRequest(state = {}) {
  const groupId = typeof state.groupId === 'string' ? state.groupId.trim() : '';
  const scriptId = typeof state.scriptId === 'string' ? state.scriptId : '';
  const name = typeof state.name === 'string' ? state.name : '';
  if (groupId.length === 0 || scriptId.length === 0 || name.length === 0 || state.typedName !== name) {
    return null;
  }
  return { method: 'POST', path: `/admin/api/v1/groups/${groupId}/scripts`, body: { scriptId, confirm: true } };
}

/** What a queue-on-members answer reads as. */
export function queuedMessage(result = {}) {
  const queued = typeof result.queued === 'number' ? result.queued : 0;
  const skipped = typeof result.skipped?.wrongPlatform === 'number' ? result.skipped.wrongPlatform : 0;
  return `Queued ${queued}, skipped ${skipped} (wrong platform)`;
}

/**
 * The queue-on-members form: a group, a library script labelled with its
 * platform, and a submit button disabled until the group's name is typed.
 */
function queueScriptForm(items, scripts, selected = {}, result = null) {
  const list = Array.isArray(scripts) ? scripts : [];
  const groupId = typeof selected.groupId === 'string' ? selected.groupId : '';
  const scriptId = typeof selected.scriptId === 'string' ? selected.scriptId : '';
  const typedName = typeof selected.typedName === 'string' ? selected.typedName : '';
  const queueable = queueScriptRequest({ groupId, scriptId, name: groupName(items, groupId), typedName }) !== null;
  const groupOptions = items
    .map(
      (item) =>
        `<option value="${escapeHtml(item.groupId)}"${item.groupId === groupId ? ' selected' : ''}>${cell(item.name)}</option>`,
    )
    .join('');
  const scriptOptions = list
    .map(
      (script) =>
        `<option value="${escapeHtml(script.scriptId)}"${script.scriptId === scriptId ? ' selected' : ''}>${escapeHtml(
          `${script.name ?? ''} (${script.platform ?? ''})`,
        )}</option>`,
    )
    .join('');
  return join([
    '<form class="queue-group-script">',
    '<label for="queue-group-id">group</label>',
    `<select id="queue-group-id" name="groupId"><option value=""></option>${groupOptions}</select>`,
    '<label for="queue-group-script-id">command</label>',
    `<select id="queue-group-script-id" name="scriptId"><option value=""></option>${scriptOptions}</select>`,
    '<label for="queue-group-name">Type the group name to queue it on every member</label>',
    `<input id="queue-group-name" name="typedName" value="${escapeHtml(typedName)}" autocomplete="off">`,
    `<button type="submit" class="queue"${attributes({ disabled: !queueable })}>Queue on members</button>`,
    '</form>',
    result === null || result === undefined ? '' : `<p class="queued">${escapeHtml(queuedMessage(result))}</p>`,
  ]);
}

/** The name of a listed group, or `''` when it is not listed. */
export function groupName(items, groupId) {
  const item = (Array.isArray(items) ? items : []).find((group) => group.groupId === groupId);
  return typeof item?.name === 'string' ? item.name : '';
}

/** One group. */
function row(item) {
  const cells = COLUMNS.map((column) =>
    column === 'autoAssign'
      ? `<td class="col-autoAssign">${autoAssignForm(item)}</td>`
      : `<td class="col-${column}">${cell(item[column])}</td>`,
  ).join('');
  return `<tr class="group" data-group-id="${escapeHtml(item.groupId)}">${cells}</tr>`;
}

/** What each auto-assign value reads as; the stored `byoc` is shown as BYOD. */
export const AUTO_ASSIGN_OPTIONS = [
  { value: '', label: 'None' },
  { value: 'officehq', label: 'OfficeHQ devices' },
  { value: 'byoc', label: 'BYOD devices' },
];

/** A group's auto-assign select, preselected from the group, with its own Save. */
function autoAssignForm(item) {
  const current = AUTO_ASSIGN_OPTIONS.some(({ value }) => value !== '' && value === item.autoAssignOwnership)
    ? item.autoAssignOwnership
    : '';
  const id = `auto-assign-${escapeHtml(item.groupId)}`;
  const options = AUTO_ASSIGN_OPTIONS.map(
    ({ value, label }) => `<option value="${value}"${value === current ? ' selected' : ''}>${label}</option>`,
  ).join('');
  return join(
    [
      '<form class="auto-assign-group">',
      `<input type="hidden" name="groupId" value="${escapeHtml(item.groupId)}">`,
      `<label class="visually-hidden" for="${id}">Auto-assign devices to ${cell(item.name)}</label>`,
      `<select id="${id}" name="ownership">${options}</select>`,
      '<button type="submit" class="save-auto-assign">Save</button>',
      '</form>',
    ],
    '',
  );
}

/** The auto-assign request; "None" (`""`) is sent as `null`. `null` when there is no group. */
export function autoAssignRequest({ groupId, ownership } = {}) {
  if (typeof groupId !== 'string' || groupId.length === 0) {
    return null;
  }
  return {
    method: 'PUT',
    path: `/admin/api/v1/groups/${encodeURIComponent(groupId)}/auto-assign`,
    body: { ownership: typeof ownership === 'string' && ownership.length > 0 ? ownership : null },
  };
}

/** The groups screen. */
export function render(state = {}) {
  const items = Array.isArray(state.items) ? state.items : [];
  const list =
    items.length === 0
      ? `<p class="empty">${EMPTY_MESSAGE}</p>`
      : [
          '<table class="grid groups">',
          `<thead><tr>${COLUMNS.map((column) => `<th>${column}</th>`).join('')}</tr></thead>`,
          `<tbody>${items.map(row).join('')}</tbody>`,
          '</table>',
        ].join('');

  const added =
    typeof state.added === 'number'
      ? `<p class="added" data-added="${state.added}">${state.added} device${state.added === 1 ? '' : 's'} added</p>`
      : '';

  const removed =
    typeof state.removed === 'number'
      ? `<p class="removed" data-removed="${state.removed}">${state.removed} device${
          state.removed === 1 ? '' : 's'
        } removed</p>`
      : '';

  const deletable =
    deleteRequest({
      groupId: state.groupId,
      name: groupName(items, state.groupId),
      typedName: typeof state.typedName === 'string' ? state.typedName : '',
    }) !== null;

  const options = items
    .map(
      (item) =>
        `<option value="${escapeHtml(item.groupId)}"${item.groupId === state.groupId ? ' selected' : ''}>${cell(
          item.name,
        )}</option>`,
    )
    .join('');

  // The membership form keeps its own chosen group across repaints.
  const memberGroupId = typeof state.memberGroupId === 'string' ? state.memberGroupId : state.groupId;
  const memberOptions = items
    .map(
      (item) =>
        `<option value="${escapeHtml(item.groupId)}"${item.groupId === memberGroupId ? ' selected' : ''}>${cell(
          item.name,
        )}</option>`,
    )
    .join('');

  return join([
    '<section class="screen" id="screen-groups"><h2>Groups</h2>',
    list,
    '<form class="create-group">',
    '<label for="group-name">name</label>',
    `<input id="group-name" name="name" value="${escapeHtml(state.name)}">`,
    '<button type="submit" class="create">Create group</button>',
    '</form>',
    '<form class="add-members">',
    '<label for="member-group">group</label>',
    `<select id="member-group" name="groupId"><option value=""></option>${memberOptions}</select>`,
    lookupFields(state),
    '<button type="submit" class="add">Add to group</button>',
    '<button type="button" class="remove-members">Remove from group</button>',
    '</form>',
    added,
    removed,
    '<form class="rename-group">',
    '<label for="rename-group-id">group</label>',
    `<select id="rename-group-id" name="groupId"><option value=""></option>${options}</select>`,
    '<label for="rename-group-name">name</label>',
    '<input id="rename-group-name" name="name" value="">',
    '<button type="submit" class="rename">Rename group</button>',
    '</form>',
    '<form class="delete-group">',
    '<label for="delete-group-id">group</label>',
    `<select id="delete-group-id" name="groupId"><option value=""></option>${options}</select>`,
    '<label for="delete-group-name">Type the group name to delete it</label>',
    `<input id="delete-group-name" name="typedName" value="${escapeHtml(state.typedName)}" autocomplete="off">`,
    `<button type="submit" class="delete"${attributes({ disabled: !deletable })}>Delete group</button>`,
    '</form>',
    queueScriptForm(items, state.scripts, state.queueScript, state.queued),
    '</section>',
  ]);
}

export const renderGroups = render;
