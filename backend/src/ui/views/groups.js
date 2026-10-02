/**
 * Groups and their membership.
 *
 *   render({items, added})
 *   createRequest({name})                   -> POST /admin/api/v1/groups {name}
 *   membershipRequest({groupId, deviceIds}) -> POST /admin/api/v1/groups/{groupId}/members {deviceIds}
 *
 * Groups are how a policy reaches a device and how a command reaches a fleet,
 * so the screen keeps both halves together: the list, a create form, and a
 * membership form. `added` is echoed back from the membership response --
 * adding a device twice adds nothing, and the count is what tells an operator
 * how many of the ids they pasted were actually new.
 */
import { cell, escapeHtml, join } from '../public/html.js';

/** The columns a group row shows, in order. */
export const COLUMNS = ['groupId', 'name', 'createdAt'];

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

/** One group. */
function row(item) {
  const cells = COLUMNS.map((column) => `<td class="col-${column}">${cell(item[column])}</td>`).join('');
  return `<tr class="group" data-group-id="${escapeHtml(item.groupId)}">${cells}</tr>`;
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

  const options = items
    .map(
      (item) =>
        `<option value="${escapeHtml(item.groupId)}"${item.groupId === state.groupId ? ' selected' : ''}>${cell(
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
    `<select id="member-group" name="groupId"><option value=""></option>${options}</select>`,
    '<label for="member-devices">deviceIds</label>',
    `<textarea id="member-devices" name="deviceIds">${escapeHtml(
      Array.isArray(state.deviceIds) ? state.deviceIds.join('\n') : state.deviceIds,
    )}</textarea>`,
    '<button type="submit" class="add">Add to group</button>',
    '</form>',
    added,
    '</section>',
  ]);
}

export const renderGroups = render;
