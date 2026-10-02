/**
 * Policies and the groups they are assigned to.
 *
 *   render({items, name, settings, policyId, groupId, groups})
 *   createRequest(state)                 -> POST /admin/api/v1/policies {name, settings}
 *   assignRequest({policyId, groupId})   -> POST /admin/api/v1/policies/{policyId}/assignments {groupId}
 *   unassignRequest({policyId, groupId}) -> DELETE on that same path
 *
 * The settings a policy may carry are a closed set: seven keys, each with its
 * own type and range, exactly as `src/admin/policies.ts` enforces them. A key
 * this console does not know is dropped rather than sent, and a value out of
 * range is named in its own field instead of being posted -- a policy an agent
 * cannot apply is worse than a form that will not submit.
 *
 * Assignment is by group, never by device, which is why the assignment form
 * picks a group and the removal is the same path with `DELETE`.
 */
import { attributes, cell, escapeHtml, join } from '../public/html.js';

/** The only settings keys a policy may carry. */
export const SETTING_KEYS = [
  'firewallEnabled',
  'diskEncryptionRequired',
  'screenLockTimeoutSeconds',
  'osUpdateMaxAgeDays',
  'localAdminAllowlist',
  'firewallBlockedDomains',
  'firewallAllowedDomains',
];

/** The keys whose values are lists typed as text. */
const LIST_KEYS = ['localAdminAllowlist', 'firewallBlockedDomains', 'firewallAllowedDomains'];

/** The keys whose values are lists of domain names. */
const DOMAIN_KEYS = ['firewallBlockedDomains', 'firewallAllowedDomains'];

/** What one domain entry must look like, exactly as `src/admin/policies.ts` checks it. */
export const DOMAIN_PATTERN = /^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;

/** Longest accepted domain entry, in characters. */
export const DOMAIN_MAX_LENGTH = 253;

/** Most entries a domain list may hold. */
export const DOMAIN_LIST_MAX_ENTRIES = 500;

/** The range `screenLockTimeoutSeconds` must fall inside. */
export const SCREEN_LOCK_TIMEOUT_SECONDS = { min: 60, max: 3600 };

/** The range `osUpdateMaxAgeDays` must fall inside. */
export const OS_UPDATE_MAX_AGE_DAYS = { min: 1, max: 180 };

/** A number as typed: `'120'` and `120` are the same value, anything else is not a number. */
function asNumber(value) {
  if (typeof value === 'number') {
    return value;
  }
  if (typeof value === 'string' && value.trim().length > 0 && Number.isFinite(Number(value))) {
    return Number(value);
  }
  return null;
}

/** An allowlist as typed: an array, or a list separated by commas, spaces or newlines. */
function asList(value) {
  if (Array.isArray(value)) {
    return value.map((entry) => String(entry).trim()).filter((entry) => entry.length > 0);
  }
  if (typeof value !== 'string') {
    return null;
  }
  return value
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/** True when a list holds at most 500 entries, each a valid domain name. */
function isDomainList(list) {
  return (
    list.length <= DOMAIN_LIST_MAX_ENTRIES &&
    list.every((entry) => entry.length <= DOMAIN_MAX_LENGTH && DOMAIN_PATTERN.test(entry))
  );
}

/** True when a number is an integer inside a range. */
function inRange(value, range) {
  return Number.isInteger(value) && value >= range.min && value <= range.max;
}

/** The settings the state carries, with every unknown key dropped and every value coerced. */
export function settingsOf(state = {}) {
  const source = state.settings ?? {};
  const settings = {};
  for (const key of SETTING_KEYS) {
    const value = source[key];
    if (value === undefined || value === null || value === '') {
      continue;
    }
    if (key === 'firewallEnabled' || key === 'diskEncryptionRequired') {
      settings[key] = value === true || value === 'true';
      continue;
    }
    if (LIST_KEYS.includes(key)) {
      const list = asList(value);
      if (list !== null) {
        settings[key] = list;
      }
      continue;
    }
    settings[key] = asNumber(value) ?? value;
  }
  return settings;
}

/** The settings fields whose values the API would refuse, named one by one. */
export function fieldErrors(state = {}) {
  const settings = settingsOf(state);
  const errors = [];
  if (settings.screenLockTimeoutSeconds !== undefined && !inRange(settings.screenLockTimeoutSeconds, SCREEN_LOCK_TIMEOUT_SECONDS)) {
    errors.push('screenLockTimeoutSeconds');
  }
  if (settings.osUpdateMaxAgeDays !== undefined && !inRange(settings.osUpdateMaxAgeDays, OS_UPDATE_MAX_AGE_DAYS)) {
    errors.push('osUpdateMaxAgeDays');
  }
  for (const key of DOMAIN_KEYS) {
    if (settings[key] !== undefined && !isDomainList(settings[key])) {
      errors.push(key);
    }
  }
  return errors;
}

/** The create request, or `null` when a field is out of range or the policy has no name. */
export function createRequest(state = {}) {
  const name = typeof state.name === 'string' ? state.name.trim() : '';
  if (name.length === 0 || fieldErrors(state).length > 0) {
    return null;
  }
  return { method: 'POST', path: '/admin/api/v1/policies', body: { name, settings: settingsOf(state) } };
}

/** Just the create body, or `null`. */
export function createBody(state = {}) {
  return createRequest(state)?.body ?? null;
}

/** The path a policy's assignments live at. */
export function assignmentPath(policyId) {
  return `/admin/api/v1/policies/${policyId}/assignments`;
}

/** Assign a policy to a group. */
export function assignRequest(state = {}) {
  if (!state.policyId || !state.groupId) {
    return null;
  }
  return { method: 'POST', path: assignmentPath(state.policyId), body: { groupId: state.groupId } };
}

/** Take that assignment back: the same path, with `DELETE`. */
export function unassignRequest(state = {}) {
  if (!state.policyId || !state.groupId) {
    return null;
  }
  return { method: 'DELETE', path: assignmentPath(state.policyId), body: { groupId: state.groupId } };
}

/** One named field error. */
function errorFor(errors, field, message) {
  return errors.includes(field) ? `<p class="field-error" data-field="${field}">${message}</p>` : '';
}

/** One policy. */
function row(item) {
  return [
    `<tr class="policy" data-policy-id="${escapeHtml(item.policyId)}">`,
    `<td class="col-policyId">${cell(item.policyId)}</td>`,
    `<td class="col-name">${cell(item.name)}</td>`,
    `<td class="col-version">${cell(item.version)}</td>`,
    '</tr>',
  ].join('');
}

/** The policies screen. */
export function render(state = {}) {
  const items = Array.isArray(state.items) ? state.items : [];
  const groups = Array.isArray(state.groups) ? state.groups : [];
  const settings = settingsOf(state);
  const errors = fieldErrors(state);

  const list =
    items.length === 0
      ? '<p class="empty">No policies yet</p>'
      : [
          '<table class="grid policies">',
          '<thead><tr><th>policyId</th><th>name</th><th>version</th></tr></thead>',
          `<tbody>${items.map(row).join('')}</tbody>`,
          '</table>',
        ].join('');

  const groupOptions = groups
    .map((group) => `<option value="${escapeHtml(group.groupId)}"${group.groupId === state.groupId ? ' selected' : ''}>${cell(group.name)}</option>`)
    .join('');

  const policyOptions = items
    .map((item) => `<option value="${escapeHtml(item.policyId)}"${item.policyId === state.policyId ? ' selected' : ''}>${cell(item.name)}</option>`)
    .join('');

  return join([
    '<section class="screen" id="screen-policies"><h2>Policies</h2>',
    list,
    '<form class="create-policy">',
    '<label for="policy-name">name</label>',
    `<input id="policy-name" name="name" value="${escapeHtml(state.name)}">`,
    '<label for="firewall-enabled">firewallEnabled</label>',
    `<input id="firewall-enabled" name="firewallEnabled" type="checkbox"${attributes({
      checked: settings.firewallEnabled === true,
    })}>`,
    '<label for="disk-encryption-required">diskEncryptionRequired</label>',
    `<input id="disk-encryption-required" name="diskEncryptionRequired" type="checkbox"${attributes({
      checked: settings.diskEncryptionRequired === true,
    })}>`,
    '<label for="screen-lock">screenLockTimeoutSeconds</label>',
    `<input id="screen-lock" name="screenLockTimeoutSeconds" type="number" min="${SCREEN_LOCK_TIMEOUT_SECONDS.min}" max="${SCREEN_LOCK_TIMEOUT_SECONDS.max}" value="${escapeHtml(
      settings.screenLockTimeoutSeconds,
    )}">`,
    errorFor(
      errors,
      'screenLockTimeoutSeconds',
      `screenLockTimeoutSeconds must be between ${SCREEN_LOCK_TIMEOUT_SECONDS.min} and ${SCREEN_LOCK_TIMEOUT_SECONDS.max}`,
    ),
    '<label for="os-update-age">osUpdateMaxAgeDays</label>',
    `<input id="os-update-age" name="osUpdateMaxAgeDays" type="number" min="${OS_UPDATE_MAX_AGE_DAYS.min}" max="${OS_UPDATE_MAX_AGE_DAYS.max}" value="${escapeHtml(
      settings.osUpdateMaxAgeDays,
    )}">`,
    errorFor(
      errors,
      'osUpdateMaxAgeDays',
      `osUpdateMaxAgeDays must be between ${OS_UPDATE_MAX_AGE_DAYS.min} and ${OS_UPDATE_MAX_AGE_DAYS.max}`,
    ),
    '<label for="local-admins">localAdminAllowlist</label>',
    `<textarea id="local-admins" name="localAdminAllowlist">${escapeHtml(
      (settings.localAdminAllowlist ?? []).join('\n'),
    )}</textarea>`,
    '<label for="firewall-blocked-domains">firewallBlockedDomains</label>',
    `<textarea id="firewall-blocked-domains" name="firewallBlockedDomains">${escapeHtml(
      (settings.firewallBlockedDomains ?? []).join('\n'),
    )}</textarea>`,
    errorFor(
      errors,
      'firewallBlockedDomains',
      `firewallBlockedDomains must hold at most ${DOMAIN_LIST_MAX_ENTRIES} domain names such as example.com`,
    ),
    '<label for="firewall-allowed-domains">firewallAllowedDomains</label>',
    `<textarea id="firewall-allowed-domains" name="firewallAllowedDomains">${escapeHtml(
      (settings.firewallAllowedDomains ?? []).join('\n'),
    )}</textarea>`,
    errorFor(
      errors,
      'firewallAllowedDomains',
      `firewallAllowedDomains must hold at most ${DOMAIN_LIST_MAX_ENTRIES} domain names such as example.com`,
    ),
    `<button type="submit" class="create"${attributes({ disabled: errors.length > 0 })}>Create policy</button>`,
    '</form>',
    '<form class="assign-policy">',
    '<label for="assign-policy">policy</label>',
    `<select id="assign-policy" name="policyId"><option value=""></option>${policyOptions}</select>`,
    '<label for="assign-group">group</label>',
    `<select id="assign-group" name="groupId"><option value=""></option>${groupOptions}</select>`,
    '<button type="submit" class="assign">Assign</button>',
    '<button type="button" class="unassign">Remove</button>',
    '</form>',
    '</section>',
  ]);
}

export const renderPolicies = render;
