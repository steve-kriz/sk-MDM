/**
 * Policies and the groups they are assigned to.
 *
 *   render({items, name, settings, policyId, groupId, groups, editing, editDraft})
 *   createRequest(state)                 -> POST /admin/api/v1/policies {name, settings}
 *   createRefusal(state)                 -> why createRequest returned null, or null
 *   updateRequest({policyId, name, settings})  -> PUT /admin/api/v1/policies/{policyId} {name, settings}
 *   deleteRequest({policyId, name, typedName}) -> DELETE that path {confirm: true}, once typedName === name
 *   assignRequest({policyId, groupId})   -> POST /admin/api/v1/policies/{policyId}/assignments {groupId}
 *   unassignRequest({policyId, groupId}) -> DELETE on that same path
 *
 * The settings a policy may carry are a closed set: sixteen keys, each with its
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
  'antivirusEnabled',
  'antivirusScanFrequency',
  'locationTracking',
  'defenderRealTimeProtection',
  'defenderCloudProtection',
  'defenderNetworkProtection',
  'defenderRansomwareProtection',
  'defenderReputationProtection',
  'defenderDailySignatureUpdate',
];

/** The values `antivirusScanFrequency` may take, exactly as `src/admin/policies.ts` checks it. */
export const ANTIVIRUS_SCAN_FREQUENCIES = ['off', 'daily', 'weekly', 'monthly'];

/** The values `defenderRansomwareProtection` may take, exactly as `src/admin/policies.ts` checks it. */
export const DEFENDER_RANSOMWARE_MODES = ['audit', 'block'];

/** The boolean Defender protection keys, each rendered as a checkbox. */
export const DEFENDER_BOOLEAN_KEYS = [
  'defenderRealTimeProtection',
  'defenderCloudProtection',
  'defenderNetworkProtection',
  'defenderReputationProtection',
  'defenderDailySignatureUpdate',
];

/** The keys whose values are booleans, sent as `true` or `false`. */
const BOOLEAN_KEYS = ['firewallEnabled', 'diskEncryptionRequired', 'antivirusEnabled', 'locationTracking', ...DEFENDER_BOOLEAN_KEYS];

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
    if (BOOLEAN_KEYS.includes(key)) {
      settings[key] = value === true || value === 'true';
      continue;
    }
    if (key === 'antivirusScanFrequency' || key === 'defenderRansomwareProtection') {
      settings[key] = String(value);
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
  if (
    settings.antivirusScanFrequency !== undefined &&
    !ANTIVIRUS_SCAN_FREQUENCIES.includes(settings.antivirusScanFrequency)
  ) {
    errors.push('antivirusScanFrequency');
  }
  if (
    settings.defenderRansomwareProtection !== undefined &&
    !DEFENDER_RANSOMWARE_MODES.includes(settings.defenderRansomwareProtection)
  ) {
    errors.push('defenderRansomwareProtection');
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

/**
 * Why `createRequest` refused the state, as the banner says it, or `null` when
 * it would not. Every reason is named at once -- a missing name and each field
 * the API would refuse -- so one submit tells the admin everything to fix.
 */
export function createRefusal(state = {}) {
  const reasons = refusalReasons(state);
  return reasons.length === 0 ? null : `Policy not created: ${reasons.join('; ')}`;
}

/** A missing name and each field the API would refuse, as the banner names them. */
function refusalReasons(state) {
  const name = typeof state.name === 'string' ? state.name.trim() : '';
  return [
    ...(name.length === 0 ? ['name is required'] : []),
    ...fieldErrors(state).map((field) =>
      DOMAIN_KEYS.includes(field)
        ? `${field} is not a valid domain list`
        : field === 'defenderRansomwareProtection'
          ? `${field} must be one of ${DEFENDER_RANSOMWARE_MODES.join(', ')}`
          : `${field} is out of range`,
    ),
  ];
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

/**
 * The `antivirusScanFrequency` options: a blank one (key not set), then each
 * allowed value. The option equal to `current` is selected; the blank one is
 * when nothing is stored.
 */
function scanFrequencyOptions(current) {
  const selected = typeof current === 'string' ? current : '';
  return ['', ...ANTIVIRUS_SCAN_FREQUENCIES]
    .map(
      (value) =>
        `<option value="${escapeHtml(value)}"${attributes({ selected: value === selected })}>${escapeHtml(value)}</option>`,
    )
    .join('');
}

/**
 * The `defenderRansomwareProtection` options: a blank one (key not set), then
 * audit and block. The option equal to `current` is selected; the blank one is
 * when nothing is stored.
 */
function ransomwareModeOptions(current) {
  const selected = typeof current === 'string' ? current : '';
  return ['', ...DEFENDER_RANSOMWARE_MODES]
    .map(
      (value) =>
        `<option value="${escapeHtml(value)}"${attributes({ selected: value === selected })}>${escapeHtml(value)}</option>`,
    )
    .join('');
}

/** The kebab-case element id suffix of a Defender key, e.g. `defender-cloud-protection`. */
function kebab(key) {
  return key.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`);
}

/**
 * The Defender protection inputs: one checkbox per boolean key, then the
 * ransomware mode select and its warning hint.
 */
function defenderFields(settings, errors, id) {
  return [
    ...DEFENDER_BOOLEAN_KEYS.flatMap((key) => [
      `<label for="${id(kebab(key))}">${key}</label>`,
      `<input id="${id(kebab(key))}" name="${key}" type="checkbox"${attributes({
        checked: settings[key] === true,
      })}>`,
    ]),
    `<label for="${id('defender-ransomware-protection')}">defenderRansomwareProtection</label>`,
    `<select id="${id('defender-ransomware-protection')}" name="defenderRansomwareProtection">${ransomwareModeOptions(
      settings.defenderRansomwareProtection,
    )}</select>`,
    `<p class="hint">Controlled folder access can block legitimate applications from writing to protected folders. Start with audit and review the blocked applications before choosing block.</p>`,
    errorFor(
      errors,
      'defenderRansomwareProtection',
      `defenderRansomwareProtection must be one of ${DEFENDER_RANSOMWARE_MODES.join(', ')}`,
    ),
  ];
}

/**
 * The sixteen settings inputs, shared by the create and edit forms. `prefix` is
 * put in front of every element id so the two forms never share one.
 */
function settingsFields(settings, errors, prefix) {
  const id = (name) => `${prefix}${name}`;
  return join([
    `<label for="${id('firewall-enabled')}">firewallEnabled</label>`,
    `<input id="${id('firewall-enabled')}" name="firewallEnabled" type="checkbox"${attributes({
      checked: settings.firewallEnabled === true,
    })}>`,
    `<label for="${id('disk-encryption-required')}">diskEncryptionRequired</label>`,
    `<input id="${id('disk-encryption-required')}" name="diskEncryptionRequired" type="checkbox"${attributes({
      checked: settings.diskEncryptionRequired === true,
    })}>`,
    `<label for="${id('antivirus-enabled')}">antivirusEnabled</label>`,
    `<input id="${id('antivirus-enabled')}" name="antivirusEnabled" type="checkbox"${attributes({
      checked: settings.antivirusEnabled === true,
    })}>`,
    `<label for="${id('antivirus-scan-frequency')}">antivirusScanFrequency</label>`,
    `<select id="${id('antivirus-scan-frequency')}" name="antivirusScanFrequency">${scanFrequencyOptions(
      settings.antivirusScanFrequency,
    )}</select>`,
    errorFor(
      errors,
      'antivirusScanFrequency',
      `antivirusScanFrequency must be one of ${ANTIVIRUS_SCAN_FREQUENCIES.join(', ')}`,
    ),
    `<label for="${id('location-tracking')}">locationTracking</label>`,
    `<input id="${id('location-tracking')}" name="locationTracking" type="checkbox"${attributes({
      checked: settings.locationTracking === true,
    })}>`,
    ...defenderFields(settings, errors, id),
    `<label for="${id('screen-lock')}">screenLockTimeoutSeconds</label>`,
    `<input id="${id('screen-lock')}" name="screenLockTimeoutSeconds" type="number" min="${SCREEN_LOCK_TIMEOUT_SECONDS.min}" max="${SCREEN_LOCK_TIMEOUT_SECONDS.max}" value="${escapeHtml(
      settings.screenLockTimeoutSeconds,
    )}">`,
    errorFor(
      errors,
      'screenLockTimeoutSeconds',
      `screenLockTimeoutSeconds must be between ${SCREEN_LOCK_TIMEOUT_SECONDS.min} and ${SCREEN_LOCK_TIMEOUT_SECONDS.max}`,
    ),
    `<label for="${id('os-update-age')}">osUpdateMaxAgeDays</label>`,
    `<input id="${id('os-update-age')}" name="osUpdateMaxAgeDays" type="number" min="${OS_UPDATE_MAX_AGE_DAYS.min}" max="${OS_UPDATE_MAX_AGE_DAYS.max}" value="${escapeHtml(
      settings.osUpdateMaxAgeDays,
    )}">`,
    errorFor(
      errors,
      'osUpdateMaxAgeDays',
      `osUpdateMaxAgeDays must be between ${OS_UPDATE_MAX_AGE_DAYS.min} and ${OS_UPDATE_MAX_AGE_DAYS.max}`,
    ),
    `<label for="${id('local-admins')}">localAdminAllowlist</label>`,
    `<textarea id="${id('local-admins')}" name="localAdminAllowlist">${escapeHtml(
      (settings.localAdminAllowlist ?? []).join('\n'),
    )}</textarea>`,
    `<label for="${id('firewall-blocked-domains')}">firewallBlockedDomains</label>`,
    `<textarea id="${id('firewall-blocked-domains')}" name="firewallBlockedDomains">${escapeHtml(
      (settings.firewallBlockedDomains ?? []).join('\n'),
    )}</textarea>`,
    errorFor(
      errors,
      'firewallBlockedDomains',
      `firewallBlockedDomains must hold at most ${DOMAIN_LIST_MAX_ENTRIES} domain names such as example.com`,
    ),
    `<label for="${id('firewall-allowed-domains')}">firewallAllowedDomains</label>`,
    `<textarea id="${id('firewall-allowed-domains')}" name="firewallAllowedDomains">${escapeHtml(
      (settings.firewallAllowedDomains ?? []).join('\n'),
    )}</textarea>`,
    errorFor(
      errors,
      'firewallAllowedDomains',
      `firewallAllowedDomains must hold at most ${DOMAIN_LIST_MAX_ENTRIES} domain names such as example.com`,
    ),
  ]);
}

/**
 * The edit panel for the policy being edited: `form.edit-policy`, then -- as a
 * sibling, never nested, since a browser drops a form inside a form --
 * `form.delete-policy`, whose Delete button stays disabled until the policy's
 * name is typed exactly.
 *
 * `editing` is the policy as stored; `draft` holds what was typed into the edit
 * form when the API refused it, so the form shows it again.
 */
function editPanel(editing, draft) {
  if (editing === null || editing === undefined || !editing.policyId) {
    return '';
  }
  const shown = draft ?? editing;
  const settings = settingsOf(shown);
  const errors = fieldErrors(shown);
  const policyId = escapeHtml(editing.policyId);
  const deletable = deleteRequest({ policyId: editing.policyId, name: editing.name, typedName: '' }) !== null;
  return join([
    `<div class="edit-panel" data-policy-id="${policyId}">`,
    `<h3>Edit policy ${cell(editing.name)}</h3>`,
    '<form class="edit-policy">',
    `<input type="hidden" name="policyId" value="${policyId}">`,
    '<label for="edit-policy-name">name</label>',
    `<input id="edit-policy-name" name="name" value="${escapeHtml(shown.name)}">`,
    settingsFields(settings, errors, 'edit-'),
    `<button type="submit" class="save"${attributes({ disabled: errors.length > 0 })}>Save policy</button>`,
    '</form>',
    '<form class="delete-policy">',
    `<input type="hidden" name="policyId" value="${policyId}">`,
    '<label for="delete-policy-name">Type the policy name to delete it</label>',
    '<input id="delete-policy-name" name="typedName" value="" autocomplete="off">',
    `<button type="submit" class="delete"${attributes({ disabled: !deletable })}>Delete policy</button>`,
    '</form>',
    '</div>',
  ]);
}

/** The path one policy lives at. */
export function policyPath(policyId) {
  return `/admin/api/v1/policies/${policyId}`;
}

/**
 * The update request, or `null` when there is no policy id, the name is blank
 * or a field is out of range. Settings are sent wholesale, as `PUT` replaces them.
 */
export function updateRequest(state = {}) {
  const policyId = typeof state.policyId === 'string' ? state.policyId : '';
  const name = typeof state.name === 'string' ? state.name.trim() : '';
  if (policyId.length === 0 || name.length === 0 || fieldErrors(state).length > 0) {
    return null;
  }
  return { method: 'PUT', path: policyPath(policyId), body: { name, settings: settingsOf(state) } };
}

/** Why `updateRequest` refused the state, as the banner says it, or `null`. */
export function updateRefusal(state = {}) {
  const reasons = refusalReasons(state);
  return reasons.length === 0 ? null : `Policy not updated: ${reasons.join('; ')}`;
}

/**
 * The delete request: only once the admin has typed the policy's name exactly,
 * the typed confirmation `src/ui/views/dispatch.js` uses for a hostname.
 */
export function deleteRequest(state = {}) {
  const name = typeof state.name === 'string' ? state.name : '';
  if (!state.policyId || state.typedName !== name) {
    return null;
  }
  return { method: 'DELETE', path: policyPath(state.policyId), body: { confirm: true } };
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
    // Policies created before the list index existed only appear once indexed.
    '<p><button type="button" class="reindex-policies">Find older policies</button></p>',
    editPanel(state.editing, state.editDraft),
    '<form class="create-policy">',
    '<label for="policy-name">name</label>',
    `<input id="policy-name" name="name" value="${escapeHtml(state.name)}">`,
    settingsFields(settings, errors, ''),
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
