/**
 * The admin console: sign-in, routing and the screens.
 *
 * Boot order is the whole design:
 *
 *   1. GET /admin/config.json           -- tenant, client, redirect, scope
 *   2. a redirect carrying ?code=       -- exchange it for an access token
 *   3. no token                         -- send the browser to Entra
 *   4. a token                          -- render the screen the hash names
 *
 * Everything that knows how a screen looks lives in `../views/`, as a pure
 * function of state, so the screens are tested without a browser. This module
 * is the only one that touches the DOM: it fetches, keeps the state, asks a
 * view for a string, and sets `innerHTML` on the mount element.
 *
 * It is served as `/assets/public/app.js`, so `../views/x.js` resolves to
 * `/assets/views/x.js` in the browser and to `src/ui/views/x.js` on disk --
 * the same import either way.
 */
import { clearToken, configureApi, del, get, getToken, post, put, request as apiRequest, setToken } from './api.js';
import { authorizeUrl, handleRedirect } from './auth.js';
import { createPkcePair, createState } from './pkce.js';
import * as analyticsView from '../views/analytics.js';
import * as applicationsView from '../views/applications.js';
import * as auditView from '../views/audit.js';
import * as commandsView from '../views/commands.js';
import * as deviceDetailView from '../views/deviceDetail.js';
import * as devicesView from '../views/devices.js';
import * as dispatchView from '../views/dispatch.js';
import * as enrollmentTokensView from '../views/enrollmentTokens.js';
import * as groupsView from '../views/groups.js';
import * as policiesView from '../views/policies.js';
import * as settingsView from '../views/settings.js';
import * as softwareView from '../views/software.js';

/** Where the PKCE values live for the length of one redirect. */
const STATE_KEY = 'skmdm.authState';
const VERIFIER_KEY = 'skmdm.codeVerifier';

/** The path the console is served at; the address bar returns here after sign-in. */
export const ADMIN_PAGE_PATH = '/admin';

/** Where the address bar points once the spent code is removed: the console, keeping the hash. */
export function signedInLocation(hash) {
  return `${ADMIN_PAGE_PATH}${hash}`;
}

/** The screens, in the order the navigation lists them. */
export const SCREENS = [
  { hash: '#/devices', label: 'Devices' },
  { hash: '#/analytics', label: 'Analytics' },
  { hash: '#/software', label: 'Software' },
  { hash: '#/applications', label: 'Applications' },
  { hash: '#/groups', label: 'Groups' },
  { hash: '#/enrollment-tokens', label: 'Enrollment tokens' },
  { hash: '#/policies', label: 'Policies' },
  { hash: '#/commands', label: 'Commands' },
  { hash: '#/audit', label: 'Audit' },
  { hash: '#/settings', label: 'Settings' },
];

/** Everything the screens render from. */
const state = {
  config: null,
  screen: 'devices',
  devices: { items: [], cursor: null, ownership: '' },
  detail: {},
  // The device page's section expanders the admin opened (TASK-062): kept out
  // of `detail` so a reload or Refresh keeps them; emptied on every hashchange.
  openSections: [],
  analytics: { days: 30 },
  software: { search: '', sort: 'name', offset: 0 },
  softwareDevices: {},
  applications: { items: [] },
  dispatch: {},
  groups: { items: [] },
  tokens: { items: [], maxUses: 1 },
  policies: { items: [], groups: [], settings: {} },
  commands: { items: [] },
  audit: { items: [], from: '', to: '' },
  settings: {},
  error: null,
};

/** The mount element the page ships with. */
function mount() {
  return document.getElementById('app');
}

/** Read the public client configuration the Lambda publishes. */
async function loadConfig() {
  const response = await fetch('/admin/config.json', { headers: { accept: 'application/json' } });
  if (!response.ok) {
    throw new Error('the admin console is not configured');
  }
  return await response.json();
}

/** Send the browser to Entra to sign in, keeping the PKCE values for the way back. */
export async function startAuthorization() {
  const config = state.config ?? (await loadConfig());
  const { verifier, challenge } = createPkcePair();
  const authState = createState();
  sessionStorage.setItem(STATE_KEY, authState);
  sessionStorage.setItem(VERIFIER_KEY, verifier);
  window.location.assign(
    authorizeUrl({
      tenantId: config.tenantId,
      clientId: config.clientId,
      redirectUri: config.redirectUri,
      scope: config.scope,
      state: authState,
      codeChallenge: challenge,
    }),
  );
}

/** Finish a redirect, if this load is one. Returns true when a token was obtained. */
async function completeAuthorization(config) {
  const params = new URLSearchParams(window.location.search);
  if (!params.has('code') && !params.has('error')) {
    return false;
  }
  const result = await handleRedirect({
    params,
    storedState: sessionStorage.getItem(STATE_KEY),
    storedVerifier: sessionStorage.getItem(VERIFIER_KEY),
    config,
  });
  sessionStorage.removeItem(STATE_KEY);
  sessionStorage.removeItem(VERIFIER_KEY);
  // The code is single-use and has been spent: take it out of the address bar.
  window.history.replaceState(null, '', signedInLocation(window.location.hash));
  if (!result.ok) {
    state.error = result.error;
    return false;
  }
  setToken(result.accessToken);
  return true;
}

/** The screen the hash names, and its parameter. */
export function routeOf(hash) {
  const parts = String(hash ?? '').replace(/^#\/?/, '').split('/');
  return { screen: parts[0] || 'devices', param: parts[1] ?? null };
}

/** A software title from the route parameter; the raw text when it is not valid percent-encoding. */
function softwareName(param) {
  try {
    return decodeURIComponent(param);
  } catch {
    return param;
  }
}

/** The most device list pages the Groups screen's lookup reads, however large the fleet. */
const MAX_FLEET_PAGES = 500;

/**
 * Every device as `{deviceId, hostname}`, paging `GET /devices?limit=200` until
 * the cursor is `null`. Any page that is not ok leaves the lookup with `[]`.
 */
async function loadFleet() {
  const devices = [];
  let cursor = null;
  for (let pages = 0; pages < MAX_FLEET_PAGES; pages += 1) {
    const page = await get('/devices', { limit: 200, cursor });
    if (!page?.ok) {
      return [];
    }
    for (const item of page.data?.items ?? []) {
      devices.push({ deviceId: item?.deviceId, hostname: item?.hostname ?? null });
    }
    const next = page.data?.cursor;
    if (next === null || next === undefined || next === '') {
      break;
    }
    cursor = next;
  }
  return devices;
}

/**
 * The device page's requests, shared by its load and its Refresh button (TASK-057).
 * Resolves to `{ ok, data, detail }`: the `GET /devices/{id}` response's `ok`
 * and `data`, and the page state built from them. Rejects when a request does.
 */
async function fetchDeviceDetail(param) {
  const response = await get(`/devices/${param}`);
  const data = response.data ?? {};
  // The Run a command panel offers only the library for the device's platform.
  const platform = data.profile?.platform;
  let scripts = [];
  if (platform === 'windows' || platform === 'darwin') {
    const library = await get('/scripts', { platform });
    scripts = library.data?.items ?? [];
  }
  // The Software panel's install form offers only the safe list for the device's platform (TASK-049).
  let applications = [];
  if (platform === 'windows' || platform === 'darwin') {
    const safeList = await get('/applications', { platform });
    applications = safeList?.data?.items ?? [];
  }
  // The Groups panel's add form offers every group the device is not in yet.
  const allGroups = await get('/groups');
  const detail = { ...data, scripts, applications, runCommand: {}, allGroups: allGroups.data?.items ?? [] };
  return { ok: response.ok, data: response.data, detail };
}

/** `state.detail` without the Refresh button's in-flight flag. */
function withoutRefreshing(detail) {
  const rest = { ...(detail ?? {}) };
  delete rest.refreshing;
  return rest;
}

/**
 * The device page's Refresh (TASK-057): fetch the page's stored data again and
 * repaint in place. Only the page load's GET requests; nothing reaches the device.
 * A failure keeps the page as it was and shows the banner. A result that arrives
 * after the operator left this device's page is thrown away.
 */
async function refreshDevice() {
  const { screen, param } = routeOf(window.location.hash);
  if (screen !== 'devices' || param === null) {
    return;
  }
  state.detail = { ...state.detail, refreshing: true };
  paint(screen, param);

  let result = null;
  let error = null;
  try {
    result = await fetchDeviceDetail(param);
    if (!result.ok) {
      error = result.data?.error ?? 'request_failed';
    }
  } catch {
    error = 'request_failed';
  }

  const now = routeOf(window.location.hash);
  if (now.screen !== 'devices' || now.param !== param) {
    return;
  }
  if (error === null) {
    state.detail = result.detail;
    state.error = null;
  } else {
    state.detail = withoutRefreshing(state.detail);
    state.error = error;
  }
  paint(screen, param);
}

/** Load whatever the named screen renders from. */
async function load(screen, param) {
  if (screen === 'devices' && param === null) {
    // The ownership filter is applied by the API; an empty one is not sent.
    const ownership = state.devices.ownership ?? '';
    const page = await get('/devices', { ownership });
    state.devices = { ...(page.data ?? { items: [], cursor: null }), ownership };
    return;
  }
  if (screen === 'devices') {
    const { detail } = await fetchDeviceDetail(param);
    state.detail = detail;
    return;
  }
  if (screen === 'dispatch') {
    const detail = await get(`/devices/${param}`);
    const profile = detail.data?.profile ?? {};
    state.dispatch = { deviceId: param, hostname: profile.hostname, type: 'lock', payload: {}, typedHostname: '' };
    return;
  }
  if (screen === 'analytics') {
    // The window is the picker's; the API answers with the four ranked lists.
    const days = state.analytics.days ?? 30;
    state.analytics = { days };
    const response = await get('/analytics', { days });
    if (!response.ok) {
      throw new Error(response.data?.error ?? 'request_failed');
    }
    state.analytics = { ...(response.data ?? {}), days };
    return;
  }
  if (screen === 'software' && param === null) {
    // The search, sort and page are the screen's; the API aggregates the titles.
    const { search = '', sort = 'name', offset = 0 } = state.software;
    state.software = { search, sort, offset };
    const response = await get('/software', { search, sort, offset });
    if (!response.ok) {
      throw new Error(response.data?.error ?? 'request_failed');
    }
    state.software = { ...(response.data ?? {}), search, sort, offset };
    return;
  }
  if (screen === 'software') {
    const name = softwareName(param);
    state.softwareDevices = { name };
    const response = await get('/software/devices', { name });
    if (!response.ok) {
      throw new Error(response.data?.error ?? 'request_failed');
    }
    state.softwareDevices = { ...(response.data ?? {}), name };
    return;
  }
  if (screen === 'groups') {
    // The library fills the queue-on-members form's command picker.
    // The whole fleet fills the membership form's device lookup.
    const [page, library, devices] = await Promise.all([get('/groups'), get('/scripts'), loadFleet()]);
    state.groups = { ...state.groups, items: page.data?.items ?? [], scripts: library.data?.items ?? [], devices };
    return;
  }
  if (screen === 'applications') {
    const response = await get('/applications');
    if (!response.ok) {
      throw new Error(response.data?.error ?? 'request_failed');
    }
    state.applications = { ...state.applications, items: response.data?.items ?? [] };
    return;
  }
  if (screen === 'commands') {
    const response = await get('/scripts');
    if (!response.ok) {
      throw new Error(response.data?.error ?? 'request_failed');
    }
    const items = response.data?.items ?? [];
    // The command being edited follows the reloaded list, or closes once gone.
    const editingId = state.commands.editing?.scriptId;
    const editing = editingId ? items.find((item) => item.scriptId === editingId) ?? null : null;
    state.commands = { ...state.commands, items, editing };
    return;
  }
  if (screen === 'enrollment-tokens') {
    // The freshly minted token lives only in `created` (the creation response),
    // so the reload after a create keeps it next to the reloaded list.
    const response = await get('/enrollment-tokens');
    if (!response.ok) {
      throw new Error(response.data?.error ?? 'request_failed');
    }
    state.tokens = { ...state.tokens, items: response.data?.items ?? [] };
    return;
  }
  if (screen === 'policies') {
    // The list is what the table and the assign form's policy picker render
    // from; the groups fill the assign form's group picker.
    const [policies, groups] = await Promise.all([get('/policies'), get('/groups')]);
    if (!policies.ok) {
      throw new Error(policies.data?.error ?? 'request_failed');
    }
    const items = policies.data?.items ?? [];
    // The policy being edited follows the reloaded list: its new version after
    // a save, or closed once it is no longer listed.
    const editingId = state.policies.editing?.policyId;
    const editing = editingId ? items.find((item) => item.policyId === editingId) ?? null : null;
    state.policies = { ...state.policies, items, groups: groups.data?.items ?? [], editing };
    return;
  }
  if (screen === 'audit') {
    const page = await get('/audit', { from: state.audit.from, to: state.audit.to });
    state.audit = { ...state.audit, items: page.data?.items ?? [] };
    return;
  }
  if (screen === 'settings') {
    // The console is served by the Lambda the agents report to, so the URL the
    // installers need is the one this page was loaded from.
    state.settings = { collectionUrl: `${window.location.origin}/` };
    // The fleet-wide "When a command fails" setting preselects its select.
    const commandSettings = await get('/settings/commands');
    state.settings = {
      ...state.settings,
      onFailure: commandSettings.data?.onFailure ?? 'continue',
    };
  }
}

/** The navigation bar, with the current screen marked. */
function navigation(current) {
  const links = SCREENS.map(
    (screen) =>
      `<a href="${screen.hash}"${screen.hash === `#/${current}` ? ' class="current"' : ''}>${screen.label}</a>`,
  ).join('');
  return `<nav>${links}</nav>`;
}

/** Ask the screen's view for its HTML. */
function screenHtml(screen, param) {
  if (screen === 'devices' && param !== null) {
    return deviceDetailView.render({ ...state.detail, deviceId: param, openSections: state.openSections });
  }
  if (screen === 'dispatch') {
    return dispatchView.render(state.dispatch);
  }
  if (screen === 'analytics') {
    // The requested window is passed through, so the picker shows the chosen
    // window even when the request failed.
    return analyticsView.render({ ...state.analytics, windowDays: state.analytics.days });
  }
  if (screen === 'software' && param !== null) {
    return softwareView.render({ ...state.softwareDevices, name: softwareName(param) });
  }
  if (screen === 'software') {
    return softwareView.render(state.software);
  }
  if (screen === 'groups') {
    return groupsView.render(state.groups);
  }
  if (screen === 'enrollment-tokens') {
    return enrollmentTokensView.render(state.tokens);
  }
  if (screen === 'policies') {
    return policiesView.render(state.policies);
  }
  if (screen === 'commands') {
    return commandsView.render(state.commands);
  }
  if (screen === 'applications') {
    return applicationsView.render(state.applications);
  }
  if (screen === 'audit') {
    return auditView.render(state.audit);
  }
  if (screen === 'settings') {
    return settingsView.render(state.settings);
  }
  return devicesView.render(state.devices);
}

/** Render the current screen into the mount element. */
export function paint(screen, param) {
  const banner = state.error === null ? '' : `<p class="error">${state.error}</p>`;
  mount().innerHTML = `${navigation(screen)}${banner}${screenHtml(screen, param)}`;
}

/**
 * Load and render whatever the address bar names.
 *
 * `error` is the banner to keep across the reload -- a refresh that failed
 * reloads the screen and must still say why. With no argument the banner is
 * cleared. A load failure overwrites it either way.
 */
export async function show({ error } = {}) {
  const { screen, param } = routeOf(window.location.hash);
  state.screen = screen;
  state.error = error ?? null;
  try {
    await load(screen, param);
  } catch (error) {
    state.error = error instanceof Error ? error.message : String(error);
  }
  paint(screen, param);
}

/** The value of a named form field, as a string. */
function fieldValue(form, name) {
  const field = form.elements.namedItem(name);
  if (field === null || field === undefined) {
    return '';
  }
  return field.type === 'checkbox' ? field.checked : field.value;
}

/** What the create-policy form holds, in the shape `policiesView` reads. */
function createPolicyState(form) {
  return {
    name: fieldValue(form, 'name'),
    settings: {
      firewallEnabled: fieldValue(form, 'firewallEnabled'),
      diskEncryptionRequired: fieldValue(form, 'diskEncryptionRequired'),
      screenLockTimeoutSeconds: fieldValue(form, 'screenLockTimeoutSeconds'),
      osUpdateMaxAgeDays: fieldValue(form, 'osUpdateMaxAgeDays'),
      localAdminAllowlist: fieldValue(form, 'localAdminAllowlist'),
      firewallBlockedDomains: fieldValue(form, 'firewallBlockedDomains'),
      firewallAllowedDomains: fieldValue(form, 'firewallAllowedDomains'),
      antivirusEnabled: fieldValue(form, 'antivirusEnabled'),
      antivirusScanFrequency: fieldValue(form, 'antivirusScanFrequency'),
      locationTracking: fieldValue(form, 'locationTracking'),
      defenderRealTimeProtection: fieldValue(form, 'defenderRealTimeProtection'),
      defenderCloudProtection: fieldValue(form, 'defenderCloudProtection'),
      defenderNetworkProtection: fieldValue(form, 'defenderNetworkProtection'),
      defenderRansomwareProtection: fieldValue(form, 'defenderRansomwareProtection'),
      defenderReputationProtection: fieldValue(form, 'defenderReputationProtection'),
      defenderDailySignatureUpdate: fieldValue(form, 'defenderDailySignatureUpdate'),
    },
  };
}

/**
 * Create a policy from the form, or say why not.
 *
 * A form the view refuses is never sent; what was typed is kept in
 * `state.policies` so the reload shows it again with each named field error,
 * and the banner says why. Typed values are also kept when the API refuses the
 * request, and cleared only once a policy has actually been created.
 */
async function createPolicy(form) {
  const typed = createPolicyState(form);
  const request = policiesView.createRequest(typed);
  if (request === null) {
    state.policies = { ...state.policies, name: typed.name, settings: typed.settings };
    state.error = policiesView.createRefusal(typed);
    return;
  }
  const response = await send(request);
  state.policies = response?.ok
    ? { ...state.policies, name: '', settings: {} }
    : { ...state.policies, name: typed.name, settings: typed.settings };
}

/**
 * Save the policy being edited from `form.edit-policy`, or say why not.
 *
 * What was typed is kept as the edit draft when the view or the API refuses it,
 * so the reload shows it again; a saved policy drops the draft and the form
 * shows the stored policy at its new version.
 */
async function updatePolicy(form) {
  const typed = { ...createPolicyState(form), policyId: state.policies.editing?.policyId ?? fieldValue(form, 'policyId') };
  const request = policiesView.updateRequest(typed);
  if (request === null) {
    state.policies = { ...state.policies, editDraft: { name: typed.name, settings: typed.settings } };
    state.error = policiesView.updateRefusal(typed) ?? 'request_failed';
    return;
  }
  const response = await send(request);
  state.policies = {
    ...state.policies,
    editDraft: response?.ok ? null : { name: typed.name, settings: typed.settings },
  };
}

/** The delete request for the policy being edited, from what `form.delete-policy` holds. */
function deletePolicyRequest(form) {
  const editing = state.policies.editing;
  return policiesView.deleteRequest({
    policyId: editing?.policyId ?? '',
    name: editing?.name ?? '',
    typedName: fieldValue(form, 'typedName'),
  });
}

/** What a command library form holds, in the shape `commandsView` reads. */
function scriptFormState(form) {
  return {
    name: fieldValue(form, 'name'),
    interpreter: fieldValue(form, 'interpreter'),
    timeoutSeconds: fieldValue(form, 'timeoutSeconds'),
    description: fieldValue(form, 'description'),
    script: fieldValue(form, 'script'),
  };
}

/** The banner for a library form the view refused. */
function scriptRefusal(typed) {
  return `Command not saved: ${commandsView.fieldErrors(typed).join(', ')}`;
}

/** Save a new library command from `form.create-script`; what was typed is kept until it is saved. */
async function createScript(form) {
  const typed = scriptFormState(form);
  const request = commandsView.createRequest(typed);
  if (request === null) {
    state.commands = { ...state.commands, ...typed };
    state.error = scriptRefusal(typed);
    return;
  }
  const response = await send(request);
  state.commands = response?.ok
    ? { ...state.commands, name: '', interpreter: undefined, timeoutSeconds: undefined, description: '', script: '' }
    : { ...state.commands, ...typed };
}

/** Save the library command being edited from `form.edit-script`. */
async function updateScript(form) {
  const typed = { ...scriptFormState(form), scriptId: state.commands.editing?.scriptId ?? fieldValue(form, 'scriptId') };
  const request = commandsView.updateRequest(typed);
  if (request === null) {
    state.commands = { ...state.commands, editDraft: typed };
    state.error = scriptRefusal(typed);
    return;
  }
  const response = await send(request);
  state.commands = { ...state.commands, editDraft: response?.ok ? null : typed };
}

/**
 * Generate a script with AI from the form holding `button` (TASK-053). The
 * script textarea is the request; on success only that textarea's text is
 * replaced, in the create draft or the edit draft. Nothing is saved or queued:
 * the admin reviews the script and clicks Save. While a generate is pending,
 * further clicks send nothing.
 */
async function generateScript(button) {
  if (button.disabled || state.commands.generating) {
    return;
  }
  const form = button.closest('form');
  if (form === null || form === undefined) {
    return;
  }
  const mode = form.classList.contains('edit-script') ? 'edit' : 'create';
  const scriptId = mode === 'edit' ? state.commands.editing?.scriptId ?? fieldValue(form, 'scriptId') : undefined;
  const keep = (fields) => {
    state.commands =
      mode === 'edit' ? { ...state.commands, editDraft: { ...fields, scriptId } } : { ...state.commands, ...fields };
  };
  const typed = scriptFormState(form);
  keep(typed);

  const { screen, param } = routeOf(window.location.hash);
  const request = commandsView.generateRequest(typed);
  if (request === null) {
    state.error = `Command not generated: ${commandsView.generateRefusals(typed).join(', ')}`;
    paint(screen, param);
    return;
  }

  state.error = null;
  state.commands = { ...state.commands, generating: mode };
  paint(screen, param);
  try {
    const response = await send(request);
    if (response?.ok) {
      if (typeof response.data?.script === 'string') {
        keep({ ...typed, script: response.data.script });
      } else {
        state.error = 'empty_result';
      }
    }
  } finally {
    state.commands = { ...state.commands, generating: null };
  }
  await show({ error: state.error });
}

/** The delete request for the library command being edited, from what `form.delete-script` holds. */
function deleteScriptRequest(form) {
  const editing = state.commands.editing;
  return commandsView.deleteRequest({
    scriptId: editing?.scriptId ?? '',
    name: editing?.name ?? '',
    typedName: fieldValue(form, 'typedName'),
  });
}

/** The queue request for `form.queue-script`, checked against the loaded device's hostname. */
function queueScriptRequest(form) {
  return deviceDetailView.queueRequest({
    deviceId: fieldValue(form, 'deviceId'),
    scriptId: fieldValue(form, 'scriptId'),
    hostname: state.detail?.profile?.hostname,
    typedHostname: fieldValue(form, 'typedHostname'),
  });
}

/** The queue-on-members request for `form.queue-group-script`, checked against the selected group's name. */
function queueGroupScriptRequest(form) {
  const groupId = fieldValue(form, 'groupId');
  return groupsView.queueScriptRequest({
    groupId,
    scriptId: fieldValue(form, 'scriptId'),
    name: groupsView.groupName(state.groups.items, groupId),
    typedName: fieldValue(form, 'typedName'),
  });
}

/** The delete request for `form.delete-group`, checked against the selected group's listed name. */
function deleteGroupRequest(form) {
  const groupId = fieldValue(form, 'groupId');
  return groupsView.deleteRequest({
    groupId,
    name: groupsView.groupName(state.groups.items, groupId),
    typedName: fieldValue(form, 'typedName'),
  });
}

/** The delete request for `form.delete-device`, checked against the loaded device's hostname. */
function deleteDeviceRequest(form) {
  const hostname = state.detail?.profile?.hostname;
  return deviceDetailView.deleteRequest({
    deviceId: fieldValue(form, 'deviceId'),
    hostname: typeof hostname === 'string' && hostname.length > 0 ? hostname : null,
    typedHostname: fieldValue(form, 'typedHostname'),
  });
}

/** Drop the delete-device popup's state (TASK-051), so the next render has no popup. */
function closeDeleteDialog() {
  if (state.detail !== null && typeof state.detail === 'object') {
    const detail = { ...state.detail };
    delete detail.deleteDialog;
    state.detail = detail;
  }
}

/** The hex SHA-256 of a file, computed in the browser with WebCrypto. */
async function sha256Hex(file) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', await file.arrayBuffer());
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Add an application from `form.create-application` (TASK-049).
 *
 * A URL source is one request, with no sha256: the server computes it
 * (TASK-050). An upload never passes through the backend: the
 * file is checked (`fileRefusal`), hashed, a presigned PUT URL is requested,
 * the file is PUT straight to S3 with plain `fetch` -- never api.js, so the
 * admin bearer is never sent to S3 -- and only after a successful PUT is the
 * application registered.
 */
async function createApplication(form) {
  const typed = {
    name: fieldValue(form, 'name'),
    description: fieldValue(form, 'description'),
    url: fieldValue(form, 'url'),
    installerType: fieldValue(form, 'installerType'),
    installArgs: fieldValue(form, 'installArgs'),
  };
  if (fieldValue(form, 'source') === 'url') {
    const request = applicationsView.createUrlRequest(typed);
    if (request === null) {
      state.error = 'invalid_request';
      return;
    }
    await send(request);
    return;
  }

  const file = form.elements.namedItem('file')?.files?.[0] ?? null;
  const refusal = applicationsView.fileRefusal({ name: file?.name, size: file?.size });
  if (refusal !== null) {
    state.error = refusal;
    return;
  }
  const sha256 = await sha256Hex(file);
  const upload = await send({
    method: 'POST',
    path: applicationsView.UPLOAD_URL_PATH,
    body: { fileName: file.name, sizeBytes: file.size },
  });
  if (!upload?.ok) {
    return;
  }
  let uploaded = false;
  try {
    const response = await fetch(upload.data?.url, {
      method: 'PUT',
      headers: { 'content-type': 'application/octet-stream' },
      body: file,
    });
    uploaded = response?.ok === true;
  } catch {
    uploaded = false;
  }
  if (!uploaded) {
    state.error = 'upload_failed';
    return;
  }
  await send(
    applicationsView.createUploadRequest({
      name: typed.name,
      description: typed.description,
      uploadKey: upload.data?.uploadKey,
      sha256,
      installArgs: typed.installArgs,
    }),
  );
}

/**
 * After an add or edit from the application popup: success closes it; a
 * failure keeps it open with the error shown inside it rather than as the
 * page banner, so the typed values are not lost behind a banner.
 */
function settleApplicationDialog() {
  const dialog = state.applications.dialog;
  if (state.error === null) {
    state.applications = { ...state.applications, dialog: null };
    return;
  }
  state.applications = { ...state.applications, dialog: { ...dialog, open: true, error: state.error } };
  state.error = null;
}

/** Open the application popup (`{mode: 'create'}` or `{mode: 'edit', applicationId}`) and focus its name. */
function openApplicationDialog(dialog) {
  state.applications = { ...state.applications, dialog: { open: true, error: null, ...dialog } };
  const { screen, param } = routeOf(window.location.hash);
  paint(screen, param);
  document.getElementById('application-name')?.focus?.();
}

/** Close the application popup with no request. */
function closeApplicationDialog() {
  state.applications = { ...state.applications, dialog: null };
  const { screen, param } = routeOf(window.location.hash);
  paint(screen, param);
}

/** The install request for `form.install-application`. */
function installApplicationRequest(form) {
  return deviceDetailView.installRequest({
    deviceId: fieldValue(form, 'deviceId'),
    applicationId: fieldValue(form, 'applicationId'),
  });
}

/** The api.js call for each method a view may produce. */
const SENDERS = { POST: post, PUT: put, DELETE: del };

/**
 * Send a request a view produced. A refused request leaves its error in
 * `state.error`, which the caller carries across the reload with
 * `show({ error: state.error })`.
 */
async function send(request) {
  if (request === null) {
    return null;
  }
  const sender = SENDERS[request.method];
  const response =
    sender === undefined
      ? await apiRequest(request.path, { method: request.method, body: request.body })
      : await sender(request.path, request.body);
  if (!response.ok) {
    state.error = response.data?.error ?? 'request_failed';
  }
  return response;
}

/**
 * Form submissions, one branch per form the screens render.
 *
 * The banner starts clear, so a successful submit removes an old one; a branch
 * that fails sets `state.error`, and that error is handed to `show` so the
 * reload keeps it on screen instead of wiping it.
 */
async function onSubmit(event) {
  const form = event.target;
  event.preventDefault();
  state.error = null;

  if (form.classList.contains('create-group')) {
    await send(groupsView.createRequest({ name: fieldValue(form, 'name') }));
  } else if (form.classList.contains('add-members')) {
    // The pending list is sent in list order; it is cleared only once accepted.
    const memberGroupId = fieldValue(form, 'groupId');
    const response = await send(
      groupsView.membershipRequest({ groupId: memberGroupId, deviceIds: groupsView.pendingIds(state.groups.pending) }),
    );
    state.groups = {
      ...state.groups,
      memberGroupId,
      added: response?.data?.added,
      pending: response?.ok ? [] : state.groups.pending,
    };
  } else if (form.classList.contains('add-device-group')) {
    await send(
      deviceDetailView.addGroupRequest({ deviceId: fieldValue(form, 'deviceId'), groupId: fieldValue(form, 'groupId') }),
    );
  } else if (form.classList.contains('auto-assign-group')) {
    await send(groupsView.autoAssignRequest({ groupId: fieldValue(form, 'groupId'), ownership: fieldValue(form, 'ownership') }));
  } else if (form.classList.contains('rename-group')) {
    await send(groupsView.renameRequest({ groupId: fieldValue(form, 'groupId'), name: fieldValue(form, 'name') }));
  } else if (form.classList.contains('delete-group')) {
    await send(deleteGroupRequest(form));
  } else if (form.classList.contains('create-token')) {
    const response = await send(
      enrollmentTokensView.createRequest({
        label: fieldValue(form, 'label'),
        maxUses: Number(fieldValue(form, 'maxUses')),
        expiresAt: fieldValue(form, 'expiresAt'),
      }),
    );
    state.tokens = { ...state.tokens, created: response?.data ?? null };
  } else if (form.classList.contains('create-policy')) {
    await createPolicy(form);
  } else if (form.classList.contains('edit-policy')) {
    await updatePolicy(form);
  } else if (form.classList.contains('delete-policy')) {
    const response = await send(deletePolicyRequest(form));
    if (response?.ok) {
      state.policies = { ...state.policies, editing: null, editDraft: null };
    }
  } else if (form.classList.contains('assign-policy')) {
    await send(
      policiesView.assignRequest({ policyId: fieldValue(form, 'policyId'), groupId: fieldValue(form, 'groupId') }),
    );
  } else if (form.classList.contains('software-search')) {
    // A new search starts again from the first page.
    state.software = { ...state.software, search: fieldValue(form, 'search'), offset: 0 };
  } else if (form.classList.contains('audit-range')) {
    state.audit = { ...state.audit, from: fieldValue(form, 'from'), to: fieldValue(form, 'to') };
  } else if (form.classList.contains('dispatch')) {
    await send(dispatchView.requestFor(state.dispatch));
  } else if (form.classList.contains('edit-device')) {
    await send(
      deviceDetailView.updateRequest({ deviceId: fieldValue(form, 'deviceId'), ownership: fieldValue(form, 'ownership') }),
    );
  } else if (form.classList.contains('delete-device')) {
    // The confirmation popup (TASK-051): only a 2xx leaves it, for the fleet.
    // Anything else keeps it open with the typed text, and a failure is shown
    // inside it rather than as the page banner.
    const typedHostname = fieldValue(form, 'typedHostname');
    const request = deleteDeviceRequest(form);
    if (request === null) {
      // Not the device name: nothing is sent and the popup stays as it is.
      state.detail = {
        ...state.detail,
        deleteDialog: { open: true, error: null, ...state.detail?.deleteDialog, typedHostname },
      };
      return;
    }
    let error = null;
    try {
      const response = await send(request);
      if (!response?.ok) {
        error = response?.data?.error ?? 'request_failed';
      }
    } catch {
      error = 'request_failed';
    }
    if (error !== null) {
      state.error = null;
      state.detail = { ...state.detail, deleteDialog: { open: true, typedHostname, error } };
      const { screen, param } = routeOf(window.location.hash);
      paint(screen, param);
      return;
    }
    // The device is gone: back to the fleet, which the reload below shows.
    closeDeleteDialog();
    window.location.hash = '#/devices';
  } else if (form.classList.contains('create-script')) {
    await createScript(form);
  } else if (form.classList.contains('edit-script')) {
    await updateScript(form);
  } else if (form.classList.contains('delete-script')) {
    const response = await send(deleteScriptRequest(form));
    if (response?.ok) {
      state.commands = { ...state.commands, editing: null, editDraft: null };
    }
  } else if (form.classList.contains('create-application')) {
    await createApplication(form);
    settleApplicationDialog();
  } else if (form.classList.contains('edit-application-form')) {
    const applicationId = fieldValue(form, 'applicationId');
    const existing = (state.applications.items ?? []).find((item) => item.applicationId === applicationId) ?? {};
    const request = applicationsView.updateRequest(
      {
        name: fieldValue(form, 'name'),
        description: fieldValue(form, 'description'),
        url: fieldValue(form, 'url'),
        installerType: fieldValue(form, 'installerType'),
        installArgs: fieldValue(form, 'installArgs'),
      },
      existing,
    );
    if (request === null) {
      state.error = 'invalid_request';
    } else {
      await send(request);
    }
    settleApplicationDialog();
  } else if (form.classList.contains('install-application')) {
    await send(installApplicationRequest(form));
  } else if (form.classList.contains('queue-script')) {
    await send(queueScriptRequest(form));
  } else if (form.classList.contains('queue-group-script')) {
    const response = await send(queueGroupScriptRequest(form));
    state.groups = { ...state.groups, queued: response?.ok ? response.data : null };
  } else if (form.classList.contains('command-settings')) {
    await send(settingsView.commandSettingsRequest({ onFailure: fieldValue(form, 'onFailure') }));
  }

  await show({ error: state.error });
}

/** Clicks the screens care about: rows, copy buttons and the one `DELETE`. */
async function onClick(event) {
  const copy = event.target.closest('.copy');
  if (copy !== null) {
    const field = document.getElementById(copy.dataset.copyTarget);
    await navigator.clipboard.writeText(field.value);
    return;
  }

  // The Profile panel's Refresh re-fetches the page's data (TASK-057). Ignored
  // while the delete popup is open or while a refresh is already in flight.
  const refreshDeviceButton = event.target.closest('.refresh-device');
  if (refreshDeviceButton !== null) {
    if (state.detail?.deleteDialog?.open === true || state.detail?.refreshing === true) {
      return;
    }
    await refreshDevice();
    return;
  }

  // The Profile panel's Delete device opens the confirmation popup (TASK-051),
  // empty and with no error, and puts the focus in its name field. No request.
  const openDeleteDevice = event.target.closest('.open-delete-device');
  if (openDeleteDevice !== null) {
    state.detail = { ...state.detail, deleteDialog: { open: true, typedHostname: '', error: null } };
    const { screen, param } = routeOf(window.location.hash);
    paint(screen, param);
    const input = document.getElementById('delete-device-hostname');
    if (input !== null && input !== undefined && typeof input.focus === 'function') {
      input.focus();
    }
    return;
  }

  // The popup's Cancel closes it with no request.
  const cancelDeleteDevice = event.target.closest('.cancel-delete-device');
  if (cancelDeleteDevice !== null) {
    closeDeleteDialog();
    const { screen, param } = routeOf(window.location.hash);
    paint(screen, param);
    return;
  }

  // The Applications screen's popup: Add opens it empty, Edit pre-filled;
  // Cancel, or a click on the dimmed backdrop itself, closes it with no request.
  if (event.target.closest('.open-create-application') !== null) {
    openApplicationDialog({ mode: 'create' });
    return;
  }
  const editApplication = event.target.closest('.edit-application');
  if (editApplication !== null) {
    openApplicationDialog({ mode: 'edit', applicationId: editApplication.dataset.applicationId });
    return;
  }
  if (
    event.target.closest('.cancel-application-dialog') !== null ||
    event.target.classList?.contains?.('application-dialog-backdrop') === true
  ) {
    closeApplicationDialog();
    return;
  }

  // Any other click inside the popup or on its dimmed backdrop leaves it as it is.
  if (event.target.closest('.modal-backdrop') !== null) {
    return;
  }

  const unassign = event.target.closest('.unassign');
  if (unassign !== null) {
    const form = unassign.closest('form');
    state.error = null;
    await send(
      policiesView.unassignRequest({ policyId: fieldValue(form, 'policyId'), groupId: fieldValue(form, 'groupId') }),
    );
    await show({ error: state.error });
    return;
  }

  const removeMembers = event.target.closest('.remove-members');
  if (removeMembers !== null) {
    const form = removeMembers.closest('form');
    state.error = null;
    const memberGroupId = fieldValue(form, 'groupId');
    const response = await send(
      groupsView.removeMembersRequest({ groupId: memberGroupId, deviceIds: groupsView.pendingIds(state.groups.pending) }),
    );
    state.groups = {
      ...state.groups,
      memberGroupId,
      removed: response?.data?.removed,
      pending: response?.ok ? [] : state.groups.pending,
    };
    await show({ error: state.error });
    return;
  }

  // The lookup list's ×: drops that one device, with no request.
  const removePending = event.target.closest('.remove-pending');
  if (removePending !== null) {
    state.groups = {
      ...state.groups,
      pending: groupsView.removePending(state.groups.pending, removePending.dataset.deviceId),
    };
    const { screen, param } = routeOf(window.location.hash);
    paint(screen, param);
    return;
  }

  // The device page's Groups panel: remove this device from one group.
  const removeDeviceGroup = event.target.closest('.remove-device-group');
  if (removeDeviceGroup !== null) {
    state.error = null;
    await send(
      deviceDetailView.removeGroupRequest({
        deviceId: removeDeviceGroup.dataset.deviceId,
        groupId: removeDeviceGroup.dataset.groupId,
      }),
    );
    await show({ error: state.error });
    return;
  }

  const reindex = event.target.closest('.reindex-policies');
  if (reindex !== null) {
    const response = await post('/policies/reindex', {});
    await (response.ok ? show() : show({ error: response.data?.error ?? 'request_failed' }));
    return;
  }

  // The analytics panel's switch: the button carries the state to set.
  const analyticsToggle = event.target.closest('.analytics-collection-toggle');
  if (analyticsToggle !== null) {
    const response = await post(`/devices/${analyticsToggle.dataset.deviceId}/analytics-collection`, {
      enabled: analyticsToggle.dataset.enabled === 'true',
    });
    await (response.ok ? show() : show({ error: response.data?.error ?? 'request_failed' }));
    return;
  }

  // The heartbeat switch (TASK-044): the toggle carries the state to set; Save
  // keeps it on at the frequency the select now holds.
  const heartbeatToggle = event.target.closest('.heartbeat-toggle');
  const heartbeatSave = heartbeatToggle === null ? event.target.closest('.heartbeat-save') : null;
  const heartbeatButton = heartbeatToggle ?? heartbeatSave;
  if (heartbeatButton !== null) {
    const form = heartbeatButton.closest('form');
    const enabled = heartbeatSave !== null ? true : heartbeatToggle.dataset.enabled === 'true';
    const response = await post(`/devices/${fieldValue(form, 'deviceId')}/heartbeat`, {
      enabled,
      intervalSeconds: Number(fieldValue(form, 'intervalSeconds')),
    });
    await (response.ok ? show() : show({ error: response.data?.error ?? 'request_failed' }));
    return;
  }

  // The "Analytics history" expander: fetched on expand, closed without a request.
  const historySummary = event.target.closest('.heartbeat-history summary');
  if (historySummary !== null) {
    event.preventDefault();
    // The summary repeats the expander's device id, so no second lookup is needed.
    const deviceId =
      historySummary.dataset?.deviceId ?? event.target.closest('.heartbeat-history')?.dataset?.deviceId ?? '';
    const { screen, param } = routeOf(window.location.hash);
    if (state.detail?.heartbeatHistory?.open === true) {
      state.detail = { ...state.detail, heartbeatHistory: undefined };
      paint(screen, param);
      return;
    }
    const response = await get(`/devices/${deviceId}/heartbeats`);
    state.detail = {
      ...state.detail,
      heartbeatHistory: response.ok
        ? { open: true, items: Array.isArray(response.data?.items) ? response.data.items : [] }
        : { open: true, error: response.data?.error ?? 'request_failed' },
    };
    paint(screen, param);
    return;
  }

  // A device section expander's summary (TASK-062): record the toggle so the
  // next repaint keeps it, and let the browser open or close it natively -- no
  // preventDefault, no request, no repaint (typed form input survives). `open`
  // still holds the pre-toggle value here: the native toggle runs after click
  // dispatch. Nested summaries (Software list, output) have another parent.
  const sectionSummary = event.target.closest('summary');
  const sectionDetails = sectionSummary?.parentElement ?? null;
  if (
    sectionDetails !== null &&
    typeof sectionDetails.matches === 'function' &&
    sectionDetails.matches('details.device-section')
  ) {
    const sectionId = sectionDetails.dataset.section;
    const others = state.openSections.filter((id) => id !== sectionId);
    state.openSections = sectionDetails.open === true ? others : [...others, sectionId];
    return;
  }

  // Revoke one enrollment token: one click, no confirmation; permanent.
  const revokeToken = event.target.closest('.revoke-token');
  if (revokeToken !== null) {
    const response = await post(`/enrollment-tokens/${revokeToken.dataset.tokenId}/revoke`, {});
    await (response.ok ? show() : show({ error: response.data?.error ?? 'request_failed' }));
    return;
  }

  // The device credential panel's switch: disable or re-enable the device.
  const disableDevice = event.target.closest('.disable-device');
  if (disableDevice !== null) {
    const response = await post(`/devices/${disableDevice.dataset.deviceId}/disable`, {});
    await (response.ok ? show() : show({ error: response.data?.error ?? 'request_failed' }));
    return;
  }
  const enableDevice = event.target.closest('.enable-device');
  if (enableDevice !== null) {
    const response = await post(`/devices/${enableDevice.dataset.deviceId}/enable`, {});
    await (response.ok ? show() : show({ error: response.data?.error ?? 'request_failed' }));
    return;
  }

  // The Applications screen's Delete: one click, then the list reloads (TASK-049).
  const deleteApplication = event.target.closest('.delete-application');
  if (deleteApplication !== null) {
    state.error = null;
    await send(applicationsView.deleteRequest({ applicationId: deleteApplication.dataset.applicationId }));
    await show({ error: state.error });
    return;
  }

  // The Applications screen's Retry on a URL source's hash, then the list reloads (TASK-050).
  const retryApplicationHash = event.target.closest('.retry-application-hash');
  if (retryApplicationHash !== null) {
    state.error = null;
    await send(applicationsView.retryHashRequest({ applicationId: retryApplicationHash.dataset.applicationId }));
    await show({ error: state.error });
    return;
  }

  // A queued command's up, down and Cancel buttons; disabled on leased rows.
  const moveCommand = event.target.closest('.move-command');
  const cancelCommand = event.target.closest('.cancel-command');
  if (moveCommand !== null || cancelCommand !== null) {
    const button = moveCommand ?? cancelCommand;
    if (button.disabled) {
      return;
    }
    state.error = null;
    const target = { deviceId: button.dataset.deviceId, commandId: button.dataset.commandId };
    await send(
      moveCommand !== null
        ? deviceDetailView.moveRequest({ ...target, direction: button.dataset.direction })
        : deviceDetailView.cancelRequest(target),
    );
    await show({ error: state.error });
    return;
  }

  // A command form's Generate: the script textarea becomes the AI's script; nothing is saved (TASK-053).
  const generateButton = event.target.closest('.generate-script');
  if (generateButton !== null) {
    await generateScript(generateButton);
    return;
  }

  // A library row opens the edit form, prefilled with the command as listed.
  const scriptRow = event.target.closest('tr.script');
  if (scriptRow !== null) {
    const scriptId = scriptRow.dataset.scriptId;
    const item = (state.commands.items ?? []).find((script) => script.scriptId === scriptId);
    state.commands = { ...state.commands, editing: item ? { ...item } : { scriptId }, editDraft: null };
    const { screen, param } = routeOf(window.location.hash);
    paint(screen, param);
    return;
  }

  // A policy row opens the edit panel, prefilled with the policy as listed.
  const policyRow = event.target.closest('tr.policy');
  if (policyRow !== null) {
    const policyId = policyRow.dataset.policyId;
    const item = (state.policies.items ?? []).find((policy) => policy.policyId === policyId);
    state.policies = { ...state.policies, editing: item ? { ...item } : { policyId }, editDraft: null };
    const { screen, param } = routeOf(window.location.hash);
    paint(screen, param);
    return;
  }

  // A software title opens the devices that have it.
  const softwareTitle = event.target.closest('tr.software-title');
  if (softwareTitle !== null) {
    window.location.hash = `#/software/${encodeURIComponent(softwareTitle.dataset.name)}`;
    return;
  }

  // The software list's pager moves one page through the titles.
  const softwareNext = event.target.closest('.software-next');
  const softwarePrev = event.target.closest('.software-prev');
  if (softwareNext !== null || softwarePrev !== null) {
    const limit = state.software.limit ?? 50;
    const offset = state.software.offset ?? 0;
    state.software = {
      ...state.software,
      offset: softwareNext !== null ? offset + limit : Math.max(0, offset - limit),
    };
    await show();
    return;
  }

  const device = event.target.closest('tr.device');
  if (device !== null) {
    window.location.hash = `#/devices/${device.dataset.deviceId}`;
  }
}

/** Keep the dispatch screen's state in step with its form as it is typed. */
function onInput(event) {
  // The device list's ownership filter reloads the list through the API.
  if (event.type === 'change' && event.target?.classList?.contains('ownership-filter')) {
    state.devices = { ...state.devices, ownership: event.target.value };
    void show();
    return;
  }
  // The analytics window picker reloads the screen with the chosen window.
  if (event.type === 'change' && event.target?.classList?.contains('analytics-window')) {
    state.analytics = { ...state.analytics, days: Number(event.target.value) };
    void show();
    return;
  }
  // The software sort reloads the title list from its first page.
  if (event.type === 'change' && event.target?.classList?.contains('software-sort')) {
    state.software = { ...state.software, sort: event.target.value, offset: 0 };
    void show();
    return;
  }
  // The membership form's group and lookup text are remembered without a
  // repaint, so the pending list and the typed text survive a group change and
  // the next repaint shows both again.
  if (event.target?.id === 'member-group') {
    state.groups = { ...state.groups, memberGroupId: event.target.value };
    return;
  }
  if (event.target?.id === 'member-lookup') {
    state.groups = { ...state.groups, lookup: event.target.value };
    return;
  }
  // The create-policy button is disabled while a field is out of range; it is
  // re-checked as the form is typed in, without a repaint that would take the
  // focus away, so correcting a kept value makes the form submittable again.
  const createPolicyForm = event.target?.closest?.('form.create-policy') ?? null;
  if (createPolicyForm !== null) {
    const button = createPolicyForm.querySelector('button.create');
    if (button !== null && button !== undefined) {
      button.disabled = policiesView.fieldErrors(createPolicyState(createPolicyForm)).length > 0;
    }
    return;
  }
  // The Delete button is enabled only once the policy's name is typed exactly,
  // re-checked as it is typed without a repaint.
  const deletePolicyForm = event.target?.closest?.('form.delete-policy') ?? null;
  if (deletePolicyForm !== null) {
    const button = deletePolicyForm.querySelector('button.delete');
    if (button !== null && button !== undefined) {
      button.disabled = deletePolicyRequest(deletePolicyForm) === null;
    }
    return;
  }
  // The same for a group: re-checked as the name is typed and as the group
  // picker changes, against the selected group's listed name.
  const deleteGroupForm = event.target?.closest?.('form.delete-group') ?? null;
  if (deleteGroupForm !== null) {
    const button = deleteGroupForm.querySelector('button.delete');
    if (button !== null && button !== undefined) {
      button.disabled = deleteGroupRequest(deleteGroupForm) === null;
    }
    return;
  }
  // The same for a device: enabled only once its hostname (or, with none, its
  // id) is typed exactly, re-checked as it is typed without a repaint. The
  // typed text is kept in the popup's state for its next repaint (TASK-051).
  const deleteDeviceForm = event.target?.closest?.('form.delete-device') ?? null;
  if (deleteDeviceForm !== null) {
    const button = deleteDeviceForm.querySelector('button.delete');
    if (button !== null && button !== undefined) {
      button.disabled = deleteDeviceRequest(deleteDeviceForm) === null;
    }
    state.detail = {
      ...state.detail,
      deleteDialog: {
        open: true,
        error: null,
        ...state.detail?.deleteDialog,
        typedHostname: fieldValue(deleteDeviceForm, 'typedHostname'),
      },
    };
    return;
  }
  // The library Delete button: enabled only once the command's name is typed exactly.
  const deleteScriptForm = event.target?.closest?.('form.delete-script') ?? null;
  if (deleteScriptForm !== null) {
    const button = deleteScriptForm.querySelector('button.delete');
    if (button !== null && button !== undefined) {
      button.disabled = deleteScriptRequest(deleteScriptForm) === null;
    }
    return;
  }
  // The Run a command Queue button: a script chosen and the hostname typed exactly.
  const queueScriptForm = event.target?.closest?.('form.queue-script') ?? null;
  if (queueScriptForm !== null) {
    const button = queueScriptForm.querySelector('button.queue');
    if (button !== null && button !== undefined) {
      button.disabled = queueScriptRequest(queueScriptForm) === null;
    }
    return;
  }
  // The Software panel's Install button: enabled once an application is chosen (TASK-049).
  const installApplicationForm = event.target?.closest?.('form.install-application') ?? null;
  if (installApplicationForm !== null) {
    const button = installApplicationForm.querySelector('button.install');
    if (button !== null && button !== undefined) {
      button.disabled = installApplicationRequest(installApplicationForm) === null;
    }
    return;
  }
  // The queue-on-members button: a group and a script chosen and the group's name typed exactly.
  const queueGroupForm = event.target?.closest?.('form.queue-group-script') ?? null;
  if (queueGroupForm !== null) {
    const button = queueGroupForm.querySelector('button.queue');
    if (button !== null && button !== undefined) {
      button.disabled = queueGroupScriptRequest(queueGroupForm) === null;
    }
    return;
  }
  if (state.screen !== 'dispatch') {
    return;
  }
  const { name, value } = event.target;
  if (name === 'type') {
    state.dispatch = { ...state.dispatch, type: value, payload: {} };
  } else if (name === 'typedHostname') {
    state.dispatch = { ...state.dispatch, typedHostname: value };
  } else if (name.startsWith('payload.')) {
    state.dispatch = { ...state.dispatch, payload: { ...state.dispatch.payload, [name.slice(8)]: value } };
  } else {
    return;
  }
  paint('dispatch', state.dispatch.deviceId);
}

/**
 * Enter in the Groups screen's device lookup adds the matching device to the
 * pending list. It never submits the form and never sends a request: the view
 * is repainted from `state.groups` and the focus put back in the lookup.
 */
function onKeyDown(event) {
  // Escape closes the delete-device popup as Cancel does (TASK-051); with no
  // popup open it does nothing.
  if (event.key === 'Escape') {
    if (state.detail?.deleteDialog?.open === true) {
      closeDeleteDialog();
      const { screen, param } = routeOf(window.location.hash);
      paint(screen, param);
    } else if (state.applications?.dialog?.open === true) {
      closeApplicationDialog();
    }
    return;
  }
  if (event.key !== 'Enter' || !event.target?.classList?.contains('device-lookup')) {
    return;
  }
  event.preventDefault();
  const form = event.target.closest?.('form') ?? null;
  const memberGroupId = form?.elements?.namedItem ? fieldValue(form, 'groupId') : state.groups.memberGroupId;
  const outcome = groupsView.addPending(
    { devices: state.groups.devices ?? [], pending: state.groups.pending ?? [] },
    typeof event.target.value === 'string' ? event.target.value : '',
  );
  state.groups = { ...state.groups, ...outcome, memberGroupId };
  const { screen, param } = routeOf(window.location.hash);
  paint(screen, param);
  document.getElementById('member-lookup')?.focus?.();
}

/** Boot the console. */
export async function start() {
  configureApi({ startAuthorization });
  state.config = await loadConfig();
  await completeAuthorization(state.config);

  if (getToken() === null) {
    await startAuthorization();
    return;
  }

  window.addEventListener('hashchange', () => {
    // Arriving at a device page (fresh or by going back) shows every section closed (TASK-062).
    state.openSections = [];
    void show();
  });
  mount().addEventListener('submit', (event) => {
    void onSubmit(event);
  });
  mount().addEventListener('click', (event) => {
    void onClick(event);
  });
  mount().addEventListener('input', onInput);
  mount().addEventListener('change', onInput);
  mount().addEventListener('keydown', onKeyDown);

  await show();
}

/** `clearToken` is re-exported so a sign-out button is one import away. */
export { clearToken };

if (typeof document !== 'undefined') {
  void start();
}
