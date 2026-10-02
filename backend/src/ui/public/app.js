/**
 * The admin console: sign-in, routing and the eight screens.
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
import { clearToken, configureApi, del, get, getToken, post, setToken } from './api.js';
import { authorizeUrl, handleRedirect } from './auth.js';
import { createPkcePair, createState } from './pkce.js';
import * as auditView from '../views/audit.js';
import * as deviceDetailView from '../views/deviceDetail.js';
import * as devicesView from '../views/devices.js';
import * as dispatchView from '../views/dispatch.js';
import * as enrollmentTokensView from '../views/enrollmentTokens.js';
import * as groupsView from '../views/groups.js';
import * as policiesView from '../views/policies.js';
import * as settingsView from '../views/settings.js';

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
  { hash: '#/groups', label: 'Groups' },
  { hash: '#/enrollment-tokens', label: 'Enrollment tokens' },
  { hash: '#/policies', label: 'Policies' },
  { hash: '#/audit', label: 'Audit' },
  { hash: '#/settings', label: 'Settings' },
];

/** Everything the screens render from. */
const state = {
  config: null,
  screen: 'devices',
  devices: { items: [], cursor: null },
  detail: {},
  dispatch: {},
  groups: { items: [] },
  tokens: { items: [], maxUses: 1 },
  policies: { items: [], groups: [], settings: {} },
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

/** Load whatever the named screen renders from. */
async function load(screen, param) {
  if (screen === 'devices' && param === null) {
    const page = await get('/devices');
    state.devices = page.data ?? { items: [], cursor: null };
    return;
  }
  if (screen === 'devices') {
    const detail = await get(`/devices/${param}`);
    state.detail = detail.data ?? {};
    return;
  }
  if (screen === 'dispatch') {
    const detail = await get(`/devices/${param}`);
    const profile = detail.data?.profile ?? {};
    state.dispatch = { deviceId: param, hostname: profile.hostname, type: 'lock', payload: {}, typedHostname: '' };
    return;
  }
  if (screen === 'groups') {
    const page = await get('/groups');
    state.groups = { ...state.groups, items: page.data?.items ?? [] };
    return;
  }
  if (screen === 'policies') {
    const page = await get('/groups');
    state.policies = { ...state.policies, groups: page.data?.items ?? [] };
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
    return deviceDetailView.render({ ...state.detail, deviceId: param });
  }
  if (screen === 'dispatch') {
    return dispatchView.render(state.dispatch);
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

/** The most bulk refresh requests one click sends, however many pages the fleet has. */
export const MAX_REFRESH_CALLS = 100;

/**
 * Refresh every device's user link, one fleet page per request, following the
 * cursor until the last page. Stops at the first failure.
 */
export async function refreshAllUserLinks(postFn) {
  let cursor = null;
  let calls = 0;
  while (calls < MAX_REFRESH_CALLS) {
    const response = await postFn('/user-links/refresh', { cursor });
    calls += 1;
    if (!response?.ok) {
      return { ok: false, error: response?.data?.error ?? 'request_failed' };
    }
    const next = response.data?.cursor;
    if (next === null || next === undefined || next === '') {
      break;
    }
    cursor = next;
  }
  return { ok: true, calls };
}

/** The value of a named form field, as a string. */
function fieldValue(form, name) {
  const field = form.elements.namedItem(name);
  if (field === null || field === undefined) {
    return '';
  }
  return field.type === 'checkbox' ? field.checked : field.value;
}

/** Send a request a view produced, then reload the screen. */
async function send(request) {
  if (request === null) {
    return null;
  }
  const response =
    request.method === 'POST' ? await post(request.path, request.body) : await del(request.path, request.body);
  if (!response.ok) {
    state.error = response.data?.error ?? 'request_failed';
  }
  return response;
}

/** Form submissions, one branch per form the screens render. */
async function onSubmit(event) {
  const form = event.target;
  event.preventDefault();

  if (form.classList.contains('create-group')) {
    await send(groupsView.createRequest({ name: fieldValue(form, 'name') }));
  } else if (form.classList.contains('add-members')) {
    const response = await send(
      groupsView.membershipRequest({ groupId: fieldValue(form, 'groupId'), deviceIds: fieldValue(form, 'deviceIds') }),
    );
    state.groups = { ...state.groups, added: response?.data?.added };
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
    await send(
      policiesView.createRequest({
        name: fieldValue(form, 'name'),
        settings: {
          firewallEnabled: fieldValue(form, 'firewallEnabled'),
          diskEncryptionRequired: fieldValue(form, 'diskEncryptionRequired'),
          screenLockTimeoutSeconds: fieldValue(form, 'screenLockTimeoutSeconds'),
          osUpdateMaxAgeDays: fieldValue(form, 'osUpdateMaxAgeDays'),
          localAdminAllowlist: fieldValue(form, 'localAdminAllowlist'),
        },
      }),
    );
  } else if (form.classList.contains('assign-policy')) {
    await send(
      policiesView.assignRequest({ policyId: fieldValue(form, 'policyId'), groupId: fieldValue(form, 'groupId') }),
    );
  } else if (form.classList.contains('audit-range')) {
    state.audit = { ...state.audit, from: fieldValue(form, 'from'), to: fieldValue(form, 'to') };
  } else if (form.classList.contains('dispatch')) {
    await send(dispatchView.requestFor(state.dispatch));
  }

  await show();
}

/** Clicks the screens care about: rows, copy buttons and the one `DELETE`. */
async function onClick(event) {
  const copy = event.target.closest('.copy');
  if (copy !== null) {
    const field = document.getElementById(copy.dataset.copyTarget);
    await navigator.clipboard.writeText(field.value);
    return;
  }

  const unassign = event.target.closest('.unassign');
  if (unassign !== null) {
    const form = unassign.closest('form');
    await send(
      policiesView.unassignRequest({ policyId: fieldValue(form, 'policyId'), groupId: fieldValue(form, 'groupId') }),
    );
    await show();
    return;
  }

  const refreshAll = event.target.closest('.refresh-user-links');
  if (refreshAll !== null) {
    const result = await refreshAllUserLinks(post);
    await (result.ok ? show() : show({ error: result.error }));
    return;
  }

  const refreshOne = event.target.closest('.refresh-user-link');
  if (refreshOne !== null) {
    const response = await post(`/devices/${refreshOne.dataset.deviceId}/user-link/refresh`, {});
    await (response.ok ? show() : show({ error: response.data?.error ?? 'request_failed' }));
    return;
  }

  const device = event.target.closest('tr.device');
  if (device !== null) {
    window.location.hash = `#/devices/${device.dataset.deviceId}`;
  }
}

/** Keep the dispatch screen's state in step with its form as it is typed. */
function onInput(event) {
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

  await show();
}

/** `clearToken` is re-exported so a sign-out button is one import away. */
export { clearToken };

if (typeof document !== 'undefined') {
  void start();
}
