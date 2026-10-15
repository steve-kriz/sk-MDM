/**
 * The signed-in Applications page: the application safe list a user of the
 * tenant may download from.
 *
 * Boot order mirrors the admin console (`app.js`), with its own storage keys so
 * the two never share a token:
 *
 *   1. GET /applications/config.json       -- tenant, client, redirect, scope (MDM.User)
 *   2. a redirect carrying ?code= / ?error= -- finish it with `handleRedirect`
 *   3. no token                            -- send the browser to Entra
 *   4. a token                             -- GET /api/v1/applications with the bearer
 *
 * A browser cannot attach a bearer to a plain link, so a Download button asks
 * `GET /api/v1/applications/{id}/download` for a URL and then navigates to it
 * with `location.assign`.
 *
 * A 401 clears the token and signs in again; a 403 (a token without `MDM.User`)
 * clears it and says so without redirecting, so the page can never loop. A
 * sign-in error redirect is shown and starts no new sign-in.
 *
 * Everything the page touches -- `fetch`, `storage`, `location`, `history`,
 * `document` -- is injected into `start(deps)`, so it is tested without a
 * browser. It never reads or writes the admin console's `skmdm.accessToken`.
 */
import { authorizeUrl, handleRedirect } from './auth.js';
import { escapeHtml } from './html.js';
import { createPkcePair, createState } from './pkce.js';

/** Where the page keeps its access token; never the console's `skmdm.accessToken`. */
export const USER_TOKEN_KEY = 'skmdm.userAccessToken';

/** Where the PKCE values live for the length of one redirect. */
export const APPS_STATE_KEY = 'skmdm.apps.authState';
export const APPS_VERIFIER_KEY = 'skmdm.apps.codeVerifier';

/** The path the page is served at; the address bar returns here after sign-in. */
export const APPLICATIONS_PAGE_PATH = '/applications';

/** The page's public client configuration. */
export const CONFIG_URL = '/applications/config.json';

/** The signed-in user's application list. */
export const LIST_URL = '/api/v1/applications';

/** The element every message and the list are rendered into. */
export const MOUNT_ID = 'applications';

/** How each platform reads on the page. */
export const PLATFORM_LABELS = { windows: 'Windows', darwin: 'macOS' };

export const EMPTY_MESSAGE = 'No applications available';
export const FORBIDDEN_MESSAGE = 'Your account does not have access to applications';
export const LOAD_FAILED_MESSAGE = 'Applications could not be loaded';
export const DOWNLOAD_FAILED_MESSAGE = 'Download could not be started';

/** The path a Download button asks for its URL on. */
export function downloadPath(applicationId) {
  return `${LIST_URL}/${encodeURIComponent(String(applicationId ?? ''))}/download`;
}

/** The fetch init every API call carries: JSON, with the bearer. */
export function bearerInit(token) {
  return { headers: { accept: 'application/json', authorization: `Bearer ${token}` } };
}

/** What an API answer means for the page. */
export function outcomeFor(status) {
  if (status >= 200 && status < 300) {
    return 'ok';
  }
  if (status === 401) {
    return 'reauthorize';
  }
  if (status === 403) {
    return 'forbidden';
  }
  return 'failed';
}

/** The platform as the page shows it. */
function platformLabel(platform) {
  return PLATFORM_LABELS[platform] ?? escapeHtml(platform ?? '');
}

/** The list, one row per application, or the empty message. */
export function renderApplications(items) {
  const list = Array.isArray(items) ? items : [];
  if (list.length === 0) {
    return `<p class="empty">${EMPTY_MESSAGE}</p>`;
  }
  const rows = list
    .map((item) => {
      const description =
        item?.description === null || item?.description === undefined || item?.description === ''
          ? '&mdash;'
          : escapeHtml(item.description);
      return (
        `<tr class="application">` +
        `<td>${escapeHtml(item?.name)}</td>` +
        `<td>${description}</td>` +
        `<td>${platformLabel(item?.platform)}</td>` +
        `<td><button type="button" class="download-application" data-application-id="${escapeHtml(item?.applicationId)}">Download</button></td>` +
        `</tr>`
      );
    })
    .join('');
  return (
    `<h2>Applications</h2>` +
    `<table class="applications"><thead><tr><th>Name</th><th>Description</th><th>Platform</th><th></th></tr></thead>` +
    `<tbody>${rows}</tbody></table>`
  );
}

/** A message paragraph, escaped. */
function messageHtml(text) {
  return `<p class="error">${escapeHtml(text)}</p>`;
}

/** The browser's own objects, used when `start` is called with none. */
function browserDeps() {
  return {
    fetch: (url, init) => globalThis.fetch(url, init),
    storage: globalThis.sessionStorage,
    location: globalThis.window?.location,
    history: globalThis.window?.history,
    document: globalThis.document,
  };
}

/** Boot the page. Every browser object is injected. */
export async function start(deps = browserDeps()) {
  const { fetch: fetchFn, storage, location, history, document: doc } = deps;
  const mountEl = doc?.getElementById?.(MOUNT_ID) ?? null;
  let listHtml = '';

  function paint(message) {
    if (mountEl !== null) {
      mountEl.innerHTML = `${message ? messageHtml(message) : ''}${listHtml}`;
    }
  }

  // 1. The public client configuration.
  let config;
  try {
    const response = await fetchFn(CONFIG_URL, { headers: { accept: 'application/json' } });
    if (!response.ok) {
      throw new Error('not_configured');
    }
    config = await response.json();
  } catch {
    paint(LOAD_FAILED_MESSAGE);
    return;
  }

  function startSignIn() {
    const { verifier, challenge } = createPkcePair();
    const authState = createState();
    storage.setItem(APPS_STATE_KEY, authState);
    storage.setItem(APPS_VERIFIER_KEY, verifier);
    location.assign(
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

  // 2. A redirect back from Entra, successful or not.
  const params = new URLSearchParams(location?.search ?? '');
  if (params.has('code') || params.has('error')) {
    const result = await handleRedirect({
      params,
      storedState: storage.getItem(APPS_STATE_KEY),
      storedVerifier: storage.getItem(APPS_VERIFIER_KEY),
      config,
      post: (url, init) => fetchFn(url, init),
    });
    storage.removeItem(APPS_STATE_KEY);
    storage.removeItem(APPS_VERIFIER_KEY);
    // The code is single-use and has been spent: take it out of the address bar.
    history?.replaceState?.(null, '', APPLICATIONS_PAGE_PATH);
    if (!result.ok) {
      paint(`Sign-in failed: ${result.error}`);
      return;
    }
    storage.setItem(USER_TOKEN_KEY, result.accessToken);
  }

  // 3. No token: sign in.
  const stored = storage.getItem(USER_TOKEN_KEY);
  if (typeof stored !== 'string' || stored.length === 0) {
    startSignIn();
    return;
  }

  /** React to a refusal the way every call does; returns true when it was handled. */
  function refused(outcome) {
    if (outcome === 'reauthorize') {
      storage.removeItem(USER_TOKEN_KEY);
      startSignIn();
      return true;
    }
    if (outcome === 'forbidden') {
      storage.removeItem(USER_TOKEN_KEY);
      listHtml = '';
      paint(FORBIDDEN_MESSAGE);
      return true;
    }
    return false;
  }

  async function download(applicationId) {
    const token = storage.getItem(USER_TOKEN_KEY);
    if (typeof token !== 'string' || token.length === 0) {
      startSignIn();
      return;
    }
    try {
      const response = await fetchFn(downloadPath(applicationId), bearerInit(token));
      const outcome = outcomeFor(response.status);
      if (outcome === 'ok') {
        const data = await response.json();
        if (typeof data?.url === 'string' && data.url.length > 0) {
          location.assign(data.url);
          return;
        }
        paint(DOWNLOAD_FAILED_MESSAGE);
        return;
      }
      if (!refused(outcome)) {
        paint(DOWNLOAD_FAILED_MESSAGE);
      }
    } catch {
      paint(DOWNLOAD_FAILED_MESSAGE);
    }
  }

  if (mountEl !== null && typeof mountEl.addEventListener === 'function') {
    mountEl.addEventListener('click', (event) => {
      const button = event?.target?.closest?.('.download-application') ?? null;
      if (button === null) {
        return undefined;
      }
      const applicationId = button.dataset?.applicationId ?? button.getAttribute?.('data-application-id') ?? '';
      return download(applicationId);
    });
  }

  // 4. The list.
  try {
    const response = await fetchFn(LIST_URL, bearerInit(stored));
    const outcome = outcomeFor(response.status);
    if (outcome === 'ok') {
      const data = await response.json();
      listHtml = renderApplications(data?.items ?? []);
      paint(null);
      return;
    }
    if (!refused(outcome)) {
      paint(LOAD_FAILED_MESSAGE);
    }
  } catch {
    paint(LOAD_FAILED_MESSAGE);
  }
}

if (typeof document !== 'undefined' && typeof window !== 'undefined' && typeof sessionStorage !== 'undefined') {
  void start();
}
