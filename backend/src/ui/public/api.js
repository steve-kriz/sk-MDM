/**
 * Every call the console makes to the admin API.
 *
 *   setToken(accessToken);
 *   const page = await request('/devices');          // GET /admin/api/v1/devices
 *   await request('/groups', {method: 'POST', body: {name: 'Sydney'}});
 *   await put('/policies/pol-1', {name, settings});  // likewise post() and del()
 *
 * One module owns the access token so there is exactly one place it can be
 * read from, refreshed, or thrown away. It lives in a module-level variable
 * and, so a page reload during a session does not bounce the operator through
 * Entra again, in a single `sessionStorage` key -- never a cookie, which the
 * browser would attach to every request to this origin by itself, and never a
 * store that outlives the tab.
 *
 * A 401 or 403 is the end of the token, not a reason to try again: the token is
 * discarded and a fresh authorization redirect is started. The rejected call is
 * never retried -- a retry with the same dead token is one more rejection, and
 * a retry after a redirect is a request the page will not be alive to receive.
 *
 * `fetch` and the redirect are injected through `configureApi` so `node --test`
 * can drive this module with neither.
 */

/** Every admin API path hangs off this prefix. */
export const API_PREFIX = '/admin/api/v1';

/** The `Authorization` scheme the admin API accepts. */
export const BEARER_PREFIX = 'Bearer ';

/** The one `sessionStorage` key the token may be held under. */
export const TOKEN_KEY = 'skmdm.accessToken';

/** The statuses that mean "this token is finished". */
export const REAUTH_STATUSES = [401, 403];

/** The token, held in memory for the life of the page. */
let heldToken = null;

/** What the browser supplies; replaced wholesale in a test. */
let dependencies = {
  fetch: (...args) => globalThis.fetch(...args),
  startAuthorization: () => {},
  storage: () => (typeof sessionStorage === 'undefined' ? null : sessionStorage),
};

/** Inject `fetch`, the authorization restart and the session store. */
export function configureApi(overrides) {
  dependencies = { ...dependencies, ...overrides };
}

/** The session store, or `null` where there is none (a test, a worker). */
function store() {
  try {
    return dependencies.storage();
  } catch {
    return null;
  }
}

/** Hold a freshly obtained access token. */
export function setToken(token) {
  heldToken = typeof token === 'string' && token.length > 0 ? token : null;
  const session = store();
  if (session === null) {
    return;
  }
  try {
    if (heldToken === null) {
      session.removeItem(TOKEN_KEY);
    } else {
      session.setItem(TOKEN_KEY, heldToken);
    }
  } catch {
    // A storage that refuses to be written is not a reason to fail the sign-in.
  }
}

/** The held token, restored from the session store on the first read after a reload. */
export function getToken() {
  if (heldToken !== null) {
    return heldToken;
  }
  const session = store();
  if (session === null) {
    return null;
  }
  try {
    heldToken = session.getItem(TOKEN_KEY);
  } catch {
    heldToken = null;
  }
  return heldToken;
}

/** Throw the token away, in memory and in the session store. */
export function clearToken() {
  heldToken = null;
  const session = store();
  if (session === null) {
    return;
  }
  try {
    session.removeItem(TOKEN_KEY);
  } catch {
    // Nothing to do: the in-memory copy is already gone.
  }
}

/** `'/devices'` and `'/admin/api/v1/devices'` both address the same route. */
export function apiPath(path) {
  const wanted = path.startsWith('/') ? path : `/${path}`;
  return wanted.startsWith(`${API_PREFIX}/`) ? wanted : `${API_PREFIX}${wanted}`;
}

/** Read a fetch `Response`, a stub carrying `json()`, or a plain object. */
async function readBody(response) {
  if (response !== null && typeof response === 'object' && typeof response.json === 'function') {
    try {
      return await response.json();
    } catch {
      return null;
    }
  }
  return response?.body ?? null;
}

/**
 * One admin API call.
 *
 * Returns `{ok, status, data}`; a rejected call returns
 * `{ok:false, status, error:'unauthorized', reauthorized:true}` after the token
 * has been discarded and the authorization redirect has been started.
 */
export async function request(path, { method = 'GET', body, query, headers = {} } = {}) {
  const token = getToken();
  const target = new URL(apiPath(path), 'http://placeholder.invalid');
  for (const [name, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== null && value !== '') {
      target.searchParams.set(name, String(value));
    }
  }
  const url = `${target.pathname}${target.search}`;

  const init = {
    method,
    headers: {
      accept: 'application/json',
      ...headers,
      authorization: `${BEARER_PREFIX}${token ?? ''}`,
    },
  };
  if (body !== undefined) {
    init.headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

  const response = await dependencies.fetch(url, init);
  const status = response?.status ?? 0;

  if (REAUTH_STATUSES.includes(status)) {
    // Discard, re-authorize, and stop: this call is not retried.
    clearToken();
    dependencies.startAuthorization();
    return { ok: false, status, error: 'unauthorized', reauthorized: true };
  }

  const data = await readBody(response);
  return { ok: status >= 200 && status < 300, status, data };
}

/** `GET` a collection or a resource. */
export function get(path, query) {
  return request(path, { method: 'GET', query });
}

/** `POST` a JSON body. */
export function post(path, body) {
  return request(path, { method: 'POST', body });
}

/** `PUT` a JSON body: replace a resource. */
export function put(path, body) {
  return request(path, { method: 'PUT', body });
}

/** `DELETE`, with the JSON body the assignment routes read their `groupId` from. */
export function del(path, body) {
  return request(path, { method: 'DELETE', body });
}
