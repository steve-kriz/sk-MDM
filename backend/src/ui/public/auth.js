/**
 * The browser half of sign-in: the OIDC authorization-code flow with PKCE,
 * run against Entra ID by the console itself.
 *
 *   location.assign(authorizeUrl({tenantId, clientId, redirectUri, scope, state, codeChallenge}));
 *   // ... Entra sends the browser back to redirectUri?code=...&state=...
 *   const result = await handleRedirect({params, storedState, storedVerifier, post, ...config});
 *
 * There is no server side to this. The console is a public client: it holds no
 * secret, so no request this module builds carries one, and the code exchange
 * is proved by the PKCE verifier alone. Nothing is written to a cookie and
 * nothing is persisted here -- the caller (`app.js`) keeps the `state` and the
 * verifier in `sessionStorage` for the length of one redirect and hands them
 * back in.
 *
 * `state` is checked before anything is exchanged: a redirect whose `state` is
 * not the one this browser sent is someone else's, and its code is never sent
 * anywhere.
 */

/** Entra's public authority host; the only host this module ever addresses. */
export const ENTRA_HOST = 'https://login.microsoftonline.com';

/** The PKCE transform the console uses; `plain` is never offered. */
export const CODE_CHALLENGE_METHOD = 'S256';

/** The tenant used when a caller names none. */
export const DEFAULT_TENANT = 'common';

/** Entra's authorize endpoint for a tenant. */
export function authorizeEndpoint(tenantId) {
  return `${ENTRA_HOST}/${encodeURIComponent(tenantId ?? DEFAULT_TENANT)}/oauth2/v2.0/authorize`;
}

/** Entra's token endpoint for a tenant. */
export function tokenEndpoint(tenantId) {
  return `${ENTRA_HOST}/${encodeURIComponent(tenantId ?? DEFAULT_TENANT)}/oauth2/v2.0/token`;
}

/**
 * Where to send the browser to sign in.
 *
 * Only the parameters a public client may send are present: there is no
 * `client_secret`, and the challenge is always `S256`.
 */
export function authorizeUrl({ tenantId, clientId, redirectUri, scope, state, codeChallenge }) {
  const query = new URLSearchParams({
    client_id: clientId ?? '',
    response_type: 'code',
    redirect_uri: redirectUri ?? '',
    scope: scope ?? '',
    state: state ?? '',
    code_challenge: codeChallenge ?? '',
    code_challenge_method: CODE_CHALLENGE_METHOD,
  });
  return `${authorizeEndpoint(tenantId)}?${query.toString()}`;
}

/** Read one value from either a plain object or a `URLSearchParams`. */
function param(params, name) {
  if (params === null || params === undefined) {
    return undefined;
  }
  if (typeof params.get === 'function') {
    return params.get(name) ?? undefined;
  }
  return params[name];
}

/** The token response, whether `post` resolved a `Response` or a plain object. */
async function readTokenResponse(result) {
  if (result !== null && typeof result === 'object' && typeof result.json === 'function') {
    return await result.json();
  }
  return result ?? {};
}

/**
 * Finish the flow: check the `state`, then exchange the code for a token.
 *
 * `post(url, request)` is injected so a test can observe the exchange without a
 * network; the default is `fetch`. `request` is an ordinary fetch init -- an
 * `application/x-www-form-urlencoded` POST -- with one extra key, `form`,
 * carrying the same fields unencoded so a caller never has to re-parse them.
 *
 * `tenantId`, `clientId` and `redirectUri` may be passed at the top level or
 * inside a `config` object, whichever the caller already holds.
 *
 * Returns `{ok:false, error}` on a mismatched `state` or an error redirect,
 * and `{ok:true, accessToken, expiresIn, response}` once the code is exchanged.
 */
export async function handleRedirect({
  params,
  storedState,
  storedVerifier,
  post,
  config = {},
  tenantId,
  clientId,
  redirectUri,
}) {
  const state = param(params, 'state');
  if (state !== storedState) {
    return { ok: false, error: 'invalid_state' };
  }

  const returnedError = param(params, 'error');
  if (returnedError !== undefined && returnedError !== null && returnedError !== '') {
    return { ok: false, error: String(returnedError) };
  }

  const tenant = tenantId ?? config.tenantId ?? DEFAULT_TENANT;
  const form = {
    client_id: clientId ?? config.clientId ?? '',
    grant_type: 'authorization_code',
    code: param(params, 'code') ?? '',
    redirect_uri: redirectUri ?? config.redirectUri ?? '',
    code_verifier: storedVerifier ?? '',
  };

  const exchange = post ?? ((url, request) => fetch(url, request));
  const result = await exchange(tokenEndpoint(tenant), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form).toString(),
    form,
  });

  const response = await readTokenResponse(result);
  const accessToken = response.access_token;
  if (typeof accessToken !== 'string' || accessToken.length === 0) {
    return { ok: false, error: response.error ?? 'token_request_failed', response };
  }
  return { ok: true, accessToken, expiresIn: response.expires_in, response };
}
