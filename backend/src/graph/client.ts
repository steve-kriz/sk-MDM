/**
 * Microsoft Graph, read through the app registration's client credentials.
 *
 *   const graph = createGraphClient({
 *     tenantId, clientId,
 *     clientSecret: createGraphSecretProvider({ secretsClient, secretId, key }),
 *     fetch, now: () => Math.floor(Date.now() / 1000),
 *   });
 *   const devices = await graph.findDevicesByDisplayName('LAT-7440');
 *   const users = await graph.listRegisteredUsers(devices[0].id);
 *
 * The access token comes from the OAuth2 client-credentials flow against the
 * tenant's v2.0 token endpoint and is reused until 60 seconds before it
 * expires. Every outside dependency -- the HTTP `fetch`, the clock and the
 * Secrets Manager client -- is injected, so nothing here opens a connection
 * under test.
 *
 * Failures reject with a plain `{status, error}` object (`GraphFailure`), never
 * with a raw response, so a caller maps one straight onto a route result. The
 * client secret and the access token never appear in a rejection, and nothing
 * here logs.
 *
 * Nothing is fetched when a client is built: the secret is read and the token
 * requested on the first lookup.
 */
import { GET_SECRET_VALUE, type SecretsClient, type SecretsResponse } from '../crypto/pepper.js';

/** Graph's v1.0 endpoint; every Graph request and every followed `nextLink` starts here. */
export const GRAPH_BASE_URL = 'https://graph.microsoft.com/v1.0';

/** The client-credentials scope: whatever application permissions the app was granted. */
export const GRAPH_SCOPE = 'https://graph.microsoft.com/.default';

/** How long a Graph or token request may take, in milliseconds, when none is configured. */
export const DEFAULT_GRAPH_TIMEOUT_MILLIS = 10000;

/** A token is renewed this many seconds before Entra says it expires. */
export const TOKEN_EXPIRY_LEEWAY_SECONDS = 60;

/** The most pages one lookup reads, following `@odata.nextLink`. */
export const MAX_GRAPH_PAGES = 10;

/** The `@odata.type` of a user; any other directory object is left out of `registeredUsers`. */
export const GRAPH_USER_TYPE = '#microsoft.graph.user';

/** The JSON key of the client secret in the secret, when `GRAPH_SECRET_KEY` names none. */
export const DEFAULT_GRAPH_SECRET_KEY = 'ENTRA_CLIENT_SECRET';

/** Why a Graph call failed. A plain object, so it maps straight onto a `RouteResult`. */
export interface GraphFailure {
  status: number;
  error: string;
}

/** True for a `{status, error}` rejection from this module. */
export function isGraphFailure(value: unknown): value is GraphFailure {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as GraphFailure).status === 'number' &&
    typeof (value as GraphFailure).error === 'string'
  );
}

/** The token endpoint refused the credentials, or answered without a token. */
const AUTH_FAILED: GraphFailure = { status: 502, error: 'graph_auth_failed' };
/** Graph answered 401/403: usually missing application permissions or admin consent. */
const FORBIDDEN: GraphFailure = { status: 502, error: 'graph_forbidden' };
/** Anything else: throttling, an outage, a network error, a timeout or a body that is not JSON. */
const UNAVAILABLE: GraphFailure = { status: 502, error: 'graph_unavailable' };
/** The secret is absent, unparsable or lacks the key. */
const NOT_CONFIGURED: GraphFailure = { status: 503, error: 'graph_not_configured' };
/** The Secrets Manager call itself failed. */
const SECRET_UNAVAILABLE: GraphFailure = { status: 503, error: 'graph_secret_unavailable' };

/** A fresh copy, so a caller can never mutate the shared constants. */
function failure(kind: GraphFailure): GraphFailure {
  return { status: kind.status, error: kind.error };
}

/** The request options this module passes to `fetch`. */
export interface GraphFetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  signal?: AbortSignal;
}

/** The parts of a `fetch` response this module reads. */
export interface GraphFetchResponse {
  ok?: boolean;
  status: number;
  text?(): Promise<string>;
  json?(): Promise<unknown>;
}

/** The injected `fetch`. `globalThis.fetch` satisfies it. */
export type GraphFetch = (url: string, init?: GraphFetchInit) => Promise<GraphFetchResponse>;

/** Injected clock: integer epoch *seconds*. */
export type GraphClock = () => number;

/** The client secret, or an async provider of it. */
export type ClientSecretSource = string | (() => Promise<string> | string);

/** One Entra device object, as `$select=id,displayName,accountEnabled` returns it. */
export interface GraphDevice {
  id?: string;
  displayName?: string;
  accountEnabled?: boolean;
  [field: string]: unknown;
}

/** One registered user, as `$select=id,displayName,userPrincipalName,mail` returns it. */
export interface GraphUser {
  id?: string;
  displayName?: string | null;
  userPrincipalName?: string | null;
  mail?: string | null;
  '@odata.type'?: string;
  [field: string]: unknown;
}

/** The two directory reads the user-link routes need. */
export interface GraphDirectory {
  /** Entra devices whose `displayName` equals `name`. */
  findDevicesByDisplayName(name: string): Promise<GraphDevice[]>;
  /** The users registered on the Entra device with this object id. */
  listRegisteredUsers(objectId: string): Promise<GraphUser[]>;
}

export interface GraphClientOptions {
  /** Entra tenant id; fixes the token endpoint. */
  tenantId: string;
  /** Application (client) id of the app registration. */
  clientId: string;
  /** The client secret, or an async provider of it (see `createGraphSecretProvider`). */
  clientSecret: ClientSecretSource;
  /** The HTTP client. Required; `globalThis.fetch` is never read here. */
  fetch: GraphFetch;
  /** Current time in epoch seconds. Required; `Date.now` is never read here. */
  now: GraphClock;
  /** Per-request timeout in milliseconds. Defaults to `DEFAULT_GRAPH_TIMEOUT_MILLIS`. */
  timeoutMillis?: number;
}

/** The tenant's v2.0 token endpoint. */
export function tokenUrl(tenantId: string): string {
  return `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`;
}

/** An OData string literal: every `'` doubled. */
export function odataString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

/** A query string with every value URL-encoded and the `$` parameter names kept literal. */
function queryString(params: Record<string, string>): string {
  return Object.entries(params)
    .map(([name, value]) => `${name}=${encodeURIComponent(value)}`)
    .join('&');
}

/** What `fetchJson` resolves: the status and the parsed body, or `undefined` when it was not JSON. */
interface JsonResponse {
  status: number;
  ok: boolean;
  body: unknown;
  parsed: boolean;
}

/** Parse a response body, reporting rather than throwing when it is not JSON. */
async function readBody(response: GraphFetchResponse): Promise<{ body: unknown; parsed: boolean }> {
  try {
    if (typeof response.text === 'function') {
      return { body: JSON.parse(await response.text()), parsed: true };
    }
    if (typeof response.json === 'function') {
      return { body: await response.json(), parsed: true };
    }
  } catch {
    // Fall through: an unparsable body.
  }
  return { body: undefined, parsed: false };
}

export function createGraphClient({
  tenantId,
  clientId,
  clientSecret,
  fetch,
  now,
  timeoutMillis = DEFAULT_GRAPH_TIMEOUT_MILLIS,
}: GraphClientOptions): GraphDirectory {
  if (typeof fetch !== 'function') {
    throw new Error('invalid fetch: expected a function');
  }
  if (typeof now !== 'function') {
    throw new Error('invalid now: expected a function returning epoch seconds');
  }

  /**
   * One request, bounded by `timeoutMillis`. The timeout aborts the request
   * through the signal handed to `fetch`; the race makes sure a `fetch` that
   * ignores the signal still cannot hold the caller past the bound. Any network
   * failure or timeout rejects with `graph_unavailable`.
   */
  async function fetchJson(url: string, init: GraphFetchInit): Promise<JsonResponse> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timedOut = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(failure(UNAVAILABLE));
      }, timeoutMillis);
    });
    try {
      return await Promise.race([
        (async (): Promise<JsonResponse> => {
          const response = await fetch(url, { ...init, signal: controller.signal });
          const status = typeof response?.status === 'number' ? response.status : 0;
          const { body, parsed } = await readBody(response);
          return { status, ok: status >= 200 && status <= 299, body, parsed };
        })(),
        timedOut,
      ]);
    } catch {
      // Never surface the raw error: it may carry the request, and so the token.
      throw failure(UNAVAILABLE);
    } finally {
      clearTimeout(timer);
    }
  }

  async function resolveSecret(): Promise<string> {
    try {
      const secret = typeof clientSecret === 'function' ? await clientSecret() : clientSecret;
      if (typeof secret !== 'string' || secret.length === 0) {
        throw failure(NOT_CONFIGURED);
      }
      return secret;
    } catch (error) {
      if (isGraphFailure(error)) {
        throw failure(error);
      }
      throw failure(SECRET_UNAVAILABLE);
    }
  }

  /** The cached token and the epoch second it stops being reused. */
  let cached: { token: string; reuseUntil: number } | null = null;
  /** An in-flight token request, shared by concurrent callers; dropped once settled. */
  let pending: Promise<string> | null = null;

  async function requestToken(): Promise<string> {
    const secret = await resolveSecret();
    const acquiredAt = now();
    const response = await fetchJson(tokenUrl(tenantId), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: secret,
        scope: GRAPH_SCOPE,
      }).toString(),
    });
    if (!response.ok) {
      throw failure(AUTH_FAILED);
    }
    if (!response.parsed) {
      throw failure(UNAVAILABLE);
    }
    const body = response.body as { access_token?: unknown; expires_in?: unknown } | null;
    const token = typeof body === 'object' && body !== null ? body.access_token : undefined;
    if (typeof token !== 'string' || token.length === 0) {
      throw failure(AUTH_FAILED);
    }
    const expiresIn = Number(body?.expires_in);
    cached = {
      token,
      reuseUntil: acquiredAt + (Number.isFinite(expiresIn) ? expiresIn : 0) - TOKEN_EXPIRY_LEEWAY_SECONDS,
    };
    return token;
  }

  async function accessToken(): Promise<string> {
    if (cached !== null && now() < cached.reuseUntil) {
      return cached.token;
    }
    if (pending === null) {
      // A failed request is never cached: the next lookup asks again.
      pending = requestToken().finally(() => {
        pending = null;
      });
    }
    return pending;
  }

  /** Every page of a Graph collection, following `@odata.nextLink` up to `MAX_GRAPH_PAGES`. */
  async function readCollection(firstUrl: string): Promise<unknown[]> {
    const values: unknown[] = [];
    let url: string | null = firstUrl;
    for (let page = 0; page < MAX_GRAPH_PAGES && url !== null; page += 1) {
      const token = await accessToken();
      const response = await fetchJson(url, {
        method: 'GET',
        headers: { authorization: `Bearer ${token}`, accept: 'application/json' },
      });
      if (response.status === 401 || response.status === 403) {
        throw failure(FORBIDDEN);
      }
      if (!response.ok || !response.parsed) {
        throw failure(UNAVAILABLE);
      }
      const body = response.body;
      if (typeof body !== 'object' || body === null || Array.isArray(body)) {
        throw failure(UNAVAILABLE);
      }
      const { value, '@odata.nextLink': nextLink } = body as { value?: unknown; '@odata.nextLink'?: unknown };
      if (Array.isArray(value)) {
        values.push(...value);
      }
      // Only Graph itself is followed: the bearer token is never sent elsewhere.
      url = typeof nextLink === 'string' && nextLink.startsWith(`${GRAPH_BASE_URL}/`) ? nextLink : null;
    }
    return values;
  }

  return {
    async findDevicesByDisplayName(name: string): Promise<GraphDevice[]> {
      const query = queryString({
        $filter: `displayName eq ${odataString(String(name))}`,
        $select: 'id,displayName,accountEnabled',
      });
      const values = await readCollection(`${GRAPH_BASE_URL}/devices?${query}`);
      return values.filter((entry): entry is GraphDevice => typeof entry === 'object' && entry !== null);
    },

    async listRegisteredUsers(objectId: string): Promise<GraphUser[]> {
      const query = queryString({ $select: 'id,displayName,userPrincipalName,mail' });
      const values = await readCollection(
        `${GRAPH_BASE_URL}/devices/${encodeURIComponent(String(objectId))}/registeredUsers?${query}`,
      );
      return values.filter((entry): entry is GraphUser => {
        if (typeof entry !== 'object' || entry === null) {
          return false;
        }
        const type = (entry as GraphUser)['@odata.type'];
        return type === undefined || type === GRAPH_USER_TYPE;
      });
    },
  };
}

export interface GraphSecretProviderOptions {
  /** The Secrets Manager client, in the shapes `src/crypto/pepper.ts` accepts. */
  secretsClient: SecretsClient;
  /** Name or ARN of the secret, from `GRAPH_SECRET_ID`. */
  secretId: string;
  /** JSON key of the client secret inside the secret, from `GRAPH_SECRET_KEY`. */
  key: string;
}

/** The `SecretString` of whatever the injected client resolved, or `null`. */
function secretStringOf(response: SecretsResponse): string | null {
  if (typeof response === 'string') {
    return response;
  }
  if (typeof response === 'object' && response !== null && typeof response.SecretString === 'string') {
    return response.SecretString;
  }
  return null;
}

/**
 * The client secret, read from a JSON secret in Secrets Manager.
 *
 * Fetched at most once: the in-flight promise is cached so concurrent callers
 * share one call, and dropped again on failure so a later call retries.
 */
export function createGraphSecretProvider({
  secretsClient,
  secretId,
  key,
}: GraphSecretProviderOptions): () => Promise<string> {
  let pending: Promise<string> | null = null;

  async function fetchSecret(): Promise<string> {
    let response: SecretsResponse;
    try {
      if (typeof secretsClient?.getSecretValue === 'function') {
        response = await secretsClient.getSecretValue({ SecretId: secretId });
      } else if (typeof secretsClient?.send === 'function') {
        response = await secretsClient.send({ operation: GET_SECRET_VALUE, SecretId: secretId });
      } else {
        throw new Error('invalid secretsClient');
      }
    } catch {
      throw failure(SECRET_UNAVAILABLE);
    }

    const text = secretStringOf(response);
    if (text === null || text.length === 0) {
      throw failure(NOT_CONFIGURED);
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw failure(NOT_CONFIGURED);
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw failure(NOT_CONFIGURED);
    }
    const value = (parsed as Record<string, unknown>)[key];
    if (typeof value !== 'string' || value.length === 0) {
      throw failure(NOT_CONFIGURED);
    }
    return value;
  }

  return (): Promise<string> => {
    if (pending === null) {
      pending = fetchSecret().catch((error: unknown) => {
        pending = null;
        throw error;
      });
    }
    return pending;
  };
}

export interface GraphDirectoryDependencies {
  secretsClient: SecretsClient;
  fetch: GraphFetch;
  now: GraphClock;
}

/** A non-empty environment value, or `null`. */
function envValue(env: Record<string, string | undefined>, name: string): string | null {
  const value = env[name];
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/**
 * The Graph directory the Lambda environment describes, or `undefined` when
 * Graph is not configured (`ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID` or
 * `GRAPH_SECRET_ID` absent or empty). Building it sends no request.
 */
export function createGraphDirectoryFromEnv(
  env: Record<string, string | undefined>,
  { secretsClient, fetch, now }: GraphDirectoryDependencies,
): GraphDirectory | undefined {
  const tenantId = envValue(env, 'ENTRA_TENANT_ID');
  const clientId = envValue(env, 'ENTRA_CLIENT_ID');
  const secretId = envValue(env, 'GRAPH_SECRET_ID');
  if (tenantId === null || clientId === null || secretId === null) {
    return undefined;
  }
  const key = envValue(env, 'GRAPH_SECRET_KEY') ?? DEFAULT_GRAPH_SECRET_KEY;
  return createGraphClient({
    tenantId,
    clientId,
    clientSecret: createGraphSecretProvider({ secretsClient, secretId, key }),
    fetch,
    now,
  });
}
