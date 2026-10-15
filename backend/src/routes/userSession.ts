/**
 * Agent user sign-in: the public sign-in configuration and the signed-in user
 * report.
 *
 *   GET  /api/v1/agent-auth/config
 *   -> {"tenantId":"t-1","clientId":"c-1","scopes":["api://c-1/MDM.Agent","offline_access","openid","profile"]}
 *
 *   POST /api/v1/devices/{deviceId}/user-session   (device HMAC only)   {"username":"CONTOSO\amy" | null}
 *   -> {"user":{"username":"CONTOSO\amy"}}
 *
 * The config route is unauthenticated: it publishes only what a public client
 * needs to start a sign-in, built key by key so no other environment value
 * (`ENTRA_ADMIN_GROUP_ID`, `PEPPER_SECRET_ARN`) can leak.
 *
 * The user-session route records the user logged in to the operating system,
 * as the agent reports it after each check-in (spec Amendment B: no Entra
 * token is involved any more). Checks run in a fixed order and the first
 * failure returns immediately, having written nothing beyond the nonce
 * `verifyDeviceRequest` burns:
 *
 *   1. `verifyDeviceRequest`          -> its own `{status, body}`, unchanged
 *   2. path device == signed device   -> 403 device_mismatch
 *   3. body `{"username": <string <= 256> | null}`
 *                                     -> 400 invalid_request, fields ["username"]
 *
 * The body is covered by the device signature (its SHA-256 is one of the
 * canonical lines), so it is read only after the signature has verified. An
 * `Authorization` header is ignored. The report is stored as
 * `DEVICE#<id>` / `SIGNEDINUSER` = `{deviceId, username, source: "os", reportedAt}`,
 * replacing the previous one. After it is stored, a 200 answer also refreshes
 * the device profile's last-seen (best-effort, see `./deviceContact.ts`); a
 * failed refresh never changes the response.
 *
 * The route also keeps a per-device login history: one
 * `DEVICE#<id>` / `LOGINUSER#<loginUserKey(username)>` =
 * `{deviceId, username, firstSeenAt, lastSeenAt, loginCount}` record per
 * distinct normalised username (trimmed, lower-cased). After the body has
 * validated, the handler:
 *
 *   1. reads the previous `SIGNEDINUSER` (a failure skips step 3),
 *   2. stores the new `SIGNEDINUSER` (unchanged),
 *   3. upserts the history record when the trimmed username is non-empty --
 *      `loginCount` rises by 1 only when the previous console user was absent,
 *      empty or a different normalised username; a new record starting at 1
 *      first evicts the least recently seen record when the device already has
 *      `MAX_LOGIN_USERS_PER_DEVICE`,
 *   4. refreshes the device's last-seen, and
 *   5. answers 200.
 *
 * The history is best-effort like the last-seen refresh: any failure is logged
 * as one `console.warn` line and never changes the response.
 */
import { createHash } from 'node:crypto';
import { isoUtc } from '../audit.js';
import { AGENT_SCOPE_NAME } from '../auth/userToken.js';
import { deviceLoginUser, deviceSignedInUser, type TableKey } from '../db/keys.js';
import type { Item, QueryPage, QueryRequest, RequestFields, WriteOutcome } from '../db/table.js';
import { verifyDeviceRequest, type DeviceAuthResult, type EpochSecondsClock } from '../http/deviceAuth.js';
import type { RouteHandler, RouteRequest, RouteResult, Router, RouterRequest } from '../http/router.js';
import { recordDeviceContact } from './deviceContact.js';

/** Path of the public agent sign-in configuration. */
export const AGENT_AUTH_CONFIG_PATH = '/api/v1/agent-auth/config';

/** Path the agent reports its signed-in user on. */
export const USER_SESSION_PATH = '/api/v1/devices/{deviceId}/user-session';

/** The longest username the route accepts, in characters. */
export const USERNAME_MAX_LENGTH = 256;

/** Where a reported username came from: the operating system's console user. */
export const SIGNED_IN_USER_SOURCE = 'os';

/** The most login history records kept per device. */
export const MAX_LOGIN_USERS_PER_DEVICE = 100;

/** The login history's merge form of a username: trimmed, then lower-cased. */
function normaliseUsername(username: string): string {
  return username.trim().toLowerCase();
}

/**
 * The login history key of a username: the SHA-256 hex of the UTF-8 bytes of
 * its trimmed, lower-cased form, so case and whitespace variants share a record.
 */
export function loginUserKey(username: string): string {
  return createHash('sha256').update(normaliseUsername(username), 'utf8').digest('hex');
}

/** The environment `agentAuthConfig` reads: `process.env`, or a fake in a test. */
export type AgentAuthEnv = Record<string, string | undefined>;

/** The whole of what `GET /api/v1/agent-auth/config` answers with. */
export interface AgentAuthConfig {
  tenantId: string;
  clientId: string;
  scopes: string[];
}

/** A configured value, or `null` when it is absent or the empty string. */
function configured(value: string | undefined): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/**
 * The agent sign-in configuration, or `null` when Entra is not configured --
 * which the route answers as 500 `not_configured`.
 */
export function agentAuthConfig(env: AgentAuthEnv): AgentAuthConfig | null {
  const tenantId = configured(env.ENTRA_TENANT_ID);
  const clientId = configured(env.ENTRA_CLIENT_ID);
  if (tenantId === null || clientId === null) {
    return null;
  }
  return {
    tenantId,
    clientId,
    scopes: [`api://${clientId}/${AGENT_SCOPE_NAME}`, 'offline_access', 'openid', 'profile'],
  };
}

/** `GET /api/v1/agent-auth/config`. Needs no authentication. */
export function handleAgentAuthConfig(): RouteResult {
  const config = agentAuthConfig(process.env);
  if (config === null) {
    return { statusCode: 500, body: { error: 'not_configured' } };
  }
  return { statusCode: 200, body: config };
}

/**
 * The storage operations this route needs. `get` and `putIfAbsent` are here
 * only because `verifyDeviceRequest` reads the profile and burns a nonce;
 * `update` only refreshes the device's last-seen. `query` and `delete` serve
 * the login history's cap.
 */
export interface UserSessionTable {
  get(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
  put(item: Item, fields?: RequestFields): Promise<void>;
  putIfAbsent(item: Item, fields?: RequestFields): Promise<WriteOutcome>;
  update(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
  query(request?: QueryRequest): Promise<QueryPage>;
  delete(key: TableKey, fields?: RequestFields): Promise<void>;
}

/** Current time: integer epoch seconds, or any instant a `Date` can be built from. */
export type UserSessionClock = () => number | string | Date;

/** The authenticator this route calls; injectable so tests need no signed request. */
export type DeviceVerifier = (
  req: RouterRequest,
  options: { table: UserSessionTable; now: EpochSecondsClock; pepper: string },
) => Promise<DeviceAuthResult>;

/** The pepper key, or anything that resolves it (a `PepperProvider` fits). */
export type PepperSource = string | (() => string | Promise<string>);

export interface UserSessionDependencies {
  /** Table client. Required; never created here. */
  table: UserSessionTable;
  /** Current time. Defaults to the system clock, in epoch seconds. */
  now?: UserSessionClock;
  /** The 64-character hex pepper key, or `getPepper`. Unused when `verifyDevice` is injected. */
  pepper?: PepperSource;
  /** Overrides the device authenticator; defaults to `verifyDeviceRequest`. */
  verifyDevice?: DeviceVerifier;
}

/** Dependencies, or something that resolves them when the request arrives. */
export type UserSessionDependencySource =
  | UserSessionDependencies
  | (() => UserSessionDependencies | Promise<UserSessionDependencies>);

function failure(statusCode: number, error: string, extra?: Record<string, unknown>): RouteResult {
  return { statusCode, body: { error, ...(extra ?? {}) } };
}

/** Normalise whatever the injected clock returned into a `Date`; a number is epoch seconds. */
function toDate(instant: number | string | Date): Date {
  if (instant instanceof Date) {
    return new Date(instant.getTime());
  }
  if (typeof instant === 'string') {
    return new Date(instant);
  }
  return new Date(instant * 1000);
}

async function resolvePepper(pepper: PepperSource | undefined): Promise<string> {
  if (pepper === undefined) {
    return '';
  }
  return typeof pepper === 'function' ? await pepper() : pepper;
}

/**
 * The reported username: a string of at most `USERNAME_MAX_LENGTH` characters,
 * or `null` when nobody is logged in at the console. `undefined` means the
 * body is not a JSON object carrying a valid `username`.
 */
function readUsername(body: string | null | undefined): string | null | undefined {
  if (typeof body !== 'string' || body.length === 0) {
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return undefined;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return undefined;
  }
  if (!Object.prototype.hasOwnProperty.call(parsed, 'username')) {
    return undefined;
  }
  const username = (parsed as Record<string, unknown>).username;
  if (username === null) {
    return null;
  }
  if (typeof username === 'string' && [...username].length <= USERNAME_MAX_LENGTH) {
    return username;
  }
  return undefined;
}

/** Log the login history's one best-effort failure line. */
function warnLoginHistoryFailure(deviceId: string): void {
  console.warn(JSON.stringify({ msg: 'login history update failed', deviceId }));
}

/** Earliest `lastSeenAt` first; equal instants by the smaller `sk`. */
function byLastSeenAtAscending(a: Item, b: Item): number {
  const left = typeof a.lastSeenAt === 'string' ? a.lastSeenAt : '';
  const right = typeof b.lastSeenAt === 'string' ? b.lastSeenAt : '';
  if (left !== right) {
    return left < right ? -1 : 1;
  }
  const leftSk = typeof a.sk === 'string' ? a.sk : '';
  const rightSk = typeof b.sk === 'string' ? b.sk : '';
  return leftSk < rightSk ? -1 : leftSk > rightSk ? 1 : 0;
}

/** Every `LOGINUSER#` item of the device, following the query cursor to the end. */
async function readLoginUsers(table: UserSessionTable, deviceId: string): Promise<Item[]> {
  // An empty username key yields the device's partition key and the prefix.
  const { pk, sk: loginPrefix } = deviceLoginUser(deviceId, '');
  const items: Item[] = [];
  let cursor: string | null = null;
  do {
    const page: QueryPage = await table.query({
      KeyConditionExpression: '#pk = :pk AND begins_with(#sk, :loginPrefix)',
      ExpressionAttributeNames: { '#pk': 'pk', '#sk': 'sk' },
      ExpressionAttributeValues: { ':pk': pk, ':loginPrefix': loginPrefix },
      cursor,
    });
    items.push(...page.items);
    const next = page.cursor ?? null;
    // A cursor that does not move would page forever; treat it as the end.
    cursor = next === cursor ? null : next;
  } while (cursor !== null);
  return items;
}

/**
 * Upsert the device's login history record for `username`, given the
 * `SIGNEDINUSER` item read before this request overwrote it. Does nothing for
 * a null or blank username. Never throws: a failure is one `console.warn` line.
 */
async function recordLoginHistory(
  table: UserSessionTable,
  deviceId: string,
  username: string | null,
  previous: Item | undefined,
  at: Date,
): Promise<void> {
  if (username === null) {
    return;
  }
  const trimmed = username.trim();
  if (trimmed.length === 0) {
    return;
  }
  try {
    const normalised = normaliseUsername(username);
    const previousNormalised = typeof previous?.username === 'string' ? normaliseUsername(previous.username) : '';
    const becameConsoleUser = previousNormalised.length === 0 || previousNormalised !== normalised;
    const now = isoUtc(at);
    const key = deviceLoginUser(deviceId, loginUserKey(username));

    const existing = await table.get(key);
    if (existing !== undefined && existing !== null) {
      const count =
        typeof existing.loginCount === 'number' && Number.isFinite(existing.loginCount) ? existing.loginCount : 0;
      await table.put({
        ...key,
        deviceId,
        username: trimmed,
        firstSeenAt: existing.firstSeenAt ?? now,
        lastSeenAt: now,
        loginCount: becameConsoleUser ? count + 1 : count,
      });
      return;
    }

    // A new record: make room first when the device is at the cap.
    const stored = await readLoginUsers(table, deviceId);
    if (stored.length >= MAX_LOGIN_USERS_PER_DEVICE) {
      const evict = stored.sort(byLastSeenAtAscending).slice(0, stored.length - MAX_LOGIN_USERS_PER_DEVICE + 1);
      for (const item of evict) {
        await table.delete({ pk: item.pk as string, sk: item.sk as string });
      }
    }
    await table.put({
      ...key,
      deviceId,
      username: trimmed,
      firstSeenAt: now,
      lastSeenAt: now,
      loginCount: 1,
    });
  } catch {
    warnLoginHistoryFailure(deviceId);
  }
}

/**
 * Build the user-session route handler.
 *
 * @param source the dependencies, or a function resolving them on first use
 */
export function createUserSessionHandler(source: UserSessionDependencySource): RouteHandler {
  async function dependencies(): Promise<UserSessionDependencies> {
    return typeof source === 'function' ? await source() : source;
  }

  return async function handleUserSession(req: RouteRequest): Promise<RouteResult> {
    const deps = await dependencies();
    const clock: UserSessionClock = deps.now ?? ((): number => Math.floor(Date.now() / 1000));
    const nowSeconds: EpochSecondsClock = () => Math.floor(toDate(clock()).getTime() / 1000);

    // 1. The signed device.
    const verifyDevice: DeviceVerifier = deps.verifyDevice ?? verifyDeviceRequest;
    const auth = await verifyDevice(req, {
      table: deps.table,
      now: nowSeconds,
      pepper: await resolvePepper(deps.pepper),
    });
    if (!auth.ok) {
      return { statusCode: auth.status, body: auth.body };
    }

    // 2. That it is the device the path names.
    if (auth.deviceId !== (req.params?.deviceId ?? '')) {
      return failure(403, 'device_mismatch');
    }
    const deviceId = auth.deviceId;

    // 3. The body, read only now that its signature has verified.
    const username = readUsername(req.body);
    if (username === undefined) {
      return failure(400, 'invalid_request', { fields: ['username'] });
    }

    // The previous console user, read before the put below overwrites it. A
    // failed read skips the login history for this request.
    let previous: Item | undefined;
    let previousRead = false;
    try {
      previous = await deps.table.get(deviceSignedInUser(deviceId));
      previousRead = true;
    } catch {
      warnLoginHistoryFailure(deviceId);
    }

    await deps.table.put({
      ...deviceSignedInUser(deviceId),
      deviceId,
      username,
      source: SIGNED_IN_USER_SOURCE,
      reportedAt: isoUtc(toDate(clock())),
    });

    if (previousRead) {
      await recordLoginHistory(deps.table, deviceId, username, previous, toDate(clock()));
    }

    await recordDeviceContact(deps.table, deviceId, toDate(clock()));

    return { statusCode: 200, body: { user: { username } } };
  };
}

/** Register both routes on a router. Returns the router, so calls chain. */
export function registerUserSessionRoutes(router: Router, source: UserSessionDependencySource): Router {
  router.add('GET', AGENT_AUTH_CONFIG_PATH, () => handleAgentAuthConfig());
  return router.add('POST', USER_SESSION_PATH, createUserSessionHandler(source));
}

/**
 * Dependencies supplied at start-up by `bootstrap`, so no AWS client is
 * constructed at import time.
 */
let configuredDependencies: UserSessionDependencies | null = null;

/** Supply the user-session route's storage, clock and pepper. */
export function configureUserSessionRoute(dependencies: UserSessionDependencies): void {
  configuredDependencies = dependencies;
}

/** The configured dependencies, or a thrown error when start-up skipped them. */
export function resolveUserSessionDependencies(): UserSessionDependencies {
  if (configuredDependencies === null) {
    throw new Error('user-session route is not configured: call configureUserSessionRoute() at start-up');
  }
  return configuredDependencies;
}
