/**
 * Agent user sign-in: the public sign-in configuration and the signed-in user
 * report.
 *
 *   GET  /api/v1/agent-auth/config
 *   -> {"tenantId":"t-1","clientId":"c-1","scopes":["api://c-1/MDM.Agent","offline_access","openid","profile"]}
 *
 *   POST /api/v1/devices/{deviceId}/user-session   (device HMAC + Authorization: Bearer <user token>)
 *   -> {"user":{"oid":"o-1","upn":"amy@contoso.com","name":"Amy"}}
 *
 * The config route is unauthenticated: it publishes only what a public client
 * needs to start the device authorization grant, built key by key so no other
 * environment value (`ENTRA_ADMIN_GROUP_ID`, `PEPPER_SECRET_ARN`) can leak.
 *
 * The user-session route runs its checks in a fixed order and the first
 * failure returns immediately, having written nothing beyond the nonce
 * `verifyDeviceRequest` burns:
 *
 *   1. `verifyDeviceRequest`          -> its own `{status, body}`, unchanged
 *   2. path device == signed device   -> 403 device_mismatch
 *   3. `Authorization: Bearer <token>` -> 403 user_token_missing
 *   4. verifier rejects with 503      -> 503 jwks_unavailable
 *   5. any other verifier rejection   -> 403 user_token_invalid
 *
 * No bearer problem ever answers 401: the agent reads any 401 as "the device
 * credential was rejected" and re-enrolls. The raw token is never logged,
 * stored or echoed.
 */
import { isoUtc } from '../audit.js';
import { AGENT_SCOPE_NAME } from '../auth/userToken.js';
import { deviceSignedInUser, type TableKey } from '../db/keys.js';
import type { Item, RequestFields, WriteOutcome } from '../db/table.js';
import { verifyDeviceRequest, type DeviceAuthResult, type EpochSecondsClock } from '../http/deviceAuth.js';
import type { RouteHandler, RouteRequest, RouteResult, Router, RouterRequest } from '../http/router.js';
import { isVerifyFailure, type TokenClaims } from '../auth/jwtCore.js';

/** Path of the public agent sign-in configuration. */
export const AGENT_AUTH_CONFIG_PATH = '/api/v1/agent-auth/config';

/** Path the agent reports its signed-in user on. */
export const USER_SESSION_PATH = '/api/v1/devices/{deviceId}/user-session';

/** The authorization scheme the user token is carried under, compared case-insensitively. */
const BEARER_SCHEME = 'bearer ';

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
 * only because `verifyDeviceRequest` reads the profile and burns a nonce.
 */
export interface UserSessionTable {
  get(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
  put(item: Item, fields?: RequestFields): Promise<void>;
  putIfAbsent(item: Item, fields?: RequestFields): Promise<WriteOutcome>;
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

/** Verifies the user's bearer token; `createUserTokenVerifier` fits. */
export interface UserVerifier {
  verify(token: string): Promise<TokenClaims>;
}

export interface UserSessionDependencies {
  /** Table client. Required; never created here. */
  table: UserSessionTable;
  /** Verifies the agent user token. Required. */
  userVerifier: UserVerifier;
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

function failure(statusCode: number, error: string): RouteResult {
  return { statusCode, body: { error } };
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

/** The `authorization` header value, whatever case its name arrived in. */
function authorizationHeader(headers: Record<string, string> | undefined): string | undefined {
  if (headers === undefined || headers === null) {
    return undefined;
  }
  for (const [name, value] of Object.entries(headers)) {
    if (name.toLowerCase() === 'authorization') {
      return value;
    }
  }
  return undefined;
}

/** The bearer token, or `null` when the header is absent or not `Bearer <non-empty>`. */
function readBearer(header: string | undefined): string | null {
  if (typeof header !== 'string' || header.length <= BEARER_SCHEME.length) {
    return null;
  }
  if (header.slice(0, BEARER_SCHEME.length).toLowerCase() !== BEARER_SCHEME) {
    return null;
  }
  const token = header.slice(BEARER_SCHEME.length).trim();
  return token.length > 0 ? token : null;
}

function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
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

    // 3. The bearer token.
    const token = readBearer(authorizationHeader(req.headers));
    if (token === null) {
      return failure(403, 'user_token_missing');
    }

    // 4./5. The token itself. The rejection reason is not echoed: the agent
    // only needs to know whether to retry later or refresh its token.
    let claims: TokenClaims;
    try {
      claims = await deps.userVerifier.verify(token);
    } catch (rejection) {
      if (isVerifyFailure(rejection) && rejection.status === 503) {
        return failure(503, 'jwks_unavailable');
      }
      return failure(403, 'user_token_invalid');
    }

    const oid = claims.oid as string;
    const tid = claims.tid as string;
    const upn = stringOrNull(claims.preferred_username);
    const name = stringOrNull(claims.name);
    const exp = claims.exp as number;

    await deps.table.put({
      ...deviceSignedInUser(deviceId),
      deviceId,
      oid,
      tid,
      upn,
      name,
      verifiedAt: isoUtc(toDate(clock())),
      tokenExpiresAt: isoUtc(new Date(exp * 1000)),
    });

    return { statusCode: 200, body: { user: { oid, upn, name } } };
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

/** Supply the user-session route's storage, clock, pepper and user token verifier. */
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
