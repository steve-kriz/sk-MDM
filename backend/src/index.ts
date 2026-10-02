/**
 * Lambda Function URL entry point.
 *
 * This module owns the single application router; later tickets register their
 * routes on the exported `router` and need no change here.
 */
import { registerDeviceRoutes } from './admin/devices.js';
import { registerAuditRoutes, resolveAdminDependencies } from './admin/router.js';
import { createRouter, type Router, type RouterRequest, type RouterResponse } from './http/router.js';
import { registerCheckInRoute, resolveCheckInDependencies } from './routes/checkin.js';
import { registerCommandRoutes, type CommandRouteDeps } from './routes/commands.js';

import { registerEnrollRoute, resolveEnrollDependencies } from './routes/enroll.js';

/** The subset of the Lambda Function URL (payload format 2.0) event we use. */
export interface FunctionUrlEvent {
  requestContext: {
    http: {
      method: string;
      path: string;
    };
  };
  rawQueryString?: string;
  headers?: Record<string, string | undefined>;
  body?: string | null;
  isBase64Encoded?: boolean;
}

export interface FunctionUrlResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
}

/** The application router. Register routes with `router.add(method, pattern, handler)`. */
export const router: Router = createRouter();

// The agent command queue. Its dependencies -- the table client and the
// pepper -- come from the deployment wiring, which hands them over once per
// cold start; they are resolved per request so registration never depends on
// the order the module graph loads in.
let commandRouteDeps: CommandRouteDeps | null = null;

/** Supply the dependencies the agent command routes run with. */
export function setCommandRouteDeps(deps: CommandRouteDeps): void {
  commandRouteDeps = deps;
}

registerCommandRoutes(router, () => {
  if (commandRouteDeps === null) {
    throw new Error('command route dependencies are not configured');
  }
  return commandRouteDeps;
});

// --- TASK-006: POST /api/v1/enroll -----------------------------------------
// Registered outside the device HMAC scheme: enroll is authenticated by its
// `X-MDM-Enrollment-Token` alone. Dependencies are resolved on each request so
// no AWS client is constructed at import time; start-up calls
// `configureEnrollRoute({ table, pepper })` before the first request.
registerEnrollRoute(router, resolveEnrollDependencies);
export { ENROLL_PATH, configureEnrollRoute, createEnrollHandler, registerEnrollRoute } from './routes/enroll.js';
export type { EnrollDependencies, EnrollTable, PepperSource } from './routes/enroll.js';
// --- end TASK-006 ----------------------------------------------------------

// --- TASK-007: POST /api/v1/devices/{deviceId}/checkin ---------------------
// The agent heartbeat. Authenticated inside the handler by `verifyDeviceRequest`,
// so it needs no wiring here beyond its dependencies, which are resolved on each
// request: start-up calls `configureCheckInRoute({ table, pepper })` before the
// first request so no AWS client is constructed at import time.
registerCheckInRoute(router, resolveCheckInDependencies);
export {
  CHECKIN_PATH,
  MAX_BODY_BYTES,
  MAX_SOFTWARE_ENTRIES,
  configureCheckInRoute,
  createCheckInHandler,
  registerCheckInRoute,
} from './routes/checkin.js';
export type { CheckInDependencies, CheckInTable } from './routes/checkin.js';
// --- end TASK-007 ----------------------------------------------------------

// --- TASK-010: GET /admin/api/v1/* ------------------------------------------
// The admin read surface, every route behind the Entra token verifier. Its
// dependencies -- the verifier, the table client and the clock -- are resolved
// on each request, so nothing is constructed at import time; start-up calls
// `configureAdminRoutes({ verifier, table, now })` before the first request.
// A later admin route registers itself the same way, with
// `registerAdminRoute(router, method, subPath, handler, resolveAdminDependencies)`.
registerDeviceRoutes(router, resolveAdminDependencies);
registerAuditRoutes(router, resolveAdminDependencies);
export {
  DEVICE_DETAIL_PATH,
  DEVICE_LIST_PATH,
  DEVICE_SUMMARY_FIELDS,
  MAX_DETAIL_COMMANDS,
  STALE_AFTER_MILLIS,
  UNKNOWN_COMPLIANCE,
  deviceSummary,
  handleDeviceDetail,
  handleDeviceList,
  registerDeviceRoutes,
} from './admin/devices.js';
export {
  ADMIN_PREFIX,
  AUDIT_PATH,
  BEARER_PREFIX,
  DEFAULT_LIMIT,
  MAX_LIMIT,
  adminPath,
  configureAdminRoutes,
  handleAuditQuery,
  parseLimit,
  registerAdminRoute,
  registerAuditRoutes,
  requireAdmin,
  resolveAdminDependencies,
} from './admin/router.js';
export type {
  AdminClock,
  AdminDependencies,
  AdminDependencySource,
  AdminRequest,
  AdminRouteHandler,
  AdminTable,
} from './admin/router.js';
export {
  AUDIT_DEFAULT_LIMIT,
  AUDIT_MAX_DAYS_PER_PAGE,
  AUDIT_MAX_LIMIT,
  SEQ_PATTERN,
  appendAudit,
  auditSeq,
  isoUtc,
  queryAudit,
  utcDay,
} from './audit.js';
export type { AuditPage, AuditQuery, AuditQueryTable } from './audit.js';
// --- end TASK-010 ----------------------------------------------------------

function parseQuery(rawQueryString: string | undefined): Record<string, string> {
  const query: Record<string, string> = {};
  if (!rawQueryString) {
    return query;
  }
  for (const [key, value] of new URLSearchParams(rawQueryString)) {
    query[key] = value;
  }
  return query;
}

function normaliseHeaders(headers: Record<string, string | undefined> | undefined): Record<string, string> {
  const normalised: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (value !== undefined) {
      normalised[key.toLowerCase()] = value;
    }
  }
  return normalised;
}

function decodeBody(event: FunctionUrlEvent): string | null {
  const body = event.body;
  if (body === undefined || body === null) {
    return null;
  }
  if (event.isBase64Encoded === true) {
    return Buffer.from(body, 'base64').toString('utf8');
  }
  return body;
}

/** Translate a Function URL event into the router's request shape. */
export function toRouterRequest(event: FunctionUrlEvent): RouterRequest {
  return {
    method: event.requestContext.http.method,
    path: event.requestContext.http.path,
    query: parseQuery(event.rawQueryString),
    headers: normaliseHeaders(event.headers),
    body: decodeBody(event),
  };
}

export async function handler(event: FunctionUrlEvent): Promise<FunctionUrlResponse> {
  let response: RouterResponse;
  try {
    response = await router.handle(toRouterRequest(event));
  } catch (error) {
    // The router handles route errors itself; this only fires on a malformed event.
    const text = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
    console.error(`[handler] request could not be adapted: ${text.replace(/[\r\n]+/g, ' ')}`);
    return {
      statusCode: 500,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ error: 'internal_error' }),
    };
  }

  return {
    statusCode: response.statusCode,
    headers: { ...response.headers, 'content-type': 'application/json' },
    body: response.body,
  };
}

export { createRouter } from './http/router.js';
export {
  ADMIN_ROLE,
  CLOCK_SKEW_SECONDS,
  DEFAULT_CACHE_TTL_SECONDS,
  SIGNING_ALGORITHM,
  createTokenVerifier,
  isVerifyFailure,
} from './auth/entra.js';
export type {
  EpochSecondsClock,
  JwksDocument,
  JwksFetcher,
  TokenClaims,
  TokenVerifier,
  TokenVerifierOptions,
  VerifyFailure,
} from './auth/entra.js';
export type {
  RouteHandler,
  RouteRequest,
  RouteResult,
  Router,
  RouterRequest,
  RouterResponse,
} from './http/router.js';
