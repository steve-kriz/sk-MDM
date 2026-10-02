/**
 * Lambda Function URL entry point.
 *
 * This module owns the single application router; later tickets register their
 * routes on the exported `router` and need no change here.
 */
import { registerAgentReleaseRoutes } from './admin/agentRelease.js';
import { registerCommandDispatchRoutes } from './admin/commandDispatch.js';
import { registerDeviceRoutes } from './admin/devices.js';
import { registerEnrollmentTokenRoutes } from './admin/enrollmentTokens.js';
import { registerGroupRoutes } from './admin/groups.js';
import { registerPolicyRoutes } from './admin/policies.js';
import { registerAuditRoutes, resolveAdminDependencies } from './admin/router.js';
import { registerUserLinkRoutes } from './admin/userLinks.js';
import { createRouter, type Router, type RouterRequest, type RouterResponse } from './http/router.js';
import { registerCheckInRoute, resolveCheckInDependencies } from './routes/checkin.js';
import { registerCommandRoutes, type CommandRouteDeps } from './routes/commands.js';
import { registerDownloadRoute, resolveDownloadDependencies } from './routes/downloads.js';
import { registerPolicyBundleRoute, resolvePolicyBundleDependencies } from './routes/policies.js';

import { registerEnrollRoute, resolveEnrollDependencies } from './routes/enroll.js';
import { registerUiRoutes } from './ui/index.js';

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

// --- TASK-011: POST /admin/api/v1/* -----------------------------------------
// The admin write surface -- groups, enrollment tokens and command dispatch --
// registered behind the same token verifier and resolving the same injected
// dependencies as the read routes, so start-up still configures everything with
// one `configureAdminRoutes({ verifier, table, now, randomBytes })` call.
registerGroupRoutes(router, resolveAdminDependencies);
registerEnrollmentTokenRoutes(router, resolveAdminDependencies);
registerCommandDispatchRoutes(router, resolveAdminDependencies);
export {
  GROUP_CREATED_ACTION,
  GROUP_ID_PREFIX,
  GROUP_MEMBERS_ADDED_ACTION,
  GROUP_MEMBERS_PATH,
  GROUP_PATH,
  GROUP_SUMMARY_FIELDS,
  groupSummary,
  handleGroupCreate,
  handleGroupList,
  handleGroupMembersAdd,
  readGroupMemberIds,
  registerGroupRoutes,
} from './admin/groups.js';
export {
  ENROLLMENT_TOKEN_CREATED_ACTION,
  ENROLLMENT_TOKEN_PATH,
  TOKEN_ID_BYTES,
  TOKEN_SECRET_BYTES,
  TOKEN_SEPARATOR,
  handleEnrollmentTokenCreate,
  registerEnrollmentTokenRoutes,
} from './admin/enrollmentTokens.js';
export {
  COMMAND_ID_PREFIX,
  COMMAND_QUEUED_ACTION,
  COMMAND_TTL_MILLIS,
  COMMAND_TYPES,
  CONFIRM_REQUIRED_TYPES,
  DEVICE_COMMAND_PATH,
  GROUP_COMMAND_PATH,
  SCRIPT_INTERPRETERS,
  handleDeviceCommandCreate,
  handleGroupCommandCreate,
  offendingPayloadFields,
  registerCommandDispatchRoutes,
} from './admin/commandDispatch.js';
export {
  adminActor,
  adminNow,
  adminRandomBytes,
  adminWriteTable,
  readJsonBody,
  toAdminDate,
} from './admin/router.js';
export type { AdminRandomBytes, AdminWriteTable } from './admin/router.js';
// --- end TASK-011 ----------------------------------------------------------

// --- TASK-012: policies and compliance --------------------------------------
// Two surfaces over one entity. The admin routes -- create, version, assign and
// the per-policy compliance view -- register behind the same token verifier and
// resolve the same injected dependencies as every other admin route.
// `GET /api/v1/devices/{deviceId}/policies` is an agent route instead: it is
// authenticated inside its handler by `verifyDeviceRequest` and resolves its own
// dependencies on each request, so start-up calls
// `configurePolicyBundleRoute({ table, pepper })` before the first request and
// no AWS client is constructed at import time.
registerPolicyRoutes(router, resolveAdminDependencies);
registerPolicyBundleRoute(router, resolvePolicyBundleDependencies);
export {
  FIRST_POLICY_VERSION,
  OS_UPDATE_MAX_AGE_DAYS,
  POLICY_ASSIGNED_ACTION,
  POLICY_ASSIGNMENT_PATH,
  POLICY_COMPLIANCE_PATH,
  POLICY_CREATED_ACTION,
  POLICY_DETAIL_PATH,
  POLICY_ID_PREFIX,
  POLICY_PATH,
  POLICY_SETTING_KEYS,
  POLICY_UNASSIGNED_ACTION,
  POLICY_UPDATED_ACTION,
  SCREEN_LOCK_TIMEOUT_SECONDS,
  handlePolicyAssign,
  handlePolicyCompliance,
  handlePolicyCreate,
  handlePolicyUnassign,
  handlePolicyUpdate,
  offendingSettingsFields,
  registerPolicyRoutes,
} from './admin/policies.js';
export {
  POLICY_BUNDLE_PATH,
  configurePolicyBundleRoute,
  createPolicyBundleHandler,
  registerPolicyBundleRoute,
} from './routes/policies.js';
export type { PolicyBundleDependencies, PolicyBundleTable } from './routes/policies.js';
export { mergePolicySettings } from './policies/merge.js';
export type { MergedPolicies, PolicyConflict, PolicyDocument } from './policies/merge.js';
export {
  COMPLIANT_STATE,
  NONCOMPLIANT_STATE,
  UNKNOWN_STATE,
  computeComplianceState,
  readAssignedPolicies,
  readAssignedPolicyIds,
  readComplianceResults,
  readDeviceGroupIds,
  readGroupPolicyIds,
  readPolicyGroupIds,
} from './policies/resolve.js';
export type { ComplianceResult, ComplianceState, PolicyReadTable } from './policies/resolve.js';
// --- end TASK-012 ----------------------------------------------------------

// --- TASK-013: the admin console --------------------------------------------
// The single page, its browser modules and the public client configuration,
// served by this same Lambda. Nothing here is behind the token verifier and
// nothing here holds a session: the browser runs the OIDC authorization-code
// flow with PKCE itself and calls `/admin/api/v1/*` with the resulting bearer
// token. The static responses use the router's `rawBody` pass-through, so they
// keep their own content-types while every API route stays JSON.
registerUiRoutes(router);
export {
  ADMIN_PATH,
  ASSET_PATH,
  CONFIG_PATH,
  CONTENT_TYPES,
  INDEX_FILE,
  INDEX_PATH,
  LANDING_FILE,
  PUBLIC_ASSET_PATH,
  PUBLIC_DIR,
  SECURITY_HEADERS,
  VIEWS_DIR,
  VIEW_ASSET_PATH,
  handleAdmin,
  handleConfig,
  handleIndex,
  registerUiRoutes,
  serveAsset,
} from './ui/index.js';
export { ADMIN_SCOPE_NAME, CONFIG_KEYS, adminClientConfig, adminScope } from './ui/config.js';
export type { AdminClientConfig, ConfigEnv } from './ui/config.js';
export { collectionUrl } from './ui/settings.js';
export type { SettingsEnv } from './ui/settings.js';
// --- end TASK-013 ----------------------------------------------------------

// --- TASK-022: agent self-update --------------------------------------------
// Publishing a build is an admin write like any other: behind the same token
// verifier, resolving the same injected dependencies. Nothing else is wired
// here -- the build is advertised by the check-in route, which reads the
// published record itself.
registerAgentReleaseRoutes(router, resolveAdminDependencies);
export {
  AGENT_RELEASE_PATH,
  AGENT_RELEASE_PUBLISHED_ACTION,
  handleAgentReleasePublish,
  offendingReleaseFields,
  registerAgentReleaseRoutes,
} from './admin/agentRelease.js';
// --- end TASK-022 ----------------------------------------------------------

// --- TASK-025: GET /downloads/{platform} -------------------------------------
// Public, outside both the device HMAC scheme and the admin token verifier: the
// landing page's download links. Dependencies are resolved per request so no
// S3 client is constructed at import time; start-up calls
// `configureDownloadRoute({ bucket, installers })`.
registerDownloadRoute(router, resolveDownloadDependencies);
export {
  DOWNLOAD_PATH,
  DOWNLOAD_PLATFORMS,
  DOWNLOAD_URL_TTL_SECONDS,
  configureDownloadRoute,
  createDownloadHandler,
  installerKey,
  isDownloadPlatform,
  registerDownloadRoute,
  resolveDownloadDependencies,
} from './routes/downloads.js';
export type { DownloadDependencies, DownloadPlatform, InstallerStore } from './routes/downloads.js';
// --- end TASK-025 ----------------------------------------------------------
// --- TASK-027: Entra user links through Microsoft Graph ---------------------
// Two admin writes behind the same token verifier. Graph arrives as the
// optional `graph` admin dependency (built by bootstrap from the environment);
// when it is absent both routes answer 503 `graph_not_configured`.
registerUserLinkRoutes(router, resolveAdminDependencies);
export {
  DEVICE_USER_LINK_REFRESHED_ACTION,
  DEVICE_USER_LINK_REFRESH_PATH,
  USER_LINKS_DEFAULT_LIMIT,
  USER_LINKS_MAX_LIMIT,
  USER_LINKS_REFRESHED_ACTION,
  USER_LINKS_REFRESH_PATH,
  USER_LINK_STATUSES,
  handleDeviceUserLinkRefresh,
  handleUserLinksBulkRefresh,
  lookupName,
  registerUserLinkRoutes,
  resolveUserLink,
  userLinkTable,
} from './admin/userLinks.js';
export type { UserLinkStatus, UserLinkTable, UserLinkUser } from './admin/userLinks.js';
export {
  DEFAULT_GRAPH_SECRET_KEY,
  DEFAULT_GRAPH_TIMEOUT_MILLIS,
  GRAPH_BASE_URL,
  GRAPH_SCOPE,
  GRAPH_USER_TYPE,
  MAX_GRAPH_PAGES,
  TOKEN_EXPIRY_LEEWAY_SECONDS,
  createGraphClient,
  createGraphDirectoryFromEnv,
  createGraphSecretProvider,
  isGraphFailure,
  odataString,
  tokenUrl,
} from './graph/client.js';
export type {
  ClientSecretSource,
  GraphClientOptions,
  GraphClock,
  GraphDevice,
  GraphDirectory,
  GraphDirectoryDependencies,
  GraphFailure,
  GraphFetch,
  GraphFetchInit,
  GraphFetchResponse,
  GraphSecretProviderOptions,
  GraphUser,
} from './graph/client.js';
export { deviceUserLink } from './db/keys.js';
// --- end TASK-027 ----------------------------------------------------------

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
    headers: withDefaultContentType(response.headers),
    body: response.body,
  };
}

/**
 * JSON is the default, never an override: a route that named its own
 * content-type (the UI's HTML, CSS and script responses) keeps it, and every
 * route that named none is answered as `application/json`, as all of them were
 * before the UI existed.
 */
function withDefaultContentType(headers: Record<string, string>): Record<string, string> {
  const named = Object.keys(headers).some((key) => key.toLowerCase() === 'content-type');
  return named ? { ...headers } : { ...headers, 'content-type': 'application/json' };
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
