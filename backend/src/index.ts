/**
 * Lambda Function URL entry point.
 *
 * This module owns the single application router; later tickets register their
 * routes on the exported `router` and need no change here.
 */
import { gunzipSync, gzipSync } from 'node:zlib';
import { registerAgentReleaseRoutes } from './admin/agentRelease.js';
import { registerAnalyticsRoutes } from './admin/analytics.js';
import { registerCommandDispatchRoutes } from './admin/commandDispatch.js';
import { registerCommandSettingsRoutes } from './admin/commandSettings.js';
import { registerScriptRoutes } from './admin/scripts.js';
import { registerApplicationAdminRoutes } from './admin/applications.js';
import { registerApplicationRoutes, resolveApplicationDependencies } from './routes/applications.js';
import { registerDeviceRoutes } from './admin/devices.js';
import { registerEnrollmentTokenRoutes } from './admin/enrollmentTokens.js';
import { registerGroupRoutes } from './admin/groups.js';
import { registerPolicyRoutes } from './admin/policies.js';
import { registerAuditRoutes, resolveAdminDependencies } from './admin/router.js';
import { registerSoftwareRoutes } from './admin/software.js';
import { createRouter, type Router, type RouterRequest, type RouterResponse } from './http/router.js';
import { registerCheckInRoute, resolveCheckInDependencies } from './routes/checkin.js';
import { registerCommandRoutes, type CommandRouteDeps } from './routes/commands.js';
import { registerDownloadRoute, resolveDownloadDependencies } from './routes/downloads.js';
import { registerPolicyBundleRoute, resolvePolicyBundleDependencies } from './routes/policies.js';

import { registerEnrollRoute, resolveEnrollDependencies } from './routes/enroll.js';
import { registerUserSessionRoutes, resolveUserSessionDependencies } from './routes/userSession.js';
import { registerHeartbeatRoute, resolveHeartbeatDependencies } from './routes/heartbeat.js';
import { registerHeartbeatAdminRoutes } from './admin/heartbeat.js';
import { registerAgentSignInRoutes, resolveAgentSignInDependencies } from './routes/agentSignIn.js';
import {
  registerAgentEnrollmentTokenRoute,
  resolveAgentEnrollmentTokenDependencies,
} from './routes/agentEnrollmentToken.js';
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
  /** True when `body` is base64 (a gzip-compressed response). */
  isBase64Encoded?: boolean;
}

/**
 * The most a gzip request body may inflate to. Inflation stops at this cap, so
 * a decompression bomb costs at most this much memory; a body that would grow
 * beyond it is answered 413 `payload_too_large` before any route runs.
 */
export const MAX_INFLATED_BODY_BYTES = 1048576;

/** The smallest `/api/v1/*` response body that is gzip-compressed. */
export const COMPRESS_MIN_BYTES = 1024;

/** The response header that tells the agent gzip request bodies are accepted. */
export const ACCEPT_CONTENT_ENCODING_HEADER = 'x-mdm-accept-content-encoding';

/** The path prefix whose responses may be compressed: the agent API only. */
const COMPRESSIBLE_PATH_PREFIX = '/api/v1/';

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
// Registered outside the device HMAC scheme: enroll is authenticated by the
// `X-MDM-Enrollment-Token` only (admin-minted, or minted by the agent sign-in
// at `POST /api/v1/agent-auth/enrollment-token`). Dependencies are resolved on
// each request so no AWS client is constructed at import time; start-up calls
// `configureEnrollRoute({ table, pepper })` before the first request.
registerEnrollRoute(router, resolveEnrollDependencies);
export {
  DEFAULT_OWNERSHIP,
  ENROLL_PATH,
  OWNERSHIP_VALUES,
  configureEnrollRoute,
  createEnrollHandler,
  registerEnrollRoute,
} from './routes/enroll.js';
export type { EnrollDependencies, EnrollTable, EnrolledBy, PepperSource } from './routes/enroll.js';
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
registerAnalyticsRoutes(router, resolveAdminDependencies);
registerSoftwareRoutes(router, resolveAdminDependencies);
registerAuditRoutes(router, resolveAdminDependencies);
export {
  ANALYTICS_COLLECTION_CHANGED_ACTION,
  ANALYTICS_COLLECTION_PATH,
  ANALYTICS_DEFAULT_TOP,
  ANALYTICS_DEFAULT_WINDOW_DAYS,
  ANALYTICS_MAX_QUERY_PAGES,
  ANALYTICS_MAX_TOP,
  ANALYTICS_MAX_WINDOW_DAYS,
  ANALYTICS_PATH,
  HIGH_MEMORY_USED_PERCENT,
  LOW_DISK_FREE_PERCENT,
  MAX_DETAIL_CRASHES,
  handleAnalyticsCollectionSet,
  handleFleetAnalytics,
  registerAnalyticsRoutes,
} from './admin/analytics.js';
export {
  SOFTWARE_DEVICES_PATH,
  SOFTWARE_MAX_QUERY_PAGES,
  SOFTWARE_PATH,
  handleSoftwareDevices,
  handleSoftwareList,
  registerSoftwareRoutes,
} from './admin/software.js';
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
// TASK-045: the command library and the fleet-wide on-failure setting.
registerScriptRoutes(router, resolveAdminDependencies);
// TASK-049: the application safe list.
registerApplicationAdminRoutes(router, resolveAdminDependencies);
registerCommandSettingsRoutes(router, resolveAdminDependencies);
export {
  AUTO_ASSIGN_OWNERSHIPS,
  GROUP_AUTO_ASSIGN_CHANGED_ACTION,
  GROUP_AUTO_ASSIGN_PATH,
  applyAutoAssignGroups,
  effectiveAutoAssign,
  handleGroupAutoAssign,
  readLegacyAutoAssign,
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
  CANCELLED_STATUS,
  COMMAND_CANCELLED_ACTION,
  COMMAND_CANCEL_PATH,
  COMMAND_MOVED_ACTION,
  COMMAND_MOVE_PATH,
  DEVICE_SCRIPT_PATH,
  DEVICE_APPLICATION_PATH,
  GROUP_SCRIPT_PATH,
  INSTALL_APPLICATION_TIMEOUT_SECONDS,
  INSTALL_APPLICATION_TYPE,
  MOVE_DIRECTIONS,
  handleCommandCancel,
  handleCommandMove,
  handleDeviceApplicationQueue,
  handleDeviceCommandCreate,
  handleDeviceScriptQueue,
  handleGroupCommandCreate,
  handleGroupScriptQueue,
  offendingPayloadFields,
  registerCommandDispatchRoutes,
} from './admin/commandDispatch.js';
export {
  DEFAULT_SCRIPT_TIMEOUT_SECONDS,
  INTERPRETER_PLATFORMS,
  LIBRARY_INTERPRETERS,
  SCRIPT_CREATED_ACTION,
  SCRIPT_DELETED_ACTION,
  SCRIPT_DETAIL_PATH,
  SCRIPT_ID_PREFIX,
  SCRIPT_MAX_BYTES,
  SCRIPT_PATH,
  SCRIPT_PLATFORMS,
  SCRIPT_UPDATED_ACTION,
  handleScriptCreate,
  handleScriptDelete,
  handleScriptGet,
  handleScriptList,
  handleScriptUpdate,
  readScript,
  readScriptFields,
  registerScriptRoutes,
  scriptRecord,
} from './admin/scripts.js';
export {
  COMMAND_SETTINGS_PATH,
  COMMAND_SETTINGS_UPDATED_ACTION,
  DEFAULT_ON_FAILURE,
  ON_FAILURE_VALUES,
  handleCommandSettingsGet,
  handleCommandSettingsPut,
  readCommandSettings,
  registerCommandSettingsRoutes,
} from './admin/commandSettings.js';
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
// Two surfaces over one entity. The admin routes -- create, list, re-index,
// version, assign and the per-policy compliance view -- register behind the same token verifier and
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
  POLICY_REINDEX_PATH,
  POLICY_REINDEXED_ACTION,
  POLICY_SETTING_KEYS,
  POLICY_SUMMARY_FIELDS,
  POLICY_UNASSIGNED_ACTION,
  POLICY_UPDATED_ACTION,
  SCREEN_LOCK_TIMEOUT_SECONDS,
  handlePolicyAssign,
  handlePolicyCompliance,
  handlePolicyCreate,
  handlePolicyList,
  handlePolicyReindex,
  handlePolicyUnassign,
  handlePolicyUpdate,
  offendingSettingsFields,
  policySummary,
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
export { ADMIN_SCOPE_NAME, CONFIG_KEYS, adminClientConfig, adminScope, publicHost } from './ui/config.js';
export { USER_SCOPE_NAME, userClientConfig, userScope } from './ui/config.js';
export {
  APPLICATIONS_CONFIG_PATH,
  APPLICATIONS_FILE,
  APPLICATIONS_PATH,
  handleApplications,
  handleApplicationsConfig,
} from './ui/index.js';
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
// `configureDownloadRoute({ bucket, installers })`. Also registers the public
// `GET /api/v1/downloads`, the published version shown next to each link.
registerDownloadRoute(router, resolveDownloadDependencies);
export {
  DOWNLOAD_PATH,
  DOWNLOAD_PLATFORMS,
  DOWNLOAD_URL_TTL_SECONDS,
  DOWNLOAD_VERSIONS_PATH,
  configureDownloadRoute,
  createDownloadHandler,
  createDownloadVersionsHandler,
  installerKey,
  isDownloadPlatform,
  registerDownloadRoute,
  resolveDownloadDependencies,
  versionFromContentDisposition,
} from './routes/downloads.js';
export type { DownloadDependencies, DownloadPlatform, InstallerStore } from './routes/downloads.js';
// --- end TASK-025 ----------------------------------------------------------

// --- TASK-049: application safe list ----------------------------------------
// The signed-in user routes (bearer, `MDM.User`) and the device-signed download
// details route. Dependencies are resolved per request; start-up calls
// `configureApplicationRoutes({ table, pepper, now, userVerifier, installers })`.
registerApplicationRoutes(router, resolveApplicationDependencies);
export {
  APPLICATION_DEVICE_DOWNLOAD_TTL_SECONDS,
  APPLICATION_USER_DOWNLOAD_TTL_SECONDS,
  DEVICE_APPLICATION_DOWNLOAD_PATH,
  USER_APPLICATIONS_PATH,
  USER_APPLICATION_DOWNLOAD_PATH,
  configureApplicationRoutes,
  createDeviceApplicationDownloadHandler,
  createUserApplicationDownloadHandler,
  createUserApplicationListHandler,
  registerApplicationRoutes,
  resolveApplicationDependencies,
  userApplicationItem,
} from './routes/applications.js';
export type { ApplicationDependencies, ApplicationTable, ApplicationUserVerifier } from './routes/applications.js';
export {
  APPLICATION_CREATED_ACTION,
  APPLICATION_DELETED_ACTION,
  APPLICATION_DETAIL_PATH,
  APPLICATION_HASH_RETRIED_ACTION,
  APPLICATION_HASH_STALE_SECONDS,
  APPLICATION_ID_PREFIX,
  APPLICATION_INSTALLER_TYPES,
  APPLICATION_PATH,
  APPLICATION_RETRY_HASH_PATH,
  APPLICATION_UPLOAD_MAX_BYTES,
  APPLICATION_UPLOAD_URL_PATH,
  APPLICATION_UPLOAD_URL_TTL_SECONDS,
  INSTALLER_TYPE_PLATFORMS,
  applicationHashStatus,
  applicationRecord,
  handleApplicationCreate,
  handleApplicationDelete,
  handleApplicationList,
  handleApplicationRetryHash,
  handleApplicationUploadUrl,
  isApplicationFileName,
  readApplication,
  readApplicationFields,
  registerApplicationAdminRoutes,
} from './admin/applications.js';
export { APP_USER_SCOPE_NAME, createAppUserTokenVerifier } from './auth/userToken.js';
export { application, applicationListIndex } from './db/keys.js';
// --- end TASK-049 ----------------------------------------------------------
// --- TASK-031: agent user sign-in -------------------------------------------
// `GET /api/v1/agent-auth/config` is public: it publishes the tenant, client
// and scopes the agent's device authorization grant needs. The user-session
// route is a device route authenticated inside its handler by
// `verifyDeviceRequest` only (Amendment B): it records the operating-system
// user the agent reports. Its dependencies are resolved on each request:
// start-up calls `configureUserSessionRoute({ table, pepper, now })`.
registerUserSessionRoutes(router, resolveUserSessionDependencies);
export {
  AGENT_AUTH_CONFIG_PATH,
  USER_SESSION_PATH,
  agentAuthConfig,
  configureUserSessionRoute,
  createUserSessionHandler,
  registerUserSessionRoutes,
  resolveUserSessionDependencies,
} from './routes/userSession.js';
export type {
  AgentAuthConfig,
  UserSessionDependencies,
  UserSessionTable,
} from './routes/userSession.js';
export { AGENT_SCOPE_NAME, createUserTokenVerifier } from './auth/userToken.js';
export type { UserTokenVerifier, UserTokenVerifierOptions } from './auth/userToken.js';
export { deviceLoginUser, deviceSignedInUser } from './db/keys.js';
// --- end TASK-031 ----------------------------------------------------------

// --- Amendment A: agent sign-in brokered by the MDM site --------------------
// Four public routes: the agent creates a PKCE sign-in session and polls it;
// the browser goes through `/agent/signin/{sessionId}` to Entra and back to
// `/agent/callback`, which stores the authorization code on the session. The
// code is useless without the verifier, which never leaves the device.
// Dependencies are resolved per request: start-up calls
// `configureAgentSignInRoutes({ table })`.
registerAgentSignInRoutes(router, resolveAgentSignInDependencies);
export {
  AGENT_CALLBACK_PATH,
  AGENT_SIGNIN_LIFETIME_SECONDS,
  AGENT_SIGNIN_PAGE_PATH,
  AGENT_SIGNIN_SESSIONS_PATH,
  AGENT_SIGNIN_SESSION_ID_BYTES,
  AGENT_SIGNIN_SESSION_PATH,
  configureAgentSignInRoutes,
  createAgentSignInHandlers,
  registerAgentSignInRoutes,
  resolveAgentSignInDependencies,
} from './routes/agentSignIn.js';
export type {
  AgentSignInDependencies,
  AgentSignInHandlers,
  AgentSignInTable,
} from './routes/agentSignIn.js';
export { AGENT_SIGNIN_SESSION_ID_PATTERN, agentSignInSession } from './db/keys.js';
// --- end Amendment A -------------------------------------------------------

// --- Amendment B: the user token mints a single-use enrollment token --------
// Public route: the agent presents the Entra access token from the brokered
// sign-in once and receives an enrollment token (maxUses 1, never expires), which
// it then enrolls with. Start-up calls
// `configureAgentEnrollmentTokenRoute({ table, userVerifier })`.
registerAgentEnrollmentTokenRoute(router, resolveAgentEnrollmentTokenDependencies);
export {
  AGENT_ENROLLMENT_TOKEN_PATH,
  configureAgentEnrollmentTokenRoute,
  createAgentEnrollmentTokenHandler,
  registerAgentEnrollmentTokenRoute,
  resolveAgentEnrollmentTokenDependencies,
} from './routes/agentEnrollmentToken.js';
export type {
  AgentEnrollmentTokenDependencies,
  AgentUserVerifier,
} from './routes/agentEnrollmentToken.js';
export { mintEnrollmentToken } from './admin/enrollmentTokens.js';
// --- end Amendment B -------------------------------------------------------

// --- TASK-044: per-device heartbeat -----------------------------------------
// The device route is authenticated inside its handler by `verifyDeviceRequest`
// and writes each sample to the device's CloudWatch Logs stream when the
// admin has turned its heartbeat on. The two admin routes set the heartbeat and
// read its history back. Dependencies are resolved per request: start-up calls
// `configureHeartbeatRoute({ table, pepper, heartbeatLog })` and passes the
// same `heartbeatLog` to `configureAdminRoutes`.
registerHeartbeatRoute(router, resolveHeartbeatDependencies);
registerHeartbeatAdminRoutes(router, resolveAdminDependencies);
export {
  HEARTBEAT_PATH,
  MAX_HEARTBEAT_BODY_BYTES,
  configureHeartbeatRoute,
  createHeartbeatHandler,
  isHeartbeatEnabled,
  registerHeartbeatRoute,
  resolveHeartbeatDependencies,
} from './routes/heartbeat.js';
export type {
  HeartbeatDependencies,
  HeartbeatEvent,
  HeartbeatLog,
  HeartbeatTable,
} from './routes/heartbeat.js';
export {
  HEARTBEAT_CHANGED_ACTION,
  HEARTBEAT_HISTORY_LIMIT,
  HEARTBEAT_HISTORY_PATH,
  HEARTBEAT_SETTING_PATH,
  handleHeartbeatHistory,
  handleHeartbeatSet,
  registerHeartbeatAdminRoutes,
} from './admin/heartbeat.js';
export { createCloudWatchHeartbeatLog } from './aws/heartbeatLog.js';
export {
  HEARTBEAT_DEFAULT_INTERVAL_SECONDS,
  HEARTBEAT_INTERVAL_OPTIONS_SECONDS,
} from './config/intervals.js';
export { deviceHeartbeatSettings } from './db/keys.js';
// --- end TASK-044 ----------------------------------------------------------

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

/**
 * The outcome of reading a request body under its `content-encoding`: the body
 * the router should see (with the headers it should see), or the response that
 * refuses the request before any route runs.
 */
type RequestBody =
  | { ok: true; headers: Record<string, string>; body: string | null }
  | { ok: false; response: RouterResponse };

function refuse(statusCode: number, error: string): { ok: false; response: RouterResponse } {
  return {
    ok: false,
    response: {
      statusCode,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ error }),
    },
  };
}

/**
 * Apply the request's `content-encoding`. No header, an empty one or `identity`
 * leaves the body exactly as `decodeBody` produces it. `gzip` (any case,
 * surrounding whitespace ignored) is inflated -- from base64 when the event says
 * so, otherwise from the body's UTF-8 bytes -- to a UTF-8 string, and the header
 * is dropped, so every route and `verifyDeviceRequest` see the uncompressed
 * JSON the signature covers. Anything else is 415.
 */
function readRequestBody(event: FunctionUrlEvent, headers: Record<string, string>): RequestBody {
  const encoding = (headers['content-encoding'] ?? '').trim().toLowerCase();
  if (encoding === '' || encoding === 'identity') {
    return { ok: true, headers, body: decodeBody(event) };
  }
  if (encoding !== 'gzip') {
    return refuse(415, 'unsupported_content_encoding');
  }

  const { 'content-encoding': _dropped, ...rest } = headers;
  const raw = event.body;
  if (raw === undefined || raw === null || raw === '') {
    return { ok: true, headers: rest, body: null };
  }
  const compressed = event.isBase64Encoded === true ? Buffer.from(raw, 'base64') : Buffer.from(raw, 'utf8');
  try {
    const inflated = gunzipSync(compressed, { maxOutputLength: MAX_INFLATED_BODY_BYTES });
    return { ok: true, headers: rest, body: inflated.toString('utf8') };
  } catch (error) {
    if (error instanceof RangeError || (error as { code?: unknown } | null)?.code === 'ERR_BUFFER_TOO_LARGE') {
      return refuse(413, 'payload_too_large');
    }
    return refuse(400, 'invalid_gzip_body');
  }
}

function buildRouterRequest(event: FunctionUrlEvent, headers: Record<string, string>, body: string | null): RouterRequest {
  return {
    method: event.requestContext.http.method,
    path: event.requestContext.http.path,
    query: parseQuery(event.rawQueryString),
    headers,
    body,
  };
}

/**
 * Translate a Function URL event into the router's request shape, inflating a
 * gzip body. `handler` answers an undecodable body with 400, 413 or 415 before
 * calling this; called directly, such a body throws.
 */
export function toRouterRequest(event: FunctionUrlEvent): RouterRequest {
  const read = readRequestBody(event, normaliseHeaders(event.headers));
  if (!read.ok) {
    throw new Error(`request body refused: ${read.response.body}`);
  }
  return buildRouterRequest(event, read.headers, read.body);
}

export async function handler(event: FunctionUrlEvent): Promise<FunctionUrlResponse> {
  let request: RouterRequest;
  let response: RouterResponse;
  try {
    const headers = normaliseHeaders(event.headers);
    const read = readRequestBody(event, headers);
    if (!read.ok) {
      // Refused before routing, so no route runs and no nonce is burned.
      return advertise({
        statusCode: read.response.statusCode,
        headers: { ...read.response.headers },
        body: read.response.body,
      });
    }
    request = buildRouterRequest(event, read.headers, read.body);
    response = await router.handle(request);
  } catch (error) {
    // The router handles route errors itself; this only fires on a malformed event.
    const text = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
    console.error(`[handler] request could not be adapted: ${text.replace(/[\r\n]+/g, ' ')}`);
    return advertise({
      statusCode: 500,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ error: 'internal_error' }),
    });
  }

  return advertise(
    compressResponse(request, {
      statusCode: response.statusCode,
      headers: withDefaultContentType(response.headers),
      body: response.body,
      ...(response.isBase64Encoded === true ? { isBase64Encoded: true } : {}),
    }),
  );
}

/** Every response tells the agent that gzip request bodies are accepted. */
function advertise(response: FunctionUrlResponse): FunctionUrlResponse {
  return { ...response, headers: { ...response.headers, [ACCEPT_CONTENT_ENCODING_HEADER]: 'gzip' } };
}

/**
 * Gzip an `/api/v1/*` response of `COMPRESS_MIN_BYTES` or more when the request
 * accepts gzip and the route did not encode the body itself. The compressed
 * body is base64 with `isBase64Encoded: true`, as Function URLs require for
 * binary bodies. Anything else is returned unchanged.
 */
function compressResponse(request: RouterRequest, response: FunctionUrlResponse): FunctionUrlResponse {
  if (!request.path.startsWith(COMPRESSIBLE_PATH_PREFIX) || response.isBase64Encoded === true) {
    return response;
  }
  if (!acceptsGzip(request.headers['accept-encoding'])) {
    return response;
  }
  if (findHeader(response.headers, 'content-encoding') !== undefined) {
    return response;
  }
  const bytes = Buffer.from(response.body, 'utf8');
  if (bytes.length < COMPRESS_MIN_BYTES) {
    return response;
  }

  const headers: Record<string, string> = { ...response.headers, 'content-encoding': 'gzip' };
  const varyKey = findHeader(headers, 'vary');
  if (varyKey === undefined) {
    headers.vary = 'accept-encoding';
  } else if (!/(^|,)\s*accept-encoding\s*(,|$)/i.test(headers[varyKey] ?? '')) {
    headers[varyKey] = `${headers[varyKey]}, accept-encoding`;
  }
  return {
    statusCode: response.statusCode,
    headers,
    body: gzipSync(bytes).toString('base64'),
    isBase64Encoded: true,
  };
}

/** The key under which `headers` holds `name`, compared case-insensitively. */
function findHeader(headers: Record<string, string>, name: string): string | undefined {
  return Object.keys(headers).find((key) => key.toLowerCase() === name);
}

/**
 * Whether an `accept-encoding` value lists the `gzip` token (any case) with a
 * non-zero quality: `gzip;q=0` is a refusal.
 */
function acceptsGzip(value: string | undefined): boolean {
  if (value === undefined) {
    return false;
  }
  for (const entry of value.split(',')) {
    const [token, ...params] = entry.split(';');
    if ((token ?? '').trim().toLowerCase() !== 'gzip') {
      continue;
    }
    const q = params.map((param) => param.trim().toLowerCase()).find((param) => param.startsWith('q='));
    if (q !== undefined && Number(q.slice(2).trim()) === 0) {
      return false;
    }
    return true;
  }
  return false;
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
// TASK-045: command library and ordered queue keys.
export { commandSettings, deviceCommandSeq, script, scriptListIndex, scriptNameGuard } from './db/keys.js';
// TASK-047: default group assignment by ownership.
export { defaultAssignmentSettings } from './db/keys.js';
