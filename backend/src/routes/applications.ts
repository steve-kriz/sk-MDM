/**
 * The application safe list as users and devices see it.
 *
 *   GET /api/v1/applications                                          -- signed-in user: the list
 *   GET /api/v1/applications/{applicationId}/download                 -- signed-in user: {url}
 *   GET /api/v1/devices/{deviceId}/applications/{applicationId}/download -- device-signed: download details
 *
 * The two user routes take `Authorization: Bearer <token>`, verified by
 * `createAppUserTokenVerifier` (scope `MDM.User`). A missing or malformed
 * header is 401 `unauthorized` without touching the verifier or the table; a
 * verifier rejection is answered with its own `{status, error}`, the same
 * mapping as `requireAdmin` in `src/admin/router.ts`. The list never carries
 * `objectKey`, `fileName`, `url` or `sha256`.
 *
 * A browser cannot put a bearer on a plain link, so a download is two steps:
 * the page asks this API for a URL (a short-lived presigned S3 GET for an
 * upload, the registered URL for a URL source) and then navigates to it.
 *
 * The device route authenticates with `verifyDeviceRequest`, refuses a path
 * naming another device (403 `device_mismatch`) before any application is read,
 * and answers fresh download details at the moment the agent runs the install,
 * so no presigned URL is ever stored on a queued command.
 *
 * An application whose hash is not ready (a URL source still `pending` or
 * `failed`, TASK-050) is left out of the user list, and both download routes
 * refuse it with 409 `application_not_ready`.
 *
 * Every dependency is injected; start-up calls `configureApplicationRoutes`.
 */
import {
  applicationHashStatus,
  applicationRecord,
  byApplicationName,
  readAllApplications,
  readApplication,
} from '../admin/applications.js';
import { bearerToken } from '../admin/router.js';
import { isVerifyFailure, type TokenClaims } from '../auth/jwtCore.js';
import type { TableKey } from '../db/keys.js';
import type { Item, QueryPage, QueryRequest, RequestFields, WriteOutcome } from '../db/table.js';
import { verifyDeviceRequest, type DeviceAuthResult, type EpochSecondsClock } from '../http/deviceAuth.js';
import type { RouteHandler, RouteRequest, RouteResult, Router, RouterRequest } from '../http/router.js';
import type { InstallerStore } from './downloads.js';

/** Path of the signed-in user's application list. */
export const USER_APPLICATIONS_PATH = '/api/v1/applications';

/** Path a signed-in user asks for an application's download URL on. */
export const USER_APPLICATION_DOWNLOAD_PATH = '/api/v1/applications/{applicationId}/download';

/** Path a device asks for an application's download details on. */
export const DEVICE_APPLICATION_DOWNLOAD_PATH = '/api/v1/devices/{deviceId}/applications/{applicationId}/download';

/** How long a user's presigned download URL stays valid, in seconds. */
export const APPLICATION_USER_DOWNLOAD_TTL_SECONDS = 300;

/** How long a device's presigned download URL stays valid, in seconds. */
export const APPLICATION_DEVICE_DOWNLOAD_TTL_SECONDS = 900;

/** The storage operations these routes need: the reads, plus the nonce burn of `verifyDeviceRequest`. */
export interface ApplicationTable {
  get(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
  query(request?: QueryRequest): Promise<QueryPage>;
  putIfAbsent(item: Item, fields?: RequestFields): Promise<WriteOutcome>;
}

/** The user token verifier these routes call (`createAppUserTokenVerifier`). */
export interface ApplicationUserVerifier {
  verify(token: string): Promise<TokenClaims>;
}

/** The device authenticator; injectable so tests need no signed request. */
export type ApplicationDeviceVerifier = (
  req: RouterRequest,
  options: { table: ApplicationTable; now: EpochSecondsClock; pepper: string },
) => Promise<DeviceAuthResult>;

export interface ApplicationDependencies {
  /** Table client. Required; never created here. */
  table: ApplicationTable;
  /** The 64-character hex pepper key. Unused when `verifyDevice` is injected. */
  pepper?: string;
  /** Current time as integer epoch seconds. Defaults to the system clock. */
  now?: EpochSecondsClock;
  /** The `MDM.User` token verifier. Without one the user routes answer 500 not_configured. */
  userVerifier?: ApplicationUserVerifier;
  /** The installer store; `undefined` when `INSTALLER_BUCKET` is not configured. */
  installers?: InstallerStore;
  /** Overrides the device authenticator; defaults to `verifyDeviceRequest`. */
  verifyDevice?: ApplicationDeviceVerifier;
}

/** Dependencies, or something that resolves them when the request arrives. */
export type ApplicationDependencySource =
  | ApplicationDependencies
  | (() => ApplicationDependencies | Promise<ApplicationDependencies>);

const NO_STORE = { 'cache-control': 'no-store' };

function failure(statusCode: number, error: string): RouteResult {
  return { statusCode, body: { error } };
}

function noStore(statusCode: number, body: Record<string, unknown>): RouteResult {
  return { statusCode, headers: { ...NO_STORE }, body };
}

async function resolve(source: ApplicationDependencySource): Promise<ApplicationDependencies> {
  return typeof source === 'function' ? await source() : source;
}

function systemSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** A string attribute, or `null`. */
function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

/** The user-facing list item: exactly these five keys. */
export function userApplicationItem(item: Item): Item {
  const record = applicationRecord(item);
  return {
    applicationId: record.applicationId,
    name: record.name,
    description: record.description,
    platform: record.platform,
    installerType: record.installerType,
  };
}

/**
 * Wrap a user handler so it runs only for a verified `MDM.User` token. The
 * bearer header is settled before the dependencies, the verifier or the table
 * are touched.
 */
function requireAppUser(
  handler: (req: RouteRequest, deps: ApplicationDependencies) => Promise<RouteResult>,
  source: ApplicationDependencySource,
): RouteHandler {
  return async function authorised(req: RouteRequest): Promise<RouteResult> {
    const token = bearerToken(req?.headers);
    if (token === null) {
      return failure(401, 'unauthorized');
    }

    const deps = await resolve(source);
    if (deps.userVerifier === undefined || deps.userVerifier === null) {
      return failure(500, 'not_configured');
    }

    try {
      await deps.userVerifier.verify(token);
    } catch (error) {
      if (isVerifyFailure(error)) {
        return failure(error.status, error.error);
      }
      throw error;
    }

    return handler(req, deps);
  };
}

/** `GET /api/v1/applications` -- the safe list, by name ignoring case, without any download detail. */
export function createUserApplicationListHandler(source: ApplicationDependencySource): RouteHandler {
  return requireAppUser(async (_req, deps) => {
    const items = (await readAllApplications(deps.table))
      .filter((item) => applicationHashStatus(item) === 'ready')
      .map(applicationRecord)
      .sort(byApplicationName)
      .map(userApplicationItem);
    return noStore(200, { items });
  }, source);
}

/** `GET /api/v1/applications/{applicationId}/download` -- `{url}` the page navigates to. */
export function createUserApplicationDownloadHandler(source: ApplicationDependencySource): RouteHandler {
  return requireAppUser(async (req, deps) => {
    const app = await readApplication(deps.table, req.params?.applicationId ?? '');
    if (app === null) {
      return noStore(404, { error: 'not_found' });
    }
    if (applicationHashStatus(app) !== 'ready') {
      return noStore(409, { error: 'application_not_ready' });
    }
    if (app.source === 'upload') {
      const objectKey = stringOrNull(app.objectKey);
      if (deps.installers === undefined || deps.installers === null || objectKey === null) {
        return noStore(500, { error: 'not_configured' });
      }
      const url = await deps.installers.presignGet(objectKey, APPLICATION_USER_DOWNLOAD_TTL_SECONDS);
      return noStore(200, { url });
    }
    return noStore(200, { url: stringOrNull(app.url) });
  }, source);
}

/** `GET /api/v1/devices/{deviceId}/applications/{applicationId}/download` -- fresh details for the agent. */
export function createDeviceApplicationDownloadHandler(source: ApplicationDependencySource): RouteHandler {
  return async function handleDeviceApplicationDownload(req: RouteRequest): Promise<RouteResult> {
    const deps = await resolve(source);
    const verify: ApplicationDeviceVerifier = deps.verifyDevice ?? verifyDeviceRequest;
    const auth = await verify(req, { table: deps.table, now: deps.now ?? systemSeconds, pepper: deps.pepper ?? '' });
    if (!auth.ok) {
      return { statusCode: auth.status, body: auth.body };
    }
    if (auth.deviceId !== (req.params?.deviceId ?? '')) {
      return failure(403, 'device_mismatch');
    }

    const app = await readApplication(deps.table, req.params?.applicationId ?? '');
    if (app === null) {
      return failure(404, 'application_not_found');
    }
    if (applicationHashStatus(app) !== 'ready') {
      return failure(409, 'application_not_ready');
    }

    const details = {
      sha256: stringOrNull(app.sha256),
      installerType: stringOrNull(app.installerType),
      installArgs: stringOrNull(app.installArgs),
    };
    if (app.source === 'upload') {
      const objectKey = stringOrNull(app.objectKey);
      if (deps.installers === undefined || deps.installers === null || objectKey === null) {
        return failure(500, 'not_configured');
      }
      const url = await deps.installers.presignGet(objectKey, APPLICATION_DEVICE_DOWNLOAD_TTL_SECONDS);
      return { statusCode: 200, body: { url, ...details, fileName: stringOrNull(app.fileName) } };
    }
    return { statusCode: 200, body: { url: stringOrNull(app.url), ...details, fileName: null } };
  };
}

/** Register the user and device application routes on a router. Returns the router, so calls chain. */
export function registerApplicationRoutes(router: Router, source: ApplicationDependencySource): Router {
  return router
    .add('GET', USER_APPLICATIONS_PATH, createUserApplicationListHandler(source))
    .add('GET', USER_APPLICATION_DOWNLOAD_PATH, createUserApplicationDownloadHandler(source))
    .add('GET', DEVICE_APPLICATION_DOWNLOAD_PATH, createDeviceApplicationDownloadHandler(source));
}

/**
 * Dependencies supplied at start-up by `bootstrap`, so no AWS client is
 * constructed at import time.
 */
let configuredDependencies: ApplicationDependencies | null = null;

/** Supply the application routes' storage, clock, pepper, user verifier and installer store. */
export function configureApplicationRoutes(dependencies: ApplicationDependencies): void {
  configuredDependencies = dependencies;
}

/** The configured dependencies, or a thrown error when start-up skipped them. */
export function resolveApplicationDependencies(): ApplicationDependencies {
  if (configuredDependencies === null) {
    throw new Error('application routes are not configured: call configureApplicationRoutes() at start-up');
  }
  return configuredDependencies;
}
