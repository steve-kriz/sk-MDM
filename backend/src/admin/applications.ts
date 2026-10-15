/**
 * The application safe list: approved installers users may download and
 * admins may push to a device.
 *
 *   GET    /admin/api/v1/applications                   -- list, by name ignoring case (?platform=windows|darwin)
 *   POST   /admin/api/v1/applications/upload-url        -- a presigned S3 PUT URL for a new installer
 *   POST   /admin/api/v1/applications                   -- register an application (upload or url source)
 *   PATCH  /admin/api/v1/applications/{applicationId}   -- edit name, description, installArgs (and a URL source's url, installerType)
 *   DELETE /admin/api/v1/applications/{applicationId}   -- delete the record (the S3 object stays)
 *   POST   /admin/api/v1/applications/{applicationId}/retry-hash -- hash a URL source again (TASK-050)
 *
 *   registerApplicationAdminRoutes(router, { verifier, table, now, randomBytes, installers, hasher });
 *
 * Every route is registered through `registerAdminRoute`, so it is reached only
 * by a verified admin (see `src/admin/router.ts`).
 *
 * Installers are far larger than a Lambda request body, so an upload never
 * passes through the backend: the admin browser asks for a presigned PUT URL,
 * PUTs the file straight to the bucket, then registers the application, at
 * which point the uploaded object's size is checked with one HeadObject.
 *
 * A record lives at `keys.application(applicationId)` and carries the
 * `keys.applicationListIndex(name)` attributes, so the list is a query on one
 * `gsi1` partition, never a scan. An edit rewrites those attributes when the name
 * changes; an uploaded installer's file and an application's source cannot be
 * edited (delete it and add it again).
 *
 * The agent verifies the downloaded bytes against `sha256` before running
 * anything. For an upload the admin browser computes it and it is mandatory on
 * create. For a URL source the server computes it (TASK-050): the record is
 * saved `pending` with `sha256: null` and the asynchronous hasher Lambda
 * (`src/hasher.ts`) is invoked; it stores the hash (`ready`) or an error code
 * (`failed`). Until then the application cannot be downloaded or queued.
 */
import { appendAudit, isoUtc } from '../audit.js';
import { GSI1_NAME, application as applicationKey, applicationListIndex, type TableKey } from '../db/keys.js';
import { CONDITIONAL_CHECK_FAILED, type Item, type QueryPage } from '../db/table.js';
import { HASH_OUTCOME_CONDITION, type HasherEvent } from '../hashing/urlHasher.js';
import type { HasherInvoker } from '../aws/hasherInvoker.js';
import type { RouteResult, Router } from '../http/router.js';
import {
  adminActor,
  adminDeleteTable,
  adminNow,
  adminRandomBytes,
  adminUpdateTable,
  adminWriteTable,
  jsonError,
  readJsonBody,
  registerAdminRoute,
  type AdminDependencies,
  type AdminDependencySource,
  type AdminRouteHandler,
  type AdminTable,
} from './router.js';

/** Sub-path of the application list. */
export const APPLICATION_PATH = '/applications';

/** Sub-path that issues a presigned upload URL. */
export const APPLICATION_UPLOAD_URL_PATH = '/applications/upload-url';

/** Sub-path of one application. */
export const APPLICATION_DETAIL_PATH = '/applications/{applicationId}';

/** Sub-path that starts hashing a URL-source application again. */
export const APPLICATION_RETRY_HASH_PATH = '/applications/{applicationId}/retry-hash';

/** Prefix of a generated application id. */
export const APPLICATION_ID_PREFIX = 'app-';

/** Length of the random part of a generated application id, in bytes (16 hex characters). */
export const APPLICATION_ID_BYTES = 8;

/** Length of the random part of an upload key, in bytes (16 hex characters). */
export const APPLICATION_UPLOAD_KEY_BYTES = 8;

/** The object key prefix every uploaded installer is stored under. */
export const APPLICATION_UPLOAD_PREFIX = 'applications/';

/** Largest accepted uploaded installer, in bytes (500 MiB). */
export const APPLICATION_UPLOAD_MAX_BYTES = 524288000;

/** How long a presigned upload URL stays valid, in seconds. */
export const APPLICATION_UPLOAD_URL_TTL_SECONDS = 900;

/** Longest accepted name, in characters. */
export const APPLICATION_NAME_MAX_LENGTH = 100;

/** Longest accepted description, in characters. */
export const APPLICATION_DESCRIPTION_MAX_LENGTH = 500;

/** Longest accepted `installArgs`, in characters. */
export const APPLICATION_INSTALL_ARGS_MAX_LENGTH = 500;

/** Longest accepted URL source, in characters. */
export const APPLICATION_URL_MAX_LENGTH = 2048;

/** Where an application's installer comes from. */
export const APPLICATION_SOURCES = ['upload', 'url'] as const;

/** The installer types the safe list accepts. */
export const APPLICATION_INSTALLER_TYPES = ['msi', 'exe', 'pkg'] as const;

/** The platforms an application installs on. */
export const APPLICATION_PLATFORMS = ['windows', 'darwin'] as const;

export type ApplicationInstallerType = (typeof APPLICATION_INSTALLER_TYPES)[number];
export type ApplicationPlatform = (typeof APPLICATION_PLATFORMS)[number];

/** The platform each installer type installs on. */
export const INSTALLER_TYPE_PLATFORMS: Readonly<Record<ApplicationInstallerType, ApplicationPlatform>> = {
  msi: 'windows',
  exe: 'windows',
  pkg: 'darwin',
};

/** The audit action recorded when an application is registered. */
export const APPLICATION_CREATED_ACTION = 'application.created';

/** The audit action recorded when an application is edited. */
export const APPLICATION_UPDATED_ACTION = 'application.updated';

/** The audit action recorded when an application is deleted. */
export const APPLICATION_DELETED_ACTION = 'application.deleted';

/** The audit action recorded when a URL source's hash is retried. */
export const APPLICATION_HASH_RETRIED_ACTION = 'application.hash_retried';

/** How long a `pending` hash run must be outstanding before Retry may restart it, in seconds. */
export const APPLICATION_HASH_STALE_SECONDS = 960;

/** Length of a hash run id, in bytes (16 hex characters). */
export const APPLICATION_HASH_RUN_ID_BYTES = 8;

/** The hash states of an application record. */
export const APPLICATION_HASH_STATUSES = ['pending', 'ready', 'failed'] as const;

export type ApplicationHashStatus = (typeof APPLICATION_HASH_STATUSES)[number];

/** The `hashError` recorded when the hasher Lambda could not be started. */
export const APPLICATION_HASH_INVOKE_FAILED = 'invoke_failed';

/** An accepted installer file name (its extension is checked separately). */
const FILE_NAME_BODY = '[A-Za-z0-9][A-Za-z0-9._ -]{0,199}';
const FILE_NAME_PATTERN = new RegExp(`^${FILE_NAME_BODY}$`);
const FILE_EXTENSION_PATTERN = /\.(msi|exe|pkg)$/i;
const UPLOAD_KEY_PATTERN = new RegExp(`^applications/[0-9a-f]{16}/(${FILE_NAME_BODY})$`);
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

const INSTALLER_TYPES: ReadonlySet<string> = new Set(APPLICATION_INSTALLER_TYPES);
const PLATFORMS: ReadonlySet<string> = new Set(APPLICATION_PLATFORMS);

/** True when `fileName` is an installer file name the safe list accepts. */
export function isApplicationFileName(fileName: unknown): fileName is string {
  return typeof fileName === 'string' && FILE_NAME_PATTERN.test(fileName) && FILE_EXTENSION_PATTERN.test(fileName);
}

/** The installer type of an accepted file name, from its lower-cased extension. */
function installerTypeOf(fileName: string): ApplicationInstallerType {
  return fileName.slice(fileName.lastIndexOf('.') + 1).toLowerCase() as ApplicationInstallerType;
}

/** The file name of an accepted upload key, or `null` when the key is not one. */
function uploadKeyFileName(uploadKey: unknown): string | null {
  if (typeof uploadKey !== 'string') {
    return null;
  }
  const match = UPLOAD_KEY_PATTERN.exec(uploadKey);
  const fileName = match?.[1];
  return fileName !== undefined && isApplicationFileName(fileName) ? fileName : null;
}

/** A string attribute, or `null`. */
function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

/** A number attribute, or `null`. */
function numberOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/**
 * The hash status of a stored application. A stored `pending` or `failed` is
 * returned as is; otherwise it is `ready` when `sha256` is 64 lowercase hex
 * (so a TASK-049 record with no `hashStatus` reads as ready), else `failed`.
 */
export function applicationHashStatus(item: Item): ApplicationHashStatus {
  if (item.hashStatus === 'pending' || item.hashStatus === 'failed') {
    return item.hashStatus;
  }
  return typeof item.sha256 === 'string' && SHA256_PATTERN.test(item.sha256) ? 'ready' : 'failed';
}

/** The public shape of a stored application: exactly these keys, `null` where one does not apply. */
export function applicationRecord(item: Item): Item {
  const hashStatus = applicationHashStatus(item);
  return {
    applicationId: stringOrNull(item.applicationId),
    name: stringOrNull(item.name),
    description: stringOrNull(item.description),
    source: stringOrNull(item.source),
    installerType: stringOrNull(item.installerType),
    platform: stringOrNull(item.platform),
    fileName: stringOrNull(item.fileName),
    sizeBytes: numberOrNull(item.sizeBytes),
    url: stringOrNull(item.url),
    sha256: stringOrNull(item.sha256),
    installArgs: stringOrNull(item.installArgs),
    createdAt: stringOrNull(item.createdAt),
    createdBy: stringOrNull(item.createdBy),
    hashStatus,
    hashError: hashStatus === 'failed' ? stringOrNull(item.hashError) : null,
  };
}

/** The key of the application a request names, or `null` when no key can be built from it. */
function requestedApplicationKey(applicationId: string): TableKey | null {
  try {
    return applicationKey(applicationId);
  } catch {
    return null;
  }
}

/**
 * Read one application by id, or `null` when it does not exist (or the id
 * cannot form a key). Shared with the queue route and the user/device routes.
 */
export async function readApplication(table: AdminTable, applicationId: string): Promise<Item | null> {
  const key = requestedApplicationKey(applicationId);
  if (key === null) {
    return null;
  }
  const item = await table.get(key);
  return item === undefined || item === null ? null : item;
}

/** Every application record, following the `gsi1` query cursor to the end. */
export async function readAllApplications(table: AdminTable): Promise<Item[]> {
  const { gsi1pk } = applicationListIndex('');
  const records: Item[] = [];
  let cursor: string | null = null;
  do {
    const page: QueryPage = await table.query({
      IndexName: GSI1_NAME,
      KeyConditionExpression: '#gsi1pk = :gsi1pk',
      ExpressionAttributeNames: { '#gsi1pk': 'gsi1pk' },
      ExpressionAttributeValues: { ':gsi1pk': gsi1pk },
      cursor,
    });
    records.push(...page.items);
    const next = page.cursor ?? null;
    // A cursor that does not move would page forever; treat it as the end.
    cursor = next === cursor ? null : next;
  } while (cursor !== null);
  return records;
}

/** Ascending by name ignoring case; ties by name, then by id, so the order is stable. */
export function byApplicationName(left: Item, right: Item): number {
  const leftName = String(left.name ?? '');
  const rightName = String(right.name ?? '');
  const a = leftName.toLowerCase();
  const b = rightName.toLowerCase();
  if (a !== b) {
    return a < b ? -1 : 1;
  }
  if (leftName !== rightName) {
    return leftName < rightName ? -1 : 1;
  }
  const leftId = String(left.applicationId ?? '');
  const rightId = String(right.applicationId ?? '');
  return leftId === rightId ? 0 : leftId < rightId ? -1 : 1;
}

/** A validated create body, ready to store (the upload's size is read afterwards). */
export type ApplicationFields =
  | {
      source: 'upload';
      name: string;
      description: string | null;
      uploadKey: string;
      fileName: string;
      installerType: ApplicationInstallerType;
      sha256: string;
      installArgs: string | null;
    }
  | {
      source: 'url';
      name: string;
      description: string | null;
      url: string;
      installerType: ApplicationInstallerType;
      installArgs: string | null;
    };

/** True when `value` is an https URL of acceptable length. */
function isHttpsUrl(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > APPLICATION_URL_MAX_LENGTH) {
    return false;
  }
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Validate a create body: the fields, or every offending field name in the
 * order `source, name, description, uploadKey, url, installerType, sha256,
 * installArgs`. `sha256` is read for an upload only; a URL source's is
 * computed by the server, so one sent anyway is ignored (TASK-050).
 */
export function readApplicationFields(body: Record<string, unknown>): { fields: ApplicationFields } | { offending: string[] } {
  const offending: string[] = [];

  const source = body.source;
  const isUpload = source === 'upload';
  const isUrl = source === 'url';
  if (!isUpload && !isUrl) {
    offending.push('source');
  }

  const name = body.name;
  if (typeof name !== 'string' || name.length < 1 || name.length > APPLICATION_NAME_MAX_LENGTH || name.trim().length === 0) {
    offending.push('name');
  }

  const description = body.description;
  if (
    description !== undefined &&
    description !== null &&
    (typeof description !== 'string' || description.length > APPLICATION_DESCRIPTION_MAX_LENGTH)
  ) {
    offending.push('description');
  }

  let installerType: ApplicationInstallerType | null = null;
  let fileName: string | null = null;
  if (isUpload) {
    fileName = uploadKeyFileName(body.uploadKey);
    if (fileName === null) {
      offending.push('uploadKey');
    } else {
      installerType = installerTypeOf(fileName);
    }
  }
  if (isUrl) {
    if (!isHttpsUrl(body.url)) {
      offending.push('url');
    }
    const type = body.installerType;
    if (typeof type !== 'string' || !INSTALLER_TYPES.has(type)) {
      offending.push('installerType');
    } else {
      installerType = type as ApplicationInstallerType;
    }
  }

  const sha256 = body.sha256;
  if (isUpload && (typeof sha256 !== 'string' || !SHA256_PATTERN.test(sha256))) {
    offending.push('sha256');
  }

  // An empty string is treated as no arguments at all.
  const installArgs = body.installArgs;
  const hasInstallArgs = installArgs !== undefined && installArgs !== null && installArgs !== '';
  if (
    hasInstallArgs &&
    (typeof installArgs !== 'string' ||
      installArgs.length > APPLICATION_INSTALL_ARGS_MAX_LENGTH ||
      (installerType !== null && installerType !== 'exe'))
  ) {
    offending.push('installArgs');
  }

  if (offending.length > 0 || installerType === null) {
    return { offending: offending.length > 0 ? offending : ['installerType'] };
  }

  const common = {
    name: name as string,
    description: typeof description === 'string' ? description : null,
    installerType,
    installArgs: hasInstallArgs ? (installArgs as string) : null,
  };
  if (isUpload) {
    return {
      fields: {
        source: 'upload',
        ...common,
        sha256: sha256 as string,
        uploadKey: body.uploadKey as string,
        fileName: fileName as string,
      },
    };
  }
  return { fields: { source: 'url', ...common, url: body.url as string } };
}

/** `GET /admin/api/v1/applications` -- the safe list, by name ignoring case, optionally for one platform. */
export const handleApplicationList: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const platform = req.query?.platform;
  if (platform !== undefined && !PLATFORMS.has(platform)) {
    return jsonError(400, 'invalid_request');
  }
  const items = (await readAllApplications(deps.table))
    .map(applicationRecord)
    .filter((record) => platform === undefined || record.platform === platform)
    .sort(byApplicationName);
  return { statusCode: 200, body: { items } };
};

/** `POST /admin/api/v1/applications/upload-url` -- a presigned PUT URL; writes nothing. */
export const handleApplicationUploadUrl: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body) ?? {};
  const offending: string[] = [];

  const fileName = body.fileName;
  if (!isApplicationFileName(fileName)) {
    offending.push('fileName');
  }
  const sizeBytes = body.sizeBytes;
  if (
    typeof sizeBytes !== 'number' ||
    !Number.isInteger(sizeBytes) ||
    sizeBytes < 1 ||
    sizeBytes > APPLICATION_UPLOAD_MAX_BYTES
  ) {
    offending.push('sizeBytes');
  }
  if (offending.length > 0) {
    return jsonError(400, 'invalid_request', { fields: offending });
  }

  const installers = deps.installers;
  if (installers === undefined || installers === null || typeof installers.presignPut !== 'function') {
    return jsonError(500, 'not_configured');
  }

  const random = adminRandomBytes(deps)(APPLICATION_UPLOAD_KEY_BYTES).toString('hex');
  const uploadKey = `${APPLICATION_UPLOAD_PREFIX}${random}/${fileName as string}`;
  const url = await installers.presignPut(uploadKey, APPLICATION_UPLOAD_URL_TTL_SECONDS);
  return { statusCode: 200, body: { uploadKey, url, expiresInSeconds: APPLICATION_UPLOAD_URL_TTL_SECONDS } };
};

/** The injected hasher, or `null` when none is configured. */
function configuredHasher(deps: AdminDependencies): HasherInvoker | null {
  const hasher = deps.hasher;
  return hasher === undefined || hasher === null || typeof hasher.invoke !== 'function' ? null : hasher;
}

/** A new hash run id: 16 lowercase hex characters. */
function newHashRunId(deps: AdminDependencies): string {
  return adminRandomBytes(deps)(APPLICATION_HASH_RUN_ID_BYTES).toString('hex');
}

function isConditionalCheckFailure(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === CONDITIONAL_CHECK_FAILED
  );
}

/**
 * Start a hashing run. When the hasher cannot be started the record is marked
 * `failed` / `invoke_failed`, conditional on this run still being the latest,
 * and the failed item is returned; the invoke error is never propagated.
 */
async function startHashRun(
  deps: AdminDependencies,
  hasher: HasherInvoker,
  key: TableKey,
  item: Item,
  event: HasherEvent,
): Promise<Item> {
  try {
    await hasher.invoke(event);
    return item;
  } catch {
    // Fall through: record the failure instead of answering 500.
  }
  const table = adminUpdateTable(deps.table);
  try {
    await table.update(key, {
      UpdateExpression: 'SET hashStatus = :hashStatus, hashError = :hashError',
      ConditionExpression: HASH_OUTCOME_CONDITION,
      ExpressionAttributeValues: {
        ':hashStatus': 'failed',
        ':hashError': APPLICATION_HASH_INVOKE_FAILED,
        ':runId': event.hashRunId,
      },
    });
  } catch (error) {
    // The application was deleted, or a newer run replaced this one: nothing to mark.
    if (!isConditionalCheckFailure(error)) {
      throw error;
    }
  }
  return { ...item, hashStatus: 'failed', hashError: APPLICATION_HASH_INVOKE_FAILED };
}

/** `POST /admin/api/v1/applications` -- register an application from an upload or a URL. */
export const handleApplicationCreate: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const read = readApplicationFields(readJsonBody(req.body) ?? {});
  if ('offending' in read) {
    return jsonError(400, 'invalid_request', { fields: read.offending });
  }
  const { fields } = read;

  // A URL source is hashed by the hasher Lambda; without one nothing is written.
  const hasher = fields.source === 'url' ? configuredHasher(deps) : null;
  if (fields.source === 'url' && hasher === null) {
    return jsonError(500, 'not_configured');
  }

  let uploaded: { objectKey: string; fileName: string; sizeBytes: number } | null = null;
  if (fields.source === 'upload') {
    const installers = deps.installers;
    if (installers === undefined || installers === null || typeof installers.objectSize !== 'function') {
      return jsonError(500, 'not_configured');
    }
    const size = await installers.objectSize(fields.uploadKey);
    if (size === null) {
      return jsonError(400, 'upload_not_found');
    }
    if (size > APPLICATION_UPLOAD_MAX_BYTES) {
      return jsonError(400, 'upload_too_large');
    }
    uploaded = { objectKey: fields.uploadKey, fileName: fields.fileName, sizeBytes: size };
  }

  const table = adminWriteTable(deps.table);
  const at = adminNow(deps);
  const actor = adminActor(req.claims);
  const applicationId = `${APPLICATION_ID_PREFIX}${adminRandomBytes(deps)(APPLICATION_ID_BYTES).toString('hex')}`;

  const key = applicationKey(applicationId);
  let item: Item = {
    ...key,
    ...applicationListIndex(fields.name),
    applicationId,
    name: fields.name,
    description: fields.description,
    source: fields.source,
    installerType: fields.installerType,
    platform: INSTALLER_TYPE_PLATFORMS[fields.installerType],
    sha256: fields.source === 'upload' ? fields.sha256 : null,
    installArgs: fields.installArgs,
    createdAt: isoUtc(at),
    createdBy: actor,
  };
  if (uploaded !== null) {
    item.objectKey = uploaded.objectKey;
    item.fileName = uploaded.fileName;
    item.sizeBytes = uploaded.sizeBytes;
    item.hashStatus = 'ready';
    item.hashError = null;
  }
  let hashRunId: string | null = null;
  if (fields.source === 'url') {
    hashRunId = newHashRunId(deps);
    item.url = fields.url;
    item.hashStatus = 'pending';
    item.hashError = null;
    item.hashRunId = hashRunId;
    item.hashRequestedAt = isoUtc(at);
  }
  await table.put(item);

  if (fields.source === 'url' && hasher !== null && hashRunId !== null) {
    item = await startHashRun(deps, hasher, key, item, { applicationId, url: fields.url, hashRunId });
  }

  await appendAudit(table, {
    action: APPLICATION_CREATED_ACTION,
    actor,
    target: applicationId,
    detail: { name: fields.name, source: fields.source, installerType: fields.installerType },
    now: at,
  });

  return { statusCode: 201, body: applicationRecord(item) };
};

/** `DELETE /admin/api/v1/applications/{applicationId}` -- delete the record; the S3 object is untouched. */
export const handleApplicationDelete: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const applicationId = req.params?.applicationId ?? '';
  const key = requestedApplicationKey(applicationId);
  if (key === null) {
    return jsonError(404, 'not_found');
  }
  const existing = await deps.table.get(key);
  if (existing === undefined || existing === null) {
    return jsonError(404, 'not_found');
  }

  const table = adminDeleteTable(deps.table);
  const at = adminNow(deps);
  await table.delete(key);

  await appendAudit(table, {
    action: APPLICATION_DELETED_ACTION,
    actor: adminActor(req.claims),
    target: applicationId,
    detail: { name: stringOrNull(existing.name) },
    now: at,
  });

  return { statusCode: 204, rawBody: '', headers: {} };
};

/** Seconds since an ISO time, or `NaN` when it does not parse. */
function secondsSince(at: Date, iso: unknown): number {
  const then = typeof iso === 'string' ? Date.parse(iso) : Number.NaN;
  return (at.getTime() - then) / 1000;
}

/**
 * `POST /admin/api/v1/applications/{applicationId}/retry-hash` -- hash a URL
 * source again. Allowed from `failed`, and from `pending` once the run is
 * stale (`APPLICATION_HASH_STALE_SECONDS` after `hashRequestedAt`), which
 * covers a hasher that stopped without writing an outcome. Every refusal
 * writes nothing.
 */
export const handleApplicationRetryHash: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const applicationId = req.params?.applicationId ?? '';
  const key = requestedApplicationKey(applicationId);
  if (key === null) {
    return jsonError(404, 'not_found');
  }
  const existing = await deps.table.get(key);
  if (existing === undefined || existing === null) {
    return jsonError(404, 'not_found');
  }
  if (existing.source !== 'url') {
    return jsonError(409, 'not_url_source');
  }
  const at = adminNow(deps);
  const status = applicationHashStatus(existing);
  if (status === 'ready') {
    return jsonError(409, 'already_hashed');
  }
  if (status === 'pending' && secondsSince(at, existing.hashRequestedAt) < APPLICATION_HASH_STALE_SECONDS) {
    return jsonError(409, 'hash_in_progress');
  }
  const hasher = configuredHasher(deps);
  if (hasher === null) {
    return jsonError(500, 'not_configured');
  }

  const table = adminUpdateTable(deps.table);
  const previousRunId = typeof existing.hashRunId === 'string' ? existing.hashRunId : null;
  const hashRunId = newHashRunId(deps);
  const hashRequestedAt = isoUtc(at);
  const values: Record<string, unknown> = {
    ':hashStatus': 'pending',
    ':hashError': null,
    ':sha256': null,
    ':newRunId': hashRunId,
    ':hashRequestedAt': hashRequestedAt,
  };
  if (previousRunId !== null) {
    values[':runId'] = previousRunId;
  }
  let updated: Item | undefined;
  try {
    updated = await table.update(key, {
      UpdateExpression:
        'SET hashStatus = :hashStatus, hashError = :hashError, sha256 = :sha256, hashRunId = :newRunId, hashRequestedAt = :hashRequestedAt',
      ConditionExpression:
        previousRunId !== null ? HASH_OUTCOME_CONDITION : 'attribute_exists(pk) AND attribute_not_exists(hashRunId)',
      ExpressionAttributeValues: values,
    });
  } catch (error) {
    if (isConditionalCheckFailure(error)) {
      return jsonError(409, 'hash_in_progress');
    }
    throw error;
  }

  let item: Item = {
    ...existing,
    ...(typeof updated === 'object' && updated !== null ? updated : {}),
    hashStatus: 'pending',
    hashError: null,
    sha256: null,
    hashRunId,
    hashRequestedAt,
  };
  const url = typeof existing.url === 'string' ? existing.url : '';
  item = await startHashRun(deps, hasher, key, item, { applicationId, url, hashRunId });

  await appendAudit(table, {
    action: APPLICATION_HASH_RETRIED_ACTION,
    actor: adminActor(req.claims),
    target: applicationId,
    detail: { name: stringOrNull(existing.name) },
    now: at,
  });

  return { statusCode: 202, body: applicationRecord(item) };
};

/** The fields an edit may carry, in the order offending ones are reported. */
export const APPLICATION_EDITABLE_FIELDS = ['name', 'description', 'url', 'installerType', 'installArgs'] as const;

/** The edit fields only a URL source may change. */
const URL_ONLY_FIELDS: ReadonlySet<string> = new Set(['url', 'installerType']);

/** The edited values, merged over the stored record, before they are written. */
interface EditedApplication {
  name: string;
  description: string | null;
  url: string | null;
  installerType: ApplicationInstallerType;
  installArgs: string | null;
}

/**
 * Validate an edit body against the stored record. Absent keys keep their
 * stored value; the merged result is checked with the create rules, so an
 * `installArgs` left over from an exe is refused once the type is changed away
 * from exe. A key outside `APPLICATION_EDITABLE_FIELDS`, or `url` /
 * `installerType` on an upload source, is offending too.
 */
export function readApplicationEdit(
  body: Record<string, unknown>,
  existing: Item,
): { edited: EditedApplication; changed: string[] } | { offending: string[] } {
  const isUrl = existing.source === 'url';
  const offending = new Set<string>();
  for (const field of Object.keys(body)) {
    if (!(APPLICATION_EDITABLE_FIELDS as readonly string[]).includes(field) || (!isUrl && URL_ONLY_FIELDS.has(field))) {
      offending.add(field);
    }
  }

  const has = (field: string): boolean => Object.prototype.hasOwnProperty.call(body, field);
  const name = has('name') ? body.name : existing.name;
  if (typeof name !== 'string' || name.length < 1 || name.length > APPLICATION_NAME_MAX_LENGTH || name.trim().length === 0) {
    offending.add('name');
  }

  const description = has('description') ? body.description : existing.description;
  const hasDescription = description !== undefined && description !== null && description !== '';
  if (hasDescription && (typeof description !== 'string' || description.length > APPLICATION_DESCRIPTION_MAX_LENGTH)) {
    offending.add('description');
  }

  const url = isUrl ? (has('url') ? body.url : existing.url) : null;
  if (isUrl && !isHttpsUrl(url)) {
    offending.add('url');
  }

  const installerType = has('installerType') && isUrl ? body.installerType : existing.installerType;
  const knownType = typeof installerType === 'string' && INSTALLER_TYPES.has(installerType);
  if (!knownType) {
    offending.add('installerType');
  }

  // An empty string is treated as no arguments at all, as on create.
  const installArgs = has('installArgs') ? body.installArgs : existing.installArgs;
  const hasInstallArgs = installArgs !== undefined && installArgs !== null && installArgs !== '';
  if (
    hasInstallArgs &&
    (typeof installArgs !== 'string' ||
      installArgs.length > APPLICATION_INSTALL_ARGS_MAX_LENGTH ||
      (knownType && installerType !== 'exe'))
  ) {
    offending.add('installArgs');
  }

  if (offending.size > 0) {
    const known = APPLICATION_EDITABLE_FIELDS.filter((field) => offending.has(field));
    const unknown = [...offending].filter((field) => !(APPLICATION_EDITABLE_FIELDS as readonly string[]).includes(field));
    return { offending: [...known, ...unknown] };
  }

  const edited: EditedApplication = {
    name: name as string,
    description: hasDescription ? (description as string) : null,
    url: isUrl ? (url as string) : null,
    installerType: installerType as ApplicationInstallerType,
    installArgs: hasInstallArgs ? (installArgs as string) : null,
  };
  const stored: Record<keyof EditedApplication, unknown> = {
    name: existing.name,
    description: stringOrNull(existing.description),
    url: isUrl ? stringOrNull(existing.url) : null,
    installerType: existing.installerType,
    installArgs: stringOrNull(existing.installArgs),
  };
  const changed = APPLICATION_EDITABLE_FIELDS.filter((field) => edited[field] !== stored[field]);
  return { edited, changed };
}

/**
 * `PATCH /admin/api/v1/applications/{applicationId}` -- edit an application's
 * name, description and install arguments, and a URL source's URL and
 * installer type. A changed URL is hashed again: the record goes back to
 * `pending` (so it cannot be downloaded or queued) and the hasher is started,
 * as on create. A queued install fetches its download details when it runs,
 * so it picks the edit up. An edit that changes nothing writes nothing.
 */
export const handleApplicationUpdate: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body);
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return jsonError(400, 'invalid_request', { fields: [] });
  }

  const applicationId = req.params?.applicationId ?? '';
  const key = requestedApplicationKey(applicationId);
  if (key === null) {
    return jsonError(404, 'not_found');
  }
  const existing = await deps.table.get(key);
  if (existing === undefined || existing === null) {
    return jsonError(404, 'not_found');
  }

  const read = readApplicationEdit(body, existing);
  if ('offending' in read) {
    return jsonError(400, 'invalid_request', { fields: read.offending });
  }
  const { edited, changed } = read;
  if (changed.length === 0) {
    return { statusCode: 200, body: applicationRecord(existing) };
  }

  const rehash = changed.includes('url');
  const hasher = rehash ? configuredHasher(deps) : null;
  if (rehash && hasher === null) {
    return jsonError(500, 'not_configured');
  }

  const table = adminUpdateTable(deps.table);
  const at = adminNow(deps);
  const actor = adminActor(req.claims);
  const set: Record<string, unknown> = {
    ...applicationListIndex(edited.name),
    name: edited.name,
    description: edited.description,
    installerType: edited.installerType,
    platform: INSTALLER_TYPE_PLATFORMS[edited.installerType],
    installArgs: edited.installArgs,
    updatedAt: isoUtc(at),
    updatedBy: actor,
  };
  if (existing.source === 'url') {
    set.url = edited.url;
  }
  let hashRunId: string | null = null;
  if (rehash) {
    hashRunId = newHashRunId(deps);
    // A new run id supersedes any run still in flight: its outcome write is
    // conditional on its own id (HASH_OUTCOME_CONDITION), so it lands nowhere.
    Object.assign(set, {
      sha256: null,
      hashStatus: 'pending',
      hashError: null,
      hashRunId,
      hashRequestedAt: isoUtc(at),
    });
  }

  const names: Record<string, string> = {};
  const values: Record<string, unknown> = {};
  const assignments = Object.entries(set).map(([attribute, value]) => {
    names[`#${attribute}`] = attribute;
    values[`:${attribute}`] = value;
    return `#${attribute} = :${attribute}`;
  });
  let updated: Item | undefined;
  try {
    updated = await table.update(key, {
      UpdateExpression: `SET ${assignments.join(', ')}`,
      ConditionExpression: 'attribute_exists(pk)',
      ExpressionAttributeNames: names,
      ExpressionAttributeValues: values,
    });
  } catch (error) {
    if (isConditionalCheckFailure(error)) {
      return jsonError(404, 'not_found');
    }
    throw error;
  }

  let item: Item = { ...existing, ...(typeof updated === 'object' && updated !== null ? updated : {}), ...set };
  if (rehash && hasher !== null && hashRunId !== null) {
    item = await startHashRun(deps, hasher, key, item, { applicationId, url: edited.url as string, hashRunId });
  }

  await appendAudit(table, {
    action: APPLICATION_UPDATED_ACTION,
    actor,
    target: applicationId,
    detail: { name: edited.name, changed },
    now: at,
  });

  return { statusCode: 200, body: applicationRecord(item) };
};

/** Register the admin application routes on a router. Returns the router, so calls chain. */
export function registerApplicationAdminRoutes(router: Router, source: AdminDependencySource): Router {
  registerAdminRoute(router, 'GET', APPLICATION_PATH, handleApplicationList, source);
  registerAdminRoute(router, 'POST', APPLICATION_PATH, handleApplicationCreate, source);
  registerAdminRoute(router, 'POST', APPLICATION_UPLOAD_URL_PATH, handleApplicationUploadUrl, source);
  registerAdminRoute(router, 'POST', APPLICATION_RETRY_HASH_PATH, handleApplicationRetryHash, source);
  registerAdminRoute(router, 'PATCH', APPLICATION_DETAIL_PATH, handleApplicationUpdate, source);
  return registerAdminRoute(router, 'DELETE', APPLICATION_DETAIL_PATH, handleApplicationDelete, source);
}
