/**
 * `POST /api/v1/enroll` -- the one route that issues a device its identity.
 *
 * Enroll is authenticated by the enrollment token alone, carried over TLS in
 * `X-MDM-Enrollment-Token` as `<tokenId>.<secret>`. It never calls
 * `verifyDeviceRequest` and never looks at the device HMAC headers: at enroll
 * time the agent has no device id and no device secret, so there is nothing to
 * sign with (see `src/http/deviceAuth.ts`).
 *
 *   router.add('POST', ENROLL_PATH, createEnrollHandler({ table, pepper }));
 *
 * `tokenId` locates the stored token record and the SHA-256 of the *whole*
 * presented header value is compared, in constant time, against the stored
 * `tokenHash`. The checks run in a fixed order, each returning immediately:
 *
 *   1. header shape        -> 401 invalid_enrollment_token (nothing is read)
 *   2. record found + hash -> 401 invalid_enrollment_token
 *   3. not expired         -> 403 enrollment_token_expired
 *   4. uses remaining      -> 403 enrollment_token_exhausted
 *   5. body valid          -> 400 invalid_request, naming every bad field
 *   6. use count claimed   -> 403 enrollment_token_exhausted (lost the race)
 *
 * The use count is claimed with a conditional update *before* anything is
 * written, so a refused enrollment leaves no device, pointer or audit item
 * behind.
 *
 * A machine that re-enrolls is recognised by its hardware uuid: the
 * `deviceByHardware` pointer item holds the device id the uuid was first bound
 * to, and the loser of a concurrent `putIfAbsent` re-reads that pointer rather
 * than creating a second device.
 *
 * The issued secret is the agent's HMAC key, so it is stored encrypted under
 * the pepper (`secretEnc`) and never hashed. The plaintext exists in exactly
 * one place -- the response body. It is never written to an item, never passed
 * to `appendAudit` and never logged.
 *
 * Storage, the clock, the random source and the pepper are all injected and no
 * AWS client is constructed here, so tests drive the route with fakes.
 */
import { createHash, randomBytes as cryptoRandomBytes, timingSafeEqual } from 'node:crypto';
import { appendAudit, isoUtc, toUtcDate, type AuditClock, type AuditInstant } from '../audit.js';
import { DEFAULT_CHECKIN_INTERVAL_SECONDS } from '../config/intervals.js';
import type { EnrollResponse } from '../contract/types.js';
import { encryptDeviceSecret } from '../crypto/deviceSecret.js';
import { deviceByHardware, deviceListIndex, deviceProfile, enrollmentToken, type TableKey } from '../db/keys.js';
import { CONDITIONAL_CHECK_FAILED, type Item, type RequestFields, type WriteOutcome } from '../db/table.js';
import type { RouteHandler, RouteRequest, RouteResult, Router } from '../http/router.js';

/** Path this route is registered on. */
export const ENROLL_PATH = '/api/v1/enroll';

/** The enrollment token header, lower-cased; lookups are case-insensitive. */
export const ENROLLMENT_TOKEN_HEADER = 'x-mdm-enrollment-token';

/** Length of an issued device secret, in bytes (64 hex characters). */
export const DEVICE_SECRET_BYTES = 32;

/** Length of the random part of a generated device id, in bytes. */
export const DEVICE_ID_BYTES = 8;

/** Prefix of a generated device id. */
export const DEVICE_ID_PREFIX = 'dev-';

/** The `<tokenId>` half: 16 lower-case hex characters. */
const TOKEN_ID_PATTERN = /^[0-9a-f]{16}$/;

/** The `<secret>` half: 64 lower-case hex characters. */
const TOKEN_SECRET_PATTERN = /^[0-9a-f]{64}$/;

/** The platforms the contract allows. */
const PLATFORMS = new Set(['windows', 'darwin']);

/** Required string fields of the enroll body, in the order they are reported. */
const REQUIRED_FIELDS = ['hostname', 'platform', 'osVersion', 'hardwareUuid', 'agentVersion'] as const;

/** The storage operations this route needs: the subset a fake must implement. */
export interface EnrollTable {
  get(key: TableKey): Promise<Item | undefined>;
  put(item: Item): Promise<void>;
  putIfAbsent(item: Item): Promise<WriteOutcome>;
  update(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
}

/** The pepper key, or anything that resolves it (a `PepperProvider` fits). */
export type PepperSource = string | (() => string | Promise<string>);

export interface EnrollDependencies {
  /** Table client. Required; never created here. */
  table: EnrollTable;
  /** The 64-character hex pepper key, or `getPepper`. */
  pepper: PepperSource;
  /** Current time. Defaults to the system clock. */
  now?: AuditClock | AuditInstant;
  /** Random source, injected so a test can make the issued secret predictable. */
  randomBytes?: (size: number) => Buffer;
}

/** Dependencies, or something that resolves them when the first request arrives. */
export type EnrollDependencySource =
  | EnrollDependencies
  | (() => EnrollDependencies | Promise<EnrollDependencies>);

/** The stored enrollment token record as this route reads it. */
interface TokenRecord extends Item {
  tokenHash?: unknown;
  expiresAt?: unknown;
  maxUses?: unknown;
  useCount?: unknown;
}

/** A validated enroll body. */
interface EnrollBody {
  hostname: string;
  platform: 'windows' | 'darwin';
  osVersion: string;
  hardwareUuid: string;
  agentVersion: string;
}

function failure(statusCode: number, error: string, extra?: Record<string, unknown>): RouteResult {
  return { statusCode, body: { error, ...(extra ?? {}) } };
}

/** Index headers by lower-cased name, so `X-MDM-...` and `x-mdm-...` both read. */
function headerValue(headers: RouteRequest['headers'] | undefined, name: string): string {
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (key.toLowerCase() === name && typeof value === 'string') {
      return value;
    }
  }
  return '';
}

/**
 * Split the presented header at its *first* `.` and check both halves, before
 * any key is built: a `tokenId` carrying a `#` must never reach a key builder.
 */
function splitToken(presented: string): { tokenId: string } | null {
  if (presented.length === 0) {
    return null;
  }
  const dot = presented.indexOf('.');
  if (dot < 0) {
    return null;
  }
  const tokenId = presented.slice(0, dot);
  const secret = presented.slice(dot + 1);
  if (!TOKEN_ID_PATTERN.test(tokenId) || !TOKEN_SECRET_PATTERN.test(secret)) {
    return null;
  }
  return { tokenId };
}

/** Constant-time compare of the stored hash against the presented value's. */
function tokenHashMatches(storedHash: unknown, presented: string): boolean {
  if (typeof storedHash !== 'string' || storedHash.length === 0) {
    return false;
  }
  const expected = Buffer.from(storedHash, 'hex');
  const actual = createHash('sha256').update(presented, 'utf8').digest();
  if (expected.length !== actual.length) {
    return false;
  }
  return timingSafeEqual(expected, actual);
}

/** Parse the body and name every field that is missing or wrong. */
function readBody(raw: string | null): { body: EnrollBody } | { fields: string[] } {
  let parsed: unknown;
  try {
    parsed = raw === null || raw.length === 0 ? null : JSON.parse(raw);
  } catch {
    parsed = null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    // Nothing usable arrived, so every required field is missing.
    return { fields: [...REQUIRED_FIELDS] };
  }

  const candidate = parsed as Record<string, unknown>;
  const fields: string[] = [];
  for (const name of REQUIRED_FIELDS) {
    const value = candidate[name];
    if (typeof value !== 'string' || value.length === 0) {
      fields.push(name);
      continue;
    }
    if (name === 'platform' && !PLATFORMS.has(value)) {
      fields.push(name);
      continue;
    }
    // A `#` would collide with the key separator, so such a uuid can never be
    // stored: it is a bad field rather than a failed write.
    if (name === 'hardwareUuid' && value.includes('#')) {
      fields.push(name);
    }
  }
  if (fields.length > 0) {
    return { fields };
  }
  return { body: candidate as unknown as EnrollBody };
}

/** True when the token's `expiresAt` is at or before now. */
function isExpired(expiresAt: unknown, at: Date): boolean {
  if (expiresAt === undefined || expiresAt === null) {
    return false;
  }
  const expiry = new Date(expiresAt as string | number).getTime();
  if (Number.isNaN(expiry)) {
    return false;
  }
  return expiry <= at.getTime();
}

/** A stored count, defaulting the way a freshly created token reads. */
function countOf(value: unknown, fallback: number): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

/** True when a thrown value is DynamoDB's failed-condition rejection. */
function isConditionalCheckFailure(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === CONDITIONAL_CHECK_FAILED
  );
}

async function resolvePepper(pepper: PepperSource): Promise<string> {
  return typeof pepper === 'function' ? await pepper() : pepper;
}

/**
 * Build the enroll route handler.
 *
 * @param source the dependencies, or a function resolving them on first use
 */
export function createEnrollHandler(source: EnrollDependencySource): RouteHandler {
  async function dependencies(): Promise<EnrollDependencies> {
    return typeof source === 'function' ? await source() : source;
  }

  return async function handleEnroll(req: RouteRequest): Promise<RouteResult> {
    const { table, pepper, now = (): Date => new Date(), randomBytes = cryptoRandomBytes } =
      await dependencies();

    // 1. The token's shape, before anything is read.
    const presented = headerValue(req?.headers, ENROLLMENT_TOKEN_HEADER);
    const split = splitToken(presented);
    if (split === null) {
      return failure(401, 'invalid_enrollment_token');
    }

    // 2. The token record, and the hash of the whole presented value.
    const record = (await table.get(enrollmentToken(split.tokenId))) as TokenRecord | undefined;
    if (record === undefined || record === null || !tokenHashMatches(record.tokenHash, presented)) {
      return failure(401, 'invalid_enrollment_token');
    }

    const at = toUtcDate(now);

    // 3. Expiry is checked before exhaustion: an expired token says so even
    //    when it also has no uses left.
    if (isExpired(record.expiresAt, at)) {
      return failure(403, 'enrollment_token_expired');
    }

    // 4. Uses remaining.
    if (countOf(record.useCount, 0) >= countOf(record.maxUses, Number.POSITIVE_INFINITY)) {
      return failure(403, 'enrollment_token_exhausted');
    }

    // 5. The body, reporting every offending field at once.
    const read = readBody(req?.body ?? null);
    if ('fields' in read) {
      return failure(400, 'invalid_request', { fields: read.fields });
    }
    const { hostname, platform, osVersion, hardwareUuid, agentVersion } = read.body;

    // 6. Claim one use before writing anything, so a token that runs out
    //    between the read above and here leaves no half-made device behind.
    try {
      await table.update(enrollmentToken(split.tokenId), {
        UpdateExpression: 'SET useCount = if_not_exists(useCount, :zero) + :one',
        ConditionExpression: 'useCount < maxUses',
        ExpressionAttributeValues: { ':zero': 0, ':one': 1 },
      });
    } catch (error) {
      if (isConditionalCheckFailure(error)) {
        return failure(403, 'enrollment_token_exhausted');
      }
      throw error;
    }

    const lastSeenAt = isoUtc(at);
    const pointerKey = deviceByHardware(hardwareUuid);

    // The hardware uuid decides whether this is a new device or the same
    // machine coming back.
    let deviceId: string;
    let rebound = true;
    const pointer = await table.get(pointerKey);
    if (typeof pointer?.deviceId === 'string' && pointer.deviceId.length > 0) {
      deviceId = pointer.deviceId;
    } else {
      const candidate = `${DEVICE_ID_PREFIX}${randomBytes(DEVICE_ID_BYTES).toString('hex')}`;
      const outcome = await table.putIfAbsent({ ...pointerKey, deviceId: candidate, createdAt: lastSeenAt });
      if (outcome?.written) {
        deviceId = candidate;
        rebound = false;
      } else {
        // Another agent enrolled this machine first: use its device rather
        // than creating a second one.
        const winner = await table.get(pointerKey);
        deviceId =
          typeof winner?.deviceId === 'string' && winner.deviceId.length > 0 ? winner.deviceId : candidate;
      }
    }

    // A fresh secret every time, stored only as ciphertext bound to this device.
    const deviceSecret = randomBytes(DEVICE_SECRET_BYTES).toString('hex');
    const secretEnc = encryptDeviceSecret(deviceSecret, await resolvePepper(pepper), deviceId);

    // On a re-bind the existing profile is carried forward so attributes other
    // tickets own (status, group, posture) survive re-enrollment; `secretEnc`
    // is replaced, which stops the previous secret verifying.
    const profileKey = deviceProfile(deviceId);
    const carried: Item = { ...((rebound ? await table.get(profileKey) : undefined) ?? {}) };
    // The secret is never stored as a hash, so an item carrying one is stale.
    delete carried.secretHash;
    await table.put({
      ...carried,
      ...profileKey,
      ...deviceListIndex(lastSeenAt),
      deviceId,
      hostname,
      platform,
      osVersion,
      hardwareUuid,
      agentVersion,
      secretEnc,
      lastSeenAt,
      enrolledAt: typeof carried.enrolledAt === 'string' ? carried.enrolledAt : lastSeenAt,
    });

    await appendAudit(table, {
      action: 'device.enrolled',
      actor: `device:${deviceId}`,
      target: deviceId,
      detail: { hardwareUuid, platform, agentVersion },
      now: at,
    });

    const body: EnrollResponse = {
      deviceId,
      deviceSecret,
      checkInIntervalSeconds: DEFAULT_CHECKIN_INTERVAL_SECONDS,
      serverTime: lastSeenAt,
    };
    return { statusCode: 200, body };
  };
}

/** Register the route on a router. Returns the router, so calls chain. */
export function registerEnrollRoute(router: Router, source: EnrollDependencySource): Router {
  return router.add('POST', ENROLL_PATH, createEnrollHandler(source));
}

/**
 * Dependencies supplied at start-up.
 *
 * Nothing in this package constructs an AWS client, so the route is registered
 * at import time and the deployment hands it a table client and a pepper
 * provider by calling `configureEnrollRoute` before the first request.
 */
let configured: EnrollDependencies | null = null;

/** Supply the enroll route's storage and pepper. */
export function configureEnrollRoute(dependencies: EnrollDependencies): void {
  configured = dependencies;
}

/** The configured dependencies, or a thrown error when start-up skipped them. */
export function resolveEnrollDependencies(): EnrollDependencies {
  if (configured === null) {
    throw new Error('enroll route is not configured: call configureEnrollRoute() at start-up');
  }
  return configured;
}
