/**
 * Minting enrollment tokens: the credential an installer presents once.
 *
 *   POST /admin/api/v1/enrollment-tokens                    -- mint one token
 *   GET  /admin/api/v1/enrollment-tokens                    -- list, newest first
 *   POST /admin/api/v1/enrollment-tokens/{tokenId}/revoke   -- revoke one, permanently
 *
 *   registerEnrollmentTokenRoutes(router, { verifier, table, now, randomBytes });
 *
 * The wire format is `<tokenId>.<secret>`: 16 lower-case hex characters from 8
 * random bytes, a dot, then 64 lower-case hex characters from 32 random bytes.
 * `tokenId` is the key the record is stored under and `secret` is the proof,
 * which is why the whole string -- not the secret alone -- is what gets hashed.
 *
 * The full token exists in exactly one place: the 201 response body. The
 * stored record holds `tokenHash`, the SHA-256 hex of the full token string,
 * which is precisely what `POST /api/v1/enroll` recomputes from the presented
 * header and compares in constant time (see `src/routes/enroll.ts`). Nothing
 * here writes the token, the secret, or anything derived from the secret alone
 * to an item, to the audit trail or to a log: a leaked table is not a leaked
 * fleet, and an admin who loses the token mints another.
 *
 * `expiresAt` is stored as an ISO-8601 UTC instant, the way every other stored
 * timestamp is written, and `maxUses`/`useCount` are the counters the enroll
 * route reads and claims against.
 */
import { createHash } from 'node:crypto';
import { appendAudit, isoUtc } from '../audit.js';
import { GSI1_NAME, enrollmentToken, enrollmentTokenListIndex, type TableKey } from '../db/keys.js';
import { CONDITIONAL_CHECK_FAILED, type Item } from '../db/table.js';
import type { RouteResult, Router } from '../http/router.js';
import {
  adminActor,
  adminNow,
  adminRandomBytes,
  adminUpdateTable,
  adminWriteTable,
  isUsableCursor,
  jsonError,
  parseLimit,
  readCursor,
  readJsonBody,
  registerAdminRoute,
  type AdminDependencySource,
  type AdminRouteHandler,
} from './router.js';

/** Sub-path of the enrollment token collection. */
export const ENROLLMENT_TOKEN_PATH = '/enrollment-tokens';

/** Length of the `<tokenId>` half, in bytes (16 hex characters). */
export const TOKEN_ID_BYTES = 8;

/** Length of the `<secret>` half, in bytes (64 hex characters, 256 bits of entropy). */
export const TOKEN_SECRET_BYTES = 32;

/** The separator between the two halves of a token. */
export const TOKEN_SEPARATOR = '.';

/** The audit action recorded when a token is minted. */
export const ENROLLMENT_TOKEN_CREATED_ACTION = 'enrollment_token.created';

/** Sub-path of the revoke action on one token. */
export const ENROLLMENT_TOKEN_REVOKE_PATH = '/enrollment-tokens/{tokenId}/revoke';

/** The audit action recorded when a token is revoked. */
export const ENROLLMENT_TOKEN_REVOKED_ACTION = 'enrollment_token.revoked';

/** The only fields a listed token carries, in response order. Never `token` or `tokenHash`. */
export const ENROLLMENT_TOKEN_LIST_FIELDS = [
  'tokenId',
  'label',
  'createdBy',
  'createdAt',
  'maxUses',
  'useCount',
  'expiresAt',
  'status',
  'deviceIds',
  'revokedAt',
] as const;

/** A token's status as the admin API reports it. */
export type EnrollmentTokenStatus = 'active' | 'used' | 'expired' | 'revoked';

/** An instant as the request may spell it: an ISO-8601 string or epoch milliseconds. */
function toInstant(value: unknown): Date | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return new Date(value);
  }
  if (typeof value !== 'string' || value.length === 0) {
    return null;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** The storage a mint needs: one put for the record, one for the audit entry. */
export interface MintTable {
  put(item: Item): Promise<void>;
}

/** Who enrolled a device, as a sign-in-minted token carries it onto the profile. */
export interface TokenEnrolledBy {
  oid: string;
  upn: string | null;
  name: string | null;
}

/** What one mint is made of. Validation is the caller's job. */
export interface MintOptions {
  label: string;
  maxUses: number;
  /** The instant the token stops working; `null` for a token that never expires. */
  expiry: Date | null;
  /** Stored on the record as `createdBy`. */
  createdBy: string;
  /** Recorded as the audit entry's actor. */
  actor: string;
  /** Now: `createdAt` and the audit timestamp. */
  at: Date;
  randomBytes: (size: number) => Buffer;
  /** Stored on the record when given; the enroll route copies it onto the device. */
  enrolledBy?: TokenEnrolledBy;
  /** Extra audit detail merged after `{label, maxUses, expiresAt}`. Never the token. */
  auditDetail?: Record<string, unknown>;
}

/** What a mint hands back. `token` must reach only the caller's response body. */
export interface MintedToken {
  tokenId: string;
  token: string;
  /** `null` when the token never expires. */
  expiresAt: string | null;
}

/**
 * Generate, store and audit one enrollment token. The wire format, the hashing
 * and the record shape live here only, shared by the admin route and the agent
 * sign-in mint (`src/routes/agentEnrollmentToken.ts`).
 */
export async function mintEnrollmentToken(table: MintTable, options: MintOptions): Promise<MintedToken> {
  const { label, maxUses, expiry, createdBy, actor, at, randomBytes, enrolledBy, auditDetail } = options;
  const tokenId = randomBytes(TOKEN_ID_BYTES).toString('hex');
  const secret = randomBytes(TOKEN_SECRET_BYTES).toString('hex');
  const token = `${tokenId}${TOKEN_SEPARATOR}${secret}`;
  // The whole token string is hashed, exactly as the enroll route hashes the
  // whole presented header value.
  const tokenHash = createHash('sha256').update(token, 'utf8').digest('hex');

  const expiresAt = expiry === null ? null : isoUtc(expiry);
  const createdAt = isoUtc(at);
  await table.put({
    ...enrollmentToken(tokenId),
    // Lists the record on the admin Enrollment tokens screen, newest first.
    ...enrollmentTokenListIndex(createdAt, tokenId),
    tokenId,
    label,
    maxUses,
    useCount: 0,
    // A token that never expires carries no `expiresAt`; the enroll route
    // treats a missing one as unexpired.
    ...(expiresAt === null ? {} : { expiresAt }),
    tokenHash,
    createdAt,
    createdBy,
    ...(enrolledBy === undefined ? {} : { enrolledBy }),
  });

  // The label, the counter and the expiry are safe to record; the token is not.
  await appendAudit(table, {
    action: ENROLLMENT_TOKEN_CREATED_ACTION,
    actor,
    target: tokenId,
    detail: { label, maxUses, expiresAt, ...(auditDetail ?? {}) },
    now: at,
  });

  return { tokenId, token, expiresAt };
}

/**
 * `POST /admin/api/v1/enrollment-tokens` -- mint one token.
 *
 * A token that may never be used is a mistake, not a token: a `maxUses` below
 * one, or an expiry that has already passed, is refused before anything is
 * generated or written.
 */
export const handleEnrollmentTokenCreate: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body) ?? {};

  const maxUses = body.maxUses;
  if (!Number.isInteger(maxUses) || (maxUses as number) < 1) {
    return jsonError(400, 'invalid_request');
  }

  const at = adminNow(deps);
  const expiry = toInstant(body.expiresAt);
  if (expiry === null || expiry.getTime() <= at.getTime()) {
    return jsonError(400, 'invalid_request');
  }

  const label = typeof body.label === 'string' ? body.label : '';
  const actor = adminActor(req.claims);
  const { tokenId, token, expiresAt } = await mintEnrollmentToken(adminWriteTable(deps.table), {
    label,
    maxUses: maxUses as number,
    expiry,
    createdBy: actor,
    actor,
    at,
    randomBytes: adminRandomBytes(deps),
  });

  return { statusCode: 201, body: { tokenId, token, label, maxUses, expiresAt } };
};

/** A non-empty string, or `null`. */
function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/** A finite number, or `null`. */
function numberOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/**
 * A token record's status, decided in this order: `revoked` when `revokedAt`
 * is set; else `expired` when `expiresAt` is at or before now; else `used`
 * when `useCount` has reached `maxUses`; else `active`. Shared with the device
 * detail view (`src/admin/devices.ts`).
 */
export function enrollmentTokenStatus(record: Item, now: Date): EnrollmentTokenStatus {
  if (record.revokedAt !== undefined && record.revokedAt !== null) {
    return 'revoked';
  }
  const expiresAt = record.expiresAt;
  if (typeof expiresAt === 'string' || typeof expiresAt === 'number') {
    const expiry = new Date(expiresAt).getTime();
    if (!Number.isNaN(expiry) && expiry <= now.getTime()) {
      return 'expired';
    }
  }
  const useCount = numberOrNull(record.useCount) ?? 0;
  const maxUses = numberOrNull(record.maxUses);
  if (maxUses !== null && useCount >= maxUses) {
    return 'used';
  }
  return 'active';
}

/**
 * The device ids a token record has enrolled, always a plain array of strings:
 * `[]` when the attribute is absent.
 */
export function tokenDeviceIds(record: Item): string[] {
  const value = record.deviceIds;
  const list: unknown[] = Array.isArray(value) ? value : [];
  return list.filter((id): id is string => typeof id === 'string' && id.length > 0);
}

/** One listed token: exactly `ENROLLMENT_TOKEN_LIST_FIELDS`, never the token or its hash. */
function tokenListItem(record: Item, now: Date): Item {
  return {
    tokenId: stringOrNull(record.tokenId),
    label: typeof record.label === 'string' ? record.label : null,
    createdBy: stringOrNull(record.createdBy),
    createdAt: stringOrNull(record.createdAt),
    maxUses: numberOrNull(record.maxUses),
    useCount: numberOrNull(record.useCount) ?? 0,
    expiresAt: stringOrNull(record.expiresAt),
    status: enrollmentTokenStatus(record, now),
    deviceIds: tokenDeviceIds(record),
    revokedAt: stringOrNull(record.revokedAt),
  };
}

/**
 * `GET /admin/api/v1/enrollment-tokens` -- the minted tokens, newest first,
 * from the `gsi1` `ENROLLTOKEN` partition. A token minted before the list
 * index existed carries no index attributes and is not listed.
 */
export const handleEnrollmentTokenList: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const limit = parseLimit(req.query?.limit);
  const cursor = readCursor(req.query?.cursor);
  if (limit === null || !isUsableCursor(cursor)) {
    return jsonError(400, 'invalid_request');
  }

  const { gsi1pk } = enrollmentTokenListIndex('', '');
  const page = await deps.table.query({
    IndexName: GSI1_NAME,
    KeyConditionExpression: '#gsi1pk = :gsi1pk',
    ExpressionAttributeNames: { '#gsi1pk': 'gsi1pk' },
    ExpressionAttributeValues: { ':gsi1pk': gsi1pk },
    // Descending, so the most recently minted token comes back first.
    ScanIndexForward: false,
    limit,
    cursor,
  });

  const now = adminNow(deps);
  const items = page.items.map((record) => tokenListItem(record, now));
  return { statusCode: 200, body: { items, cursor: page.cursor } };
};

/** True when a thrown value is DynamoDB's failed-condition rejection. */
function isConditionalCheckFailure(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === CONDITIONAL_CHECK_FAILED
  );
}

/**
 * `POST /admin/api/v1/enrollment-tokens/{tokenId}/revoke` -- stop a token
 * enrolling ever again. Permanent: there is no un-revoke.
 *
 * Only the token record and one audit entry are written. No device profile is
 * read or written: devices the token already enrolled keep working, and are
 * disabled only from the device page.
 */
export const handleEnrollmentTokenRevoke: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const tokenId = req.params?.tokenId ?? '';
  let tokenKey: TableKey;
  try {
    tokenKey = enrollmentToken(tokenId);
  } catch {
    return jsonError(404, 'not_found');
  }

  const record = await deps.table.get(tokenKey);
  if (record === undefined || record === null) {
    return jsonError(404, 'not_found');
  }
  if (record.revokedAt !== undefined && record.revokedAt !== null) {
    return jsonError(409, 'already_revoked');
  }

  const table = adminUpdateTable(deps.table);
  const at = adminNow(deps);
  const revokedAt = isoUtc(at);
  const actor = adminActor(req.claims);
  try {
    await table.update(tokenKey, {
      UpdateExpression: 'SET #revokedAt = :revokedAt, #revokedBy = :revokedBy',
      // A concurrent revoke (or a delete) between the read and here writes nothing.
      ConditionExpression: 'attribute_exists(pk) AND attribute_not_exists(#revokedAt)',
      ExpressionAttributeNames: { '#revokedAt': 'revokedAt', '#revokedBy': 'revokedBy' },
      ExpressionAttributeValues: { ':revokedAt': revokedAt, ':revokedBy': actor },
    });
  } catch (error) {
    if (isConditionalCheckFailure(error)) {
      return jsonError(409, 'already_revoked');
    }
    throw error;
  }

  await appendAudit(table, {
    action: ENROLLMENT_TOKEN_REVOKED_ACTION,
    actor,
    target: tokenId,
    detail: {},
    now: at,
  });

  return { statusCode: 200, body: { tokenId, status: 'revoked', revokedAt } };
};

/** Register the enrollment token routes on a router. Returns the router, so calls chain. */
export function registerEnrollmentTokenRoutes(router: Router, source: AdminDependencySource): Router {
  registerAdminRoute(router, 'GET', ENROLLMENT_TOKEN_PATH, handleEnrollmentTokenList, source);
  registerAdminRoute(router, 'POST', ENROLLMENT_TOKEN_REVOKE_PATH, handleEnrollmentTokenRevoke, source);
  return registerAdminRoute(router, 'POST', ENROLLMENT_TOKEN_PATH, handleEnrollmentTokenCreate, source);
}
