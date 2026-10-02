/**
 * Minting enrollment tokens: the credential an installer presents once.
 *
 *   POST /admin/api/v1/enrollment-tokens
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
import { enrollmentToken } from '../db/keys.js';
import type { RouteResult, Router } from '../http/router.js';
import {
  adminActor,
  adminNow,
  adminRandomBytes,
  adminWriteTable,
  jsonError,
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

  const randomBytes = adminRandomBytes(deps);
  const tokenId = randomBytes(TOKEN_ID_BYTES).toString('hex');
  const secret = randomBytes(TOKEN_SECRET_BYTES).toString('hex');
  const token = `${tokenId}${TOKEN_SEPARATOR}${secret}`;
  // The whole token string is hashed, exactly as the enroll route hashes the
  // whole presented header value.
  const tokenHash = createHash('sha256').update(token, 'utf8').digest('hex');

  const expiresAt = isoUtc(expiry);
  const table = adminWriteTable(deps.table);
  await table.put({
    ...enrollmentToken(tokenId),
    tokenId,
    label,
    maxUses,
    useCount: 0,
    expiresAt,
    tokenHash,
    createdAt: isoUtc(at),
    createdBy: adminActor(req.claims),
  });

  // The label, the counter and the expiry are safe to record; the token is not.
  await appendAudit(table, {
    action: ENROLLMENT_TOKEN_CREATED_ACTION,
    actor: adminActor(req.claims),
    target: tokenId,
    detail: { label, maxUses, expiresAt },
    now: at,
  });

  return { statusCode: 201, body: { tokenId, token, label, maxUses, expiresAt } };
};

/** Register the enrollment token route on a router. Returns the router, so calls chain. */
export function registerEnrollmentTokenRoutes(router: Router, source: AdminDependencySource): Router {
  return registerAdminRoute(router, 'POST', ENROLLMENT_TOKEN_PATH, handleEnrollmentTokenCreate, source);
}
