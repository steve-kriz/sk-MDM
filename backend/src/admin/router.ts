/**
 * The admin API surface: every route under `/admin/api/v1`, behind the Entra
 * token verifier.
 *
 * Registration goes through this module so authorisation can never be
 * forgotten by a later route:
 *
 *   registerAdminRoute(router, 'GET', '/groups', handleGroupList, source);
 *   // -> GET /admin/api/v1/groups, reached only by a verified admin
 *
 * `registerAdminRoute` takes the sub-path under `ADMIN_PREFIX` and an
 * `AdminRouteHandler`, which is an ordinary route handler with two extras: the
 * request carries the verified `claims`, and the resolved dependencies arrive
 * as a second argument, so a handler never resolves them itself.
 *
 * Authorisation runs before the handler is ever called. A request with no
 * `Authorization` header, or one that is not of the `Bearer <token>` form, is
 * refused with 401 `unauthorized` and no handler runs. A token that the
 * verifier rejects is answered with that rejection's own `{status, error}`
 * (401 `invalid_token`, 403 `not_admin`, 503 `jwks_unavailable`, ...).
 *
 * Every dependency -- the verifier, the table client and the clock -- is
 * injected and resolved per request, so nothing is constructed at import time
 * and tests drive the routes with a stub verifier and a fake table.
 *
 * This module also owns the two things every admin read route shares: the
 * `limit` rules (default 50, maximum 200, decimal integers only) and the
 * `{items, cursor}` envelope, plus the audit range route, whose query side
 * lives in `src/audit.ts` next to the writer it shares a key shape with.
 *
 * The write routes (`src/admin/groups.ts`, `src/admin/enrollmentTokens.ts`,
 * `src/admin/commandDispatch.ts`) share what they need from here too: the
 * JSON body reader, the clock and random source, the audit actor, and the
 * `AdminWriteTable` narrowing that keeps `put` out of the read-only contract.
 */
import { randomBytes as cryptoRandomBytes } from 'node:crypto';
import { isVerifyFailure, type TokenClaims, type TokenVerifier } from '../auth/entra.js';
import { queryAudit, type AuditPage } from '../audit.js';
import type { TableKey } from '../db/keys.js';
import type { GraphDirectory } from '../graph/client.js';
import { decodeCursor, type Item, type QueryPage, type QueryRequest, type RequestFields } from '../db/table.js';
import type { RouteHandler, RouteRequest, RouteResult, Router } from '../http/router.js';

/** Every admin route is mounted under this prefix. */
export const ADMIN_PREFIX = '/admin/api/v1';

/** Sub-path of the audit range route. */
export const AUDIT_PATH = '/audit';

/** The only `Authorization` scheme the admin API accepts. */
export const BEARER_PREFIX = 'Bearer ';

/** Items per page when the request names no `limit`. */
export const DEFAULT_LIMIT = 50;

/** The largest `limit` accepted; a bigger one is refused, never clamped. */
export const MAX_LIMIT = 200;

/** A decimal integer with no sign, fraction or exponent: what `limit` must look like. */
const LIMIT_PATTERN = /^[0-9]+$/;

/** `2026-10-02T07:15:00Z` -- the timestamp shape the audit bounds must take. */
const ISO_UTC_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

/**
 * The storage operations the admin read routes need: the structural read-only
 * subset of `TableClient` (see `src/db/table.ts`) a fake has to implement.
 */
export interface AdminTable {
  get(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
  query(request?: QueryRequest): Promise<QueryPage>;
}

/**
 * What a write route additionally needs. The read routes are unchanged, so a
 * read-only fake still satisfies `AdminTable`; a write route narrows the
 * injected table with `adminWriteTable` instead.
 */
export interface AdminWriteTable extends AdminTable {
  put(item: Item, fields?: RequestFields): Promise<void>;
}

/** The injected random source, injectable so a test can make ids predictable. */
export type AdminRandomBytes = (size: number) => Buffer;

/**
 * Current time: integer epoch *seconds*, or any instant a `Date` can be built
 * from (an ISO-8601 string or a `Date`). Same unit as the agent routes' clock.
 */
export type AdminClock = () => number | string | Date;

export interface AdminDependencies {
  /** Validates the bearer token. Required; never created here. */
  verifier: TokenVerifier;
  /** Table client. Required; never created here. */
  table: AdminTable;
  /** Current time. Defaults to the system clock, in epoch seconds. */
  now?: AdminClock;
  /** Random source used by the write routes. Defaults to `node:crypto`. */
  randomBytes?: AdminRandomBytes;
  /** Microsoft Graph, for the user-link routes. `undefined` when Graph is not configured. */
  graph?: GraphDirectory;
}

/** Dependencies, or something that resolves them when the request arrives. */
export type AdminDependencySource =
  | AdminDependencies
  | (() => AdminDependencies | Promise<AdminDependencies>);

/** A route request that has passed the verifier, carrying its claims. */
export interface AdminRequest extends RouteRequest {
  claims: TokenClaims;
}

/** An admin route handler: an authorised request plus the resolved dependencies. */
export type AdminRouteHandler = (
  request: AdminRequest,
  dependencies: AdminDependencies,
) => RouteResult | Promise<RouteResult>;

/** A JSON error body, in the shape every route in this backend returns. */
export function jsonError(statusCode: number, error: string, extra?: Record<string, unknown>): RouteResult {
  return { statusCode, body: { error, ...(extra ?? {}) } };
}

/**
 * The injected table as a write route needs it.
 *
 * Writing is not part of `AdminTable`, so the one place that assumption is
 * made is here: a table client with no `put` is a wiring fault and becomes the
 * router's 500 rather than a silently skipped write.
 */
export function adminWriteTable(table: AdminTable): AdminWriteTable {
  if (typeof (table as Partial<AdminWriteTable>).put !== 'function') {
    throw new Error('admin write routes need a table client with put()');
  }
  return table as AdminWriteTable;
}

/** Normalise whatever the injected clock returned into a `Date`; a number is epoch seconds. */
export function toAdminDate(instant: number | string | Date): Date {
  if (instant instanceof Date) {
    return new Date(instant.getTime());
  }
  if (typeof instant === 'string') {
    return new Date(instant);
  }
  return new Date(instant * 1000);
}

/** The current instant, from the injected clock or the system one. */
export function adminNow(deps: AdminDependencies): Date {
  const clock = deps.now ?? ((): number => Math.floor(Date.now() / 1000));
  return toAdminDate(clock());
}

/** The injected random source, or `node:crypto`'s. */
export function adminRandomBytes(deps: AdminDependencies): AdminRandomBytes {
  return deps.randomBytes ?? cryptoRandomBytes;
}

/**
 * Who the audit trail records for this request: the admin's
 * `preferred_username`, falling back to the other identity claims a tenant may
 * issue instead so an entry is never written without an actor.
 */
export function adminActor(claims: TokenClaims | undefined): string {
  for (const claim of ['preferred_username', 'upn', 'email', 'sub']) {
    const value = claims?.[claim];
    if (typeof value === 'string' && value.length > 0) {
      return value;
    }
  }
  return 'unknown';
}

/** The posted body as an object; `null` when it is absent or not JSON object text. */
export function readJsonBody(body: string | null | undefined): Record<string, unknown> | null {
  if (typeof body !== 'string' || body.length === 0) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return null;
  }
  return parsed as Record<string, unknown>;
}

/** The full path a sub-path is mounted on; an already-prefixed path is left alone. */
export function adminPath(path: string): string {
  if (path.startsWith(ADMIN_PREFIX)) {
    return path;
  }
  return `${ADMIN_PREFIX}${path.startsWith('/') ? '' : '/'}${path}`;
}

/** Resolve dependencies, whether they were handed over directly or as a function. */
export async function resolveAdminDeps(source: AdminDependencySource): Promise<AdminDependencies> {
  return typeof source === 'function' ? await source() : source;
}

/**
 * The bearer token of a request, or `null` when there is not one.
 *
 * Header names reach the router lower-cased; both spellings are read so a
 * handler is never fooled by casing.
 */
export function bearerToken(headers: Record<string, string> | undefined): string | null {
  const header = headers?.authorization ?? headers?.Authorization;
  if (typeof header !== 'string' || !header.startsWith(BEARER_PREFIX)) {
    return null;
  }
  const token = header.slice(BEARER_PREFIX.length).trim();
  return token.length > 0 ? token : null;
}

/**
 * The `limit` query parameter, or `null` when it is not a page size this API
 * accepts. An absent or empty value is the default, never a failure.
 */
export function parseLimit(raw: string | undefined): number | null {
  if (raw === undefined || raw === '') {
    return DEFAULT_LIMIT;
  }
  if (!LIMIT_PATTERN.test(raw)) {
    return null;
  }
  const limit = Number(raw);
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_LIMIT) {
    return null;
  }
  return limit;
}

/** True when a cursor is one this backend issued; an absent cursor is fine. */
export function isUsableCursor(cursor: string | null | undefined): boolean {
  if (cursor === undefined || cursor === null || cursor === '') {
    return true;
  }
  try {
    decodeCursor(cursor);
    return true;
  } catch {
    return false;
  }
}

/** The `cursor` query parameter as `query`/`queryAudit` want it. */
export function readCursor(raw: string | undefined): string | null {
  return raw === undefined || raw === '' ? null : raw;
}

/** True for `2026-10-02T07:15:00Z` and nothing looser: an ISO-8601 UTC timestamp. */
export function isIsoUtc(value: string | undefined): value is string {
  return typeof value === 'string' && ISO_UTC_PATTERN.test(value) && !Number.isNaN(Date.parse(value));
}

/**
 * Wrap a handler so it runs only for a verified admin.
 *
 * The bearer header is settled first and a missing or malformed one is refused
 * without touching the verifier, the table or the handler.
 */
export function requireAdmin(handler: AdminRouteHandler, source: AdminDependencySource): RouteHandler {
  return async function authorised(req: RouteRequest): Promise<RouteResult> {
    const token = bearerToken(req?.headers);
    if (token === null) {
      return jsonError(401, 'unauthorized');
    }

    const deps = await resolveAdminDeps(source);

    let claims: TokenClaims;
    try {
      claims = await deps.verifier.verify(token);
    } catch (error) {
      // The verifier rejects with `{status, error}`; anything else is a fault
      // and becomes the router's 500.
      if (isVerifyFailure(error)) {
        return jsonError(error.status, error.error);
      }
      throw error;
    }

    return handler({ ...req, claims }, deps);
  };
}

/**
 * Register one admin route. `path` is the sub-path under `ADMIN_PREFIX`.
 * Returns the router, so calls chain.
 */
export function registerAdminRoute(
  router: Router,
  method: string,
  path: string,
  handler: AdminRouteHandler,
  source: AdminDependencySource,
): Router {
  return router.add(method, adminPath(path), requireAdmin(handler, source));
}

/**
 * `GET /admin/api/v1/audit?from=<iso>&to=<iso>` -- the audit trail over an
 * inclusive range of UTC days, newest first.
 *
 * Both bounds are required and must be ISO-8601 UTC timestamps
 * (`2026-10-02T00:00:00Z`); a looser spelling, a missing bound or a `from`
 * after `to` is refused with 400 `invalid_request` before anything is read.
 */
export const handleAuditQuery: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const limit = parseLimit(req.query?.limit);
  const cursor = readCursor(req.query?.cursor);
  if (limit === null || !isUsableCursor(cursor)) {
    return jsonError(400, 'invalid_request');
  }

  const fromIso = req.query?.from;
  const toIso = req.query?.to;
  if (!isIsoUtc(fromIso) || !isIsoUtc(toIso) || Date.parse(fromIso) > Date.parse(toIso)) {
    return jsonError(400, 'invalid_request');
  }

  const page: AuditPage = await queryAudit(deps.table, { fromIso, toIso, limit, cursor });
  return { statusCode: 200, body: { items: page.items, cursor: page.cursor } };
};

/** Register the audit route on a router. Returns the router, so calls chain. */
export function registerAuditRoutes(router: Router, source: AdminDependencySource): Router {
  return registerAdminRoute(router, 'GET', AUDIT_PATH, handleAuditQuery, source);
}

/**
 * Dependencies supplied at start-up.
 *
 * Nothing in this package constructs an AWS client or an HTTP client, so the
 * routes are registered at import time and the deployment hands over the
 * verifier and the table client by calling `configureAdminRoutes` before the
 * first request.
 */
let configured: AdminDependencies | null = null;

/** Supply the admin routes' verifier, storage and clock. */
export function configureAdminRoutes(dependencies: AdminDependencies): void {
  configured = dependencies;
}

/** The configured dependencies, or a thrown error when start-up skipped them. */
export function resolveAdminDependencies(): AdminDependencies {
  if (configured === null) {
    throw new Error('admin routes are not configured: call configureAdminRoutes() at start-up');
  }
  return configured;
}
