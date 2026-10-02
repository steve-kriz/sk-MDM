/**
 * Which Entra ID user each managed device belongs to, read from Microsoft Graph.
 *
 *   POST /admin/api/v1/devices/{deviceId}/user-link/refresh -- one device
 *   POST /admin/api/v1/user-links/refresh                    -- one page of the fleet
 *
 *   registerUserLinkRoutes(router, { verifier, table, now, graph });
 *
 * A link is resolved from the device profile's `hostname`, cut at its first
 * `.`: the Entra device of that display name is looked up, and its
 * `registeredUsers` read. The result is stored as the device's `USERLINK` item
 * and the primary user's UPN is denormalised onto the profile as
 * `primaryUserUpn`, so the fleet list shows it without one Graph call per row.
 *
 * Graph is only ever called from these two routes, when an admin asks. Both are
 * registered through `registerAdminRoute`, so they are reached only by a
 * verified admin, and every dependency -- including `graph` -- is injected.
 * When `graph` is absent both answer 503 `graph_not_configured`.
 *
 * Every Graph read for a device happens before anything is written for it, so
 * a Graph failure leaves the stored link and the profile exactly as they were.
 */
import { appendAudit } from '../audit.js';
import { deviceProfile, deviceUserLink, type TableKey } from '../db/keys.js';
import type { Item, RequestFields } from '../db/table.js';
import { isGraphFailure, type GraphDirectory, type GraphUser } from '../graph/client.js';
import type { RouteResult, Router } from '../http/router.js';
import { byLastSeenDescending, deviceSummary, listFleet } from './devices.js';
import {
  adminActor,
  adminNow,
  adminWriteTable,
  isUsableCursor,
  jsonError,
  readJsonBody,
  registerAdminRoute,
  type AdminDependencies,
  type AdminDependencySource,
  type AdminRouteHandler,
  type AdminTable,
  type AdminWriteTable,
} from './router.js';

/** Sub-path of the per-device refresh. */
export const DEVICE_USER_LINK_REFRESH_PATH = '/devices/{deviceId}/user-link/refresh';

/** Sub-path of the bulk refresh. */
export const USER_LINKS_REFRESH_PATH = '/user-links/refresh';

/** Audit action of a per-device refresh. */
export const DEVICE_USER_LINK_REFRESHED_ACTION = 'device.user_link.refreshed';

/** Audit action of a bulk refresh. */
export const USER_LINKS_REFRESHED_ACTION = 'user_links.refreshed';

/** Devices per bulk page when the body names no `limit`; also the largest accepted. */
export const USER_LINKS_DEFAULT_LIMIT = 25;
export const USER_LINKS_MAX_LIMIT = 25;

/** The statuses a resolution can end in. */
export const USER_LINK_STATUSES = ['linked', 'no_registered_user', 'ambiguous', 'not_found'] as const;
export type UserLinkStatus = (typeof USER_LINK_STATUSES)[number];

/**
 * Graph failures that only affect the device being resolved: a bulk refresh
 * reports them on that item and carries on. Any other failure (the token
 * endpoint, the secret) would fail every device the same way, so it ends the
 * call.
 */
const PER_DEVICE_FAILURES = new Set(['graph_unavailable', 'graph_forbidden']);

/** One user on a stored link: exactly these four fields, `null` where Graph had none. */
export interface UserLinkUser {
  id: string | null;
  displayName: string | null;
  userPrincipalName: string | null;
  mail: string | null;
}

/** What the user-link routes need of the table: reads, `put` and `update`. */
export interface UserLinkTable extends AdminWriteTable {
  update(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
}

/**
 * The injected table as these routes need it. A table client with no `update`
 * is a wiring fault and becomes the router's 500, exactly as a missing `put`
 * does in `adminWriteTable`.
 */
export function userLinkTable(table: AdminTable): UserLinkTable {
  const writable = adminWriteTable(table);
  if (typeof (writable as Partial<UserLinkTable>).update !== 'function') {
    throw new Error('the user-link routes need a table client with update()');
  }
  return writable as UserLinkTable;
}

/** A non-empty string, or `null`. */
function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/** The display name an Entra device is looked up by: the hostname cut at its first `.`. */
export function lookupName(hostname: string): string {
  const dot = hostname.indexOf('.');
  return dot === -1 ? hostname : hostname.slice(0, dot);
}

/** A Graph user reduced to the four stored fields. */
function storedUser(user: GraphUser): UserLinkUser {
  return {
    id: stringOrNull(user.id),
    displayName: stringOrNull(user.displayName),
    userPrincipalName: stringOrNull(user.userPrincipalName),
    mail: stringOrNull(user.mail),
  };
}

/** `userPrincipalName` ascending; a user with none sorts last. */
function byUpn(left: UserLinkUser, right: UserLinkUser): number {
  const a = left.userPrincipalName;
  const b = right.userPrincipalName;
  if (a === b) {
    return 0;
  }
  if (a === null) {
    return 1;
  }
  if (b === null) {
    return -1;
  }
  return a < b ? -1 : 1;
}

/** A stored item without its storage keys. */
function withoutKeys(item: Item): Item {
  const { pk: _pk, sk: _sk, ...rest } = item;
  return rest;
}

/**
 * Resolve one device's link through Graph, then store it.
 *
 * Rejects with the Graph client's `{status, error}` before anything is written
 * when a Graph read fails.
 */
export async function resolveUserLink(
  deps: AdminDependencies,
  graph: GraphDirectory,
  deviceId: string,
  hostname: string,
): Promise<Item> {
  const name = lookupName(hostname);
  const wanted = name.toLowerCase();
  const found = await graph.findDevicesByDisplayName(name);
  const kept = found.filter(
    (device) =>
      typeof device.displayName === 'string' &&
      device.displayName.toLowerCase() === wanted &&
      device.accountEnabled !== false,
  );

  let status: UserLinkStatus;
  let users: UserLinkUser[] = [];
  let entraDeviceId: string | null = null;
  if (kept.length === 0) {
    status = 'not_found';
  } else if (kept.length > 1) {
    status = 'ambiguous';
  } else {
    const device = kept[0]!;
    entraDeviceId = stringOrNull(device.id);
    users = (await graph.listRegisteredUsers(String(device.id ?? ''))).map(storedUser).sort(byUpn);
    status = users.length === 0 ? 'no_registered_user' : 'linked';
  }

  const table = userLinkTable(deps.table);
  const item: Item = {
    ...deviceUserLink(deviceId),
    deviceId,
    status,
    entraDeviceId,
    users,
    resolvedAt: adminNow(deps).toISOString(),
  };
  await table.put(item);

  const primaryUserUpn = status === 'linked' ? (users[0]?.userPrincipalName ?? null) : null;
  await table.update(
    deviceProfile(deviceId),
    primaryUserUpn === null
      ? { UpdateExpression: 'REMOVE primaryUserUpn' }
      : {
          UpdateExpression: 'SET primaryUserUpn = :primaryUserUpn',
          ExpressionAttributeValues: { ':primaryUserUpn': primaryUserUpn },
        },
  );

  return item;
}

/**
 * `POST /admin/api/v1/devices/{deviceId}/user-link/refresh` -- resolve one
 * device's link now.
 *
 * An unknown device -- or an id no key can be built from -- is a 404, and a
 * profile with no hostname a 409; neither calls Graph or writes anything.
 */
export const handleDeviceUserLinkRefresh: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const graph = deps.graph;
  if (graph === undefined) {
    return jsonError(503, 'graph_not_configured');
  }

  const deviceId = req.params?.deviceId ?? '';
  let profileKey: TableKey;
  try {
    profileKey = deviceProfile(deviceId);
  } catch {
    return jsonError(404, 'not_found');
  }
  const profile = await deps.table.get(profileKey);
  if (profile === undefined || profile === null) {
    return jsonError(404, 'not_found');
  }
  const hostname = stringOrNull(profile.hostname);
  if (hostname === null) {
    return jsonError(409, 'hostname_unknown');
  }

  let item: Item;
  try {
    item = await resolveUserLink(deps, graph, deviceId, hostname);
  } catch (error) {
    if (isGraphFailure(error)) {
      return jsonError(error.status, error.error);
    }
    throw error;
  }

  const users = Array.isArray(item.users) ? item.users : [];
  await appendAudit(userLinkTable(deps.table), {
    action: DEVICE_USER_LINK_REFRESHED_ACTION,
    actor: adminActor(req.claims),
    target: deviceId,
    detail: { status: item.status, userCount: users.length },
    now: adminNow(deps),
  });

  return { statusCode: 200, body: { userLink: withoutKeys(item) } };
};

/** The bulk body's paging input, or `null` when it is not one this route accepts. */
function readBulkInput(body: string | null | undefined): { limit: number; cursor: string | null } | null {
  let input: Record<string, unknown>;
  if (body === undefined || body === null || body === '') {
    input = {};
  } else {
    // `readJsonBody` answers `null` for unparsable text and for JSON that is
    // not an object; the absent and empty cases were settled above.
    const parsed = readJsonBody(body);
    if (parsed === null) {
      return null;
    }
    input = parsed;
  }

  let limit = USER_LINKS_DEFAULT_LIMIT;
  if (input.limit !== undefined) {
    const raw = input.limit;
    if (typeof raw !== 'number' || !Number.isInteger(raw) || raw < 1 || raw > USER_LINKS_MAX_LIMIT) {
      return null;
    }
    limit = raw;
  }

  let cursor: string | null = null;
  if (input.cursor !== undefined && input.cursor !== null) {
    if (typeof input.cursor !== 'string' || !isUsableCursor(input.cursor)) {
      return null;
    }
    cursor = input.cursor.length > 0 ? input.cursor : null;
  }

  return { limit, cursor };
}

/**
 * `POST /admin/api/v1/user-links/refresh` -- resolve one page of the fleet, in
 * the device list's order (newest check-in first).
 *
 * A device-level Graph failure is reported on that device's item and the rest
 * of the page is still processed; a failure that would fail every device (the
 * token endpoint, the secret) ends the call, keeping what was already written.
 */
export const handleUserLinksBulkRefresh: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const graph = deps.graph;
  if (graph === undefined) {
    return jsonError(503, 'graph_not_configured');
  }

  const paging = readBulkInput(req.body);
  if (paging === null) {
    return jsonError(400, 'invalid_request');
  }

  const page = await listFleet(deps.table, paging.limit, paging.cursor, null);
  const profiles = [...page.profiles].sort(byLastSeenDescending);

  const items: Item[] = [];
  for (const profile of profiles) {
    const deviceId = stringOrNull(deviceSummary(profile).deviceId);
    if (deviceId === null) {
      continue;
    }
    const hostname = stringOrNull(profile.hostname);
    if (hostname === null) {
      items.push({ deviceId, status: 'hostname_unknown', primaryUser: null });
      continue;
    }
    try {
      const link = await resolveUserLink(deps, graph, deviceId, hostname);
      const users = Array.isArray(link.users) ? (link.users as UserLinkUser[]) : [];
      items.push({
        deviceId,
        status: link.status,
        primaryUser: link.status === 'linked' ? (users[0]?.userPrincipalName ?? null) : null,
      });
    } catch (error) {
      if (!isGraphFailure(error)) {
        throw error;
      }
      if (!PER_DEVICE_FAILURES.has(error.error)) {
        return jsonError(error.status, error.error);
      }
      items.push({ deviceId, status: 'error', error: error.error, primaryUser: null });
    }
  }

  await appendAudit(userLinkTable(deps.table), {
    action: USER_LINKS_REFRESHED_ACTION,
    actor: adminActor(req.claims),
    target: 'fleet',
    detail: { count: items.length, linked: items.filter((item) => item.status === 'linked').length },
    now: adminNow(deps),
  });

  return { statusCode: 200, body: { items, cursor: page.cursor } };
};

/** Register the user-link routes on a router. Returns the router, so calls chain. */
export function registerUserLinkRoutes(router: Router, source: AdminDependencySource): Router {
  registerAdminRoute(router, 'POST', DEVICE_USER_LINK_REFRESH_PATH, handleDeviceUserLinkRefresh, source);
  return registerAdminRoute(router, 'POST', USER_LINKS_REFRESH_PATH, handleUserLinksBulkRefresh, source);
}
