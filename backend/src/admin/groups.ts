/**
 * Device groups: the admin write side of the group entity.
 *
 *   POST /admin/api/v1/groups                   -- create a group
 *   GET  /admin/api/v1/groups                   -- list groups, by name
 *   POST /admin/api/v1/groups/{groupId}/members -- add devices to a group
 *
 *   registerGroupRoutes(router, { verifier, table, now, randomBytes });
 *
 * Every route is registered through `registerAdminRoute`, so it is reached
 * only by a verified admin (see `src/admin/router.ts`), and every dependency --
 * the table client, the clock and the random source -- is injected, so tests
 * drive them with a stub verifier and a fake table.
 *
 * Two items make up a group. The group record lives at `keys.group(groupId)`
 * and carries the `keys.groupListIndex` attributes, which is what makes the
 * list a query on one `gsi1` partition rather than a scan. A membership lives
 * at `keys.groupMember(groupId, deviceId)` and carries `keys.groupIndex`; that
 * is the exact item the device list reads for its `?group=` filter (see
 * `src/admin/devices.ts`), so nothing else may invent a membership shape.
 *
 * Adding members is idempotent -- a membership is written at a key derived
 * from the device id, so adding the same device twice leaves one item -- and
 * only devices that actually exist are written, so a mistyped id can never
 * leave a membership pointing at nothing. `added` counts exactly the devices
 * written.
 *
 * Every successful write is audited through `appendAudit` (see `src/audit.ts`)
 * with the admin's own identity as the actor.
 */
import { appendAudit, isoUtc } from '../audit.js';
import { GSI1_NAME, group, groupIndex, groupListIndex, groupMember, deviceProfile } from '../db/keys.js';
import type { Item, QueryPage } from '../db/table.js';
import type { RouteResult, Router } from '../http/router.js';
import {
  adminActor,
  adminNow,
  adminRandomBytes,
  adminWriteTable,
  isUsableCursor,
  jsonError,
  parseLimit,
  readCursor,
  readJsonBody,
  registerAdminRoute,
  type AdminDependencySource,
  type AdminRouteHandler,
  type AdminTable,
} from './router.js';

/** Sub-path of the group collection: created and listed here. */
export const GROUP_PATH = '/groups';

/** Sub-path of a group's membership collection. */
export const GROUP_MEMBERS_PATH = '/groups/{groupId}/members';

/** Prefix of a generated group id. */
export const GROUP_ID_PREFIX = 'grp-';

/** Length of the random part of a generated group id, in bytes (16 hex characters). */
export const GROUP_ID_BYTES = 8;

/** The only fields a group list item carries. */
export const GROUP_SUMMARY_FIELDS = ['groupId', 'name', 'createdAt'] as const;

/** The audit action recorded when a group is created. */
export const GROUP_CREATED_ACTION = 'group.created';

/** The audit action recorded when devices are added to a group. */
export const GROUP_MEMBERS_ADDED_ACTION = 'group.members_added';

/** The string value of an attribute, or `null` when it is not a non-empty string. */
function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/** A group record's id: its own attribute, else the `GROUP#` key it lives under. */
function groupIdOf(record: Item): string | null {
  const pk = typeof record.pk === 'string' ? record.pk : '';
  return stringOrNull(record.groupId) ?? (pk.startsWith('GROUP#') ? pk.slice('GROUP#'.length) : null);
}

/** A membership item's device: its own attribute, else the `MEMBER#` sort key. */
function memberDeviceId(member: Item): string | null {
  const sk = typeof member.sk === 'string' ? member.sk : '';
  return stringOrNull(member.deviceId) ?? (sk.startsWith('MEMBER#') ? sk.slice('MEMBER#'.length) : null);
}

/** The three fields a listed group carries, and nothing else. */
export function groupSummary(record: Item): Item {
  return {
    groupId: groupIdOf(record),
    name: stringOrNull(record.name),
    createdAt: stringOrNull(record.createdAt),
  };
}

/**
 * Every device id in a group, following the cursor to the end.
 *
 * This is a query on the group's own partition, never a scan. It is shared
 * with the group command dispatcher (see `src/admin/commandDispatch.ts`), so
 * the `MEMBER#` shape is read in one place.
 */
export async function readGroupMemberIds(table: AdminTable, groupId: string): Promise<string[]> {
  // An empty device id yields the group's partition key and the `MEMBER#`
  // prefix its memberships are stored under, without writing key text here.
  let partition: { pk: string; sk: string };
  try {
    partition = groupMember(groupId, '');
  } catch {
    // An id no key can be built from matches nothing, exactly like a group
    // that has no members.
    return [];
  }

  const deviceIds: string[] = [];
  let cursor: string | null = null;
  do {
    const page: QueryPage = await table.query({
      KeyConditionExpression: '#pk = :pk AND begins_with(#sk, :memberPrefix)',
      ExpressionAttributeNames: { '#pk': 'pk', '#sk': 'sk' },
      ExpressionAttributeValues: { ':pk': partition.pk, ':memberPrefix': partition.sk },
      cursor,
    });
    for (const item of page.items) {
      const deviceId = memberDeviceId(item);
      if (deviceId !== null) {
        deviceIds.push(deviceId);
      }
    }
    const next = page.cursor ?? null;
    // A cursor that does not move would page forever; treat it as the end.
    cursor = next === cursor ? null : next;
  } while (cursor !== null);

  return deviceIds;
}

/**
 * `POST /admin/api/v1/groups` -- create a group.
 *
 * The id is generated here, so a caller can never choose one that collides
 * with an existing group or carries the key separator.
 */
export const handleGroupCreate: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body) ?? {};
  const name = stringOrNull(body.name);
  if (name === null) {
    return jsonError(400, 'invalid_request');
  }

  const table = adminWriteTable(deps.table);
  const at = adminNow(deps);
  const createdAt = isoUtc(at);
  const groupId = `${GROUP_ID_PREFIX}${adminRandomBytes(deps)(GROUP_ID_BYTES).toString('hex')}`;

  await table.put({
    ...group(groupId),
    ...groupListIndex(name),
    groupId,
    name,
    createdAt,
  });

  await appendAudit(table, {
    action: GROUP_CREATED_ACTION,
    actor: adminActor(req.claims),
    target: groupId,
    detail: { name },
    now: at,
  });

  return { statusCode: 201, body: { groupId, name } };
};

/**
 * `GET /admin/api/v1/groups` -- the groups, by name, in the same
 * `{items, cursor}` envelope and under the same `limit` rules as every other
 * admin list.
 */
export const handleGroupList: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const limit = parseLimit(req.query?.limit);
  const cursor = readCursor(req.query?.cursor);
  if (limit === null || !isUsableCursor(cursor)) {
    return jsonError(400, 'invalid_request');
  }

  const { gsi1pk } = groupListIndex('');
  const page = await deps.table.query({
    IndexName: GSI1_NAME,
    KeyConditionExpression: '#gsi1pk = :gsi1pk',
    ExpressionAttributeNames: { '#gsi1pk': 'gsi1pk' },
    ExpressionAttributeValues: { ':gsi1pk': gsi1pk },
    limit,
    cursor,
  });

  return { statusCode: 200, body: { items: page.items.map(groupSummary), cursor: page.cursor } };
};

/**
 * `POST /admin/api/v1/groups/{groupId}/members` -- add devices to a group.
 *
 * A device that does not exist is skipped rather than refused: adding a list
 * of ids is a bulk operation, and `added` tells the caller how many of them
 * were real.
 */
export const handleGroupMembersAdd: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body) ?? {};
  const deviceIds = body.deviceIds;
  if (!Array.isArray(deviceIds) || deviceIds.some((deviceId) => typeof deviceId !== 'string')) {
    return jsonError(400, 'invalid_request');
  }

  const groupId = req.params?.groupId ?? '';
  // A group id that cannot form a key names no group, so nothing is written.
  try {
    groupMember(groupId, '');
  } catch {
    return jsonError(404, 'not_found');
  }

  const table = adminWriteTable(deps.table);
  const at = adminNow(deps);
  const addedAt = isoUtc(at);

  // Each id is checked before it is written, so a membership never points at a
  // device that does not exist; duplicates in the request collapse onto one key.
  const added: string[] = [];
  for (const deviceId of new Set(deviceIds as string[])) {
    let profileKey;
    try {
      profileKey = deviceProfile(deviceId);
    } catch {
      continue;
    }
    const profile = await table.get(profileKey);
    if (profile === undefined || profile === null) {
      continue;
    }
    await table.put({
      ...groupMember(groupId, deviceId),
      ...groupIndex(groupId, deviceId),
      groupId,
      deviceId,
      addedAt,
    });
    added.push(deviceId);
  }

  await appendAudit(table, {
    action: GROUP_MEMBERS_ADDED_ACTION,
    actor: adminActor(req.claims),
    target: groupId,
    detail: { deviceIds: added, added: added.length },
    now: at,
  });

  return { statusCode: 200, body: { added: added.length } };
};

/** Register the group routes on a router. Returns the router, so calls chain. */
export function registerGroupRoutes(router: Router, source: AdminDependencySource): Router {
  registerAdminRoute(router, 'POST', GROUP_PATH, handleGroupCreate, source);
  registerAdminRoute(router, 'GET', GROUP_PATH, handleGroupList, source);
  return registerAdminRoute(router, 'POST', GROUP_MEMBERS_PATH, handleGroupMembersAdd, source);
}
