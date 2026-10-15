/**
 * Device groups: the admin write side of the group entity.
 *
 *   POST /admin/api/v1/groups                   -- create a group
 *   GET  /admin/api/v1/groups                   -- list groups, by name
 *   POST /admin/api/v1/groups/{groupId}/members -- add devices to a group
 *   DELETE /admin/api/v1/groups/{groupId}/members -- remove devices from a group
 *   PUT  /admin/api/v1/groups/{groupId}         -- rename a group
 *   PUT  /admin/api/v1/groups/{groupId}/auto-assign -- {ownership: "officehq" | "byoc" | null}
 *   DELETE /admin/api/v1/groups/{groupId}       -- delete a group, its memberships
 *                                                 and its policy assignments
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
 * A group may auto-assign devices by ownership (`autoAssignOwnership`): a
 * device joins every such group when it enrolls or an admin changes its
 * ownership (`applyAutoAssignGroups`). Devices already enrolled are not added
 * when the setting is saved, and nothing is ever removed automatically. This
 * replaced the one-group-per-ownership `CONFIG` / `ASSIGNMENT` item; a group
 * with no `autoAssignOwnership` attribute of its own still reads that item, and
 * the first auto-assign save moves it onto the groups and deletes it.
 *
 * Every successful write is audited through `appendAudit` (see `src/audit.ts`)
 * with the admin's own identity as the actor.
 */
import { appendAudit, isoUtc } from '../audit.js';
import { recordDeviceEvent } from '../deviceEvents.js';
import {
  GSI1_NAME,
  group,
  groupIndex,
  groupListIndex,
  groupMember,
  defaultAssignmentSettings,
  deviceProfile,
  policyAssignment,
} from '../db/keys.js';
import { readGroupPolicyIds } from '../policies/resolve.js';
import type { Item, QueryPage } from '../db/table.js';
import type { RouteResult, Router } from '../http/router.js';
import {
  adminActor,
  adminDeleteTable,
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

/** Sub-path of one group: renamed and deleted here. */
export const GROUP_DETAIL_PATH = '/groups/{groupId}';

/** Sub-path of a group's auto-assign setting. */
export const GROUP_AUTO_ASSIGN_PATH = '/groups/{groupId}/auto-assign';

/** The ownerships a group may auto-assign; `byoc` is shown as BYOD. */
export const AUTO_ASSIGN_OWNERSHIPS = ['officehq', 'byoc'] as const;

export type AutoAssignOwnership = (typeof AUTO_ASSIGN_OWNERSHIPS)[number];

/** The audit action recorded when a group's auto-assign setting changes. */
export const GROUP_AUTO_ASSIGN_CHANGED_ACTION = 'group.auto_assign.changed';

/** Sub-path of a group's membership collection. */
export const GROUP_MEMBERS_PATH = '/groups/{groupId}/members';

/** Prefix of a generated group id. */
export const GROUP_ID_PREFIX = 'grp-';

/** Length of the random part of a generated group id, in bytes (16 hex characters). */
export const GROUP_ID_BYTES = 8;

/** The only fields a group list item carries. */
export const GROUP_SUMMARY_FIELDS = ['groupId', 'name', 'createdAt', 'autoAssignOwnership'] as const;

/** The audit action recorded when a group is created. */
export const GROUP_CREATED_ACTION = 'group.created';

/** The audit action recorded when devices are added to a group. */
export const GROUP_MEMBERS_ADDED_ACTION = 'group.members_added';

/** The audit action recorded when a group is renamed. */
export const GROUP_RENAMED_ACTION = 'group.renamed';

/** The audit action recorded when a group is deleted. */
export const GROUP_DELETED_ACTION = 'group.deleted';

/** The audit action recorded when devices are removed from a group. */
export const GROUP_MEMBERS_REMOVED_ACTION = 'group.members_removed';

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

function isAutoAssignOwnership(value: unknown): value is AutoAssignOwnership {
  return typeof value === 'string' && (AUTO_ASSIGN_OWNERSHIPS as readonly string[]).includes(value);
}

/** The legacy `CONFIG` / `ASSIGNMENT` item as group id -> ownership; empty when absent. */
export async function readLegacyAutoAssign(table: Pick<AdminTable, 'get'>): Promise<Map<string, AutoAssignOwnership>> {
  const legacy = new Map<string, AutoAssignOwnership>();
  const item = await table.get(defaultAssignmentSettings());
  for (const ownership of AUTO_ASSIGN_OWNERSHIPS) {
    const groupId = stringOrNull(item?.[ownership]);
    // One group holds one ownership; the first listed wins a collision.
    if (groupId !== null && !legacy.has(groupId)) {
      legacy.set(groupId, ownership);
    }
  }
  return legacy;
}

/**
 * The ownership a group auto-assigns: its own `autoAssignOwnership` attribute
 * when it has one (`null` meaning none), else what the legacy item says.
 */
export function effectiveAutoAssign(
  record: Item,
  legacy: ReadonlyMap<string, AutoAssignOwnership>,
): AutoAssignOwnership | null {
  if (Object.prototype.hasOwnProperty.call(record, 'autoAssignOwnership')) {
    return isAutoAssignOwnership(record.autoAssignOwnership) ? record.autoAssignOwnership : null;
  }
  const groupId = groupIdOf(record);
  return groupId === null ? null : (legacy.get(groupId) ?? null);
}

/** The fields a listed group carries, and nothing else. */
export function groupSummary(record: Item, legacy: ReadonlyMap<string, AutoAssignOwnership> = new Map()): Item {
  return {
    groupId: groupIdOf(record),
    name: stringOrNull(record.name),
    createdAt: stringOrNull(record.createdAt),
    autoAssignOwnership: effectiveAutoAssign(record, legacy),
  };
}

/** Every group record, following the `gsi1` list cursor to the end. */
async function readAllGroupRecords(table: Pick<AdminTable, 'query'>): Promise<Item[]> {
  const { gsi1pk } = groupListIndex('');
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

/** What applying auto-assign needs: reading groups and writing memberships. */
export interface AutoAssignTable extends Pick<AdminTable, 'get' | 'query'> {
  put(item: Item): Promise<void>;
}

/**
 * Add a device to every group that auto-assigns `ownership`, writing each
 * membership with exactly the shape `handleGroupMembersAdd` writes (so adding
 * twice leaves one item). Returns the group ids joined, in list order; `[]`
 * for any other ownership. Never removes a membership. Throws when the table
 * does; the callers decide that a throw never fails their request.
 */
export async function applyAutoAssignGroups(
  table: AutoAssignTable,
  deviceId: string,
  ownership: string,
  at: Date,
): Promise<string[]> {
  if (!isAutoAssignOwnership(ownership)) {
    return [];
  }
  const legacy = await readLegacyAutoAssign(table);
  const joined: string[] = [];
  for (const record of await readAllGroupRecords(table)) {
    const groupId = groupIdOf(record);
    if (groupId === null || effectiveAutoAssign(record, legacy) !== ownership) {
      continue;
    }
    let memberKey;
    let indexKey;
    try {
      memberKey = groupMember(groupId, deviceId);
      indexKey = groupIndex(groupId, deviceId);
    } catch {
      continue;
    }
    await table.put({ ...memberKey, ...indexKey, groupId, deviceId, addedAt: isoUtc(at) });
    joined.push(groupId);
  }
  return joined;
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

  const legacy = await readLegacyAutoAssign(deps.table);
  return {
    statusCode: 200,
    body: { items: page.items.map((record) => groupSummary(record, legacy)), cursor: page.cursor },
  };
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

  // A group with no record is still accepted (existing behaviour): its events
  // then name the group by its id.
  if (added.length > 0) {
    let record: Item | null = null;
    try {
      record = await readGroupRecord(table, groupId);
    } catch {
      record = null;
    }
    const name = groupEventName(record, groupId);
    for (const deviceId of added) {
      await recordDeviceEvent(table, {
        deviceId,
        source: 'admin',
        type: 'group.added',
        summary: `Added to group ${name}`,
        details: { groupId },
        actor: adminActor(req.claims),
        occurredAt: at,
      });
    }
  }

  return { statusCode: 200, body: { added: added.length } };
};

/**
 * The group record for a path id, or `null` when the id cannot form a key or
 * names no group.
 */
async function readGroupRecord(table: AdminTable, groupId: string): Promise<Item | null> {
  let key;
  try {
    key = group(groupId);
  } catch {
    return null;
  }
  const record = await table.get(key);
  return record === undefined || record === null ? null : record;
}

/** The name a group is shown by in a History event: its string `name`, else its id. */
function groupEventName(record: Item | null, groupId: string): string {
  return record !== null && typeof record.name === 'string' ? record.name : groupId;
}

/**
 * `PUT /admin/api/v1/groups/{groupId}` -- rename a group.
 *
 * The record is written back whole, so `createdAt` and every other attribute
 * survive; only `name` and the list-index sort key move. Duplicate names are
 * allowed, exactly as on create.
 */
export const handleGroupRename: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body) ?? {};
  const name = stringOrNull(body.name);
  if (name === null) {
    return jsonError(400, 'invalid_request', { fields: ['name'] });
  }

  const groupId = req.params?.groupId ?? '';
  const record = await readGroupRecord(deps.table, groupId);
  if (record === null) {
    return jsonError(404, 'not_found');
  }

  const table = adminWriteTable(deps.table);
  const at = adminNow(deps);
  const from = stringOrNull(record.name);

  await table.put({
    ...record,
    ...groupListIndex(name),
    name,
  });

  await appendAudit(table, {
    action: GROUP_RENAMED_ACTION,
    actor: adminActor(req.claims),
    target: groupId,
    detail: { from, to: name },
    now: at,
  });

  return { statusCode: 200, body: { groupId, name } };
};

/**
 * `PUT /admin/api/v1/groups/{groupId}/auto-assign` -- set which ownership the
 * group auto-assigns, or `null` for none. The body must be exactly
 * `{ownership}`. Saving adds no existing device. The first save also moves the
 * legacy `CONFIG` / `ASSIGNMENT` item onto the groups it names (a group that
 * already has its own value keeps it) and deletes it.
 */
export const handleGroupAutoAssign: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body);
  const posted: Record<string, unknown> = body !== null && typeof body === 'object' && !Array.isArray(body) ? body : {};
  const invalid = Object.keys(posted).filter((key) => key !== 'ownership');
  const ownership = posted.ownership;
  if (
    !Object.prototype.hasOwnProperty.call(posted, 'ownership') ||
    (ownership !== null && !isAutoAssignOwnership(ownership))
  ) {
    invalid.unshift('ownership');
  }
  if (invalid.length > 0) {
    return jsonError(400, 'invalid_request', { fields: invalid });
  }

  const groupId = req.params?.groupId ?? '';
  const record = await readGroupRecord(deps.table, groupId);
  if (record === null) {
    return jsonError(404, 'not_found');
  }

  const table = adminDeleteTable(deps.table);
  const at = adminNow(deps);
  const legacy = await readLegacyAutoAssign(table);
  const from = effectiveAutoAssign(record, legacy);

  if (legacy.size > 0) {
    for (const [legacyGroupId, legacyOwnership] of legacy) {
      if (legacyGroupId === groupId) {
        continue;
      }
      const legacyRecord = await readGroupRecord(table, legacyGroupId);
      if (legacyRecord !== null && !Object.prototype.hasOwnProperty.call(legacyRecord, 'autoAssignOwnership')) {
        await table.put({ ...legacyRecord, autoAssignOwnership: legacyOwnership });
      }
    }
    await table.delete(defaultAssignmentSettings());
  }

  const to = ownership as AutoAssignOwnership | null;
  await table.put({ ...record, autoAssignOwnership: to });

  await appendAudit(table, {
    action: GROUP_AUTO_ASSIGN_CHANGED_ACTION,
    actor: adminActor(req.claims),
    target: groupId,
    detail: { from, to },
    now: at,
  });

  return { statusCode: 200, body: { groupId, autoAssignOwnership: to } };
};

/**
 * `DELETE /admin/api/v1/groups/{groupId}` -- delete a group.
 *
 * The delete cascades: every membership and every policy assignment that
 * targets the group goes with it, so no policy keeps reaching devices through
 * a group that no longer exists. Policies and devices themselves are kept.
 * Like a destructive command, it needs `{confirm: true}` in the body.
 */
export const handleGroupDelete: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body) ?? {};
  const groupId = req.params?.groupId ?? '';
  const record = await readGroupRecord(deps.table, groupId);
  if (record === null) {
    return jsonError(404, 'not_found');
  }
  if (body.confirm !== true) {
    return jsonError(409, 'confirmation_required');
  }

  const table = adminDeleteTable(deps.table);
  const at = adminNow(deps);

  let assignmentsRemoved = 0;
  for (const policyId of await readGroupPolicyIds(table, groupId)) {
    let key;
    try {
      key = policyAssignment(policyId, groupId);
    } catch {
      continue;
    }
    await table.delete(key);
    assignmentsRemoved += 1;
  }

  let membersRemoved = 0;
  const removedDeviceIds: string[] = [];
  for (const deviceId of await readGroupMemberIds(table, groupId)) {
    let key;
    try {
      key = groupMember(groupId, deviceId);
    } catch {
      continue;
    }
    await table.delete(key);
    membersRemoved += 1;
    removedDeviceIds.push(deviceId);
  }

  await table.delete(group(groupId));

  const actor = adminActor(req.claims);
  await appendAudit(table, {
    action: GROUP_DELETED_ACTION,
    actor,
    target: groupId,
    detail: { name: stringOrNull(record.name), membersRemoved, assignmentsRemoved },
    now: at,
  });

  const name = groupEventName(record, groupId);
  for (const deviceId of removedDeviceIds) {
    await recordDeviceEvent(table, {
      deviceId,
      source: 'admin',
      type: 'group.removed',
      summary: `Removed from group ${name} (group deleted)`,
      details: { groupId, reason: 'group_deleted' },
      actor,
      occurredAt: at,
    });
  }

  return { statusCode: 200, body: { groupId, membersRemoved, assignmentsRemoved } };
};

/**
 * `DELETE /admin/api/v1/groups/{groupId}/members` -- remove devices from a group.
 *
 * The mirror of adding: a bulk operation, so an id that is not a member, or
 * that cannot form a key, is skipped, and `removed` counts exactly the
 * memberships that existed and were deleted.
 */
export const handleGroupMembersRemove: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body) ?? {};
  const deviceIds = body.deviceIds;
  if (!Array.isArray(deviceIds) || deviceIds.some((deviceId) => typeof deviceId !== 'string')) {
    return jsonError(400, 'invalid_request');
  }

  const groupId = req.params?.groupId ?? '';
  const record = await readGroupRecord(deps.table, groupId);
  if (record === null) {
    return jsonError(404, 'not_found');
  }

  const table = adminDeleteTable(deps.table);
  const at = adminNow(deps);

  const removed: string[] = [];
  for (const deviceId of new Set(deviceIds as string[])) {
    let key;
    try {
      key = groupMember(groupId, deviceId);
    } catch {
      continue;
    }
    const member = await table.get(key);
    if (member === undefined || member === null) {
      continue;
    }
    await table.delete(key);
    removed.push(deviceId);
  }

  const actor = adminActor(req.claims);
  await appendAudit(table, {
    action: GROUP_MEMBERS_REMOVED_ACTION,
    actor,
    target: groupId,
    detail: { deviceIds: removed, removed: removed.length },
    now: at,
  });

  const name = groupEventName(record, groupId);
  for (const deviceId of removed) {
    await recordDeviceEvent(table, {
      deviceId,
      source: 'admin',
      type: 'group.removed',
      summary: `Removed from group ${name}`,
      details: { groupId },
      actor,
      occurredAt: at,
    });
  }

  return { statusCode: 200, body: { removed: removed.length } };
};

/** Register the group routes on a router. Returns the router, so calls chain. */
export function registerGroupRoutes(router: Router, source: AdminDependencySource): Router {
  registerAdminRoute(router, 'POST', GROUP_PATH, handleGroupCreate, source);
  registerAdminRoute(router, 'GET', GROUP_PATH, handleGroupList, source);
  registerAdminRoute(router, 'PUT', GROUP_DETAIL_PATH, handleGroupRename, source);
  registerAdminRoute(router, 'PUT', GROUP_AUTO_ASSIGN_PATH, handleGroupAutoAssign, source);
  registerAdminRoute(router, 'DELETE', GROUP_DETAIL_PATH, handleGroupDelete, source);
  registerAdminRoute(router, 'DELETE', GROUP_MEMBERS_PATH, handleGroupMembersRemove, source);
  return registerAdminRoute(router, 'POST', GROUP_MEMBERS_PATH, handleGroupMembersAdd, source);
}
