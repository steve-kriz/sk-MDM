/**
 * The admin device views.
 *
 *   GET /admin/api/v1/devices                 -- the fleet, newest check-in first
 *   GET /admin/api/v1/devices?group=<groupId> -- only that group's members
 *   GET /admin/api/v1/devices?stale=true      -- only devices unseen for over 24h
 *   GET /admin/api/v1/devices/{deviceId}      -- one device in full
 *
 *   registerDeviceRoutes(router, { verifier, table, now });
 *
 * Both routes are registered through `registerAdminRoute`, so they are reached
 * only by a verified admin (see `src/admin/router.ts`), and every dependency is
 * injected, so tests drive them with a stub verifier and a fake table.
 *
 * The list always answers with the same `{items, cursor}` envelope and the same
 * seven fields per item, whichever filter produced it: a stored item is never
 * returned raw, so a membership item alone is never emitted and no device
 * secret can leak into a list. `complianceState` is read from the profile
 * attribute of that name and is `"unknown"` when the attribute is absent;
 * nothing here computes or writes it.
 *
 * The detail view redacts the same way: the profile, inventory and posture come
 * back without their storage keys and without any secret or hash attribute,
 * so `secretEnc` and anything like it stay inside the backend.
 *
 * Time units: `now()` yields an instant -- integer epoch *seconds* when it is a
 * number -- and the 24 hour staleness bound is strict, so a device last seen
 * exactly 24 hours ago is not stale.
 */
import { isoUtc } from '../audit.js';
import {
  GSI1_NAME,
  deviceAntivirusFinding,
  deviceCommand,
  deviceInventory,
  deviceListIndex,
  devicePosture,
  deviceProfile,
  groupMember,
} from '../db/keys.js';
import type { Item, QueryPage } from '../db/table.js';
import type { RouteResult, Router } from '../http/router.js';
import {
  isUsableCursor,
  jsonError,
  parseLimit,
  readCursor,
  registerAdminRoute,
  type AdminDependencies,
  type AdminDependencySource,
  type AdminRouteHandler,
  type AdminTable,
} from './router.js';

/** Sub-path of the device list. */
export const DEVICE_LIST_PATH = '/devices';

/** Sub-path of the device detail view. */
export const DEVICE_DETAIL_PATH = '/devices/{deviceId}';

/** The only fields a list item carries, in response order. */
export const DEVICE_SUMMARY_FIELDS = [
  'deviceId',
  'hostname',
  'platform',
  'osVersion',
  'lastSeenAt',
  'complianceState',
  'agentVersion',
] as const;

/** What `complianceState` reads as until TASK-012 has written one. */
export const UNKNOWN_COMPLIANCE = 'unknown';

/** How long a device may go unseen before it is stale. The bound is strict. */
export const STALE_AFTER_MILLIS = 86400000;

/** The most commands the detail view returns, newest issue first. */
export const MAX_DETAIL_COMMANDS = 20;

/** The most antivirus findings the detail view returns, newest detection first. */
export const MAX_DETAIL_FINDINGS = 50;

/**
 * Attributes never returned by an admin read route: the stored device secret
 * and anything else named like secret or hash material. The rule is a pattern
 * rather than a list so an attribute added later cannot leak by default.
 */
const SECRET_FIELD_PATTERN = /secret|hash|pepper/i;

/** Storage bookkeeping the API does not expose. */
const STORAGE_FIELDS = new Set(['pk', 'sk', 'gsi1pk', 'gsi1sk']);

/** Normalise whatever the injected clock returned into a `Date`; a number is epoch seconds. */
function toDate(instant: number | string | Date): Date {
  if (instant instanceof Date) {
    return new Date(instant.getTime());
  }
  if (typeof instant === 'string') {
    return new Date(instant);
  }
  return new Date(instant * 1000);
}

/** The current instant, from the injected clock or the system one. */
function nowDate(deps: AdminDependencies): Date {
  const clock = deps.now ?? ((): number => Math.floor(Date.now() / 1000));
  return toDate(clock());
}

/** The string value of an attribute, or `null` when it is not a string. */
function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/** The id carried by an item keyed `<PREFIX>#<id>`, read from the key it was stored under. */
function idFromKey(value: unknown, prefix: string): string | null {
  const key = typeof value === 'string' ? value : '';
  return key.startsWith(prefix) ? key.slice(prefix.length) : null;
}

/** A device profile's id: its own attribute, else the `DEVICE#` key it lives under. */
function deviceIdOf(profile: Item): string | null {
  return stringOrNull(profile.deviceId) ?? idFromKey(profile.pk, 'DEVICE#');
}

/** A membership item's device: its own attribute, else the `MEMBER#` sort key. */
function memberDeviceId(member: Item): string | null {
  return stringOrNull(member.deviceId) ?? idFromKey(member.sk, 'MEMBER#');
}

/** A command's id: its own attribute, else the `CMD#` sort key it was written under. */
function commandIdOf(command: Item): string {
  return stringOrNull(command.commandId) ?? idFromKey(command.sk, 'CMD#') ?? '';
}

/**
 * The seven fields of a list item, and nothing else.
 *
 * A field the profile does not carry is `null` rather than absent, so every
 * item has the same shape; `complianceState` is the one exception and reads
 * `"unknown"`, the value the UI shows until a compliance evaluation has run.
 */
export function deviceSummary(profile: Item): Item {
  return {
    deviceId: deviceIdOf(profile),
    hostname: stringOrNull(profile.hostname),
    platform: stringOrNull(profile.platform),
    osVersion: stringOrNull(profile.osVersion),
    lastSeenAt: stringOrNull(profile.lastSeenAt),
    complianceState: stringOrNull(profile.complianceState) ?? UNKNOWN_COMPLIANCE,
    agentVersion: stringOrNull(profile.agentVersion),
  };
}

/** Drop the storage keys and every secret-looking attribute from a stored item. */
function publicItem(item: Item | undefined | null): Item | null {
  if (item === undefined || item === null) {
    return null;
  }
  const safe: Item = {};
  for (const [name, value] of Object.entries(item)) {
    if (STORAGE_FIELDS.has(name) || SECRET_FIELD_PATTERN.test(name)) {
      continue;
    }
    safe[name] = value;
  }
  return safe;
}

/** The detail view's profile: redacted, with the compliance default applied. */
function publicProfile(profile: Item): Item {
  const safe = publicItem(profile) ?? {};
  safe.complianceState = stringOrNull(profile.complianceState) ?? UNKNOWN_COMPLIANCE;
  return safe;
}

/** The detail view's command: redacted, and always carrying its id. */
function publicCommand(command: Item): Item {
  return { ...(publicItem(command) ?? {}), commandId: commandIdOf(command) };
}

/** A command's issue time in epoch milliseconds, or `null` when it has none. */
function issuedAtOf(command: Item): number | null {
  const issuedAt = command.issuedAt;
  return typeof issuedAt === 'number' && Number.isFinite(issuedAt) ? issuedAt : null;
}

/**
 * Newest issue first, ties broken by `commandId` descending. A command with no
 * `issuedAt` -- a fixture, or an item written before the field existed -- sorts
 * last rather than anywhere, so the page is stable.
 */
function byIssuedAtDescending(left: Item, right: Item): number {
  const leftIssued = issuedAtOf(left);
  const rightIssued = issuedAtOf(right);
  if (leftIssued !== rightIssued) {
    if (leftIssued === null) {
      return 1;
    }
    if (rightIssued === null) {
      return -1;
    }
    return rightIssued - leftIssued;
  }
  const leftId = commandIdOf(left);
  const rightId = commandIdOf(right);
  if (leftId === rightId) {
    return 0;
  }
  return leftId < rightId ? 1 : -1;
}

/** Newest check-in first; a profile with no `lastSeenAt` sorts last. */
function byLastSeenDescending(left: Item, right: Item): number {
  const leftSeen = stringOrNull(left.lastSeenAt);
  const rightSeen = stringOrNull(right.lastSeenAt);
  if (leftSeen === rightSeen) {
    return 0;
  }
  if (leftSeen === null) {
    return 1;
  }
  if (rightSeen === null) {
    return -1;
  }
  return leftSeen < rightSeen ? 1 : -1;
}

/** One page of profiles, before they are hydrated into list items. */
interface ProfilePage {
  profiles: Item[];
  cursor: string | null;
}

/**
 * One page of the whole fleet, from the `gsi1` device list.
 *
 * When `staleBefore` is given the key condition also bounds `gsi1sk`, so only
 * devices last seen before that instant are read.
 */
async function listFleet(
  table: AdminTable,
  limit: number,
  cursor: string | null,
  staleBefore: string | null,
): Promise<ProfilePage> {
  const { gsi1pk } = deviceListIndex('');
  const bounded = staleBefore !== null;
  const page = await table.query({
    IndexName: GSI1_NAME,
    KeyConditionExpression: bounded
      ? '#gsi1pk = :gsi1pk AND #gsi1sk < :staleBefore'
      : '#gsi1pk = :gsi1pk',
    ExpressionAttributeNames: bounded
      ? { '#gsi1pk': 'gsi1pk', '#gsi1sk': 'gsi1sk' }
      : { '#gsi1pk': 'gsi1pk' },
    ExpressionAttributeValues: bounded
      ? { ':gsi1pk': gsi1pk, ':staleBefore': staleBefore }
      : { ':gsi1pk': gsi1pk },
    // Descending, so the most recently seen device comes back first.
    ScanIndexForward: false,
    limit,
    cursor,
  });
  return { profiles: page.items, cursor: page.cursor };
}

/**
 * One page of a group's members, hydrated into their device profiles.
 *
 * The page is taken from the membership items -- a query on the group's own
 * partition, never a scan -- and each member is then read through
 * `deviceProfile`, so the response carries devices, not memberships. A member
 * whose profile has since gone is skipped.
 */
async function listGroupMembers(
  table: AdminTable,
  groupId: string,
  limit: number,
  cursor: string | null,
): Promise<ProfilePage> {
  // An empty device id yields the group's partition key and the `MEMBER#`
  // prefix its memberships are stored under, without writing key text here.
  let partition: { pk: string; sk: string };
  try {
    partition = groupMember(groupId, '');
  } catch {
    // An id no key can be built from matches nothing, exactly like a group
    // that has no members.
    return { profiles: [], cursor: null };
  }

  const page: QueryPage = await table.query({
    KeyConditionExpression: '#pk = :pk AND begins_with(#sk, :memberPrefix)',
    ExpressionAttributeNames: { '#pk': 'pk', '#sk': 'sk' },
    ExpressionAttributeValues: { ':pk': partition.pk, ':memberPrefix': partition.sk },
    limit,
    cursor,
  });

  const deviceIds = page.items
    .map(memberDeviceId)
    .filter((deviceId): deviceId is string => deviceId !== null);
  const profiles = await Promise.all(deviceIds.map((deviceId) => table.get(deviceProfile(deviceId))));

  return {
    profiles: profiles.filter((profile): profile is Item => profile !== undefined && profile !== null),
    cursor: page.cursor,
  };
}

/**
 * `GET /admin/api/v1/devices` -- the device list and its filters.
 *
 * `group` and `stale` narrow the same list and compose: the envelope, the seven
 * item fields, the ordering and the `limit` rules never change with the filter.
 */
export const handleDeviceList: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const limit = parseLimit(req.query?.limit);
  const cursor = readCursor(req.query?.cursor);
  if (limit === null || !isUsableCursor(cursor)) {
    return jsonError(400, 'invalid_request');
  }

  // Strictly more than 24 hours ago: a device last seen exactly on the bound
  // is not stale.
  const stale = req.query?.stale === 'true';
  const staleBefore = stale ? isoUtc(new Date(nowDate(deps).getTime() - STALE_AFTER_MILLIS)) : null;

  const groupId = req.query?.group ?? '';
  const page =
    groupId.length > 0
      ? await listGroupMembers(deps.table, groupId, limit, cursor)
      : await listFleet(deps.table, limit, cursor, staleBefore);

  // The key condition already bounds the fleet query; re-applying the bound
  // here keeps the filter true for the group path and for any profile that
  // reached the page without one.
  const selected = staleBefore === null
    ? page.profiles
    : page.profiles.filter((profile) => {
        const lastSeenAt = stringOrNull(profile.lastSeenAt);
        return lastSeenAt !== null && lastSeenAt < staleBefore;
      });

  const items = [...selected].sort(byLastSeenDescending).map(deviceSummary);
  return { statusCode: 200, body: { items, cursor: page.cursor } };
};

/**
 * Every command stored for a device, newest issue first, capped at
 * `MAX_DETAIL_COMMANDS`.
 *
 * Commands are keyed by `commandId`, not by issue time, so the whole queue is
 * read -- a query on the device's own partition, never a scan, following the
 * cursor to the end -- and ordered here.
 */
async function readCommands(table: AdminTable, deviceId: string): Promise<Item[]> {
  // An empty command id yields the device's partition key and the `CMD#`
  // prefix every command of this device is stored under.
  const { pk, sk: commandPrefix } = deviceCommand(deviceId, '');

  const commands: Item[] = [];
  let cursor: string | null = null;
  do {
    const page: QueryPage = await table.query({
      KeyConditionExpression: '#pk = :pk AND begins_with(#sk, :commandPrefix)',
      ExpressionAttributeNames: { '#pk': 'pk', '#sk': 'sk' },
      ExpressionAttributeValues: { ':pk': pk, ':commandPrefix': commandPrefix },
      cursor,
    });
    commands.push(...page.items);
    const next = page.cursor ?? null;
    // A cursor that does not move would page forever; treat it as the end.
    cursor = next === cursor ? null : next;
  } while (cursor !== null);

  return commands.sort(byIssuedAtDescending).slice(0, MAX_DETAIL_COMMANDS).map(publicCommand);
}

/** Newest detection first; findings detected at the same instant by id, ascending. */
function byDetectedAtDescending(a: Item, b: Item): number {
  const left = typeof a.detectedAt === 'string' ? a.detectedAt : '';
  const right = typeof b.detectedAt === 'string' ? b.detectedAt : '';
  if (left !== right) {
    return left < right ? 1 : -1;
  }
  const leftId = typeof a.findingId === 'string' ? a.findingId : '';
  const rightId = typeof b.findingId === 'string' ? b.findingId : '';
  return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
}

/**
 * Every antivirus finding stored for a device, newest detection first, capped
 * at `MAX_DETAIL_FINDINGS`. Read like the commands: a query on the device's
 * own partition, following the cursor to the end, ordered here.
 */
async function readAntivirusFindings(table: AdminTable, deviceId: string): Promise<Item[]> {
  // An empty finding id yields the device's partition key and the
  // `AVFINDING#` prefix every finding of this device is stored under.
  const { pk, sk: findingPrefix } = deviceAntivirusFinding(deviceId, '');

  const findings: Item[] = [];
  let cursor: string | null = null;
  do {
    const page: QueryPage = await table.query({
      KeyConditionExpression: '#pk = :pk AND begins_with(#sk, :findingPrefix)',
      ExpressionAttributeNames: { '#pk': 'pk', '#sk': 'sk' },
      ExpressionAttributeValues: { ':pk': pk, ':findingPrefix': findingPrefix },
      cursor,
    });
    findings.push(...page.items);
    const next = page.cursor ?? null;
    // A cursor that does not move would page forever; treat it as the end.
    cursor = next === cursor ? null : next;
  } while (cursor !== null);

  return findings
    .sort(byDetectedAtDescending)
    .slice(0, MAX_DETAIL_FINDINGS)
    .map((finding) => publicItem(finding) ?? {});
}

/**
 * `GET /admin/api/v1/devices/{deviceId}` -- one device in full: its profile,
 * its last inventory and posture snapshots, and its most recent commands.
 *
 * An unknown device -- or an id no key can be built from -- is a 404; nothing
 * else is read once the profile is missing.
 */
export const handleDeviceDetail: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const deviceId = req.params?.deviceId ?? '';
  let profileKey;
  try {
    profileKey = deviceProfile(deviceId);
  } catch {
    return jsonError(404, 'not_found');
  }

  const profile = await deps.table.get(profileKey);
  if (profile === undefined || profile === null) {
    return jsonError(404, 'not_found');
  }

  const [inventory, posture] = await Promise.all([
    deps.table.get(deviceInventory(deviceId)),
    deps.table.get(devicePosture(deviceId)),
  ]);

  return {
    statusCode: 200,
    body: {
      profile: publicProfile(profile),
      inventory: publicItem(inventory),
      posture: publicItem(posture),
      commands: await readCommands(deps.table, deviceId),
      antivirusFindings: await readAntivirusFindings(deps.table, deviceId),
    },
  };
};

/** Register the device routes on a router. Returns the router, so calls chain. */
export function registerDeviceRoutes(router: Router, source: AdminDependencySource): Router {
  registerAdminRoute(router, 'GET', DEVICE_LIST_PATH, handleDeviceList, source);
  return registerAdminRoute(router, 'GET', DEVICE_DETAIL_PATH, handleDeviceDetail, source);
}
