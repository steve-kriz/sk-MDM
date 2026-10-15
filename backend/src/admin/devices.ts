/**
 * The admin device views.
 *
 *   GET /admin/api/v1/devices                 -- the fleet, newest check-in first
 *   GET /admin/api/v1/devices?group=<groupId> -- only that group's members
 *   GET /admin/api/v1/devices?stale=true      -- only devices unseen for over 24h
 *   GET /admin/api/v1/devices?ownership=byoc  -- only BYOC (or `officehq`) devices
 *   GET /admin/api/v1/devices/{deviceId}      -- one device in full
 *   PUT /admin/api/v1/devices/{deviceId}      -- change the device's ownership
 *   DELETE /admin/api/v1/devices/{deviceId}   -- remove the device and all it owns
 *   POST /admin/api/v1/devices/{deviceId}/disable -- refuse the device's requests
 *   POST /admin/api/v1/devices/{deviceId}/enable  -- accept them again
 *
 *   registerDeviceRoutes(router, { verifier, table, now });
 *
 * Every route is registered through `registerAdminRoute`, so they are reached
 * only by a verified admin (see `src/admin/router.ts`), and every dependency is
 * injected, so tests drive them with a stub verifier and a fake table.
 *
 * The list always answers with the same `{items, cursor}` envelope and the same
 * `DEVICE_SUMMARY_FIELDS` per item, whichever filter produced it: a stored item is never
 * returned raw, so a membership item alone is never emitted and no device
 * secret can leak into a list. `complianceState` is read from the profile
 * attribute of that name and is `"unknown"` when the attribute is absent;
 * nothing here computes or writes it. `ownership` is likewise only read:
 * written at enroll, it is `"officehq"` for a device enrolled before it existed.
 *
 * The detail view redacts the same way: the profile, inventory and posture come
 * back without their storage keys and without any secret or hash attribute,
 * so `secretEnc` and anything like it stay inside the backend. It also lists
 * the device's groups (`groups: [{groupId, name}]`, by name then id) and, read
 * only, every policy reaching the device through them (`policies: [{policyId,
 * name, version, viaGroups}]`, by name then id; a policy whose record is gone
 * is left out). Membership is changed through the group member routes, never
 * here, and there is no direct device-to-policy assignment.
 *
 * Time units: `now()` yields an instant -- integer epoch *seconds* when it is a
 * number -- and the 24 hour staleness bound is strict, so a device last seen
 * exactly 24 hours ago is not stale.
 */
import { appendAudit, isoUtc } from '../audit.js';
import {
  DEVICE_EVENT_RETENTION_SECONDS,
  MAX_DETAIL_DEVICE_EVENTS,
  deviceEventGroupName,
  recordDeviceEvent,
} from '../deviceEvents.js';
import {
  AGENT_ERROR_SK_PREFIX,
  APP_CRASH_SK_PREFIX,
  DEVICE_EVENT_SK_PREFIX,
  GSI1_NAME,
  deviceAgentError,
  deviceAnalytics,
  deviceAntivirusFinding,
  deviceAntivirusScan,
  deviceAntivirusStatus,
  deviceDefenderHardening,
  deviceAppCrash,
  deviceEvent,
  deviceBootHistory,
  deviceByHardware,
  deviceCommand,
  deviceHeartbeatSettings,
  deviceInventory,
  deviceListIndex,
  deviceLocation,
  deviceLoginUser,
  devicePosture,
  deviceProfile,
  deviceSettings,
  deviceSignedInUser,
  enrollmentToken,
  group as groupKey,
  groupMember,
  policy as policyKey,
} from '../db/keys.js';
import { REVOKED_STATUS } from '../http/deviceAuth.js';
import { applyAutoAssignGroups } from './groups.js';
import { enrollmentTokenStatus } from './enrollmentTokens.js';
import type { Item, QueryPage } from '../db/table.js';
import type { RouteResult, Router } from '../http/router.js';
import { readAllGroupIds, readDeviceGroupIds, readGroupPolicyIds } from '../policies/resolve.js';
import { locationTrackingEnabled, locationView } from '../location/capture.js';
import { AGENT_ERROR_RETENTION_SECONDS, APP_CRASH_RETENTION_SECONDS } from '../routes/checkin.js';
import { HEARTBEAT_DEFAULT_INTERVAL_SECONDS, HEARTBEAT_INTERVAL_OPTIONS_SECONDS } from '../config/intervals.js';
import { MAX_DETAIL_AGENT_ERRORS, MAX_DETAIL_CRASHES } from './analytics.js';
import {
  adminActor,
  adminDeleteTable,
  adminNow,
  adminUpdateTable,
  isUsableCursor,
  jsonError,
  parseLimit,
  readCursor,
  readJsonBody,
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

/** The audit action recorded when a device's ownership is changed. */
export const DEVICE_UPDATED_ACTION = 'device.updated';

/** The audit action recorded when a device and everything it owns is deleted. */
export const DEVICE_DELETED_ACTION = 'device.deleted';

/** Sub-path of the admin disable action on one device. */
export const DEVICE_DISABLE_PATH = '/devices/{deviceId}/disable';

/** Sub-path of the admin enable action on one device. */
export const DEVICE_ENABLE_PATH = '/devices/{deviceId}/enable';

/** The audit action recorded when an admin disables a device. Written only by the disable route. */
export const DEVICE_DISABLED_ACTION = 'device.disabled';

/** The audit action recorded when an admin re-enables a device. */
export const DEVICE_ENABLED_ACTION = 'device.enabled';

/** The only fields a list item carries, in response order. */
export const DEVICE_SUMMARY_FIELDS = [
  'deviceId',
  'hostname',
  'platform',
  'osVersion',
  'osDisplay',
  'lastSeenAt',
  'complianceState',
  'agentVersion',
  'ownership',
  'enrolledBy',
] as const;

/** What `ownership` reads as for a device enrolled before the field existed. */
export const DEFAULT_OWNERSHIP = 'officehq';

/** The ownership values the enroll route stores, and the list filter accepts. */
export const OWNERSHIP_VALUES: readonly string[] = ['officehq', 'byoc'];

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
 * A profile's ownership. A device enrolled before ownership was recorded --
 * or carrying a value the enroll route never writes -- reads as `officehq`.
 */
export function ownershipOf(profile: Item): string {
  const stored = profile.ownership;
  return typeof stored === 'string' && OWNERSHIP_VALUES.includes(stored) ? stored : DEFAULT_OWNERSHIP;
}

/** `{upn}` of the user whose sign-in enrolled the device, or `null` when none is recorded. */
function enrolledBySummary(profile: Item): { upn: string } | null {
  const enrolledBy = profile.enrolledBy;
  if (typeof enrolledBy !== 'object' || enrolledBy === null) {
    return null;
  }
  const upn = stringOrNull((enrolledBy as Item).upn);
  return upn === null ? null : { upn };
}

/**
 * The fields of a list item (`DEVICE_SUMMARY_FIELDS`), and nothing else.
 *
 * A field the profile does not carry is `null` rather than absent, so every
 * item has the same shape. `complianceState` reads `"unknown"`, the value the
 * UI shows until a compliance evaluation has run, and `ownership` reads
 * `"officehq"` for a device enrolled before ownership was recorded.
 * `enrolledBy` carries only the enrolling user's upn -- never the oid.
 */
export function deviceSummary(profile: Item): Item {
  return {
    deviceId: deviceIdOf(profile),
    hostname: stringOrNull(profile.hostname),
    platform: stringOrNull(profile.platform),
    osVersion: stringOrNull(profile.osVersion),
    // The friendly OS name the check-in derives from inventory.os; `null` until one has.
    osDisplay: stringOrNull(profile.osDisplay),
    lastSeenAt: stringOrNull(profile.lastSeenAt),
    complianceState: stringOrNull(profile.complianceState) ?? UNKNOWN_COMPLIANCE,
    agentVersion: stringOrNull(profile.agentVersion),
    // Installer sign-in enrollment: recorded at enroll, displayed only.
    ownership: ownershipOf(profile),
    enrolledBy: enrolledBySummary(profile),
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
  safe.ownership = ownershipOf(profile);
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
export function byLastSeenDescending(left: Item, right: Item): number {
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
export interface ProfilePage {
  profiles: Item[];
  cursor: string | null;
}

/**
 * One page of the whole fleet, from the `gsi1` device list.
 *
 * When `staleBefore` is given the key condition also bounds `gsi1sk`, so only
 * devices last seen before that instant are read.
 */
export async function listFleet(
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
  // An empty `ownership` is no filter; any other value must be one the
  // enroll route stores.
  const ownership = req.query?.ownership ?? '';
  if (limit === null || !isUsableCursor(cursor) || (ownership !== '' && !OWNERSHIP_VALUES.includes(ownership))) {
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
  const fresh = staleBefore === null
    ? page.profiles
    : page.profiles.filter((profile) => {
        const lastSeenAt = stringOrNull(profile.lastSeenAt);
        return lastSeenAt !== null && lastSeenAt < staleBefore;
      });
  // Ownership is not part of any key, so it narrows the page after the read:
  // a filtered page may hold fewer than `limit` items while `cursor` still
  // leads on to the rest of the fleet.
  const selected = ownership === '' ? fresh : fresh.filter((profile) => ownershipOf(profile) === ownership);

  const items = [...selected].sort(byLastSeenDescending).map(deviceSummary);
  return { statusCode: 200, body: { items, cursor: page.cursor } };
};

/**
 * The device's commands, newest issue first: the newest `MAX_DETAIL_COMMANDS`,
 * plus every `pending` or `leased` command beyond them, so a long queue is
 * never truncated in the console's Queue panel.
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

  // The newest `MAX_DETAIL_COMMANDS`, plus every command still waiting or out
  // on lease (the device's queue), each listed once, newest issue first.
  const sorted = commands.sort(byIssuedAtDescending);
  const newest = new Set(sorted.slice(0, MAX_DETAIL_COMMANDS));
  return sorted
    .filter((command) => newest.has(command) || command.status === 'pending' || command.status === 'leased')
    .map(publicCommand);
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

/** A finite number, or `null`. */
function numberOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/**
 * The device's boot history, newest boot first: each stored boot with a string
 * `bootAt`, as `{bootAt, bootDurationSeconds}`. `[]` when there is no history
 * or `boots` is not an array.
 */
function bootHistoryOf(item: Item | undefined | null): Item[] {
  const boots = item?.boots;
  if (!Array.isArray(boots)) {
    return [];
  }
  return boots
    .filter((boot): boot is Item => typeof boot === 'object' && boot !== null && typeof (boot as Item).bootAt === 'string')
    .map((boot) => ({ bootAt: boot.bootAt as string, bootDurationSeconds: numberOrNull(boot.bootDurationSeconds) }))
    .sort((a, b) => (a.bootAt < b.bootAt ? 1 : a.bootAt > b.bootAt ? -1 : 0));
}

/** Newest occurrence first; events at the same instant by id, ascending. */
function byOccurredAtDescending(a: Item, b: Item): number {
  const left = a.occurredAt as string;
  const right = b.occurredAt as string;
  if (left !== right) {
    return left < right ? 1 : -1;
  }
  const leftId = typeof a.eventId === 'string' ? a.eventId : '';
  const rightId = typeof b.eventId === 'string' ? b.eventId : '';
  return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
}

/**
 * The device's application crash and hang events of the last
 * `APP_CRASH_RETENTION_SECONDS`, newest first, capped at `MAX_DETAIL_CRASHES`.
 * Read like the findings: a query on the device's own partition, following the
 * cursor to the end. TTL deletion is lazy, so the cutoff is applied here.
 */
async function readAppCrashes(table: AdminTable, deviceId: string, now: Date): Promise<Item[]> {
  // Empty occurredAt/eventId yield the device's partition key; every crash
  // event of the device is stored under `APP_CRASH_SK_PREFIX`.
  const { pk } = deviceAppCrash(deviceId, '', '');
  const cutoff = Date.parse(isoUtc(new Date(now.getTime() - APP_CRASH_RETENTION_SECONDS * 1000)));

  const crashes: Item[] = [];
  let cursor: string | null = null;
  do {
    const page: QueryPage = await table.query({
      KeyConditionExpression: '#pk = :pk AND begins_with(#sk, :crashPrefix)',
      ExpressionAttributeNames: { '#pk': 'pk', '#sk': 'sk' },
      ExpressionAttributeValues: { ':pk': pk, ':crashPrefix': APP_CRASH_SK_PREFIX },
      cursor,
    });
    crashes.push(...page.items);
    const next = page.cursor ?? null;
    // A cursor that does not move would page forever; treat it as the end.
    cursor = next === cursor ? null : next;
  } while (cursor !== null);

  return crashes
    .filter((crash) => {
      if (typeof crash.occurredAt !== 'string') {
        return false;
      }
      const occurred = Date.parse(crash.occurredAt);
      return !Number.isNaN(occurred) && occurred >= cutoff;
    })
    .sort(byOccurredAtDescending)
    .slice(0, MAX_DETAIL_CRASHES)
    .map((crash) => ({
      eventId: stringOrNull(crash.eventId),
      appName: stringOrNull(crash.appName),
      appVersion: stringOrNull(crash.appVersion),
      occurredAt: crash.occurredAt,
      kind: stringOrNull(crash.kind),
    }));
}

/**
 * The device's History events that occurred within
 * `DEVICE_EVENT_RETENTION_SECONDS`, newest first (ties by eventId ascending),
 * capped at `MAX_DETAIL_DEVICE_EVENTS`. Read like the crash events: a query on
 * the device's own partition, following the cursor to the end. TTL deletion
 * is lazy, so the cutoff is applied here.
 */
async function readDeviceEvents(table: AdminTable, deviceId: string, now: Date): Promise<Item[]> {
  // Empty occurredAt/eventId yield the device's partition key; every event of
  // the device is stored under `DEVICE_EVENT_SK_PREFIX`.
  const { pk } = deviceEvent(deviceId, '', '');
  const cutoff = now.getTime() - DEVICE_EVENT_RETENTION_SECONDS * 1000;

  const events: Item[] = [];
  let cursor: string | null = null;
  do {
    const page: QueryPage = await table.query({
      KeyConditionExpression: '#pk = :pk AND begins_with(#sk, :eventPrefix)',
      ExpressionAttributeNames: { '#pk': 'pk', '#sk': 'sk' },
      ExpressionAttributeValues: { ':pk': pk, ':eventPrefix': DEVICE_EVENT_SK_PREFIX },
      cursor,
    });
    events.push(...page.items);
    const next = page.cursor ?? null;
    // A cursor that does not move would page forever; treat it as the end.
    cursor = next === cursor ? null : next;
  } while (cursor !== null);

  return events
    .filter((event) => {
      if (typeof event.occurredAt !== 'string') {
        return false;
      }
      const occurred = Date.parse(event.occurredAt);
      return !Number.isNaN(occurred) && occurred >= cutoff;
    })
    .sort(byOccurredAtDescending)
    .slice(0, MAX_DETAIL_DEVICE_EVENTS)
    .map((event) => ({
      eventId: stringOrNull(event.eventId),
      source: stringOrNull(event.source),
      type: stringOrNull(event.type),
      summary: stringOrNull(event.summary),
      details: agentErrorFieldsOf(event.details),
      actor: stringOrNull(event.actor),
      occurredAt: event.occurredAt,
    }));
}

/** Most recently seen first; entries seen at the same instant by signature, ascending. */
function byAgentErrorLastSeenDescending(a: Item, b: Item): number {
  const left = a.lastSeenAt as string;
  const right = b.lastSeenAt as string;
  if (left !== right) {
    return left < right ? 1 : -1;
  }
  const leftId = typeof a.signature === 'string' ? a.signature : '';
  const rightId = typeof b.signature === 'string' ? b.signature : '';
  return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
}

/** A stored agent error's fields: only string values, or `{}` when absent or malformed. */
function agentErrorFieldsOf(value: unknown): Record<string, string> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return {};
  }
  const fields: Record<string, string> = {};
  for (const [key, field] of Object.entries(value as Record<string, unknown>)) {
    if (typeof field === 'string') {
      fields[key] = field;
    }
  }
  return fields;
}

/**
 * The device's agent warn/error entries last seen within
 * `AGENT_ERROR_RETENTION_SECONDS`, newest `lastSeenAt` first, capped at
 * `MAX_DETAIL_AGENT_ERRORS`. Read like the crash events: a query on the
 * device's own partition, following the cursor to the end. TTL deletion is
 * lazy, so the cutoff is applied here.
 */
async function readAgentErrors(table: AdminTable, deviceId: string, now: Date): Promise<Item[]> {
  // An empty signature yields the device's partition key; every agent error
  // of the device is stored under `AGENT_ERROR_SK_PREFIX`.
  const { pk } = deviceAgentError(deviceId, '');
  const cutoff = now.getTime() - AGENT_ERROR_RETENTION_SECONDS * 1000;

  const entries: Item[] = [];
  let cursor: string | null = null;
  do {
    const page: QueryPage = await table.query({
      KeyConditionExpression: '#pk = :pk AND begins_with(#sk, :errorPrefix)',
      ExpressionAttributeNames: { '#pk': 'pk', '#sk': 'sk' },
      ExpressionAttributeValues: { ':pk': pk, ':errorPrefix': AGENT_ERROR_SK_PREFIX },
      cursor,
    });
    entries.push(...page.items);
    const next = page.cursor ?? null;
    // A cursor that does not move would page forever; treat it as the end.
    cursor = next === cursor ? null : next;
  } while (cursor !== null);

  return entries
    .filter((entry) => {
      if (typeof entry.lastSeenAt !== 'string') {
        return false;
      }
      const lastSeen = Date.parse(entry.lastSeenAt);
      return !Number.isNaN(lastSeen) && lastSeen >= cutoff;
    })
    .sort(byAgentErrorLastSeenDescending)
    .slice(0, MAX_DETAIL_AGENT_ERRORS)
    .map((entry) => ({
      signature: stringOrNull(entry.signature),
      level: stringOrNull(entry.level),
      component: stringOrNull(entry.component),
      message: stringOrNull(entry.message),
      fields: agentErrorFieldsOf(entry.fields),
      count: typeof entry.count === 'number' ? entry.count : null,
      firstSeenAt: stringOrNull(entry.firstSeenAt),
      lastSeenAt: entry.lastSeenAt,
    }));
}

/** Most recently seen first; users seen at the same instant by username, ascending. */
function byLastSeenAtDescending(a: Item, b: Item): number {
  const left = a.lastSeenAt as string;
  const right = b.lastSeenAt as string;
  if (left !== right) {
    return left < right ? 1 : -1;
  }
  const leftName = a.username as string;
  const rightName = b.username as string;
  return leftName < rightName ? -1 : leftName > rightName ? 1 : 0;
}

/**
 * The device's login history: one `{username, firstSeenAt, lastSeenAt,
 * loginCount}` per stored `LOGINUSER#` record with a string `username` and
 * `lastSeenAt`, most recently seen first. Read like the findings: a query on
 * the device's own partition, following the cursor to the end.
 */
async function readLoginHistory(table: AdminTable, deviceId: string): Promise<Item[]> {
  // An empty username key yields the device's partition key and the
  // `LOGINUSER#` prefix every login record of this device is stored under.
  const { pk, sk: loginPrefix } = deviceLoginUser(deviceId, '');

  const records: Item[] = [];
  let cursor: string | null = null;
  do {
    const page: QueryPage = await table.query({
      KeyConditionExpression: '#pk = :pk AND begins_with(#sk, :loginPrefix)',
      ExpressionAttributeNames: { '#pk': 'pk', '#sk': 'sk' },
      ExpressionAttributeValues: { ':pk': pk, ':loginPrefix': loginPrefix },
      cursor,
    });
    records.push(...page.items);
    const next = page.cursor ?? null;
    // A cursor that does not move would page forever; treat it as the end.
    cursor = next === cursor ? null : next;
  } while (cursor !== null);

  return records
    .filter((record) => typeof record.username === 'string' && typeof record.lastSeenAt === 'string')
    .sort(byLastSeenAtDescending)
    .map((record) => ({
      username: record.username,
      firstSeenAt: stringOrNull(record.firstSeenAt),
      lastSeenAt: record.lastSeenAt,
      loginCount: numberOrNull(record.loginCount),
    }));
}

/**
 * The OS user the agent last reported (spec Amendment B), as
 * `{username, reportedAt}`, or `null` when none was reported. An item from the
 * earlier token-based report carries no `reportedAt` and reads as `null`.
 */
export function signedInUserOf(item: Item | undefined | null): { username: string | null; reportedAt: string } | null {
  if (item === undefined || item === null) {
    return null;
  }
  const reportedAt = stringOrNull(item.reportedAt);
  if (reportedAt === null) {
    return null;
  }
  return { username: stringOrNull(item.username), reportedAt };
}

/**
 * The device's analytics collection state from its `SETTINGS` item. Only a
 * stored `analyticsEnabled === false` is off; a missing item or a missing or
 * non-boolean value is on.
 */
function analyticsCollectionOf(
  item: Item | undefined | null,
): { enabled: boolean; updatedAt: string | null; updatedBy: string | null } {
  return {
    enabled: item?.analyticsEnabled !== false,
    updatedAt: typeof item?.updatedAt === 'string' ? item.updatedAt : null,
    updatedBy: typeof item?.updatedBy === 'string' ? item.updatedBy : null,
  };
}

/**
 * The device's heartbeat state from its `HEARTBEAT` item. It is on only when
 * the stored `heartbeatEnabled === true` and the stored interval is an
 * allowed option; an interval that is not an option reads as the default.
 */
function heartbeatOf(item: Item | undefined | null): {
  enabled: boolean;
  intervalSeconds: number;
  updatedAt: string | null;
  updatedBy: string | null;
} {
  const stored = item?.intervalSeconds;
  const isOption = typeof stored === 'number' && HEARTBEAT_INTERVAL_OPTIONS_SECONDS.includes(stored);
  return {
    enabled: item?.heartbeatEnabled === true && isOption,
    intervalSeconds: isOption ? (stored as number) : HEARTBEAT_DEFAULT_INTERVAL_SECONDS,
    updatedAt: typeof item?.updatedAt === 'string' ? item.updatedAt : null,
    updatedBy: typeof item?.updatedBy === 'string' ? item.updatedBy : null,
  };
}

/**
 * The device's credential as the admin sees it: whether it is disabled
 * (`profile.status === 'revoked'`, refused by `deviceAuth`), who disabled it
 * and when, when it enrolled, and the token that enrolled it. `enrollmentToken`
 * is `{tokenId, label, createdBy, status}` -- never the token or its hash --
 * or `null` when the profile names no token or the token record is gone.
 */
async function credentialOf(table: AdminTable, profile: Item, now: Date): Promise<Item> {
  const tokenId = stringOrNull(profile.enrollmentTokenId);
  let enrollmentTokenSummary: Item | null = null;
  if (tokenId !== null) {
    let record: Item | undefined;
    try {
      record = await table.get(enrollmentToken(tokenId));
    } catch (error) {
      // An id no key can be built from names no token.
      if (!(error instanceof Error) || !error.message.startsWith('invalid id')) {
        throw error;
      }
    }
    if (record !== undefined && record !== null) {
      enrollmentTokenSummary = {
        tokenId,
        label: typeof record.label === 'string' ? record.label : null,
        createdBy: stringOrNull(record.createdBy),
        status: enrollmentTokenStatus(record, now),
      };
    }
  }
  return credentialBody(profile, enrollmentTokenSummary);
}

/** The `credential` object from a profile and an already-resolved token summary. */
function credentialBody(profile: Item, enrollmentTokenSummary: Item | null): Item {
  return {
    status: profile.status === REVOKED_STATUS ? 'disabled' : 'active',
    disabledAt: stringOrNull(profile.disabledAt),
    disabledBy: stringOrNull(profile.disabledBy),
    enrolledAt: stringOrNull(profile.enrolledAt),
    enrollmentToken: enrollmentTokenSummary,
  };
}

/**
 * `GET /admin/api/v1/devices/{deviceId}` -- one device in full: its profile,
 * its last inventory and posture snapshots, its most recent commands, its last
 * scheduled antivirus scan (`antivirusScan`, `null` when none was reported), its
 * full antivirus status (`antivirusStatus`, the stored `AVSTATUS` item, `null`
 * when none was reported), and
 * its endpoint analytics (latest snapshot, boot history, recent crashes/hangs),
 * its stored coarse `location` (`{latest: null, history: []}` when none) and
 * its effective `locationTracking` policy value.
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

  const [
    inventory,
    posture,
    signedInUser,
    analyticsSnapshot,
    bootHistory,
    settings,
    heartbeatSetting,
    antivirusScan,
    antivirusStatus,
    location,
    defenderHardening,
  ] = await Promise.all([
    deps.table.get(deviceInventory(deviceId)),
    deps.table.get(devicePosture(deviceId)),
    deps.table.get(deviceSignedInUser(deviceId)),
    deps.table.get(deviceAnalytics(deviceId)),
    deps.table.get(deviceBootHistory(deviceId)),
    deps.table.get(deviceSettings(deviceId)),
    deps.table.get(deviceHeartbeatSettings(deviceId)),
    deps.table.get(deviceAntivirusScan(deviceId)),
    deps.table.get(deviceAntivirusStatus(deviceId)),
    deps.table.get(deviceLocation(deviceId)),
    deps.table.get(deviceDefenderHardening(deviceId)),
  ]);
  const groups = await readDeviceGroups(deps.table, deviceId);

  return {
    statusCode: 200,
    body: {
      profile: publicProfile(profile),
      inventory: publicItem(inventory),
      posture: publicItem(posture),
      commands: await readCommands(deps.table, deviceId),
      antivirusFindings: await readAntivirusFindings(deps.table, deviceId),
      antivirusScan: publicItem(antivirusScan),
      antivirusStatus: publicItem(antivirusStatus),
      defenderHardening: publicItem(defenderHardening),
      signedInUser: signedInUserOf(signedInUser),
      loginHistory: await readLoginHistory(deps.table, deviceId),
      agentErrors: await readAgentErrors(deps.table, deviceId, nowDate(deps)),
      deviceEvents: await readDeviceEvents(deps.table, deviceId, nowDate(deps)),
      analytics: {
        snapshot: publicItem(analyticsSnapshot),
        bootHistory: bootHistoryOf(bootHistory),
        crashes: await readAppCrashes(deps.table, deviceId, nowDate(deps)),
      },
      analyticsCollection: analyticsCollectionOf(settings),
      heartbeat: heartbeatOf(heartbeatSetting),
      credential: await credentialOf(deps.table, profile, nowDate(deps)),
      groups,
      policies: await readDevicePolicies(deps.table, groups),
      location: locationView(location),
      locationTracking: await locationTrackingEnabled(deps.table, deviceId),
    },
  };
};

/** One group a device belongs to, as the detail view lists it. */
interface DeviceGroupEntry {
  groupId: string;
  name: string | null;
}

/** One policy reaching a device, with the device's groups it comes through. */
interface DevicePolicyEntry {
  policyId: string;
  name: string | null;
  version: number | null;
  viaGroups: string[];
}

/** Ascending by `name` (an absent name sorts first), then by id. */
function byNameThenId(nameA: string | null, idA: string, nameB: string | null, idB: string): number {
  const a = nameA ?? '';
  const b = nameB ?? '';
  if (a !== b) return a < b ? -1 : 1;
  return idA < idB ? -1 : idA > idB ? 1 : 0;
}

/** The groups holding a membership of the device, sorted by name then id. */
async function readDeviceGroups(table: AdminDependencies['table'], deviceId: string): Promise<DeviceGroupEntry[]> {
  const groupIds = await readDeviceGroupIds(table, deviceId);
  const groups: DeviceGroupEntry[] = [];
  for (const groupId of groupIds) {
    let record: Item | undefined;
    try {
      record = await table.get(groupKey(groupId));
    } catch {
      continue;
    }
    groups.push({ groupId, name: stringOrNull(record?.name) });
  }
  return groups.sort((a, b) => byNameThenId(a.name, a.groupId, b.name, b.groupId));
}

/**
 * Every policy assigned to at least one of the device's groups, read only.
 * `viaGroups` holds those groups' ids ascending; a policy whose record no
 * longer exists is left out. Sorted by name then id.
 */
async function readDevicePolicies(
  table: AdminDependencies['table'],
  groups: DeviceGroupEntry[],
): Promise<DevicePolicyEntry[]> {
  const via = new Map<string, string[]>();
  for (const { groupId } of groups) {
    for (const policyId of await readGroupPolicyIds(table, groupId)) {
      const list = via.get(policyId) ?? [];
      if (!list.includes(groupId)) list.push(groupId);
      via.set(policyId, list);
    }
  }
  const policies: DevicePolicyEntry[] = [];
  for (const [policyId, viaGroups] of via) {
    let record: Item | undefined;
    try {
      record = await table.get(policyKey(policyId));
    } catch {
      continue;
    }
    if (record === undefined || record === null) continue;
    policies.push({
      policyId,
      name: stringOrNull(record.name),
      version: typeof record.version === 'number' ? record.version : null,
      viaGroups: [...viaGroups].sort(),
    });
  }
  return policies.sort((a, b) => byNameThenId(a.name, a.policyId, b.name, b.policyId));
}

/**
 * `POST /admin/api/v1/devices/{deviceId}/disable` -- refuse every further
 * request the device signs. Reversible: the device keeps its secret, so
 * `enable` restores it without a re-enroll.
 *
 * Stored as `profile.status = 'revoked'` with `disabledAt`/`disabledBy`, set
 * in place by one update; no token record is read or written. This route is
 * the only writer of `device.disabled`.
 */
export const handleDeviceDisable: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
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
  if (profile.status === REVOKED_STATUS) {
    return jsonError(409, 'already_disabled');
  }

  const table = adminUpdateTable(deps.table);
  const at = adminNow(deps);
  const disabledAt = isoUtc(at);
  const actor = adminActor(req.claims);
  await table.update(profileKey, {
    UpdateExpression: 'SET #status = :status, #disabledAt = :disabledAt, #disabledBy = :disabledBy',
    ExpressionAttributeNames: { '#status': 'status', '#disabledAt': 'disabledAt', '#disabledBy': 'disabledBy' },
    ExpressionAttributeValues: { ':status': REVOKED_STATUS, ':disabledAt': disabledAt, ':disabledBy': actor },
  });

  await appendAudit(table, {
    action: DEVICE_DISABLED_ACTION,
    actor,
    target: deviceId,
    detail: { source: 'admin' },
    now: at,
  });

  await recordDeviceEvent(table, {
    deviceId,
    source: 'admin',
    type: DEVICE_DISABLED_ACTION,
    summary: 'Device disabled',
    actor,
    occurredAt: at,
  });

  const updated: Item = { ...profile, status: REVOKED_STATUS, disabledAt, disabledBy: actor };
  return {
    statusCode: 200,
    body: { deviceId, credential: await credentialOf(deps.table, updated, at) },
  };
};

/**
 * `POST /admin/api/v1/devices/{deviceId}/enable` -- lift an admin disable.
 * Removes `status`, `disabledAt` and `disabledBy` in place by one update; the
 * device's next request signed with its existing secret is accepted again.
 * No token record is read or written.
 */
export const handleDeviceEnable: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
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
  if (profile.status !== REVOKED_STATUS) {
    return jsonError(409, 'not_disabled');
  }

  const table = adminUpdateTable(deps.table);
  const at = adminNow(deps);
  await table.update(profileKey, {
    UpdateExpression: 'REMOVE #status, #disabledAt, #disabledBy',
    ExpressionAttributeNames: { '#status': 'status', '#disabledAt': 'disabledAt', '#disabledBy': 'disabledBy' },
  });

  const actor = adminActor(req.claims);
  await appendAudit(table, {
    action: DEVICE_ENABLED_ACTION,
    actor,
    target: deviceId,
    detail: {},
    now: at,
  });

  await recordDeviceEvent(table, {
    deviceId,
    source: 'admin',
    type: DEVICE_ENABLED_ACTION,
    summary: 'Device enabled',
    actor,
    occurredAt: at,
  });

  const updated: Item = { ...profile };
  delete updated.status;
  delete updated.disabledAt;
  delete updated.disabledBy;
  // The token is not read here, so the response names none.
  return { statusCode: 200, body: { deviceId, credential: credentialBody(updated, null) } };
};

/**
 * `PUT /admin/api/v1/devices/{deviceId}` -- change the device's `ownership`,
 * the only admin-editable device field.
 *
 * The body must be exactly `{ownership}` with a value from `OWNERSHIP_VALUES`;
 * anything else is a 400 whose `fields` name `ownership` (when it is missing or
 * unknown) and every other key present. An unknown device -- or an id no key
 * can be built from -- is a 404. Only the profile's `ownership` attribute is
 * changed, in place, so nothing else on the profile moves. Re-enrollment still
 * overwrites it (`enrollDevice`). When the ownership actually changes, the
 * device also joins every group that auto-assigns the new ownership
 * (`applyAutoAssignGroups`); the audit detail then carries `autoAssignGroupIds`.
 */
export const handleDeviceUpdate: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body) ?? {};
  const ownership = body.ownership;
  const invalid: string[] = [];
  if (typeof ownership !== 'string' || !OWNERSHIP_VALUES.includes(ownership)) {
    invalid.push('ownership');
  }
  for (const name of Object.keys(body)) {
    if (name !== 'ownership') {
      invalid.push(name);
    }
  }
  if (invalid.length > 0) {
    return jsonError(400, 'invalid_request', { fields: invalid });
  }

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

  const table = adminUpdateTable(deps.table);
  const at = adminNow(deps);
  const to = ownership as string;
  // Read before the update, so the skip below and the audit `from` use the
  // ownership the device had when the request arrived.
  const from = ownershipOf(profile);
  await table.update(profileKey, {
    UpdateExpression: 'SET #ownership = :ownership',
    ExpressionAttributeNames: { '#ownership': 'ownership' },
    ExpressionAttributeValues: { ':ownership': to },
  });

  // The new ownership's default group (TASK-047), only on an actual change.
  // The update is already committed, so a failure here never fails the
  // request; existing memberships are never removed.
  let autoAssignGroupIds: string[] = [];
  if (to !== from) {
    try {
      autoAssignGroupIds = await applyAutoAssignGroups(table, deviceId, to, at);
    } catch {
      autoAssignGroupIds = [];
    }
  }

  const actor = adminActor(req.claims);
  await appendAudit(table, {
    action: DEVICE_UPDATED_ACTION,
    actor,
    target: deviceId,
    detail: { ownership: { from, to }, ...(autoAssignGroupIds.length === 0 ? {} : { autoAssignGroupIds }) },
    now: at,
  });

  if (to !== from) {
    await recordDeviceEvent(table, {
      deviceId,
      source: 'admin',
      type: 'device.ownership_changed',
      summary: `Ownership changed from ${from} to ${to}`,
      details: { from, to },
      actor,
      occurredAt: at,
    });
  }
  for (const groupId of autoAssignGroupIds) {
    await recordDeviceEvent(table, {
      deviceId,
      source: 'system',
      type: 'group.added',
      summary: `Auto-assigned to group ${await deviceEventGroupName(table, groupId)}`,
      details: { groupId, ownership: to },
      actor: null,
      occurredAt: at,
    });
  }

  return { statusCode: 200, body: { deviceId, ownership: to } };
};

/**
 * Every item stored under the device's `DEVICE#<id>` partition, whatever its
 * sort key: a query on the partition alone, following the cursor to the end.
 */
async function readDevicePartition(table: AdminTable, deviceId: string): Promise<Item[]> {
  const { pk } = deviceProfile(deviceId);

  const items: Item[] = [];
  let cursor: string | null = null;
  do {
    const page: QueryPage = await table.query({
      KeyConditionExpression: '#pk = :pk',
      ExpressionAttributeNames: { '#pk': 'pk' },
      ExpressionAttributeValues: { ':pk': pk },
      cursor,
    });
    items.push(...page.items);
    const next = page.cursor ?? null;
    // A cursor that does not move would page forever; treat it as the end.
    cursor = next === cursor ? null : next;
  } while (cursor !== null);

  return items;
}

/**
 * `DELETE /admin/api/v1/devices/{deviceId}` -- remove the device and
 * everything it owns. The body must carry `{"confirm": true}`.
 *
 * Removed: every item in the device's `DEVICE#<id>` partition (counted in
 * `itemsRemoved`), its membership of every group (`membershipsRemoved`), and
 * its `HWUUID#` pointer when that pointer still names this device. The profile
 * is deleted last, so a delete interrupted part-way leaves a device that can
 * still be found and deleted again. Enrollment tokens, `NONCE#` items and audit
 * entries are not touched.
 *
 * An unknown device -- or an id no key can be built from -- is a 404 whatever
 * the body; an existing device without the confirmation is a 409.
 */
export const handleDeviceDelete: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
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

  const body = readJsonBody(req.body) ?? {};
  if (body.confirm !== true) {
    return jsonError(409, 'confirmation_required');
  }

  const table = adminDeleteTable(deps.table);
  const at = adminNow(deps);

  // Group memberships live in each group's own partition.
  let membershipsRemoved = 0;
  for (const groupId of await readAllGroupIds(table)) {
    let memberKey;
    try {
      memberKey = groupMember(groupId, deviceId);
    } catch {
      continue;
    }
    const member = await table.get(memberKey);
    if (member === undefined || member === null) {
      continue;
    }
    await table.delete(memberKey);
    membershipsRemoved += 1;
  }

  // The hardware pointer, only while it still names this device: a later
  // enrollment of the same machine may already own it.
  const hardwareUuid = stringOrNull(profile.hardwareUuid);
  if (hardwareUuid !== null && !hardwareUuid.includes('#')) {
    const pointerKey = deviceByHardware(hardwareUuid);
    const pointer = await table.get(pointerKey);
    if (pointer !== undefined && pointer !== null && pointer.deviceId === deviceId) {
      await table.delete(pointerKey);
    }
  }

  // Every partition item but the profile, then the profile last.
  const partition = await readDevicePartition(table, deviceId);
  let itemsRemoved = 0;
  for (const item of partition) {
    if (item.sk === profileKey.sk) {
      continue;
    }
    await table.delete({ pk: item.pk as string, sk: item.sk as string });
    itemsRemoved += 1;
  }
  await table.delete(profileKey);
  itemsRemoved += 1;

  await appendAudit(table, {
    action: DEVICE_DELETED_ACTION,
    actor: adminActor(req.claims),
    target: deviceId,
    detail: { hostname: stringOrNull(profile.hostname), hardwareUuid },
    now: at,
  });

  return { statusCode: 200, body: { deviceId, itemsRemoved, membershipsRemoved } };
};

/** Register the device routes on a router. Returns the router, so calls chain. */
export function registerDeviceRoutes(router: Router, source: AdminDependencySource): Router {
  registerAdminRoute(router, 'GET', DEVICE_LIST_PATH, handleDeviceList, source);
  registerAdminRoute(router, 'PUT', DEVICE_DETAIL_PATH, handleDeviceUpdate, source);
  registerAdminRoute(router, 'DELETE', DEVICE_DETAIL_PATH, handleDeviceDelete, source);
  registerAdminRoute(router, 'POST', DEVICE_DISABLE_PATH, handleDeviceDisable, source);
  registerAdminRoute(router, 'POST', DEVICE_ENABLE_PATH, handleDeviceEnable, source);
  return registerAdminRoute(router, 'GET', DEVICE_DETAIL_PATH, handleDeviceDetail, source);
}
