/**
 * The fleet endpoint analytics view.
 *
 *   GET /admin/api/v1/analytics?days=<1..30>&top=<1..50>
 *
 *   registerAnalyticsRoutes(router, { verifier, table, now });
 *
 * Built at read time from what the check-in route stores (TASK-034): every
 * device's latest snapshot is one `gsi1` query on the `ANALYTICS` partition,
 * and the window's crash/hang events one `gsi1` query on the `APPCRASH`
 * partition bounded by `gsi1sk >= <window start>`. Nothing is pre-aggregated
 * and nothing is scanned.
 *
 * The answer is four ranked lists -- slowest boots, most crashes and hangs per
 * device, top crashing applications, and devices under resource pressure --
 * plus the window they cover. Snapshots count only when they were received
 * inside the window; crash events only when they occurred inside it, because
 * DynamoDB's `ttl` deletion is lazy and an expired event may still be read.
 *
 * Each partition's read follows its cursor to the end, up to
 * `ANALYTICS_MAX_QUERY_PAGES` pages; stopping there with a cursor still
 * pending marks the answer `truncated`.
 */
import { appendAudit, isoUtc } from '../audit.js';
import { recordDeviceEvent } from '../deviceEvents.js';
import {
  GSI1_NAME,
  analyticsListIndex,
  appCrashListIndex,
  deviceProfile,
  deviceSettings,
  type TableKey,
} from '../db/keys.js';
import type { Item, QueryPage } from '../db/table.js';
import type { RouteResult, Router } from '../http/router.js';
import {
  adminActor,
  adminNow,
  adminWriteTable,
  isIsoUtc,
  jsonError,
  readJsonBody,
  registerAdminRoute,
  type AdminDependencySource,
  type AdminRouteHandler,
  type AdminTable,
} from './router.js';

/** Sub-path of the fleet analytics view. */
export const ANALYTICS_PATH = '/analytics';

/** Sub-path of the per-device analytics collection on/off switch. */
export const ANALYTICS_COLLECTION_PATH = '/devices/{deviceId}/analytics-collection';

/** Audit action of a change to a device's analytics collection setting. */
export const ANALYTICS_COLLECTION_CHANGED_ACTION = 'device.analytics_collection.changed';

/** The window, in whole days, when the request names none. */
export const ANALYTICS_DEFAULT_WINDOW_DAYS = 30;

/** The widest window accepted: the crash events' retention. */
export const ANALYTICS_MAX_WINDOW_DAYS = 30;

/** Entries per list when the request names no `top`. */
export const ANALYTICS_DEFAULT_TOP = 10;

/** The largest `top` accepted; a bigger one is refused, never clamped. */
export const ANALYTICS_MAX_TOP = 50;

/** The most query pages read from one `gsi1` partition per request. */
export const ANALYTICS_MAX_QUERY_PAGES = 50;

/** A device whose system disk has less than this percentage free is low on disk. */
export const LOW_DISK_FREE_PERCENT = 10;

/** A device using at least this percentage of its memory is under memory pressure. */
export const HIGH_MEMORY_USED_PERCENT = 90;

/** The most crash/hang events the device detail view returns, newest first. */
export const MAX_DETAIL_CRASHES = 50;

/** The most agent error entries the device detail view returns, newest first. */
export const MAX_DETAIL_AGENT_ERRORS = 50;

/** A decimal integer with no sign, fraction or exponent. */
const INTEGER_PATTERN = /^[0-9]+$/;

/** Seconds in a day. */
const DAY_SECONDS = 86400;

/**
 * A whole-number query parameter within `1..max`, the default when absent or
 * empty, or `null` when it is anything else.
 */
function parseBounded(raw: string | undefined, fallback: number, max: number): number | null {
  if (raw === undefined || raw === '') {
    return fallback;
  }
  if (!INTEGER_PATTERN.test(raw)) {
    return null;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1 || value > max) {
    return null;
  }
  return value;
}

/** A non-empty string attribute, or `null`. */
function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/** A finite number attribute, or `null`. */
function numberOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/** A nested object attribute, or an empty object when it is missing or not an object. */
function objectOf(value: unknown): Item {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Item) : {};
}

/** `-1`/`0`/`1` for two strings in code-unit order, independent of locale. */
function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

/** The result of reading one partition to its end, or to the page cap. */
interface PartitionRead {
  items: Item[];
  truncated: boolean;
}

/**
 * Read every page of one `gsi1` query.
 *
 * A cursor equal to the one just sent would page forever and ends the read; a
 * cursor still pending after `ANALYTICS_MAX_QUERY_PAGES` pages ends it too, and
 * marks the read truncated.
 */
async function readPartition(
  table: AdminTable,
  request: { KeyConditionExpression: string; ExpressionAttributeNames: Record<string, string>; ExpressionAttributeValues: Item },
): Promise<PartitionRead> {
  const items: Item[] = [];
  let cursor: string | null = null;
  let pages = 0;
  do {
    const page: QueryPage = await table.query({ IndexName: GSI1_NAME, ...request, cursor });
    pages += 1;
    items.push(...(Array.isArray(page.items) ? page.items : []));
    const next = page.cursor ?? null;
    if (next === null || next === cursor) {
      return { items, truncated: false };
    }
    cursor = next;
  } while (pages < ANALYTICS_MAX_QUERY_PAGES);
  return { items, truncated: true };
}

/** One normalised, in-window snapshot. */
interface Snapshot {
  deviceId: string;
  lastBootAt: string | null;
  bootDurationSeconds: number | null;
  memoryUsedBytes: number | null;
  memoryTotalBytes: number | null;
  systemDiskFreeBytes: number | null;
  systemDiskTotalBytes: number | null;
}

/** One valid, in-window crash or hang event. */
interface CrashEvent {
  deviceId: string;
  appName: string;
  occurredAt: string;
  kind: 'crash' | 'hang';
}

/** The snapshot, normalised, when it was received inside the window; otherwise `null`. */
function inWindowSnapshot(item: Item, fromMillis: number): Snapshot | null {
  const receivedAt = item.receivedAt;
  if (typeof receivedAt !== 'string' || !isIsoUtc(receivedAt) || Date.parse(receivedAt) < fromMillis) {
    return null;
  }
  const deviceId = stringOrNull(item.deviceId) ?? stringOrNull(item.gsi1sk);
  if (deviceId === null) {
    return null;
  }
  const boot = objectOf(item.boot);
  const performance = objectOf(item.performance);
  return {
    deviceId,
    lastBootAt: stringOrNull(boot.lastBootAt),
    bootDurationSeconds: numberOrNull(boot.bootDurationSeconds),
    memoryUsedBytes: numberOrNull(performance.memoryUsedBytes),
    memoryTotalBytes: numberOrNull(performance.memoryTotalBytes),
    systemDiskFreeBytes: numberOrNull(performance.systemDiskFreeBytes),
    systemDiskTotalBytes: numberOrNull(performance.systemDiskTotalBytes),
  };
}

/** The event, when it is well formed and occurred inside the window; otherwise `null`. */
function inWindowCrash(item: Item, fromMillis: number): CrashEvent | null {
  const { deviceId, appName, occurredAt, kind } = item;
  if (typeof deviceId !== 'string' || typeof appName !== 'string' || typeof occurredAt !== 'string') {
    return null;
  }
  if (kind !== 'crash' && kind !== 'hang') {
    return null;
  }
  const occurred = Date.parse(occurredAt);
  if (Number.isNaN(occurred) || occurred < fromMillis) {
    return null;
  }
  return { deviceId, appName, occurredAt, kind };
}

/** `part / total x 100`, unrounded, or `null` when either is missing or the total is not positive. */
function percentOf(part: number | null, total: number | null): number | null {
  if (part === null || total === null || !(total > 0)) {
    return null;
  }
  return (part / total) * 100;
}

/** One decimal place. */
function roundOne(value: number | null): number | null {
  return value === null ? null : Math.round(value * 10) / 10;
}

/** Ascending with `null` last. */
function ascendingNullsLast(left: number | null, right: number | null): number {
  if (left === right) {
    return 0;
  }
  if (left === null) {
    return 1;
  }
  if (right === null) {
    return -1;
  }
  return left - right;
}

/** Descending with `null` last. */
function descendingNullsLast(left: number | null, right: number | null): number {
  if (left === right) {
    return 0;
  }
  if (left === null) {
    return 1;
  }
  if (right === null) {
    return -1;
  }
  return right - left;
}

/** `slowestBoots`, before hostnames are attached. */
function slowestBoots(snapshots: Snapshot[], top: number): Item[] {
  return snapshots
    .filter((snapshot) => snapshot.bootDurationSeconds !== null)
    .sort(
      (a, b) =>
        (b.bootDurationSeconds as number) - (a.bootDurationSeconds as number) || compareStrings(a.deviceId, b.deviceId),
    )
    .slice(0, top)
    .map((snapshot) => ({
      deviceId: snapshot.deviceId,
      hostname: null,
      lastBootAt: snapshot.lastBootAt,
      bootDurationSeconds: snapshot.bootDurationSeconds,
    }));
}

/** `mostCrashes`, before hostnames are attached. */
function mostCrashes(events: CrashEvent[], top: number): Item[] {
  const byDevice = new Map<string, { crashCount: number; hangCount: number; lastOccurredAt: string }>();
  for (const event of events) {
    const entry = byDevice.get(event.deviceId) ?? { crashCount: 0, hangCount: 0, lastOccurredAt: event.occurredAt };
    if (event.kind === 'crash') {
      entry.crashCount += 1;
    } else {
      entry.hangCount += 1;
    }
    if (Date.parse(event.occurredAt) > Date.parse(entry.lastOccurredAt)) {
      entry.lastOccurredAt = event.occurredAt;
    }
    byDevice.set(event.deviceId, entry);
  }
  return [...byDevice.entries()]
    .map(([deviceId, entry]) => ({
      deviceId,
      hostname: null,
      crashCount: entry.crashCount,
      hangCount: entry.hangCount,
      eventCount: entry.crashCount + entry.hangCount,
      lastOccurredAt: entry.lastOccurredAt,
    }))
    .sort((a, b) => b.eventCount - a.eventCount || compareStrings(a.deviceId, b.deviceId))
    .slice(0, top);
}

/** `topApps`: events grouped by exact, case-sensitive application name. */
function topApps(events: CrashEvent[], top: number): Item[] {
  const byApp = new Map<string, { crashCount: number; hangCount: number; devices: Set<string>; lastOccurredAt: string }>();
  for (const event of events) {
    const entry = byApp.get(event.appName) ?? {
      crashCount: 0,
      hangCount: 0,
      devices: new Set<string>(),
      lastOccurredAt: event.occurredAt,
    };
    if (event.kind === 'crash') {
      entry.crashCount += 1;
    } else {
      entry.hangCount += 1;
    }
    entry.devices.add(event.deviceId);
    if (Date.parse(event.occurredAt) > Date.parse(entry.lastOccurredAt)) {
      entry.lastOccurredAt = event.occurredAt;
    }
    byApp.set(event.appName, entry);
  }
  return [...byApp.entries()]
    .map(([appName, entry]) => ({
      appName,
      crashCount: entry.crashCount,
      hangCount: entry.hangCount,
      eventCount: entry.crashCount + entry.hangCount,
      deviceCount: entry.devices.size,
      lastOccurredAt: entry.lastOccurredAt,
    }))
    .sort(
      (a, b) =>
        b.eventCount - a.eventCount || b.deviceCount - a.deviceCount || compareStrings(a.appName, b.appName),
    )
    .slice(0, top);
}

/** `resourcePressure`, before hostnames are attached. */
function resourcePressure(snapshots: Snapshot[], top: number): Item[] {
  const entries: Array<{ deviceId: string; hostname: null; diskFreePercent: number | null; memoryUsedPercent: number | null; reasons: string[] }> = [];
  for (const snapshot of snapshots) {
    const diskFree = percentOf(snapshot.systemDiskFreeBytes, snapshot.systemDiskTotalBytes);
    const memoryUsed = percentOf(snapshot.memoryUsedBytes, snapshot.memoryTotalBytes);
    const reasons: string[] = [];
    if (diskFree !== null && diskFree < LOW_DISK_FREE_PERCENT) {
      reasons.push('low_disk');
    }
    if (memoryUsed !== null && memoryUsed >= HIGH_MEMORY_USED_PERCENT) {
      reasons.push('high_memory');
    }
    if (reasons.length === 0) {
      continue;
    }
    entries.push({
      deviceId: snapshot.deviceId,
      hostname: null,
      diskFreePercent: roundOne(diskFree),
      memoryUsedPercent: roundOne(memoryUsed),
      reasons,
    });
  }
  return entries
    .sort(
      (a, b) =>
        ascendingNullsLast(a.diskFreePercent, b.diskFreePercent) ||
        descendingNullsLast(a.memoryUsedPercent, b.memoryUsedPercent) ||
        compareStrings(a.deviceId, b.deviceId),
    )
    .slice(0, top);
}

/** The profile hostname of each id, read once per id; `null` when absent. */
async function hostnamesOf(table: AdminTable, deviceIds: Set<string>): Promise<Map<string, string | null>> {
  const ids = [...deviceIds];
  const hostnames = await Promise.all(
    ids.map(async (deviceId) => {
      let key;
      try {
        key = deviceProfile(deviceId);
      } catch {
        return null;
      }
      const profile = await table.get(key);
      return typeof profile?.hostname === 'string' ? profile.hostname : null;
    }),
  );
  return new Map(ids.map((deviceId, index) => [deviceId, hostnames[index] ?? null]));
}

/**
 * `GET /admin/api/v1/analytics` -- the fleet's ranked analytics over a window.
 *
 * `days` and `top` are validated before anything is read; an invalid value is
 * 400 `invalid_request`.
 */
export const handleFleetAnalytics: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const days = parseBounded(req.query?.days, ANALYTICS_DEFAULT_WINDOW_DAYS, ANALYTICS_MAX_WINDOW_DAYS);
  const top = parseBounded(req.query?.top, ANALYTICS_DEFAULT_TOP, ANALYTICS_MAX_TOP);
  if (days === null || top === null) {
    return jsonError(400, 'invalid_request');
  }

  const now = adminNow(deps);
  const to = isoUtc(now);
  const from = isoUtc(new Date(now.getTime() - days * DAY_SECONDS * 1000));
  const fromMillis = Date.parse(from);

  // An empty id yields each partition's value without writing key text here.
  const { gsi1pk: analyticsPartition } = analyticsListIndex('');
  const { gsi1pk: crashPartition } = appCrashListIndex('', '');

  const [snapshotRead, crashRead] = await Promise.all([
    readPartition(deps.table, {
      KeyConditionExpression: '#gsi1pk = :gsi1pk',
      ExpressionAttributeNames: { '#gsi1pk': 'gsi1pk' },
      ExpressionAttributeValues: { ':gsi1pk': analyticsPartition },
    }),
    readPartition(deps.table, {
      KeyConditionExpression: '#gsi1pk = :gsi1pk AND #gsi1sk >= :from',
      ExpressionAttributeNames: { '#gsi1pk': 'gsi1pk', '#gsi1sk': 'gsi1sk' },
      ExpressionAttributeValues: { ':gsi1pk': crashPartition, ':from': from },
    }),
  ]);

  const snapshots = snapshotRead.items
    .map((item) => inWindowSnapshot(item, fromMillis))
    .filter((snapshot): snapshot is Snapshot => snapshot !== null);
  const events = crashRead.items
    .map((item) => inWindowCrash(item, fromMillis))
    .filter((event): event is CrashEvent => event !== null);

  const boots = slowestBoots(snapshots, top);
  const crashes = mostCrashes(events, top);
  const apps = topApps(events, top);
  const pressure = resourcePressure(snapshots, top);

  const listed = new Set<string>();
  for (const entry of [...boots, ...crashes, ...pressure]) {
    listed.add(entry.deviceId as string);
  }
  const hostnames = await hostnamesOf(deps.table, listed);
  for (const entry of [...boots, ...crashes, ...pressure]) {
    entry.hostname = hostnames.get(entry.deviceId as string) ?? null;
  }

  return {
    statusCode: 200,
    body: {
      windowDays: days,
      from,
      to,
      slowestBoots: boots,
      mostCrashes: crashes,
      topApps: apps,
      resourcePressure: pressure,
      truncated: snapshotRead.truncated || crashRead.truncated,
    },
  };
};

/**
 * `POST /admin/api/v1/devices/{deviceId}/analytics-collection` -- turn a
 * device's analytics collection on or off with `{"enabled": true|false}`.
 *
 * The body is validated before anything is read; an unknown device is 404.
 * Every successful call is audited, including one that sets the value already
 * stored.
 */
export const handleAnalyticsCollectionSet: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body);
  const enabled = body !== null && !Array.isArray(body) ? body.enabled : undefined;
  if (typeof enabled !== 'boolean') {
    return jsonError(400, 'invalid_request', { fields: ['enabled'] });
  }

  const deviceId = req.params?.deviceId ?? '';
  let profileKey: TableKey;
  let settingsKey: TableKey;
  try {
    profileKey = deviceProfile(deviceId);
    settingsKey = deviceSettings(deviceId);
  } catch {
    return jsonError(404, 'not_found');
  }

  const table = adminWriteTable(deps.table);

  const profile = await table.get(profileKey);
  if (profile === undefined || profile === null) {
    return jsonError(404, 'not_found');
  }

  const at = adminNow(deps);
  const updatedAt = isoUtc(at);
  const updatedBy = adminActor(req.claims);
  await table.put({
    ...settingsKey,
    deviceId,
    analyticsEnabled: enabled,
    updatedAt,
    updatedBy,
  });

  await appendAudit(table, {
    action: ANALYTICS_COLLECTION_CHANGED_ACTION,
    actor: updatedBy,
    target: deviceId,
    detail: { enabled },
    now: at,
  });

  await recordDeviceEvent(table, {
    deviceId,
    source: 'admin',
    type: 'analytics_collection.changed',
    summary: enabled ? 'Analytics collection turned on' : 'Analytics collection turned off',
    actor: updatedBy,
    occurredAt: at,
  });

  return { statusCode: 200, body: { deviceId, analyticsEnabled: enabled, updatedAt, updatedBy } };
};

/** Register the analytics routes on a router. Returns the router, so calls chain. */
export function registerAnalyticsRoutes(router: Router, source: AdminDependencySource): Router {
  registerAdminRoute(router, 'POST', ANALYTICS_COLLECTION_PATH, handleAnalyticsCollectionSet, source);
  return registerAdminRoute(router, 'GET', ANALYTICS_PATH, handleFleetAnalytics, source);
}
