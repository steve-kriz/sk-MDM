/**
 * `POST /api/v1/devices/{deviceId}/heartbeat` -- the agent's per-device
 * performance heartbeat.
 *
 *   POST /api/v1/devices/{deviceId}/heartbeat   (device HMAC only)
 *   {"collectedAt":"2026-10-11T11:59:58Z","performance":{...},"warnings":[...]}
 *   -> {"heartbeatIntervalSeconds":300}    (or 0 when the device's heartbeat is off)
 *
 * The heartbeat is opt-in per device: an admin turns it on and picks its
 * frequency (`DEVICE#<id>` / `HEARTBEAT`, see `src/admin/heartbeat.ts`). It is
 * independent of the TASK-040 analytics collection switch; neither reads the
 * other's setting.
 *
 * The checks run in a fixed order and the first failure returns immediately,
 * having written nothing beyond the nonce `verifyDeviceRequest` burns:
 *
 *   1. raw body <= MAX_HEARTBEAT_BODY_BYTES -> 413 payload_too_large (before authentication)
 *   2. `verifyDeviceRequest`                -> its own `{status, body}`, unchanged
 *   3. path device == signed device         -> 403 device_mismatch
 *   4. body valid                           -> 400 invalid_request, fields in the
 *                                              order `collectedAt`, `performance`
 *
 * Then the device's `HEARTBEAT` item is read. When the heartbeat is off the
 * sample is dropped and the answer is `{"heartbeatIntervalSeconds": 0}`, so the
 * agent stops. When it is on, one event is written to the CloudWatch Logs
 * stream named by the device id (`heartbeatLog`); no log configured is 503
 * `heartbeat_not_configured`, a failed write 503 `heartbeat_store_unavailable`,
 * and neither refreshes the device's last-seen. Every 200 refreshes it through
 * `recordDeviceContact`.
 *
 * `performance` and `warnings` are sanitised by the same TASK-034 rules the
 * check-in applies to its `analytics` block: an out-of-range value is stored
 * `null`, never a reason to refuse the heartbeat. `network` follows the same
 * rule (`sanitiseNetwork`): a bad value is `null`, an entry without a name
 * is dropped, and anything but an array leaves the key out.
 */
import { isoUtc } from '../audit.js';
import { HEARTBEAT_INTERVAL_OPTIONS_SECONDS } from '../config/intervals.js';
import type { AnalyticsPerformance, HeartbeatNetworkAdapter, HeartbeatResponse } from '../contract/types.js';
import { deviceHeartbeatSettings, deviceProfile, type TableKey } from '../db/keys.js';
import { CONDITIONAL_CHECK_FAILED, type Item, type RequestFields, type WriteOutcome } from '../db/table.js';
import { verifyDeviceRequest, type DeviceAuthResult, type EpochSecondsClock } from '../http/deviceAuth.js';
import type { RouteHandler, RouteRequest, RouteResult, Router, RouterRequest } from '../http/router.js';
import { sanitisePerformance, sanitiseWarnings } from './checkin.js';
import { recordDeviceContact } from './deviceContact.js';

/** Path this route is registered on. */
export const HEARTBEAT_PATH = '/api/v1/devices/{deviceId}/heartbeat';

/** The largest heartbeat body accepted, in bytes. A larger one is refused unread. */
export const MAX_HEARTBEAT_BODY_BYTES = 16384;

/** The most network adapters stored from one heartbeat. */
export const MAX_HEARTBEAT_NETWORK_ADAPTERS = 8;

/** The longest network adapter name stored; a longer one is cut. */
export const MAX_NETWORK_ADAPTER_NAME_LENGTH = 128;

/** `2026-10-02T07:15:00Z` -- the only timestamp shape the contract accepts. */
const ISO_UTC_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

/** One heartbeat as written to, and read back from, CloudWatch Logs. */
export interface HeartbeatEvent {
  deviceId: string;
  /** When the agent took the sample, as it reported it. */
  collectedAt: string;
  /** When the backend received it, `isoUtc`; also the log event's timestamp. */
  receivedAt: string;
  performance: AnalyticsPerformance;
  /** Absent when the agent sent no `network` array. */
  network?: HeartbeatNetworkAdapter[];
  /** Absent when no string warning remains after sanitising. */
  warnings?: string[];
}

/** The per-device heartbeat store: one CloudWatch Logs stream per device. */
export interface HeartbeatLog {
  /** Append one event to the device's stream, creating the stream on first use. */
  write(deviceId: string, event: HeartbeatEvent): Promise<void>;
  /** The newest `limit` events of the device's stream, newest first; `[]` when there is no stream. */
  read(deviceId: string, limit: number): Promise<Record<string, unknown>[]>;
}

/**
 * The storage operations this route needs. `get` and `putIfAbsent` serve
 * `verifyDeviceRequest` (profile read, nonce burn) and the `HEARTBEAT` read;
 * `update` only refreshes the device's last-seen and `lastHeartbeatAt`.
 */
export interface HeartbeatTable {
  get(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
  putIfAbsent(item: Item, fields?: RequestFields): Promise<WriteOutcome>;
  update(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
}

/** Current time: integer epoch seconds, or any instant a `Date` can be built from. */
export type HeartbeatClock = () => number | string | Date;

/** The authenticator this route calls; injectable so tests need no signed request. */
export type DeviceVerifier = (
  req: RouterRequest,
  options: { table: HeartbeatTable; now: EpochSecondsClock; pepper: string },
) => Promise<DeviceAuthResult>;

/** The pepper key, or anything that resolves it (a `PepperProvider` fits). */
export type PepperSource = string | (() => string | Promise<string>);

export interface HeartbeatDependencies {
  /** Table client. Required; never created here. */
  table: HeartbeatTable;
  /** Current time. Defaults to the system clock, in epoch seconds. */
  now?: HeartbeatClock;
  /** The 64-character hex pepper key, or `getPepper`. Unused when `verifyDevice` is injected. */
  pepper?: PepperSource;
  /** Overrides the device authenticator; defaults to `verifyDeviceRequest`. */
  verifyDevice?: DeviceVerifier;
  /** The CloudWatch Logs store. Absent when `HEARTBEAT_LOG_GROUP` is not configured. */
  heartbeatLog?: HeartbeatLog;
}

/** Dependencies, or something that resolves them when the request arrives. */
export type HeartbeatDependencySource =
  | HeartbeatDependencies
  | (() => HeartbeatDependencies | Promise<HeartbeatDependencies>);

function failure(statusCode: number, error: string, extra?: Record<string, unknown>): RouteResult {
  return { statusCode, body: { error, ...(extra ?? {}) } };
}

/** True for a plain JSON object: not a primitive, not null, not an array. */
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

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

async function resolvePepper(pepper: PepperSource | undefined): Promise<string> {
  if (pepper === undefined) {
    return '';
  }
  return typeof pepper === 'function' ? await pepper() : pepper;
}

/** The posted body as an object; `undefined` when it is absent or not JSON object text. */
function parseBody(body: string | null): Record<string, unknown> | undefined {
  if (typeof body !== 'string' || body.length === 0) {
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return undefined;
  }
  return isObject(parsed) ? parsed : undefined;
}

/** Every missing or wrong field of the body, in the order `collectedAt`, `performance`. */
function offendingFields(body: Record<string, unknown> | undefined): string[] {
  if (body === undefined) {
    return ['collectedAt', 'performance'];
  }
  const fields: string[] = [];
  const collectedAt = body.collectedAt;
  if (
    typeof collectedAt !== 'string' ||
    !ISO_UTC_PATTERN.test(collectedAt) ||
    Number.isNaN(Date.parse(collectedAt))
  ) {
    fields.push('collectedAt');
  }
  if (!isObject(body.performance)) {
    fields.push('performance');
  }
  return fields;
}

/** A non-negative safe integer, else `null`. */
function counter(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

/** A finite number within `[0, max]`, else `null`. */
function nonNegative(value: unknown, max = Number.MAX_VALUE): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= max ? value : null;
}

/**
 * A reported `network` block reduced to what may be stored: `undefined` when
 * it is not an array; otherwise its first `MAX_HEARTBEAT_NETWORK_ADAPTERS`
 * entries, dropping any that is not an object or has no string name, with
 * every wrong-typed or out-of-range value `null`.
 */
export function sanitiseNetwork(reported: unknown): HeartbeatNetworkAdapter[] | undefined {
  if (!Array.isArray(reported)) {
    return undefined;
  }
  const kept: HeartbeatNetworkAdapter[] = [];
  for (const entry of reported.slice(0, MAX_HEARTBEAT_NETWORK_ADAPTERS)) {
    if (!isObject(entry) || typeof entry.name !== 'string' || entry.name.trim().length === 0) {
      continue;
    }
    const linkSpeed = counter(entry.linkSpeedBitsPerSecond);
    kept.push({
      name: entry.name.trim().slice(0, MAX_NETWORK_ADAPTER_NAME_LENGTH),
      linkSpeedBitsPerSecond: linkSpeed === 0 ? null : linkSpeed,
      receiveBitsPerSecond: counter(entry.receiveBitsPerSecond),
      sendBitsPerSecond: counter(entry.sendBitsPerSecond),
      utilizationPercent: nonNegative(entry.utilizationPercent, 100),
      packetsReceivedPerSecond: nonNegative(entry.packetsReceivedPerSecond),
      packetsSentPerSecond: nonNegative(entry.packetsSentPerSecond),
      receiveErrors: counter(entry.receiveErrors),
      sendErrors: counter(entry.sendErrors),
      receiveDiscards: counter(entry.receiveDiscards),
      sendDiscards: counter(entry.sendDiscards),
    });
  }
  return kept;
}

/** A thrown value's `name` when it is a non-empty string (e.g. `AccessDeniedException`), else `unknown`. */
function errorName(error: unknown): string {
  const name = typeof error === 'object' && error !== null ? (error as { name?: unknown }).name : undefined;
  return typeof name === 'string' && name.length > 0 ? name : 'unknown';
}

/** The `lastHeartbeatAt` update expression, issued after a heartbeat is stored. */
export const LAST_HEARTBEAT_UPDATE_EXPRESSION = 'SET lastHeartbeatAt = :lastHeartbeatAt';

/**
 * Record on the device profile when a heartbeat was last stored. Conditional on
 * the profile existing, so a device deleted mid-request gets no stub profile.
 * Never throws: a failed condition is ignored silently, any other error is one
 * `console.warn` line, and the heartbeat is still answered 200.
 */
async function recordLastHeartbeat(table: HeartbeatTable, deviceId: string, at: Date): Promise<void> {
  try {
    await table.update(deviceProfile(deviceId), {
      UpdateExpression: LAST_HEARTBEAT_UPDATE_EXPRESSION,
      ConditionExpression: 'attribute_exists(pk)',
      ExpressionAttributeValues: { ':lastHeartbeatAt': isoUtc(at) },
    });
  } catch (error) {
    if (typeof error === 'object' && error !== null && (error as { name?: unknown }).name === CONDITIONAL_CHECK_FAILED) {
      return;
    }
    console.warn(JSON.stringify({ msg: 'last-heartbeat update failed', deviceId }));
  }
}

/**
 * True only when the stored `HEARTBEAT` item says `heartbeatEnabled === true`
 * and its `intervalSeconds` is one of `HEARTBEAT_INTERVAL_OPTIONS_SECONDS`.
 * A missing item, a string or numeric flag, or any other interval is off.
 */
export function isHeartbeatEnabled(item: Item | undefined | null): boolean {
  if (item === undefined || item === null) {
    return false;
  }
  return (
    item.heartbeatEnabled === true &&
    typeof item.intervalSeconds === 'number' &&
    HEARTBEAT_INTERVAL_OPTIONS_SECONDS.includes(item.intervalSeconds)
  );
}

/**
 * Build the heartbeat route handler.
 *
 * @param source the dependencies, or a function resolving them on first use
 */
export function createHeartbeatHandler(source: HeartbeatDependencySource): RouteHandler {
  async function dependencies(): Promise<HeartbeatDependencies> {
    return typeof source === 'function' ? await source() : source;
  }

  return async function handleHeartbeat(req: RouteRequest): Promise<RouteResult> {
    const deps = await dependencies();
    const clock: HeartbeatClock = deps.now ?? ((): number => Math.floor(Date.now() / 1000));
    const nowSeconds: EpochSecondsClock = () => Math.floor(toDate(clock()).getTime() / 1000);

    // 1. The size of the payload, before it is parsed or authenticated.
    const raw = req?.body ?? null;
    if (raw !== null && Buffer.byteLength(raw, 'utf8') > MAX_HEARTBEAT_BODY_BYTES) {
      return failure(413, 'payload_too_large');
    }

    // 2. The signed device.
    const verifyDevice: DeviceVerifier = deps.verifyDevice ?? verifyDeviceRequest;
    const auth = await verifyDevice(req, {
      table: deps.table,
      now: nowSeconds,
      pepper: await resolvePepper(deps.pepper),
    });
    if (!auth.ok) {
      return { statusCode: auth.status, body: auth.body };
    }

    // 3. That it is the device the path names.
    if (auth.deviceId !== (req.params?.deviceId ?? '')) {
      return failure(403, 'device_mismatch');
    }
    const deviceId = auth.deviceId;

    // 4. The body, reporting every offending field at once.
    const body = parseBody(raw);
    const fields = offendingFields(body);
    if (fields.length > 0) {
      return failure(400, 'invalid_request', { fields });
    }
    const posted = body as Record<string, unknown>;

    // The admin's per-device switch: off drops the sample and tells the agent to stop.
    const setting = await deps.table.get(deviceHeartbeatSettings(deviceId));
    if (!isHeartbeatEnabled(setting)) {
      await recordDeviceContact(deps.table, deviceId, toDate(clock()));
      const off: HeartbeatResponse = { heartbeatIntervalSeconds: 0 };
      return { statusCode: 200, body: off };
    }
    const intervalSeconds = (setting as Item).intervalSeconds as number;

    if (deps.heartbeatLog === undefined) {
      return failure(503, 'heartbeat_not_configured');
    }

    const event: HeartbeatEvent = {
      deviceId,
      collectedAt: posted.collectedAt as string,
      receivedAt: isoUtc(toDate(clock())),
      performance: sanitisePerformance(posted.performance),
    };
    const network = sanitiseNetwork(posted.network);
    if (network !== undefined) {
      event.network = network;
    }
    const warnings = sanitiseWarnings(posted.warnings);
    if (warnings !== undefined) {
      event.warnings = warnings;
    }

    try {
      await deps.heartbeatLog.write(deviceId, event);
    } catch (error) {
      console.warn(JSON.stringify({ msg: 'heartbeat write failed', deviceId, error: errorName(error) }));
      return failure(503, 'heartbeat_store_unavailable');
    }

    const contactAt = toDate(clock());
    await recordDeviceContact(deps.table, deviceId, contactAt);
    await recordLastHeartbeat(deps.table, deviceId, contactAt);
    const on:HeartbeatResponse = { heartbeatIntervalSeconds: intervalSeconds };
    return { statusCode: 200, body: on };
  };
}

/** Register the route on a router. Returns the router, so calls chain. */
export function registerHeartbeatRoute(router: Router, source: HeartbeatDependencySource): Router {
  return router.add('POST', HEARTBEAT_PATH, createHeartbeatHandler(source));
}

/**
 * Dependencies supplied at start-up by `bootstrap`, so no AWS client is
 * constructed at import time.
 */
let configuredDependencies: HeartbeatDependencies | null = null;

/** Supply the heartbeat route's storage, clock, pepper and CloudWatch log. */
export function configureHeartbeatRoute(dependencies: HeartbeatDependencies): void {
  configuredDependencies = dependencies;
}

/** The configured dependencies, or a thrown error when start-up skipped them. */
export function resolveHeartbeatDependencies(): HeartbeatDependencies {
  if (configuredDependencies === null) {
    throw new Error('heartbeat route is not configured: call configureHeartbeatRoute() at start-up');
  }
  return configuredDependencies;
}
