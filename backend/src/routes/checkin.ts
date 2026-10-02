/**
 * `POST /api/v1/devices/{deviceId}/checkin` -- the agent's heartbeat.
 *
 * One request carries everything the agent collected: a top-level `collectedAt`
 * plus an `inventory` and a `posture` object (the shapes frozen in
 * `src/contract/types.ts` and produced by `agent/internal/inventory` and
 * `agent/internal/posture`). The backend stores the latest snapshot of each
 * under the device's `INVENTORY` and `POSTURE` sort keys, refreshes the
 * profile's last-seen index entry, and answers with the polling interval and
 * the number of commands waiting to be leased.
 *
 *   registerCheckInRoute(router, { table, pepper });
 *
 * Every dependency -- the table client, the clock and the authenticator -- is
 * injected, so tests drive this handler with fakes and nothing opens a
 * DynamoDB connection.
 *
 * The reject checks run in a fixed order and the first failure returns
 * immediately, having written nothing:
 *
 *   1. raw body <= MAX_BODY_BYTES -> 413 payload_too_large (before authentication,
 *      so an oversized body is never parsed or signed-checked)
 *   2. `verifyDeviceRequest`       -> its own `{status, body}`, unchanged
 *   3. path device == signed device-> 403 device_mismatch
 *   4. body valid                  -> 400 invalid_request, naming every bad field
 *
 * The mismatch is settled before the body is validated, so a request about
 * another device is refused as such whatever its payload looks like.
 *
 * Two things this route deliberately does not do. It stores nothing from
 * `policyCompliance` -- that field is accepted so an agent reporting it is not
 * refused, and is ingested by the policy-compliance ticket. And it returns no
 * policy information: resolving a device's policies belongs to
 * `GET /api/v1/devices/{deviceId}/policies`.
 *
 * Time units: `now()` yields integer epoch *seconds*, the unit
 * `verifyDeviceRequest` signs with (a `Date` or an ISO-8601 string is accepted
 * too). `lastSeenAt` is that server instant rendered ISO-8601 UTC -- never the
 * agent-supplied `collectedAt`, which is copied onto the snapshots only.
 */
import { isoUtc } from '../audit.js';
import { DEFAULT_CHECKIN_INTERVAL_SECONDS } from '../config/intervals.js';
import type { CheckInResponse } from '../contract/types.js';
import { deviceCommand, deviceInventory, deviceListIndex, devicePosture, deviceProfile, type TableKey } from '../db/keys.js';
import type { Item, QueryPage, QueryRequest, RequestFields, WriteOutcome } from '../db/table.js';
import { verifyDeviceRequest, type DeviceAuthResult, type EpochSecondsClock } from '../http/deviceAuth.js';
import type { RouteHandler, RouteRequest, RouteResult, Router, RouterRequest } from '../http/router.js';

/** Path this route is registered on. */
export const CHECKIN_PATH = '/api/v1/devices/{deviceId}/checkin';

/** The largest check-in body accepted, in bytes. A larger one is refused unread. */
export const MAX_BODY_BYTES = 262144;

/** The most software entries one check-in may report. */
export const MAX_SOFTWARE_ENTRIES = 2000;

/** Status of a command still waiting to be leased; the only status counted. */
export const PENDING_STATUS = 'pending';

/** `2026-10-02T07:15:00Z` -- the only timestamp shape the contract accepts. */
const ISO_UTC_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

/**
 * The storage operations this route needs: the structural subset of
 * `TableClient` (see `src/db/table.ts`) a fake has to implement. `putIfAbsent`
 * is here only because `verifyDeviceRequest` burns a nonce with it.
 */
export interface CheckInTable {
  get(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
  put(item: Item, fields?: RequestFields): Promise<void>;
  putIfAbsent(item: Item, fields?: RequestFields): Promise<WriteOutcome>;
  update(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
  query(request?: QueryRequest): Promise<QueryPage>;
}

/** Current time: integer epoch seconds, or any instant a `Date` can be built from. */
export type CheckInClock = () => number | string | Date;

/** The authenticator this route calls; injectable so tests need no signed request. */
export type DeviceVerifier = (
  req: RouterRequest,
  options: { table: CheckInTable; now: EpochSecondsClock; pepper: string },
) => Promise<DeviceAuthResult>;

/** The pepper key, or anything that resolves it (a `PepperProvider` fits). */
export type PepperSource = string | (() => string | Promise<string>);

export interface CheckInDependencies {
  /** Table client. Required; never created here. */
  table: CheckInTable;
  /** Current time. Defaults to the system clock, in epoch seconds. */
  now?: CheckInClock;
  /** The 64-character hex pepper key, or `getPepper`. Unused when `verifyDevice` is injected. */
  pepper?: PepperSource;
  /** Overrides the device authenticator; defaults to `verifyDeviceRequest`. */
  verifyDevice?: DeviceVerifier;
}

/** Dependencies, or something that resolves them when the request arrives. */
export type CheckInDependencySource =
  | CheckInDependencies
  | (() => CheckInDependencies | Promise<CheckInDependencies>);

function failure(statusCode: number, error: string, extra?: Record<string, unknown>): RouteResult {
  return { statusCode, body: { error, ...(extra ?? {}) } };
}

/** True for a plain JSON object: not a primitive, not null, not an array. */
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The named property as an object, or `{}` when it is anything else. */
function objectAt(source: Record<string, unknown>, name: string): Record<string, unknown> {
  const value = source[name];
  return isObject(value) ? value : {};
}

/** Drop the keys whose value is absent, so a missing field writes no attribute. */
function compact(record: Record<string, unknown>): Record<string, unknown> {
  const present: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (value !== undefined) {
      present[key] = value;
    }
  }
  return present;
}

/** The collector's `warnings`, or `undefined` when the key is absent. */
function warningsOf(source: Record<string, unknown>): string[] | undefined {
  const warnings = source.warnings;
  if (!Array.isArray(warnings)) {
    return undefined;
  }
  return warnings.filter((warning): warning is string => typeof warning === 'string');
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

/**
 * The `inventory.software` paths that are missing or wrong.
 *
 * An over-long list is reported as the list itself and its entries are not
 * walked, so one oversized check-in cannot answer with 2001 field names. The
 * key being absent is not an error here: this route names only the failures
 * the contract pins, and stores an empty list instead.
 */
function softwareFields(inventory: Record<string, unknown>): string[] {
  const software = inventory.software;
  if (software === undefined || software === null) {
    return [];
  }
  if (!Array.isArray(software)) {
    return ['inventory.software'];
  }
  if (software.length > MAX_SOFTWARE_ENTRIES) {
    return ['inventory.software'];
  }
  const fields: string[] = [];
  software.forEach((value, index) => {
    const entry = isObject(value) ? value : {};
    if (typeof entry.name !== 'string' || entry.name.length === 0) {
      fields.push(`inventory.software[${index}].name`);
    }
    if (typeof entry.version !== 'string' || entry.version.length === 0) {
      fields.push(`inventory.software[${index}].version`);
    }
  });
  return fields;
}

/**
 * Name every field of the body that is missing or wrong, in report order.
 *
 * `policyCompliance` is not inspected: it is accepted whatever it holds and
 * nothing derived from it is ever stored.
 */
function offendingFields(body: Record<string, unknown> | undefined): string[] {
  if (body === undefined) {
    // Nothing usable arrived, so every required part is missing.
    return ['collectedAt', 'inventory', 'posture'];
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

  const inventory = body.inventory;
  if (!isObject(inventory)) {
    fields.push('inventory');
  } else {
    fields.push(...softwareFields(inventory));
  }

  if (!isObject(body.posture)) {
    fields.push('posture');
  }

  return fields;
}

async function resolvePepper(pepper: PepperSource | undefined): Promise<string> {
  if (pepper === undefined) {
    return '';
  }
  return typeof pepper === 'function' ? await pepper() : pepper;
}

/**
 * Authenticate the request and confirm it is about its own device.
 *
 * Returns the device id, or the result the route must return: an
 * authentication failure unchanged, or a 403 when the path names another
 * device. Nothing is written before this passes.
 */
async function authoriseDevice(
  req: RouteRequest,
  deps: CheckInDependencies,
  now: EpochSecondsClock,
): Promise<{ ok: true; deviceId: string } | { ok: false; result: RouteResult }> {
  const verify: DeviceVerifier = deps.verifyDevice ?? verifyDeviceRequest;
  const auth = await verify(req, {
    table: deps.table,
    now,
    pepper: await resolvePepper(deps.pepper),
  });
  if (!auth.ok) {
    return { ok: false, result: { statusCode: auth.status, body: auth.body } };
  }
  if (auth.deviceId !== (req.params?.deviceId ?? '')) {
    return { ok: false, result: failure(403, 'device_mismatch') };
  }
  return { ok: true, deviceId: auth.deviceId };
}

/** The inventory snapshot item, under the frozen field names. */
function inventoryItem(deviceId: string, collectedAt: string, inventory: Record<string, unknown>): Item {
  const hardware = objectAt(inventory, 'hardware');
  const os = objectAt(inventory, 'os');
  const software = Array.isArray(inventory.software) ? inventory.software : [];
  return compact({
    ...deviceInventory(deviceId),
    deviceId,
    collectedAt,
    hardware: compact({
      manufacturer: hardware.manufacturer,
      model: hardware.model,
      serialNumber: hardware.serialNumber,
      cpu: hardware.cpu,
      ramBytes: hardware.ramBytes,
      diskBytes: hardware.diskBytes,
    }),
    os: compact({
      name: os.name,
      version: os.version,
      build: os.build,
      architecture: os.architecture,
    }),
    software: software.map((value) => {
      const entry = isObject(value) ? value : {};
      return compact({
        name: entry.name,
        version: entry.version,
        publisher: entry.publisher,
        installedAt: entry.installedAt,
      });
    }),
    warnings: warningsOf(inventory),
  });
}

/** The security posture snapshot item, under the frozen field names. */
function postureItem(deviceId: string, collectedAt: string, posture: Record<string, unknown>): Item {
  const diskEncryption = objectAt(posture, 'diskEncryption');
  const firewall = objectAt(posture, 'firewall');
  const antivirus = objectAt(posture, 'antivirus');
  const osUpdate = objectAt(posture, 'osUpdate');
  const localAdmins = Array.isArray(posture.localAdmins) ? posture.localAdmins : [];
  return compact({
    ...devicePosture(deviceId),
    deviceId,
    collectedAt,
    diskEncryption: compact({
      enabled: diskEncryption.enabled,
      method: diskEncryption.method,
    }),
    firewall: compact({ enabled: firewall.enabled }),
    antivirus: compact({
      name: antivirus.name,
      enabled: antivirus.enabled,
      definitionsAgeDays: antivirus.definitionsAgeDays,
    }),
    osUpdate: compact({
      lastCheckedAt: osUpdate.lastCheckedAt,
      pendingCount: osUpdate.pendingCount,
      rebootRequired: osUpdate.rebootRequired,
    }),
    localAdmins: localAdmins.filter((admin): admin is string => typeof admin === 'string'),
    warnings: warningsOf(posture),
  });
}

/**
 * Count this device's commands that are still waiting to be leased.
 *
 * A query on the device's own partition, never a scan, and every page of it:
 * the cursor is followed until it comes back null, so the count spans the whole
 * queue however the pages happen to fall.
 */
async function countPendingCommands(table: CheckInTable, deviceId: string): Promise<number> {
  // An empty command id yields the partition key and the `CMD#` prefix every
  // command of this device is stored under, without writing key text here.
  const { pk, sk: commandPrefix } = deviceCommand(deviceId, '');

  let pending = 0;
  let cursor: string | null = null;
  do {
    const page: QueryPage = await table.query({
      KeyConditionExpression: '#pk = :pk AND begins_with(#sk, :commandPrefix)',
      ExpressionAttributeNames: { '#pk': 'pk', '#sk': 'sk' },
      ExpressionAttributeValues: { ':pk': pk, ':commandPrefix': commandPrefix },
      cursor,
    });
    for (const item of page.items) {
      if (item.status === PENDING_STATUS) {
        pending += 1;
      }
    }
    const next = page.cursor ?? null;
    // A cursor that does not move would page forever; treat it as the end.
    cursor = next === cursor ? null : next;
  } while (cursor !== null);

  return pending;
}

/**
 * Build the check-in route handler.
 *
 * @param source the dependencies, or a function resolving them on first use
 */
export function createCheckInHandler(source: CheckInDependencySource): RouteHandler {
  async function dependencies(): Promise<CheckInDependencies> {
    return typeof source === 'function' ? await source() : source;
  }

  return async function handleCheckIn(req: RouteRequest): Promise<RouteResult> {
    const deps = await dependencies();
    const clock: CheckInClock = deps.now ?? ((): number => Math.floor(Date.now() / 1000));
    const nowSeconds: EpochSecondsClock = () => Math.floor(toDate(clock()).getTime() / 1000);

    // 1. The size of the payload, before it is parsed and before the device is
    //    authenticated: an oversized body is refused without being read.
    const raw = req?.body ?? null;
    if (raw !== null && Buffer.byteLength(raw, 'utf8') > MAX_BODY_BYTES) {
      return failure(413, 'payload_too_large');
    }

    // 2. The signed device, and 3. that it is the device the path names.
    const authorised = await authoriseDevice(req, deps, nowSeconds);
    if (!authorised.ok) {
      return authorised.result;
    }
    const deviceId = authorised.deviceId;

    // 4. The body, reporting every offending field at once.
    const body = parseBody(raw);
    const fields = offendingFields(body);
    if (fields.length > 0) {
      return failure(400, 'invalid_request', { fields });
    }
    // Every part is now known to be present and of the contract's shape.
    const posted = body as Record<string, unknown>;
    const collectedAt = posted.collectedAt as string;

    // The snapshots carry the agent's collection time; the profile carries ours.
    await deps.table.put(inventoryItem(deviceId, collectedAt, objectAt(posted, 'inventory')));
    await deps.table.put(postureItem(deviceId, collectedAt, objectAt(posted, 'posture')));

    const lastSeenAt = isoUtc(toDate(clock()));
    const { gsi1pk, gsi1sk } = deviceListIndex(lastSeenAt);
    await deps.table.update(deviceProfile(deviceId), {
      UpdateExpression: 'SET lastSeenAt = :lastSeenAt, gsi1pk = :gsi1pk, gsi1sk = :gsi1sk',
      ExpressionAttributeValues: {
        ':lastSeenAt': lastSeenAt,
        ':gsi1pk': gsi1pk,
        ':gsi1sk': gsi1sk,
      },
    });

    const responseBody: CheckInResponse = {
      checkInIntervalSeconds: DEFAULT_CHECKIN_INTERVAL_SECONDS,
      pendingCommandCount: await countPendingCommands(deps.table, deviceId),
    };
    return { statusCode: 200, body: responseBody };
  };
}

/** Register the route on a router. Returns the router, so calls chain. */
export function registerCheckInRoute(router: Router, source: CheckInDependencySource): Router {
  return router.add('POST', CHECKIN_PATH, createCheckInHandler(source));
}

/**
 * Dependencies supplied at start-up.
 *
 * Nothing in this package constructs an AWS client, so the route is registered
 * at import time and the deployment hands it a table client and a pepper
 * provider by calling `configureCheckInRoute` before the first request.
 */
let configured: CheckInDependencies | null = null;

/** Supply the check-in route's storage, clock and pepper. */
export function configureCheckInRoute(dependencies: CheckInDependencies): void {
  configured = dependencies;
}

/** The configured dependencies, or a thrown error when start-up skipped them. */
export function resolveCheckInDependencies(): CheckInDependencies {
  if (configured === null) {
    throw new Error('check-in route is not configured: call configureCheckInRoute() at start-up');
  }
  return configured;
}
