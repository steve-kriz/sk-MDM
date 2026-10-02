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
 * `policyCompliance` is ingested here when the body carries it: one result item
 * per entry naming a policy actually assigned to this device, after which the
 * profile's `complianceState` is recomputed from everything stored (see
 * `src/policies/resolve.ts`). An entry naming a policy the device does not hold
 * is dropped, so a stale or mistaken agent can never move a device's state over
 * a policy that was never its business. The field is still optional: a check-in
 * without it stores no result and leaves `complianceState` exactly as it was.
 *
 * The response is also where the fleet is moved onto a new agent build. When a
 * release is published for the device's platform and architecture, and its
 * version differs from the one the device is on, the answer carries an
 * `agentRelease` the agent downloads, verifies and swaps itself for. The
 * version the device is on is the optional top-level `agentVersion` the body
 * reported, which is written onto the profile, falling back to what an earlier
 * check-in recorded there. Nothing is read when the reported architecture is
 * not one a build is published for.
 *
 * What this route does not do is return policy information: resolving a
 * device's policies belongs to `GET /api/v1/devices/{deviceId}/policies`.
 *
 * Time units: `now()` yields integer epoch *seconds*, the unit
 * `verifyDeviceRequest` signs with (a `Date` or an ISO-8601 string is accepted
 * too). `lastSeenAt` is that server instant rendered ISO-8601 UTC -- never the
 * agent-supplied `collectedAt`, which is copied onto the snapshots only.
 */
import { isoUtc } from '../audit.js';
import { DEFAULT_CHECKIN_INTERVAL_SECONDS } from '../config/intervals.js';
import type { AgentRelease, CheckInResponse } from '../contract/types.js';
import {
  agentRelease as agentReleaseKey,
  deviceAntivirusFinding,
  deviceCommand,
  deviceCompliance,
  deviceInventory,
  deviceListIndex,
  devicePosture,
  deviceProfile,
  type TableKey,
} from '../db/keys.js';
import type { Item, QueryPage, QueryRequest, RequestFields, WriteOutcome } from '../db/table.js';
import { verifyDeviceRequest, type DeviceAuthResult, type EpochSecondsClock } from '../http/deviceAuth.js';
import type { RouteHandler, RouteRequest, RouteResult, Router, RouterRequest } from '../http/router.js';
import {
  computeComplianceState,
  readAssignedPolicyIds,
  readComplianceResults,
} from '../policies/resolve.js';

/** Path this route is registered on. */
export const CHECKIN_PATH = '/api/v1/devices/{deviceId}/checkin';

/** The largest check-in body accepted, in bytes. A larger one is refused unread. */
export const MAX_BODY_BYTES = 262144;

/** The most software entries one check-in may report. */
export const MAX_SOFTWARE_ENTRIES = 2000;

/** Status of a command still waiting to be leased; the only status counted. */
export const PENDING_STATUS = 'pending';

/**
 * What the architectures a device may report are called in a release platform
 * key. A device reporting anything else is offered no build at all: an update
 * is only ever advertised when the published binary is known to run on it.
 */
export const ARCHITECTURE_ALIASES: Record<string, string> = {
  amd64: 'amd64',
  x86_64: 'amd64',
  arm64: 'arm64',
  aarch64: 'arm64',
};

/** The most antivirus findings one check-in may report; later entries are ignored. */
export const MAX_ANTIVIRUS_FINDINGS = 20;

/** The most resources stored per antivirus finding. */
export const MAX_FINDING_RESOURCES = 3;

/** The longest stored resource of an antivirus finding, in characters. */
export const MAX_RESOURCE_LENGTH = 260;

/** The longest stored antivirus threat name, in characters. */
export const MAX_THREAT_NAME_LENGTH = 256;

/** The longest antivirus finding id accepted, in characters. */
export const MAX_FINDING_ID_LENGTH = 128;

/** The severities an antivirus finding may carry; anything else is stored as `unknown`. */
const FINDING_SEVERITIES = new Set(['unknown', 'low', 'moderate', 'high', 'severe']);

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
 * `policyCompliance` is not inspected: a check-in is never refused over what it
 * reported about its policies. Whatever it holds is filtered when it is
 * ingested, so a malformed entry is dropped rather than rejecting the heartbeat
 * the rest of the body carries.
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
 * Store the antivirus threat detections the agent reported, one item per
 * finding.
 *
 * A check-in is never refused over its findings: a value that is not an array
 * stores nothing, only the first `MAX_ANTIVIRUS_FINDINGS` entries are looked
 * at, and an entry without a usable id, threat name or detection time is
 * dropped. What is kept is clamped to the contract's bounds. A finding reported
 * again keeps the `firstReportedAt` of its first report; every other field
 * takes the latest report's value. Findings never touch `complianceState`.
 */
async function recordAntivirusFindings(
  table: CheckInTable,
  deviceId: string,
  reported: unknown,
  at: Date,
): Promise<void> {
  if (!Array.isArray(reported)) {
    return;
  }

  const reportedAt = isoUtc(at);
  for (const entry of reported.slice(0, MAX_ANTIVIRUS_FINDINGS)) {
    if (!isObject(entry)) {
      continue;
    }
    const { findingId, threatName, detectedAt } = entry;
    if (
      typeof findingId !== 'string' ||
      findingId.length === 0 ||
      findingId.length > MAX_FINDING_ID_LENGTH ||
      typeof threatName !== 'string' ||
      threatName.length === 0 ||
      typeof detectedAt !== 'string' ||
      !ISO_UTC_PATTERN.test(detectedAt)
    ) {
      continue;
    }
    let key: TableKey;
    try {
      key = deviceAntivirusFinding(deviceId, findingId);
    } catch {
      // A finding id carrying the key separator cannot be stored.
      continue;
    }

    const existing = await table.get(key);
    const firstReportedAt =
      typeof existing?.firstReportedAt === 'string' ? existing.firstReportedAt : reportedAt;
    const severity =
      typeof entry.severity === 'string' && FINDING_SEVERITIES.has(entry.severity)
        ? entry.severity
        : 'unknown';
    const resources = Array.isArray(entry.resources)
      ? entry.resources
          .filter((resource): resource is string => typeof resource === 'string')
          .slice(0, MAX_FINDING_RESOURCES)
          .map((resource) => resource.slice(0, MAX_RESOURCE_LENGTH))
      : [];

    await table.put({
      ...key,
      deviceId,
      findingId,
      threatName: threatName.slice(0, MAX_THREAT_NAME_LENGTH),
      severity,
      detectedAt,
      resources,
      // Anything that is not an explicit `true` is not known to be remediated.
      remediated: entry.remediated === true,
      firstReportedAt,
      lastReportedAt: reportedAt,
    });
  }
}

/**
 * Store what the agent reported about its policies, then settle the device's
 * compliance state.
 *
 * Only policies the device actually holds are stored: the assigned set is read
 * first and an entry outside it is dropped silently, so an agent reporting on a
 * policy that was unassigned between its last bundle and this check-in neither
 * writes an orphan item nor moves the device's state.
 *
 * The state is recomputed from everything stored rather than from this report
 * alone, so a check-in that mentions one of three policies cannot look like a
 * clean bill of health. A check-in carrying no `policyCompliance` array at all
 * leaves every compliance item and the stored state untouched.
 */
async function recordPolicyCompliance(
  table: CheckInTable,
  deviceId: string,
  reported: unknown,
  at: Date,
): Promise<void> {
  if (!Array.isArray(reported)) {
    return;
  }

  const assignedPolicyIds = await readAssignedPolicyIds(table, deviceId);
  const assigned = new Set(assignedPolicyIds);
  const reportedAt = isoUtc(at);

  for (const entry of reported) {
    if (!isObject(entry)) {
      continue;
    }
    const policyId = typeof entry.policyId === 'string' ? entry.policyId : '';
    if (!assigned.has(policyId)) {
      continue;
    }
    let key: TableKey;
    try {
      key = deviceCompliance(deviceId, policyId);
    } catch {
      continue;
    }
    await table.put({
      ...key,
      deviceId,
      policyId,
      version: typeof entry.version === 'number' ? entry.version : 0,
      // Anything that is not an explicit `true` is a device we cannot vouch for.
      compliant: entry.compliant === true,
      violations: Array.isArray(entry.violations)
        ? entry.violations.filter((violation): violation is string => typeof violation === 'string')
        : [],
      reportedAt,
    });
  }

  const complianceState = computeComplianceState(
    assignedPolicyIds,
    await readComplianceResults(table, deviceId),
  );
  await table.update(deviceProfile(deviceId), {
    UpdateExpression: 'SET complianceState = :complianceState',
    ExpressionAttributeValues: { ':complianceState': complianceState },
  });
}

/** The agent version the body reported, or `undefined` when it carried none. */
function postedAgentVersion(posted: Record<string, unknown>): string | undefined {
  const version = posted.agentVersion;
  return typeof version === 'string' && version.length > 0 ? version : undefined;
}

/**
 * The release platform architecture for what the inventory reported, or `null`
 * when it is not an architecture a build is published for.
 */
function releaseArchitecture(posted: Record<string, unknown>): string | null {
  const reported = objectAt(objectAt(posted, 'inventory'), 'os').architecture;
  if (typeof reported !== 'string') {
    return null;
  }
  return ARCHITECTURE_ALIASES[reported.trim().toLowerCase()] ?? null;
}

/**
 * The build this device should move to, or `undefined` when it is already on
 * the published one, when none is published for its platform, or when its
 * architecture is not one a build is published for.
 *
 * The architecture is settled first, so a device nothing could be published for
 * costs no read at all. The version the device is on is what it just reported,
 * falling back to what the profile recorded at its last check-in: an agent old
 * enough not to report its version is still moved forward.
 */
async function resolveAgentRelease(
  table: CheckInTable,
  deviceId: string,
  posted: Record<string, unknown>,
): Promise<AgentRelease | undefined> {
  const architecture = releaseArchitecture(posted);
  if (architecture === null) {
    return undefined;
  }

  const profile = await table.get(deviceProfile(deviceId));
  const platform = typeof profile?.platform === 'string' ? profile.platform : '';
  let key: TableKey;
  try {
    key = agentReleaseKey(`${platform}-${architecture}`);
  } catch {
    // A platform no build is published for: nothing to advertise.
    return undefined;
  }

  const release = await table.get(key);
  const version = typeof release?.version === 'string' ? release.version : '';
  if (version === '') {
    return undefined;
  }

  const profileVersion = typeof profile?.agentVersion === 'string' ? profile.agentVersion : '';
  const current = postedAgentVersion(posted) ?? profileVersion;
  if (version === current) {
    return undefined;
  }

  return {
    version,
    url: typeof release?.url === 'string' ? release.url : '',
    sha256: typeof release?.sha256 === 'string' ? release.sha256 : '',
  };
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

    const at = toDate(clock());
    const lastSeenAt = isoUtc(at);
    const { gsi1pk, gsi1sk } = deviceListIndex(lastSeenAt);
    // The build the agent reported is recorded on the profile, so the next
    // check-in still knows what it is running even if that one reports nothing.
    const agentVersion = postedAgentVersion(posted);
    await deps.table.update(deviceProfile(deviceId), {
      UpdateExpression:
        'SET lastSeenAt = :lastSeenAt, gsi1pk = :gsi1pk, gsi1sk = :gsi1sk' +
        (agentVersion === undefined ? '' : ', agentVersion = :agentVersion'),
      ExpressionAttributeValues: compact({
        ':lastSeenAt': lastSeenAt,
        ':gsi1pk': gsi1pk,
        ':gsi1sk': gsi1sk,
        ':agentVersion': agentVersion,
      }),
    });

    // Whatever the agent evaluated against the bundle it last pulled.
    await recordPolicyCompliance(deps.table, deviceId, posted.policyCompliance, at);

    // Threat detections are stored for the admin; they never move compliance.
    await recordAntivirusFindings(deps.table, deviceId, posted.antivirusFindings, at);

    const release = await resolveAgentRelease(deps.table, deviceId, posted);

    const responseBody: CheckInResponse = {
      checkInIntervalSeconds: DEFAULT_CHECKIN_INTERVAL_SECONDS,
      pendingCommandCount: await countPendingCommands(deps.table, deviceId),
    };
    if (release !== undefined) {
      responseBody.agentRelease = release;
    }
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
