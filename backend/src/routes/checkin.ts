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
 * release is published for the device's platform and architecture -- a raw
 * binary in the installer bucket or a hand-written `AGENTRELEASE` record, the
 * higher version winning -- and its version is strictly newer than the one the
 * device is on, the answer carries an `agentRelease` the agent downloads,
 * verifies and swaps itself for. The
 * version the device is on is the optional top-level `agentVersion` the body
 * reported, which is written onto the profile, falling back to what an earlier
 * check-in recorded there. Nothing is read when the reported architecture is
 * not one a build is published for.
 *
 * While the device's effective `locationTracking` policy setting is `true`, an
 * accepted check-in also records a coarse IP-based location from the
 * CloudFront viewer headers at most once per 24 h (`src/location/capture.ts`);
 * a failure there is logged and never changes the response.
 *
 * What this route does not do is return policy information: resolving a
 * device's policies belongs to `GET /api/v1/devices/{deviceId}/policies`.
 *
 * Time units: `now()` yields integer epoch *seconds*, the unit
 * `verifyDeviceRequest` signs with (a `Date` or an ISO-8601 string is accepted
 * too). `lastSeenAt` is that server instant rendered ISO-8601 UTC -- never the
 * agent-supplied `collectedAt`, which is copied onto the snapshots only.
 */
import { createHash } from 'node:crypto';
import { isoUtc } from '../audit.js';
import { recordDeviceEvent } from '../deviceEvents.js';
import { recordSoftwareChanges } from '../softwareChanges.js';
import { DEFAULT_CHECKIN_INTERVAL_SECONDS, HEARTBEAT_INTERVAL_OPTIONS_SECONDS } from '../config/intervals.js';
import type { AgentRelease, CheckInResponse } from '../contract/types.js';
import {
  agentRelease as agentReleaseKey,
  analyticsListIndex,
  appCrashListIndex,
  deviceAgentError,
  deviceAnalytics,
  deviceAntivirusFinding,
  deviceAntivirusScan,
  deviceAntivirusStatus,
  deviceAppCrash,
  deviceBootHistory,
  deviceCommand,
  deviceCompliance,
  deviceDefenderHardening,
  deviceHeartbeatSettings,
  deviceInventory,
  deviceListIndex,
  devicePosture,
  deviceProfile,
  deviceSettings,
  inventoryListIndex,
  type TableKey,
} from '../db/keys.js';
import type { Item, QueryPage, QueryRequest, RequestFields, WriteOutcome } from '../db/table.js';
import { verifyDeviceRequest, type DeviceAuthResult, type EpochSecondsClock } from '../http/deviceAuth.js';
import type { RouteHandler, RouteRequest, RouteResult, Router, RouterRequest } from '../http/router.js';
import { agentBuildKey, type InstallerStore } from './downloads.js';
import { captureLocation } from '../location/capture.js';
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

/**
 * How long the presigned URL of an advertised S3 agent build stays valid, in
 * seconds. The agent downloads in the same cycle, right after the response.
 */
export const AGENT_BUILD_URL_TTL_SECONDS = 900;

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

/** The threat statuses an antivirus finding may carry; any other string is stored as `unknown`. */
const FINDING_STATUSES = new Set([
  'unknown',
  'detected',
  'cleaned',
  'quarantined',
  'removed',
  'allowed',
  'blocked',
  'quarantine_failed',
  'remove_failed',
  'allow_failed',
  'abandoned',
  'block_failed',
]);

/** The cleaning actions an antivirus finding may carry; any other string is stored as `unknown`. */
const FINDING_ACTIONS = new Set([
  'unknown',
  'clean',
  'quarantine',
  'remove',
  'allow',
  'user_defined',
  'no_action',
  'block',
]);

/** The longest stored antivirus finding `category`, in characters. */
export const MAX_FINDING_CATEGORY_LENGTH = 64;

/** The longest stored antivirus finding `processName`, in characters. */
export const MAX_FINDING_PROCESS_NAME_LENGTH = 260;

/** The longest stored antivirus finding `user`, in characters. */
export const MAX_FINDING_USER_LENGTH = 256;

/** The longest stored antivirus status `runningMode` or `versions.*`, in characters. */
export const MAX_AV_VERSION_LENGTH = 64;

/** The longest stored antivirus status `product` or Security Center product name, in characters. */
export const MAX_AV_PRODUCT_NAME_LENGTH = 128;

/** The most Security Center products stored per antivirus status. */
export const MAX_SECURITY_CENTER_PRODUCTS = 10;

/** The largest stored antivirus signature or scan age, in days. */
export const MAX_AV_AGE_DAYS = 36500;

/** The largest stored Defender `computerState`. */
export const MAX_COMPUTER_STATE = 65535;

/** The states a Security Center product may carry; anything else is stored as `unknown`. */
const SECURITY_CENTER_STATES = new Set(['on', 'off', 'snoozed', 'expired', 'unknown']);

/** The results a reported antivirus scan may carry; anything else makes it invalid. */
const ANTIVIRUS_SCAN_RESULTS = new Set(['clean', 'threats_found', 'failed', 'timeout', 'unsupported']);

/** The most threats a reported antivirus scan may claim to have found. */
export const MAX_SCAN_THREATS_FOUND = 1000000;

/** The longest stored antivirus scan `detail`, in characters. */
export const MAX_SCAN_DETAIL_LENGTH = 256;

/** The most application crash/hang events one check-in may report; later entries are ignored. */
export const MAX_APP_CRASHES = 50;

/** The longest stored crash `appName`, in characters. */
export const MAX_APP_NAME_LENGTH = 256;

/** The longest stored crash `appVersion`, in characters. */
export const MAX_APP_VERSION_LENGTH = 128;

/** The most boots kept in a device's boot history. */
export const MAX_BOOT_HISTORY = 30;

/** How long a crash event is kept, in seconds (30 days); older reports are dropped. */
export const APP_CRASH_RETENTION_SECONDS = 2592000;

/** How far past server now a crash `occurredAt` may lie, in seconds, before it is dropped. */
export const APP_CRASH_FUTURE_SKEW_SECONDS = 86400;

/** How long an agent error item is kept past its `lastSeenAt`, in seconds (30 days); older reports are dropped. */
export const AGENT_ERROR_RETENTION_SECONDS = 2592000;

/** How far past server now an agent error `lastAt` may lie, in seconds, before it is dropped. */
export const AGENT_ERROR_FUTURE_SKEW_SECONDS = 86400;

/** The most `agentErrors` entries one check-in may carry; any beyond are ignored. */
export const MAX_AGENT_ERRORS = 50;

/** The most fields kept on one agent error entry. */
export const MAX_AGENT_ERROR_FIELDS = 8;

/** The longest stored agent error `message` or field value, in characters. */
export const MAX_AGENT_ERROR_VALUE_LENGTH = 256;

/** The longest stored agent error `component` or field key, in characters. */
export const MAX_AGENT_ERROR_KEY_LENGTH = 64;

/** The largest `count` stored from one agent error entry. */
export const MAX_AGENT_ERROR_COUNT = 1000000;

/** The most `agentActions` entries one check-in may carry; any beyond are ignored. */
export const MAX_AGENT_ACTIONS = 20;

/** The most details kept on one agent action. */
export const MAX_AGENT_ACTION_DETAILS = 8;

/** The longest stored agent action detail key, in characters. */
export const MAX_AGENT_ACTION_KEY_LENGTH = 64;

/** The longest stored agent action detail value, in characters. */
export const MAX_AGENT_ACTION_VALUE_LENGTH = 256;

/** How far before server now an agent action `occurredAt` may lie, in seconds (30 days), before it is dropped. */
export const AGENT_ACTION_RETENTION_SECONDS = 2592000;

/** How far past server now an agent action `occurredAt` may lie, in seconds, before it is dropped. */
export const AGENT_ACTION_FUTURE_SKEW_SECONDS = 86400;

/** The agent action types a check-in may report. */
const AGENT_ACTION_TYPES: ReadonlySet<string> = new Set([
  'enforce.firewall_enabled',
  'enforce.antivirus_enabled',
  'enforce.domains_updated',
  'agent.update_rolled_back',
]);

/** The longest boot duration accepted, in seconds; anything longer is stored null. */
export const MAX_BOOT_DURATION_SECONDS = 3600;

/** The longest uptime accepted, in seconds (10 years); anything longer is stored null. */
export const MAX_UPTIME_SECONDS = 315360000;

/** The most analytics warnings stored on the snapshot. */
export const MAX_ANALYTICS_WARNINGS = 20;

/** The longest stored analytics warning, in characters. */
export const MAX_ANALYTICS_WARNING_LENGTH = 512;

/** `2026-10-02T07:15:00Z` -- the only timestamp shape the contract accepts. */
/** Longest device-detail string stored; a longer one is cut to this many characters. */
export const MAX_DETAIL_STRING_LENGTH = 256;

/** Most `inventory.disks` entries stored. */
export const MAX_DETAIL_DISKS = 32;

/** Most `inventory.physicalDisks` entries stored. */
export const MAX_DETAIL_PHYSICAL_DISKS = 16;

/** Most `inventory.network` adapters stored. */
export const MAX_DETAIL_ADAPTERS = 16;

/** Most entries stored in each of an adapter's address lists. */
export const MAX_DETAIL_ADDRESSES = 16;

const FIRMWARE_TYPES = ['uefi', 'bios'] as const;
const PHYSICAL_DISK_MEDIA_TYPES = ['ssd', 'hdd', 'scm', 'unspecified'] as const;

const ISO_UTC_PATTERN =/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

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
  /**
   * The installer store the published agent builds are read and presigned
   * through. Absent (or without `agentBuild`), only the `AGENTRELEASE` record
   * is considered.
   */
  installers?: InstallerStore;
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
 * the rest of the body carries. `antivirusFindings`, `antivirusScan`,
 * `antivirusStatus`, `defenderHardening` and `analytics` are not inspected
 * either, for the same reason.
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
    ...inventoryListIndex(deviceId),
    deviceId,
    collectedAt,
    hardware: compact({
      manufacturer: hardware.manufacturer,
      model: hardware.model,
      serialNumber: hardware.serialNumber,
      cpu: hardware.cpu,
      ramBytes: hardware.ramBytes,
      diskBytes: hardware.diskBytes,
      // Optional device details: sanitised, never refused.
      systemFamily: detailString(hardware.systemFamily),
      systemSku: detailString(hardware.systemSku),
      cpuCores: detailInteger(hardware.cpuCores),
      cpuLogicalProcessors: detailInteger(hardware.cpuLogicalProcessors),
    }),
    os: compact({
      name: os.name,
      version: os.version,
      build: os.build,
      architecture: os.architecture,
      // Optional device details: sanitised, never refused.
      edition: detailString(os.edition),
      displayVersion: detailString(os.displayVersion),
      ubr: detailInteger(os.ubr),
      installDate: detailDate(os.installDate),
      lastBootAt: detailDate(os.lastBootAt),
      locale: detailString(os.locale),
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
    firmware: detailBlock(isObject(inventory.firmware) ? sanitiseFirmware(inventory.firmware) : {}),
    disks: detailEntries(inventory.disks, MAX_DETAIL_DISKS, (disk) => ({
      deviceId: detailString(disk.deviceId),
      fileSystem: detailString(disk.fileSystem),
      sizeBytes: detailInteger(disk.sizeBytes),
      freeBytes: detailInteger(disk.freeBytes),
    })),
    physicalDisks: detailEntries(inventory.physicalDisks, MAX_DETAIL_PHYSICAL_DISKS, (disk) => ({
      model: detailString(disk.model),
      mediaType: detailEnum(disk.mediaType, PHYSICAL_DISK_MEDIA_TYPES),
      sizeBytes: detailInteger(disk.sizeBytes),
    })),
    network: detailEntries(inventory.network, MAX_DETAIL_ADAPTERS, (adapter) => ({
      description: detailString(adapter.description),
      macAddress: detailString(adapter.macAddress),
      ipv4: detailStringList(adapter.ipv4),
      ipv6: detailStringList(adapter.ipv6),
      dhcpEnabled: detailBoolean(adapter.dhcpEnabled),
      dnsServers: detailStringList(adapter.dnsServers),
      gateways: detailStringList(adapter.gateways),
    })),
    join: detailBlock(isObject(inventory.join) ? sanitiseJoin(inventory.join) : {}),
    warnings: warningsOf(inventory),
  });
}

/** The firmware block's fields, each kept only when it is of the contract's type. */
function sanitiseFirmware(firmware: Record<string, unknown>): Record<string, unknown> {
  return {
    type: detailEnum(firmware.type, FIRMWARE_TYPES),
    biosVersion: detailString(firmware.biosVersion),
    biosReleaseDate: detailDate(firmware.biosReleaseDate),
    secureBootEnabled: detailBoolean(firmware.secureBootEnabled),
    tpmPresent: detailBoolean(firmware.tpmPresent),
    tpmReady: detailBoolean(firmware.tpmReady),
    tpmVersion: detailString(firmware.tpmVersion),
  };
}

/** The join block's fields, each kept only when it is of the contract's type. */
function sanitiseJoin(join: Record<string, unknown>): Record<string, unknown> {
  return {
    azureAdJoined: detailBoolean(join.azureAdJoined),
    domainJoined: detailBoolean(join.domainJoined),
    domain: detailString(join.domain),
    tenantName: detailString(join.tenantName),
    tenantId: detailString(join.tenantId),
    entraDeviceId: detailString(join.entraDeviceId),
  };
}

/** A device-detail string: trimmed, cut to MAX_DETAIL_STRING_LENGTH, and absent when empty or not a string. */
function detailString(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim().slice(0, MAX_DETAIL_STRING_LENGTH);
  return trimmed.length > 0 ? trimmed : undefined;
}

/** A device-detail count: a safe integer >= 0, else absent. */
function detailInteger(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

/** A device-detail flag: the literal `true` or `false`, else absent. */
function detailBoolean(value: unknown): boolean | undefined {
  return value === true || value === false ? value : undefined;
}

/** A device-detail timestamp: an ISO-8601 UTC string, else absent. */
function detailDate(value: unknown): string | undefined {
  return typeof value === 'string' && ISO_UTC_PATTERN.test(value) && !Number.isNaN(Date.parse(value))
    ? value
    : undefined;
}

/** A device-detail enum value: one of `allowed`, else absent. */
function detailEnum(value: unknown, allowed: readonly string[]): string | undefined {
  return typeof value === 'string' && allowed.includes(value) ? value : undefined;
}

/** A device-detail string list: its usable strings, capped at MAX_DETAIL_ADDRESSES; absent when none. */
function detailStringList(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }
  const strings = value
    .map(detailString)
    .filter((entry): entry is string => entry !== undefined)
    .slice(0, MAX_DETAIL_ADDRESSES);
  return strings.length > 0 ? strings : undefined;
}

/** A device-detail object without its absent fields; absent itself when nothing is left. */
function detailBlock(record: Record<string, unknown>): Record<string, unknown> | undefined {
  const present = compact(record);
  return Object.keys(present).length > 0 ? present : undefined;
}

/**
 * A device-detail list: non-object entries are dropped, the first `max` objects
 * are kept and sanitised by `entry`, and an entry left with no fields is
 * dropped. Absent when the value is not an array or nothing is left.
 */
function detailEntries(
  value: unknown,
  max: number,
  entry: (item: Record<string, unknown>) => Record<string, unknown>,
): Record<string, unknown>[] | undefined {
  if (!Array.isArray(value)) {
    return undefined;
  }
  const entries = value
    .filter(isObject)
    .slice(0, max)
    .map((item) => detailBlock(entry(item)))
    .filter((item): item is Record<string, unknown> => item !== undefined);
  return entries.length > 0 ? entries : undefined;
}

/**
 * The friendly OS name the console shows, built from the check-in's
 * `inventory.os`, e.g. "Windows 11 Enterprise 23H2 (build 22631.4317)" or
 * "macOS 14.5 (build 23F79)". `null` when the OS has no name.
 *
 * Windows 11 still reports itself as "Windows 10" in some places, so a
 * "Windows 10" name on build 22000 or later is shown as "Windows 11".
 */
export function osDisplayName(os: unknown): string | null {
  if (!isObject(os)) {
    return null;
  }
  const text = (value: unknown): string => (typeof value === 'string' ? value.trim() : '');

  let name = text(os.name);
  if (name.startsWith('Microsoft ')) {
    name = name.slice('Microsoft '.length).trim();
  }
  if (name.length === 0) {
    return null;
  }

  const build = text(os.build);
  if (name.startsWith('Windows 10') && Number.parseInt(build, 10) >= 22000) {
    name = 'Windows 11' + name.slice('Windows 10'.length);
  }

  const displayVersion = text(os.displayVersion);
  const version = text(os.version);
  let versionPart = '';
  if (displayVersion.length > 0) {
    versionPart = displayVersion;
  } else if (!name.startsWith('Windows') && version.length > 0) {
    versionPart = version;
  }

  let buildPart = '';
  if (build.length > 0) {
    const ubr = os.ubr;
    const withUbr = !build.includes('.') && typeof ubr === 'number' && Number.isInteger(ubr) && ubr >= 0;
    buildPart = ` (build ${withUbr ? `${build}.${ubr}` : build})`;
  }

  return (name + (versionPart.length > 0 ? ` ${versionPart}` : '') + buildPart).slice(0, MAX_DETAIL_STRING_LENGTH);
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

    await table.put(
      compact({
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
        // The optional threat-status fields: each stored only when present and valid.
        ...findingThreatStatus(entry),
      }) as Item,
    );
  }
}

/**
 * The optional threat-status fields of one reported finding, each `undefined`
 * (not stored) when absent or unusable. A `status`/`action` string outside the
 * mapped set is stored as `unknown`; `category`, `processName` and `user` are
 * strings cut to their bounds; `active` is a boolean; the two times must be
 * ISO-8601 UTC.
 */
function findingThreatStatus(entry: Record<string, unknown>): Record<string, unknown> {
  const { status, action, category, active, lastStatusChangeAt, remediatedAt, processName, user } = entry;
  return {
    status: typeof status === 'string' ? (FINDING_STATUSES.has(status) ? status : 'unknown') : undefined,
    action: typeof action === 'string' ? (FINDING_ACTIONS.has(action) ? action : 'unknown') : undefined,
    category: typeof category === 'string' ? category.slice(0, MAX_FINDING_CATEGORY_LENGTH) : undefined,
    active: typeof active === 'boolean' ? active : undefined,
    lastStatusChangeAt:
      typeof lastStatusChangeAt === 'string' && ISO_UTC_PATTERN.test(lastStatusChangeAt)
        ? lastStatusChangeAt
        : undefined,
    remediatedAt:
      typeof remediatedAt === 'string' && ISO_UTC_PATTERN.test(remediatedAt) ? remediatedAt : undefined,
    processName:
      typeof processName === 'string' ? processName.slice(0, MAX_FINDING_PROCESS_NAME_LENGTH) : undefined,
    user: typeof user === 'string' ? user.slice(0, MAX_FINDING_USER_LENGTH) : undefined,
  };
}

/** A string cut to `max` characters, or `null` when it is not a string. */
function boundedString(value: unknown, max: number): string | null {
  return typeof value === 'string' ? value.slice(0, max) : null;
}

/** `value` when it is a boolean, else `null`. */
function nullableBoolean(value: unknown): boolean | null {
  return typeof value === 'boolean' ? value : null;
}

/** `value` when it is a parseable ISO-8601 UTC timestamp, else `null`. */
function nullableIsoUtc(value: unknown): string | null {
  return typeof value === 'string' && ISO_UTC_PATTERN.test(value) && !Number.isNaN(Date.parse(value))
    ? value
    : null;
}

/** An age in days: an integer from 0 to `MAX_AV_AGE_DAYS`, else `null`. */
function antivirusAge(value: unknown): number | null {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= MAX_AV_AGE_DAYS
    ? value
    : null;
}

/**
 * The Security Center products of an antivirus status: a non-array is `[]`;
 * entries without a non-empty string `name` are dropped and the first
 * `MAX_SECURITY_CENTER_PRODUCTS` of the rest kept, each with `name` cut to
 * `MAX_AV_PRODUCT_NAME_LENGTH`, an unknown `state` stored as `unknown` and a
 * non-boolean `definitionsUpToDate` as `null`.
 */
function securityCenterProducts(value: unknown): Array<Record<string, unknown>> {
  if (!Array.isArray(value)) {
    return [];
  }
  const products: Array<Record<string, unknown>> = [];
  for (const entry of value) {
    if (products.length === MAX_SECURITY_CENTER_PRODUCTS) {
      break;
    }
    if (!isObject(entry) || typeof entry.name !== 'string' || entry.name.length === 0) {
      continue;
    }
    products.push({
      name: entry.name.slice(0, MAX_AV_PRODUCT_NAME_LENGTH),
      state: typeof entry.state === 'string' && SECURITY_CENTER_STATES.has(entry.state) ? entry.state : 'unknown',
      definitionsUpToDate: nullableBoolean(entry.definitionsUpToDate),
    });
  }
  return products;
}

/**
 * Store the full antivirus status the agent reported, overwriting the device's
 * previous one with a full put.
 *
 * A check-in is never refused over its status: a value that is not an object
 * leaves the stored item as it is. Every schema key is stored, a wrong-typed
 * or out-of-range value as `null`; a key outside the schema is not stored. The
 * item carries the body's `collectedAt` and the server's `reportedAt`. A
 * status never touches `complianceState`.
 */
async function recordAntivirusStatus(
  table: CheckInTable,
  deviceId: string,
  collectedAt: string,
  reported: unknown,
  at: Date,
): Promise<void> {
  if (!isObject(reported)) {
    return;
  }
  const protection = objectAt(reported, 'protection');
  const versions = objectAt(reported, 'versions');
  const signatures = objectAt(reported, 'signatures');
  const scans = objectAt(reported, 'scans');
  const product = reported.product;
  const computerState = reported.computerState;

  await table.put({
    ...deviceAntivirusStatus(deviceId),
    deviceId,
    collectedAt,
    reportedAt: isoUtc(at),
    product: typeof product === 'string' && product.length > 0 ? product.slice(0, MAX_AV_PRODUCT_NAME_LENGTH) : null,
    defenderAvailable: reported.defenderAvailable === true,
    runningMode: boundedString(reported.runningMode, MAX_AV_VERSION_LENGTH),
    protection: {
      amServiceEnabled: nullableBoolean(protection.amServiceEnabled),
      antispywareEnabled: nullableBoolean(protection.antispywareEnabled),
      antivirusEnabled: nullableBoolean(protection.antivirusEnabled),
      behaviorMonitorEnabled: nullableBoolean(protection.behaviorMonitorEnabled),
      ioavProtectionEnabled: nullableBoolean(protection.ioavProtectionEnabled),
      onAccessProtectionEnabled: nullableBoolean(protection.onAccessProtectionEnabled),
      realTimeProtectionEnabled: nullableBoolean(protection.realTimeProtectionEnabled),
      nisEnabled: nullableBoolean(protection.nisEnabled),
      tamperProtected: nullableBoolean(protection.tamperProtected),
    },
    versions: {
      engine: boundedString(versions.engine, MAX_AV_VERSION_LENGTH),
      product: boundedString(versions.product, MAX_AV_VERSION_LENGTH),
      service: boundedString(versions.service, MAX_AV_VERSION_LENGTH),
      nisEngine: boundedString(versions.nisEngine, MAX_AV_VERSION_LENGTH),
      antivirusSignature: boundedString(versions.antivirusSignature, MAX_AV_VERSION_LENGTH),
      antispywareSignature: boundedString(versions.antispywareSignature, MAX_AV_VERSION_LENGTH),
      nisSignature: boundedString(versions.nisSignature, MAX_AV_VERSION_LENGTH),
      xprotectDefinitions: boundedString(versions.xprotectDefinitions, MAX_AV_VERSION_LENGTH),
      xprotectRemediator: boundedString(versions.xprotectRemediator, MAX_AV_VERSION_LENGTH),
    },
    signatures: {
      antivirusLastUpdatedAt: nullableIsoUtc(signatures.antivirusLastUpdatedAt),
      antivirusAgeDays: antivirusAge(signatures.antivirusAgeDays),
      antispywareLastUpdatedAt: nullableIsoUtc(signatures.antispywareLastUpdatedAt),
      antispywareAgeDays: antivirusAge(signatures.antispywareAgeDays),
      nisLastUpdatedAt: nullableIsoUtc(signatures.nisLastUpdatedAt),
      nisAgeDays: antivirusAge(signatures.nisAgeDays),
      outOfDate: nullableBoolean(signatures.outOfDate),
    },
    scans: {
      quickStartedAt: nullableIsoUtc(scans.quickStartedAt),
      quickEndedAt: nullableIsoUtc(scans.quickEndedAt),
      quickAgeDays: antivirusAge(scans.quickAgeDays),
      quickOverdue: nullableBoolean(scans.quickOverdue),
      fullStartedAt: nullableIsoUtc(scans.fullStartedAt),
      fullEndedAt: nullableIsoUtc(scans.fullEndedAt),
      fullAgeDays: antivirusAge(scans.fullAgeDays),
      fullOverdue: nullableBoolean(scans.fullOverdue),
      fullRequired: nullableBoolean(scans.fullRequired),
    },
    computerState:
      typeof computerState === 'number' &&
      Number.isSafeInteger(computerState) &&
      computerState >= 0 &&
      computerState <= MAX_COMPUTER_STATE
        ? computerState
        : null,
    rebootRequired: nullableBoolean(reported.rebootRequired),
    securityCenterProducts: securityCenterProducts(reported.securityCenterProducts),
  });
}

/** The items a `defenderHardening` block may report, in the agent's fixed order. */
const DEFENDER_HARDENING_ITEMS: ReadonlySet<string> = new Set([
  'realTimeMonitoring',
  'behaviorMonitoring',
  'ioavProtection',
  'scriptScanning',
  'mapsReporting',
  'submitSamplesConsent',
  'networkProtection',
  'controlledFolderAccess',
  'puaProtection',
  'smartScreenWindows',
  'smartScreenEdge',
  'signatureUpdateInterval',
  'signatureScheduleDay',
  'signatureUpdate',
]);

/** The states one `defenderHardening` item may be in. */
const DEFENDER_HARDENING_STATES: ReadonlySet<string> = new Set([
  'ok',
  'applied',
  'failed',
  'tamper_blocked',
  'not_applicable',
  'waiting',
]);

/** Most items one stored `defenderHardening` block keeps. */
const MAX_DEFENDER_HARDENING_ITEMS = 14;

/** Longest `detail` kept on one `defenderHardening` item, in characters. */
const MAX_DEFENDER_HARDENING_DETAIL_LENGTH = 256;

/**
 * Store the Defender protections block the agent reported, overwriting the
 * device's previous one with a full put.
 *
 * A check-in is never refused over this block: a value that is not an object
 * leaves the stored item as it is. An entry whose `item` or `state` is outside
 * the vocabulary is dropped, a repeated `item` keeps its first entry, at most
 * 14 entries are kept and `detail` is cut to 256 characters. The item carries
 * the agent's `evaluatedAt` (`null` when it is not ISO-8601 UTC) and the
 * server's `reportedAt`. The block is stored for the admin only and never
 * moves `complianceState`: Defender violations arrive in `policyCompliance`.
 */
async function recordDefenderHardening(
  table: CheckInTable,
  deviceId: string,
  reported: unknown,
  at: Date,
): Promise<void> {
  if (!isObject(reported)) {
    return;
  }
  const items: Array<{ item: string; state: string; detail?: string }> = [];
  const seen = new Set<string>();
  const entries = Array.isArray(reported.items) ? reported.items : [];
  for (const entry of entries) {
    if (items.length >= MAX_DEFENDER_HARDENING_ITEMS) {
      break;
    }
    if (!isObject(entry)) {
      continue;
    }
    const { item, state, detail } = entry;
    if (typeof item !== 'string' || !DEFENDER_HARDENING_ITEMS.has(item)) {
      continue;
    }
    if (typeof state !== 'string' || !DEFENDER_HARDENING_STATES.has(state)) {
      continue;
    }
    if (seen.has(item)) {
      continue;
    }
    seen.add(item);
    items.push(
      typeof detail === 'string' && detail.length > 0
        ? { item, state, detail: detail.slice(0, MAX_DEFENDER_HARDENING_DETAIL_LENGTH) }
        : { item, state },
    );
  }

  // The stored block, read before it is overwritten, decides whether this is a
  // new evaluation for the device's History (TASK-067).
  const stored = await getOrUndefined(table, deviceDefenderHardening(deviceId));
  const evaluatedAt = nullableIsoUtc(reported.evaluatedAt);

  await table.put({
    ...deviceDefenderHardening(deviceId),
    deviceId,
    evaluatedAt,
    reportedAt: isoUtc(at),
    items,
  });

  // The raw evaluatedAt is compared and hashed, so a re-sent block yields the
  // same eventId and is never recorded twice.
  if (stored.ok && evaluatedAt !== null && evaluatedAt !== stored.item?.evaluatedAt) {
    const applied = items.filter((entry) => entry.state === 'applied').map((entry) => entry.item);
    if (applied.length > 0) {
      const names = applied.join(', ');
      await recordDeviceEvent(table, {
        deviceId,
        source: 'agent',
        type: 'defender.protections_applied',
        summary: `Defender protections applied: ${names}`,
        details: { items: names, evaluatedAt },
        actor: null,
        occurredAt: evaluatedAt,
        eventId: deterministicEventId('defender.protections_applied', evaluatedAt),
      });
    }
  }
}

/** The first 32 hex characters of sha256(`<type>\n<value>`): one id per reported instant. */
function deterministicEventId(type: string, value: string): string {
  return createHash('sha256').update(`${type}\n${value}`).digest('hex').slice(0, 32);
}

/**
 * Read one item for event derivation. A read that throws yields `ok: false`,
 * so no event is derived from it and the check-in is never refused over it.
 */
async function getOrUndefined(
  table: CheckInTable,
  key: TableKey,
): Promise<{ ok: boolean; item: Item | undefined }> {
  try {
    const item = await table.get(key);
    return { ok: true, item: item ?? undefined };
  } catch {
    return { ok: false, item: undefined };
  }
}

/** One `agentErrors` entry as it is stored: sanitised, and merged by signature. */
interface SanitisedAgentError {
  signature: string;
  level: 'warn' | 'error';
  component: string;
  message: string;
  fields: Record<string, string>;
  count: number;
  firstAt: string;
  lastAt: string;
}

/**
 * Keep the `agentErrors` entries the contract allows. Only the first
 * `MAX_AGENT_ERRORS` are looked at; an entry that is not an object, has a
 * level other than warn/error, no non-empty string message, an unparseable
 * `firstAt`/`lastAt`, or a `lastAt` outside the retention/future-skew window
 * is dropped. Strings are cut, non-string field values dropped, at most
 * `MAX_AGENT_ERROR_FIELDS` fields kept, and `count` clamped to
 * `[1, MAX_AGENT_ERROR_COUNT]` (anything not an integer counts 1). Entries
 * sharing a signature are merged: counts added, the earliest `firstAt` kept,
 * and the latest entry's `lastAt`, text and fields kept.
 */
function sanitiseAgentErrors(reported: unknown, nowSeconds: number): SanitisedAgentError[] {
  if (!Array.isArray(reported)) {
    return [];
  }
  const bySignature = new Map<string, SanitisedAgentError>();
  for (const entry of reported.slice(0, MAX_AGENT_ERRORS)) {
    if (!isObject(entry)) {
      continue;
    }
    const { level, message, count } = entry;
    if (level !== 'warn' && level !== 'error') {
      continue;
    }
    if (typeof message !== 'string' || message.length === 0) {
      continue;
    }
    const firstAt = normalisedInstant(entry.firstAt);
    const lastAt = normalisedInstant(entry.lastAt);
    if (firstAt === null || lastAt === null) {
      continue;
    }
    const lastSeconds = Math.floor(Date.parse(lastAt) / 1000);
    if (
      lastSeconds < nowSeconds - AGENT_ERROR_RETENTION_SECONDS ||
      lastSeconds > nowSeconds + AGENT_ERROR_FUTURE_SKEW_SECONDS
    ) {
      continue;
    }

    const component = boundedString(entry.component, MAX_AGENT_ERROR_KEY_LENGTH) ?? '';
    const text = message.slice(0, MAX_AGENT_ERROR_VALUE_LENGTH);
    const fields: Record<string, string> = {};
    if (isObject(entry.fields)) {
      let kept = 0;
      for (const [rawKey, rawValue] of Object.entries(entry.fields)) {
        if (kept >= MAX_AGENT_ERROR_FIELDS) {
          break;
        }
        if (typeof rawValue !== 'string') {
          continue;
        }
        const key = rawKey.slice(0, MAX_AGENT_ERROR_KEY_LENGTH);
        if (key.length === 0 || Object.prototype.hasOwnProperty.call(fields, key)) {
          continue;
        }
        fields[key] = rawValue.slice(0, MAX_AGENT_ERROR_VALUE_LENGTH);
        kept++;
      }
    }
    const entryCount =
      typeof count === 'number' && Number.isInteger(count) && count >= 1 ? Math.min(count, MAX_AGENT_ERROR_COUNT) : 1;
    const signature = createHash('sha256').update(`${level}\n${component}\n${text}`, 'utf8').digest('hex').slice(0, 32);

    const merged = bySignature.get(signature);
    if (merged === undefined) {
      bySignature.set(signature, {
        signature,
        level,
        component,
        message: text,
        fields,
        count: entryCount,
        firstAt,
        lastAt,
      });
      continue;
    }
    merged.count += entryCount;
    if (Date.parse(firstAt) < Date.parse(merged.firstAt)) {
      merged.firstAt = firstAt;
    }
    if (Date.parse(lastAt) >= Date.parse(merged.lastAt)) {
      merged.lastAt = lastAt;
      merged.fields = fields;
    }
  }
  return [...bySignature.values()];
}

/**
 * Store the agent's warn/error entries, one item per device and signature.
 *
 * A check-in is never refused over its `agentErrors`: a value that is not an
 * array, and any entry `sanitiseAgentErrors` drops, is ignored. Each kept
 * entry is read, compared and written back: `count` is added to the stored
 * count, `firstSeenAt` is set only on a new item, and `lastSeenAt` with the
 * entry's text, fields and `reportedAt` move only when the entry's `lastAt`
 * is later than the stored `lastSeenAt` (an older, re-sent batch never moves
 * it back). `ttl` follows the stored `lastSeenAt`. Plain get and put are used,
 * so no update expression (and no reserved word such as `count`, `level` or
 * `ttl`) is involved.
 */
async function recordAgentErrors(
  table: CheckInTable,
  deviceId: string,
  reported: unknown,
  at: Date,
): Promise<void> {
  const entries = sanitiseAgentErrors(reported, Math.floor(at.getTime() / 1000));
  if (entries.length === 0) {
    return;
  }
  const reportedAt = isoUtc(at);
  for (const entry of entries) {
    const key = deviceAgentError(deviceId, entry.signature);
    const existing = await table.get(key);
    const storedLastSeenAt =
      existing !== undefined && typeof existing.lastSeenAt === 'string' && !Number.isNaN(Date.parse(existing.lastSeenAt))
        ? existing.lastSeenAt
        : null;
    const isNew = existing === undefined;
    const storedCount =
      !isNew && typeof existing.count === 'number' && Number.isFinite(existing.count) ? existing.count : 0;
    const firstSeenAt =
      !isNew && typeof existing.firstSeenAt === 'string' ? existing.firstSeenAt : entry.firstAt;
    const count = storedCount + entry.count;

    if (storedLastSeenAt !== null && Date.parse(entry.lastAt) <= Date.parse(storedLastSeenAt)) {
      // An older (or re-sent) batch: only the count grows.
      await table.put({
        ...existing,
        ...key,
        deviceId,
        signature: entry.signature,
        count,
        firstSeenAt,
        lastSeenAt: storedLastSeenAt,
        ttl: Math.floor(Date.parse(storedLastSeenAt) / 1000) + AGENT_ERROR_RETENTION_SECONDS,
      });
      continue;
    }

    await table.put({
      ...key,
      deviceId,
      signature: entry.signature,
      level: entry.level,
      component: entry.component,
      message: entry.message,
      fields: entry.fields,
      count,
      firstSeenAt,
      lastSeenAt: entry.lastAt,
      reportedAt,
      ttl: Math.floor(Date.parse(entry.lastAt) / 1000) + AGENT_ERROR_RETENTION_SECONDS,
    });
  }
}

/** One `agentActions` entry after sanitisation. */
interface SanitisedAgentAction {
  type: string;
  occurredAt: string;
  details: Record<string, string>;
}

/**
 * Keep the `agentActions` entries the contract allows. Only the first
 * `MAX_AGENT_ACTIONS` are looked at; an entry that is not an object, has a
 * type other than the four known ones, an unparseable `occurredAt`, or an
 * `occurredAt` more than `AGENT_ACTION_FUTURE_SKEW_SECONDS` after or
 * `AGENT_ACTION_RETENTION_SECONDS` before server now is dropped. A `details`
 * that is not an object reads as `{}`; non-string values are dropped, at most
 * `MAX_AGENT_ACTION_DETAILS` entries kept in insertion order, keys and values
 * cut to their limits.
 */
function sanitiseAgentActions(reported: unknown, nowSeconds: number): SanitisedAgentAction[] {
  if (!Array.isArray(reported)) {
    return [];
  }
  const kept: SanitisedAgentAction[] = [];
  for (const entry of reported.slice(0, MAX_AGENT_ACTIONS)) {
    if (!isObject(entry)) {
      continue;
    }
    const { type } = entry;
    if (typeof type !== 'string' || !AGENT_ACTION_TYPES.has(type)) {
      continue;
    }
    const occurredAt = normalisedInstant(entry.occurredAt);
    if (occurredAt === null) {
      continue;
    }
    const occurredSeconds = Math.floor(Date.parse(occurredAt) / 1000);
    if (
      occurredSeconds < nowSeconds - AGENT_ACTION_RETENTION_SECONDS ||
      occurredSeconds > nowSeconds + AGENT_ACTION_FUTURE_SKEW_SECONDS
    ) {
      continue;
    }
    const details: Record<string, string> = {};
    if (isObject(entry.details)) {
      let count = 0;
      for (const [rawKey, rawValue] of Object.entries(entry.details)) {
        if (count >= MAX_AGENT_ACTION_DETAILS) {
          break;
        }
        if (typeof rawValue !== 'string') {
          continue;
        }
        const key = rawKey.slice(0, MAX_AGENT_ACTION_KEY_LENGTH);
        if (Object.prototype.hasOwnProperty.call(details, key)) {
          continue;
        }
        details[key] = rawValue.slice(0, MAX_AGENT_ACTION_VALUE_LENGTH);
        count++;
      }
    }
    kept.push({ type, occurredAt, details });
  }
  return kept;
}

/** The History summary of one agent action, built from its type and details. */
function agentActionSummary(type: string, details: Record<string, string>): string {
  switch (type) {
    case 'enforce.firewall_enabled':
      return 'Firewall turned on by policy';
    case 'enforce.antivirus_enabled':
      return 'Antivirus real-time protection turned on by policy';
    case 'enforce.domains_updated': {
      const blockedCount = details.blockedCount;
      if (blockedCount === '0') {
        return 'Blocked domains cleared';
      }
      if (typeof blockedCount === 'string' && /^\d{1,6}$/.test(blockedCount)) {
        const n = Number(blockedCount);
        if (n >= 1) {
          return `Blocked domains updated: ${n} names blocked`;
        }
      }
      return 'Blocked domains updated';
    }
    case 'agent.update_rolled_back': {
      const installed = details.installedVersion;
      if (typeof installed === 'string' && installed.length > 0) {
        return `Agent update to ${installed.slice(0, 64)} rolled back`;
      }
      return 'Agent update rolled back';
    }
    default:
      return type;
  }
}

/**
 * Turn each kept `agentActions` entry into one `source: 'agent'` device
 * event (TASK-070). A check-in is never refused over its `agentActions`: a
 * value that is not an array, and any entry `sanitiseAgentActions` drops, is
 * ignored, and nothing thrown here escapes. The eventId is derived from the
 * type and the normalised `occurredAt`, so a spool re-send overwrites the same
 * item. Only `recordDeviceEvent` writes, through a plain put: no expression.
 */
async function recordAgentActions(
  table: CheckInTable,
  deviceId: string,
  reported: unknown,
  at: Date,
): Promise<void> {
  try {
    const actions = sanitiseAgentActions(reported, Math.floor(at.getTime() / 1000));
    for (const action of actions) {
      await recordDeviceEvent(table, {
        deviceId,
        source: 'agent',
        type: action.type,
        summary: agentActionSummary(action.type, action.details),
        details: action.details,
        actor: null,
        occurredAt: action.occurredAt,
        eventId: deterministicEventId(action.type, action.occurredAt),
      });
    }
  } catch {
    // Agent actions are History only; they never fail a check-in.
  }
}

/** True for `null` or an ISO-8601 UTC timestamp string. */
function isNullableIsoUtc(value: unknown): boolean {
  return value === null || (typeof value === 'string' && ISO_UTC_PATTERN.test(value));
}

/**
 * Store the last scheduled antivirus scan the agent reported, overwriting the
 * device's previous one.
 *
 * A check-in is never refused over its scan: a value that is absent leaves the
 * stored item as it is, and one that is not an object, carries an unknown
 * `result`, a `scanType` other than `quick`, a `threatsFound` that is not an
 * integer from 0 to `MAX_SCAN_THREATS_FOUND`, or a `startedAt`/`completedAt`
 * that is neither null nor ISO-8601 UTC stores nothing. A string `detail` is
 * cut to `MAX_SCAN_DETAIL_LENGTH`; anything else is not stored. A scan never
 * touches `complianceState`.
 */
async function recordAntivirusScan(
  table: CheckInTable,
  deviceId: string,
  reported: unknown,
  at: Date,
): Promise<void> {
  if (!isObject(reported)) {
    return;
  }
  const { scanType, result, startedAt, completedAt, threatsFound, detail } = reported;
  if (
    typeof result !== 'string' ||
    !ANTIVIRUS_SCAN_RESULTS.has(result) ||
    scanType !== 'quick' ||
    typeof threatsFound !== 'number' ||
    !Number.isInteger(threatsFound) ||
    threatsFound < 0 ||
    threatsFound > MAX_SCAN_THREATS_FOUND ||
    !isNullableIsoUtc(startedAt) ||
    !isNullableIsoUtc(completedAt)
  ) {
    return;
  }

  // The stored scan, read before it is overwritten, decides whether this is a
  // new scan for the device's History (TASK-067).
  const stored = await getOrUndefined(table, deviceAntivirusScan(deviceId));
  const storedDetail = typeof detail === 'string' ? detail.slice(0, MAX_SCAN_DETAIL_LENGTH) : undefined;

  await table.put(
    compact({
      ...deviceAntivirusScan(deviceId),
      deviceId,
      scanType,
      result,
      startedAt,
      completedAt,
      threatsFound,
      detail: storedDetail,
      reportedAt: isoUtc(at),
    }) as Item,
  );

  // The raw startedAt is compared and hashed, so a re-sent scan yields the
  // same eventId and is never recorded twice.
  const started = nullableIsoUtc(startedAt);
  if (stored.ok && started !== null && started !== stored.item?.startedAt) {
    const completed = nullableIsoUtc(completedAt);
    await recordDeviceEvent(table, {
      deviceId,
      source: 'agent',
      type: 'antivirus.scan',
      summary: antivirusScanSummary(result, threatsFound),
      details: {
        result,
        threatsFound: String(threatsFound),
        ...(storedDetail === undefined ? {} : { detail: storedDetail }),
      },
      actor: null,
      occurredAt: completed ?? started,
      eventId: deterministicEventId('antivirus.scan', started),
    });
  }
}

/** The History summary of one scheduled scan result. */
function antivirusScanSummary(result: string, threatsFound: number): string {
  switch (result) {
    case 'clean':
      return 'Quick scan completed: clean';
    case 'threats_found':
      return `Quick scan completed: ${threatsFound} threats found`;
    case 'failed':
      return 'Quick scan failed';
    case 'timeout':
      return 'Quick scan timed out';
    default:
      return `Quick scan: ${result}`;
  }
}

/** The sanitised boot sub-block: every key present, value or `null`. */
interface SanitisedBoot {
  lastBootAt: string | null;
  bootDurationSeconds: number | null;
  uptimeSeconds: number | null;
}

/** The sanitised performance sub-block: every key present, value or `null`. */
export interface SanitisedPerformance {
  cpuPercent: number | null;
  memoryUsedBytes: number | null;
  memoryTotalBytes: number | null;
  systemDiskFreeBytes: number | null;
  systemDiskTotalBytes: number | null;
}

/** One crash/hang event kept for storage, already trimmed, bounded and normalised. */
interface SanitisedCrash {
  appName: string;
  appVersion: string | null;
  occurredAt: string;
  kind: 'crash' | 'hang';
}

/** The `analytics` block after sanitisation. */
interface SanitisedAnalytics {
  boot: SanitisedBoot;
  performance: SanitisedPerformance;
  crashes: SanitisedCrash[];
  warnings: string[] | undefined;
}

/** A valid ISO-8601 UTC instant normalised to whole seconds, or `null`. */
function normalisedInstant(value: unknown): string | null {
  if (typeof value !== 'string' || !ISO_UTC_PATTERN.test(value) || Number.isNaN(Date.parse(value))) {
    return null;
  }
  return isoUtc(new Date(value));
}

/** A finite number within `[min, max]` (or `(min, max]` when `exclusiveMin`), else `null`. */
function boundedNumber(value: unknown, min: number, max: number, exclusiveMin = false): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }
  if ((exclusiveMin ? value <= min : value < min) || value > max) {
    return null;
  }
  return value;
}

/** A safe integer within `[min, max]`, else `null`. */
function boundedInteger(value: unknown, min: number, max: number): number | null {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) {
    return null;
  }
  return value;
}

/**
 * A used/total byte pair: both `null` when the total is not a safe integer
 * above zero, otherwise only `used` is `null` when it is not within `[0, total]`.
 */
function bytePair(used: unknown, total: unknown): [number | null, number | null] {
  const validTotal = boundedInteger(total, 1, Number.MAX_SAFE_INTEGER);
  if (validTotal === null) {
    return [null, null];
  }
  return [boundedInteger(used, 0, validTotal), validTotal];
}

/**
 * Keep the crash entries the contract allows: only the first
 * `MAX_APP_CRASHES` are looked at, and an entry that is not an object, has no
 * usable name, an unknown kind, an unparseable time, or a time outside the
 * retention/future-skew window is dropped.
 */
function sanitiseCrashes(reported: unknown, nowSeconds: number): SanitisedCrash[] {
  if (!Array.isArray(reported)) {
    return [];
  }
  const kept: SanitisedCrash[] = [];
  for (const entry of reported.slice(0, MAX_APP_CRASHES)) {
    if (!isObject(entry)) {
      continue;
    }
    const { appName, appVersion, kind } = entry;
    if (typeof appName !== 'string' || appName.trim().length === 0) {
      continue;
    }
    if (kind !== 'crash' && kind !== 'hang') {
      continue;
    }
    const occurredAt = normalisedInstant(entry.occurredAt);
    if (occurredAt === null) {
      continue;
    }
    const occurredSeconds = Math.floor(Date.parse(occurredAt) / 1000);
    if (
      occurredSeconds < nowSeconds - APP_CRASH_RETENTION_SECONDS ||
      occurredSeconds > nowSeconds + APP_CRASH_FUTURE_SKEW_SECONDS
    ) {
      continue;
    }
    const version = typeof appVersion === 'string' ? appVersion.trim() : '';
    kept.push({
      appName: appName.trim().slice(0, MAX_APP_NAME_LENGTH),
      appVersion: version.length > 0 ? version.slice(0, MAX_APP_VERSION_LENGTH) : null,
      occurredAt,
      kind,
    });
  }
  return kept;
}

/**
 * The `analytics` block reduced to what may be stored, or `undefined` when the
 * body carries no object `analytics` at all.
 *
 * Nothing here ever rejects: a wrong-typed or out-of-range scalar is stored
 * `null`, a malformed crash entry is dropped, and non-string warnings are
 * filtered out.
 */
function sanitiseAnalytics(reported: unknown, nowSeconds: number): SanitisedAnalytics | undefined {
  if (!isObject(reported)) {
    return undefined;
  }
  const boot = objectAt(reported, 'boot');

  return {
    boot: {
      lastBootAt: normalisedInstant(boot.lastBootAt),
      bootDurationSeconds: boundedNumber(boot.bootDurationSeconds, 0, MAX_BOOT_DURATION_SECONDS, true),
      uptimeSeconds: boundedInteger(boot.uptimeSeconds, 0, MAX_UPTIME_SECONDS),
    },
    performance: sanitisePerformance(reported.performance),
    crashes: sanitiseCrashes(reported.crashes, nowSeconds),
    warnings: sanitiseWarnings(reported.warnings),
  };
}

/**
 * A reported `performance` block reduced to what may be stored. Anything that
 * is not an object counts as `{}`; a wrong-typed or out-of-range value is
 * `null`. Shared with the heartbeat route (`./heartbeat.ts`).
 */
export function sanitisePerformance(reported: unknown): SanitisedPerformance {
  const performance = isObject(reported) ? reported : {};
  const [memoryUsedBytes, memoryTotalBytes] = bytePair(
    performance.memoryUsedBytes,
    performance.memoryTotalBytes,
  );
  const [systemDiskFreeBytes, systemDiskTotalBytes] = bytePair(
    performance.systemDiskFreeBytes,
    performance.systemDiskTotalBytes,
  );
  return {
    cpuPercent: boundedNumber(performance.cpuPercent, 0, 100),
    memoryUsedBytes,
    memoryTotalBytes,
    systemDiskFreeBytes,
    systemDiskTotalBytes,
  };
}

/**
 * Reported warnings reduced to what may be stored: string entries only, at
 * most `MAX_ANALYTICS_WARNINGS`, each cut to `MAX_ANALYTICS_WARNING_LENGTH`
 * characters; `undefined` when none remain. Shared with the heartbeat route.
 */
export function sanitiseWarnings(reported: unknown): string[] | undefined {
  const warnings = (warningsOf({ warnings: reported }) ?? [])
    .slice(0, MAX_ANALYTICS_WARNINGS)
    .map((warning) => warning.slice(0, MAX_ANALYTICS_WARNING_LENGTH));
  return warnings.length > 0 ? warnings : undefined;
}

/** Overwrite the device's latest analytics snapshot. The snapshot has no `ttl`. */
async function recordAnalyticsSnapshot(
  table: CheckInTable,
  deviceId: string,
  collectedAt: string,
  analytics: SanitisedAnalytics,
  at: Date,
): Promise<void> {
  await table.put(
    compact({
      ...deviceAnalytics(deviceId),
      ...analyticsListIndex(deviceId),
      deviceId,
      collectedAt,
      receivedAt: isoUtc(at),
      boot: { ...analytics.boot },
      performance: { ...analytics.performance },
      warnings: analytics.warnings,
    }),
  );
}

/**
 * Fold the reported boot into the device's boot history: newest first, at most
 * `MAX_BOOT_HISTORY` entries, one entry per `bootAt`. A re-reported boot keeps
 * its stored duration unless the new report carries one. Nothing is read or
 * written when the sanitised `lastBootAt` is `null`.
 */
async function recordBootHistory(
  table: CheckInTable,
  deviceId: string,
  boot: SanitisedBoot,
  at: Date,
): Promise<void> {
  const bootAt = boot.lastBootAt;
  if (bootAt === null) {
    return;
  }
  const key = deviceBootHistory(deviceId);
  const existing = await table.get(key);
  const stored = Array.isArray(existing?.boots) ? existing.boots : [];
  const boots: Array<{ bootAt: string; bootDurationSeconds: number | null }> = [];
  for (const value of stored) {
    if (!isObject(value) || typeof value.bootAt !== 'string') {
      continue;
    }
    if (boots.some((entry) => entry.bootAt === value.bootAt)) {
      continue;
    }
    boots.push({
      bootAt: value.bootAt,
      bootDurationSeconds: typeof value.bootDurationSeconds === 'number' ? value.bootDurationSeconds : null,
    });
  }

  const match = boots.find((entry) => entry.bootAt === bootAt);
  if (match !== undefined) {
    if (boot.bootDurationSeconds !== null) {
      match.bootDurationSeconds = boot.bootDurationSeconds;
    }
  } else {
    boots.push({ bootAt, bootDurationSeconds: boot.bootDurationSeconds });
  }
  // Whole-second ISO-8601 UTC strings order lexicographically.
  boots.sort((a, b) => (a.bootAt < b.bootAt ? 1 : a.bootAt > b.bootAt ? -1 : 0));

  await table.put({
    ...key,
    deviceId,
    boots: boots.slice(0, MAX_BOOT_HISTORY),
    updatedAt: isoUtc(at),
  });
}

/**
 * Store one item per kept crash event. The key carries a hash of the stored
 * values, so an event reported again -- in the same check-in or a retried one
 * -- overwrites itself. Items expire through the table's `ttl` attribute.
 */
async function recordAppCrashes(
  table: CheckInTable,
  deviceId: string,
  crashes: SanitisedCrash[],
  at: Date,
): Promise<void> {
  const reportedAt = isoUtc(at);
  const written = new Set<string>();
  for (const crash of crashes) {
    const eventId = createHash('sha256')
      .update(`${crash.kind}\n${crash.appName}\n${crash.appVersion ?? ''}\n${crash.occurredAt}`, 'utf8')
      .digest('hex')
      .slice(0, 32);
    if (written.has(eventId)) {
      continue;
    }
    written.add(eventId);
    await table.put({
      ...deviceAppCrash(deviceId, crash.occurredAt, eventId),
      ...appCrashListIndex(crash.occurredAt, deviceId),
      deviceId,
      eventId,
      appName: crash.appName,
      appVersion: crash.appVersion,
      occurredAt: crash.occurredAt,
      kind: crash.kind,
      reportedAt,
      ttl: Math.floor(Date.parse(crash.occurredAt) / 1000) + APP_CRASH_RETENTION_SECONDS,
    });
  }
}

/**
 * Store the endpoint analytics the agent reported: the latest snapshot, the
 * boot history and the crash events. A body without an object `analytics`
 * touches none of them. Analytics never move compliance.
 */
async function recordAnalytics(
  table: CheckInTable,
  deviceId: string,
  collectedAt: string,
  reported: unknown,
  at: Date,
): Promise<void> {
  const analytics = sanitiseAnalytics(reported, Math.floor(at.getTime() / 1000));
  if (analytics === undefined) {
    return;
  }
  await recordAnalyticsSnapshot(table, deviceId, collectedAt, analytics, at);
  await recordBootHistory(table, deviceId, analytics.boot, at);
  await recordAppCrashes(table, deviceId, analytics.crashes, at);
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
 *
 * Returns the assigned policy ids it resolved, so a later step can reuse them,
 * or `undefined` when it resolved none.
 */
async function recordPolicyCompliance(
  table: CheckInTable,
  deviceId: string,
  reported: unknown,
  at: Date,
): Promise<string[] | undefined> {
  if (!Array.isArray(reported)) {
    return undefined;
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
  return assignedPolicyIds;
}

/** The agent version the body reported, or `undefined` when it carried none. */
function postedAgentVersion(posted: Record<string, unknown>): string | undefined {
  const version = posted.agentVersion;
  return typeof version === 'string' && version.length > 0 ? version : undefined;
}

/**
 * One `agent.version_changed` History event when both the stored and the
 * posted version are non-empty strings and they differ.
 */
async function recordAgentVersionChange(
  table: CheckInTable,
  deviceId: string,
  storedProfile: { ok: boolean; item: Item | undefined },
  posted: string | undefined,
  at: Date,
): Promise<void> {
  const from = storedProfile.item?.agentVersion;
  if (!storedProfile.ok || typeof from !== 'string' || from.length === 0 || posted === undefined || posted === from) {
    return;
  }
  await recordDeviceEvent(table, {
    deviceId,
    source: 'system',
    type: 'agent.version_changed',
    summary: `Agent version changed from ${from} to ${posted}`,
    details: { from, to: posted },
    actor: null,
    occurredAt: at,
  });
}

/** The posture switches the History records, in the order they are checked. */
const POSTURE_EVENT_SETTINGS: ReadonlyArray<{ setting: string; label: string }> = [
  { setting: 'antivirus', label: 'Antivirus' },
  { setting: 'firewall', label: 'Firewall' },
  { setting: 'diskEncryption', label: 'Disk encryption' },
];

/**
 * One `posture.changed` History event for each switch whose stored value is a
 * boolean and whose posted value is a different boolean. A device with no
 * stored posture gets none.
 */
async function recordPostureChanges(
  table: CheckInTable,
  deviceId: string,
  storedPosture: { ok: boolean; item: Item | undefined },
  posture: Record<string, unknown>,
  at: Date,
): Promise<void> {
  const stored = storedPosture.item;
  if (!storedPosture.ok || stored === undefined || stored === null) {
    return;
  }
  for (const { setting, label } of POSTURE_EVENT_SETTINGS) {
    const from = isObject(stored[setting]) ? (stored[setting] as Record<string, unknown>).enabled : undefined;
    const to = objectAt(posture, setting).enabled;
    if (typeof from !== 'boolean' || typeof to !== 'boolean' || from === to) {
      continue;
    }
    await recordDeviceEvent(table, {
      deviceId,
      source: 'system',
      type: 'posture.changed',
      summary: `${label} turned ${to ? 'on' : 'off'}`,
      details: { setting, from: String(from), to: String(to) },
      actor: null,
      occurredAt: at,
    });
  }
}

/**
 * The IANA time zone the body reported, or `undefined` when it carried none or
 * an unusable one: not a string, empty, longer than 64 characters, or a name
 * `Intl.DateTimeFormat` rejects. An unusable zone is ignored, never refused.
 */
function postedTimeZone(posted: Record<string, unknown>): string | undefined {
  const timeZone = posted.timeZone;
  if (typeof timeZone !== 'string' || timeZone.length < 1 || timeZone.length > 64) {
    return undefined;
  }
  try {
    new Intl.DateTimeFormat('en-US', { timeZone });
  } catch {
    return undefined;
  }
  return timeZone;
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
 * The dotted numeric components of a version, the agent's `parseVersion` rule:
 * any suffix from the first `-` or `+` is ignored, and `null` means the value
 * cannot be parsed.
 */
function parseReleaseVersion(value: unknown): number[] | null {
  if (typeof value !== 'string') {
    return null;
  }
  let text = value.trim();
  const cut = text.search(/[-+]/);
  if (cut >= 0) {
    text = text.slice(0, cut);
  }
  if (text === '') {
    return null;
  }
  const numbers: number[] = [];
  for (const part of text.split('.')) {
    if (!/^[0-9]+$/.test(part)) {
      return null;
    }
    numbers.push(Number(part));
  }
  return numbers;
}

/** Orders two parsed versions, a missing component counting as 0. */
function compareReleaseVersions(a: number[], b: number[]): number {
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    const difference = (a[i] ?? 0) - (b[i] ?? 0);
    if (difference !== 0) {
      return difference;
    }
  }
  return 0;
}

/** A build that could be advertised, with its parsed version. */
/**
 * The first Windows agent build whose self-update restarts through the service
 * control manager's recovery actions. Earlier builds restart themselves with
 * `sc.exe stop`/`start` from inside the service being stopped, which leaves the
 * service stopped, so no `agentRelease` is advertised to a Windows device below
 * this version (an absent or unparseable version counts as 0.0.0).
 */
export const MIN_WINDOWS_SELF_UPDATE_VERSION = '1.0.8';
const MIN_WINDOWS_SELF_UPDATE_VERSION_PARSED = parseReleaseVersion(MIN_WINDOWS_SELF_UPDATE_VERSION) ?? [1, 0, 8];

interface ReleaseCandidate {
  parsed: number[];
  release: AgentRelease;
  /** Set for the published S3 build, whose URL is presigned only once it is selected. */
  key?: string;
}

/**
 * The build this device should move to, or `undefined` when nothing strictly
 * newer than the version it is on is published for its platform, or when its
 * architecture is not one a build is published for.
 *
 * Two sources are considered: the hand-written `AGENTRELEASE/<platform>`
 * record, and the raw binary scripts/publish-installers.mjs published to the
 * installer bucket (read through `installers.agentBuild`). The higher version
 * is selected, the S3 build winning a tie, and its URL is presigned for
 * `AGENT_BUILD_URL_TTL_SECONDS`. An S3 lookup or presign failure never fails
 * the check-in: it is logged once and the S3 build is treated as absent.
 *
 * The architecture is settled first, so a device nothing could be published for
 * costs no read at all. The version the device is on is what it just reported,
 * falling back to what the profile recorded at its last check-in, and counting
 * as 0.0.0 when absent or unparseable: an agent old enough not to report its
 * version is still moved forward — except on Windows, where nothing is
 * advertised below `MIN_WINDOWS_SELF_UPDATE_VERSION`.
 */
async function resolveAgentRelease(
  deps: CheckInDependencies,
  deviceId: string,
  posted: Record<string, unknown>,
): Promise<AgentRelease | undefined> {
  const architecture = releaseArchitecture(posted);
  if (architecture === null) {
    return undefined;
  }

  const { table, installers } = deps;
  const profile = await table.get(deviceProfile(deviceId));
  const platform = typeof profile?.platform === 'string' ? profile.platform : '';
  const platformKey = `${platform}-${architecture}`;
  let key: TableKey;
  try {
    key = agentReleaseKey(platformKey);
  } catch {
    // A platform no build is published for: nothing to advertise.
    return undefined;
  }

  const record = await table.get(key);
  const recordParsed = parseReleaseVersion(record?.version);
  const recordCandidate: ReleaseCandidate | undefined =
    recordParsed === null
      ? undefined
      : {
          parsed: recordParsed,
          release: {
            version: record?.version as string,
            url: typeof record?.url === 'string' ? record.url : '',
            sha256: typeof record?.sha256 === 'string' ? record.sha256 : '',
          },
        };

  const warn = (): void => {
    console.warn(JSON.stringify({ msg: 'agent build lookup failed', deviceId }));
  };

  let buildCandidate: ReleaseCandidate | undefined;
  if (installers?.agentBuild !== undefined) {
    try {
      const buildKey = agentBuildKey(platformKey);
      const build = await installers.agentBuild(buildKey);
      const buildParsed = build === null ? null : parseReleaseVersion(build.version);
      if (build !== null && buildParsed !== null) {
        buildCandidate = {
          parsed: buildParsed,
          release: { version: build.version, url: '', sha256: build.sha256 },
          key: buildKey,
        };
      }
    } catch {
      // As if no S3 build existed: the manual record alone decides.
      warn();
    }
  }

  const profileVersion = typeof profile?.agentVersion === 'string' ? profile.agentVersion : '';
  const current = parseReleaseVersion(postedAgentVersion(posted) ?? profileVersion) ?? [0, 0, 0];
  if (platform === 'windows' && compareReleaseVersions(current, MIN_WINDOWS_SELF_UPDATE_VERSION_PARSED) < 0) {
    // The update is restarted by the running (old) build: below the minimum,
    // that restart stops the service and leaves it stopped. These devices
    // move forward by reinstalling the MSI instead.
    return undefined;
  }
  const isNewer = (candidate: ReleaseCandidate | undefined): candidate is ReleaseCandidate =>
    candidate !== undefined && compareReleaseVersions(candidate.parsed, current) > 0;

  // The higher version wins; the S3 build wins a tie.
  const selected =
    buildCandidate !== undefined &&
    (recordCandidate === undefined || compareReleaseVersions(buildCandidate.parsed, recordCandidate.parsed) >= 0)
      ? buildCandidate
      : recordCandidate;
  if (!isNewer(selected)) {
    return undefined;
  }
  if (selected.key === undefined || installers === undefined) {
    return selected.release;
  }

  try {
    const url = await installers.presignGet(selected.key, AGENT_BUILD_URL_TTL_SECONDS);
    return { ...selected.release, url };
  } catch {
    // As if no S3 build existed: the manual record alone decides.
    warn();
    return isNewer(recordCandidate) ? recordCandidate.release : undefined;
  }
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

    // The stored inventory, read before it is overwritten, for the History's
    // software changes (TASK-069). A failed read derives nothing.
    let storedInventory: Item | undefined;
    let storedInventoryRead = false;
    try {
      storedInventory = (await deps.table.get(deviceInventory(deviceId))) ?? undefined;
      storedInventoryRead = true;
    } catch {
      console.warn(JSON.stringify({ msg: 'software changes not derived', deviceId }));
    }
    // The snapshots carry the agent's collection time; the profile carries ours.
    await deps.table.put(inventoryItem(deviceId, collectedAt, objectAt(posted, 'inventory')));
    // The stored posture, read before it is overwritten, for the History's
    // posture switches (TASK-067).
    const storedPosture = await getOrUndefined(deps.table, devicePosture(deviceId));
    await deps.table.put(postureItem(deviceId, collectedAt, objectAt(posted, 'posture')));

    const at = toDate(clock());
    const lastSeenAt = isoUtc(at);
    const { gsi1pk, gsi1sk } = deviceListIndex(lastSeenAt);
    // The build the agent reported is recorded on the profile, so the next
    // check-in still knows what it is running even if that one reports nothing.
    const agentVersion = postedAgentVersion(posted);
    // The device's own zone, so the console shows its dates in it. An absent
    // or unusable zone leaves the stored one as it was.
    const timeZone = postedTimeZone(posted);
    if (timeZone === undefined && 'timeZone' in posted) {
      // A zone the agent sent but we cannot use is ignored, never refused;
      // one line says what it was.
      const sent = posted.timeZone;
      console.warn(
        JSON.stringify({
          msg: 'check-in time zone ignored',
          deviceId,
          timeZone: typeof sent === 'string' ? sent.slice(0, 64) : typeof sent,
        }),
      );
    }
    // The friendly OS name the console shows. An inventory without an OS name
    // leaves the stored one as it was.
    const osDisplay = osDisplayName(objectAt(objectAt(posted, 'inventory'), 'os')) ?? undefined;
    // The stored agent version, read before the profile update, for the
    // History's version changes (TASK-067).
    const storedProfile = await getOrUndefined(deps.table, deviceProfile(deviceId));
    await deps.table.update(deviceProfile(deviceId), {
      UpdateExpression:
        'SET lastSeenAt = :lastSeenAt, gsi1pk = :gsi1pk, gsi1sk = :gsi1sk, lastCheckInAt = :lastCheckInAt' +
        (agentVersion === undefined ? '' : ', agentVersion = :agentVersion') +
        // TIMEZONE is a DynamoDB reserved word, so it must go through a #name placeholder.
        (timeZone === undefined ? '' : ', #timeZone = :timeZone') +
        (osDisplay === undefined ? '' : ', osDisplay = :osDisplay'),
      ...(timeZone === undefined ? {} : { ExpressionAttributeNames: { '#timeZone': 'timeZone' } }),
      ExpressionAttributeValues: compact({
        ':lastSeenAt': lastSeenAt,
        ':gsi1pk': gsi1pk,
        ':gsi1sk': gsi1sk,
        // Only an accepted check-in sets this; other device routes refresh lastSeenAt alone.
        ':lastCheckInAt': lastSeenAt,
        ':agentVersion': agentVersion,
        ':timeZone': timeZone,
        ':osDisplay': osDisplay,
      }),
    });

    // The device's History: what changed against what was stored. Never a
    // reason to refuse the check-in; a failed write is swallowed.
    await recordAgentVersionChange(deps.table, deviceId, storedProfile, agentVersion, at);
    await recordPostureChanges(deps.table, deviceId, storedPosture, objectAt(posted, 'posture'), at);
    if (storedInventoryRead) {
      await recordSoftwareChanges(deps.table, deviceId, storedInventory, objectAt(posted, 'inventory'), collectedAt);
    }

    // Whatever the agent evaluated against the bundle it last pulled.
    const assignedPolicyIds = await recordPolicyCompliance(deps.table, deviceId, posted.policyCompliance, at);

    // Threat detections are stored for the admin; they never move compliance.
    await recordAntivirusFindings(deps.table, deviceId, posted.antivirusFindings, at);

    // The last scheduled scan result, likewise stored only for the admin.
    await recordAntivirusScan(deps.table, deviceId, posted.antivirusScan, at);

    // The full antivirus status, likewise stored only for the admin.
    await recordAntivirusStatus(deps.table, deviceId, collectedAt, posted.antivirusStatus, at);

    // The Defender protections block, likewise stored only for the admin; its
    // failures reach compliance only through policyCompliance.
    await recordDefenderHardening(deps.table, deviceId, posted.defenderHardening, at);

    // The agent's own warn/error records, likewise stored only for the admin.
    await recordAgentErrors(deps.table, deviceId, posted.agentErrors, at);

    // The actions the agent performed on the device, as agent events in its
    // History (TASK-070).
    await recordAgentActions(deps.table, deviceId, posted.agentActions, at);

    // The admin's per-device switch: only a stored `false` turns collection off.
    const settings = await deps.table.get(deviceSettings(deviceId));
    const analyticsDisabled = settings?.analyticsEnabled === false;

    // Endpoint analytics: sanitised, never a reason to refuse the heartbeat.
    // A device whose collection is off has nothing stored, spooled blocks included.
    if (!analyticsDisabled) {
      await recordAnalytics(deps.table, deviceId, collectedAt, posted.analytics, at);
    }

    // The daily IP-based location ping, only while a policy enables it. A
    // failure is logged and never changes the check-in's answer.
    try {
      await captureLocation(deps.table, deviceId, req?.headers, at, { assignedPolicyIds });
    } catch {
      console.warn(JSON.stringify({ msg: 'location capture failed', deviceId }));
    }

    // The admin's per-device heartbeat switch, independent of analytics collection.
    const heartbeat = await deps.table.get(deviceHeartbeatSettings(deviceId));
    const heartbeatOn =
      heartbeat?.heartbeatEnabled === true &&
      typeof heartbeat.intervalSeconds === 'number' &&
      HEARTBEAT_INTERVAL_OPTIONS_SECONDS.includes(heartbeat.intervalSeconds);

    const release = await resolveAgentRelease(deps, deviceId, posted);

    const responseBody: CheckInResponse = {
      checkInIntervalSeconds: DEFAULT_CHECKIN_INTERVAL_SECONDS,
      pendingCommandCount: await countPendingCommands(deps.table, deviceId),
    };
    if (analyticsDisabled) {
      responseBody.analyticsEnabled = false;
    }
    if (heartbeatOn) {
      responseBody.heartbeatIntervalSeconds = heartbeat.intervalSeconds as number;
    }
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
