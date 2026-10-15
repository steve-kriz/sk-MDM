/**
 * Coarse device location, worked out on the server from the request's source IP.
 *
 * CloudFront adds viewer geolocation headers (`CloudFront-Viewer-Latitude`,
 * `-Longitude`, `-City`, `-Country`, `-Country-Region-Name`) to every request
 * it forwards to the Function URL origin. This module is the one place those
 * headers are parsed, so the enrollment route (`src/routes/enroll.ts`) and the
 * check-in route (`src/routes/checkin.ts`) apply exactly the same rules:
 *
 *   const capture = parseViewerLocation(req.headers, at);
 *   if (capture !== null && (await locationTrackingEnabled(table, deviceId))) {
 *     await writeLocation(table, deviceId, capture);
 *   }
 *
 * A location is only ever collected while the device's effective
 * `locationTracking` setting -- the existing smallest-`policyId`-wins merge
 * (`src/policies/merge.ts`) over its assigned policies -- is exactly `true`.
 *
 * One `DEVICE#<deviceId>` / `LOCATION` item holds the latest capture as
 * top-level fields plus `history`, newest first, at most `MAX_LOCATION_HISTORY`
 * entries. A request without usable coordinates (the raw Function URL bypasses
 * CloudFront, and so do local tests) writes nothing.
 *
 * Spoofing is an accepted risk: a device that calls the raw Function URL can
 * forge these headers, and nothing here tries to detect it.
 */
import { isoUtc } from '../audit.js';
import { deviceLocation, policy as policyKey, type TableKey } from '../db/keys.js';
import type { Item } from '../db/table.js';
import type { RouteRequest } from '../http/router.js';
import { mergePolicySettings, type PolicyDocument } from '../policies/merge.js';
import { readAssignedPolicies, type PolicyReadTable } from '../policies/resolve.js';

/** Most captures kept in `history`: about 30 days of daily pings. */
export const MAX_LOCATION_HISTORY = 30;

/** Longest stored city or region, in characters. */
export const MAX_LOCATION_TEXT_LENGTH = 128;

/** How long a check-in capture stays current before the next one is taken. */
export const LOCATION_CAPTURE_INTERVAL_SECONDS = 86400;

/** The source every IP-derived capture records. */
export const IP_LOCATION_SOURCE = 'ip';

/** The CloudFront viewer headers read, lower-cased. */
export const VIEWER_LATITUDE_HEADER = 'cloudfront-viewer-latitude';
export const VIEWER_LONGITUDE_HEADER = 'cloudfront-viewer-longitude';
export const VIEWER_CITY_HEADER = 'cloudfront-viewer-city';
export const VIEWER_REGION_HEADER = 'cloudfront-viewer-country-region-name';
export const VIEWER_COUNTRY_HEADER = 'cloudfront-viewer-country';

/** One capture, as stored at the top level of the item and in each `history` entry. */
export interface LocationCapture {
  latitude: number;
  longitude: number;
  city: string | null;
  region: string | null;
  country: string | null;
  source: string;
  accuracyMeters: number | null;
  capturedAt: string;
}

/** The storage operations a capture needs: policy resolution plus the item read and write. */
export interface LocationTable extends PolicyReadTable {
  put(item: Item): Promise<void>;
}

/** A plain decimal number: no hex, no exponent, no blanks. */
const DECIMAL_PATTERN = /^[+-]?(\d+(\.\d*)?|\.\d+)$/;

/** A two-letter upper-case country code. */
const COUNTRY_PATTERN = /^[A-Z]{2}$/;

/** True for a plain JSON object: not a primitive, not null, not an array. */
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** A header's value, matched case-insensitively; `''` when absent. */
function headerValue(headers: RouteRequest['headers'] | undefined, name: string): string {
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (key.toLowerCase() === name && typeof value === 'string') {
      return value;
    }
  }
  return '';
}

/** A coordinate parsed from header text, or `null` when it is not a finite number inside the range. */
function coordinate(text: string, limit: number): number | null {
  const trimmed = text.trim();
  if (!DECIMAL_PATTERN.test(trimmed)) {
    return null;
  }
  const value = Number(trimmed);
  return Number.isFinite(value) && value >= -limit && value <= limit ? value : null;
}

/** Trimmed text cut to the stored length, or `null` when empty. */
function boundedText(value: unknown): string | null {
  if (typeof value !== 'string') {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed.slice(0, MAX_LOCATION_TEXT_LENGTH) : null;
}

/** A country code, or `null` when it is not two upper-case letters. */
function countryCode(value: unknown): string | null {
  return typeof value === 'string' && COUNTRY_PATTERN.test(value) ? value : null;
}

/**
 * The capture the request's viewer headers describe, stamped with the server
 * instant `at`, or `null` when the latitude or longitude is missing or unusable.
 */
export function parseViewerLocation(
  headers: RouteRequest['headers'] | undefined,
  at: Date,
): LocationCapture | null {
  const latitude = coordinate(headerValue(headers, VIEWER_LATITUDE_HEADER), 90);
  const longitude = coordinate(headerValue(headers, VIEWER_LONGITUDE_HEADER), 180);
  if (latitude === null || longitude === null) {
    return null;
  }
  return {
    latitude,
    longitude,
    city: boundedText(headerValue(headers, VIEWER_CITY_HEADER)),
    region: boundedText(headerValue(headers, VIEWER_REGION_HEADER)),
    country: countryCode(headerValue(headers, VIEWER_COUNTRY_HEADER)),
    source: IP_LOCATION_SOURCE,
    accuracyMeters: null,
    capturedAt: isoUtc(at),
  };
}

/** A stored capture in the stored shape, or `null` when it is malformed. */
export function storedCapture(value: unknown): LocationCapture | null {
  if (!isObject(value)) {
    return null;
  }
  const { latitude, longitude, capturedAt } = value;
  if (
    typeof latitude !== 'number' ||
    !Number.isFinite(latitude) ||
    latitude < -90 ||
    latitude > 90 ||
    typeof longitude !== 'number' ||
    !Number.isFinite(longitude) ||
    longitude < -180 ||
    longitude > 180 ||
    typeof capturedAt !== 'string' ||
    Number.isNaN(Date.parse(capturedAt))
  ) {
    return null;
  }
  return {
    latitude,
    longitude,
    city: boundedText(value.city),
    region: boundedText(value.region),
    country: countryCode(value.country),
    source: typeof value.source === 'string' && value.source.length > 0 ? value.source : IP_LOCATION_SOURCE,
    accuracyMeters:
      typeof value.accuracyMeters === 'number' && Number.isFinite(value.accuracyMeters)
        ? value.accuracyMeters
        : null,
    capturedAt,
  };
}

/** The stored item's history, malformed entries dropped, in stored order. */
export function storedHistory(item: Item | undefined | null): LocationCapture[] {
  const history = Array.isArray(item?.history) ? item.history : [];
  return history
    .map((entry) => storedCapture(entry))
    .filter((entry): entry is LocationCapture => entry !== null);
}

/**
 * The item a capture leaves behind: its fields at the top level, and the new
 * capture prepended to the valid stored history, capped at
 * `MAX_LOCATION_HISTORY` entries, newest first.
 */
export function foldLocation(
  deviceId: string,
  existing: Item | undefined | null,
  capture: LocationCapture,
): Item {
  return {
    ...deviceLocation(deviceId),
    deviceId,
    ...capture,
    history: [capture, ...storedHistory(existing)].slice(0, MAX_LOCATION_HISTORY),
  };
}

/**
 * True when the stored item's `capturedAt` is less than
 * `LOCATION_CAPTURE_INTERVAL_SECONDS` before `at`, so a check-in takes no new capture.
 */
export function isCaptureCurrent(existing: Item | undefined | null, at: Date): boolean {
  const capturedAt = typeof existing?.capturedAt === 'string' ? Date.parse(existing.capturedAt) : NaN;
  if (Number.isNaN(capturedAt)) {
    return false;
  }
  return (at.getTime() - capturedAt) / 1000 < LOCATION_CAPTURE_INTERVAL_SECONDS;
}

/** The effective `locationTracking` of a set of policies: on only when exactly `true`. */
export function trackingFromPolicies(policies: readonly PolicyDocument[]): boolean {
  return mergePolicySettings(policies).effectiveSettings.locationTracking === true;
}

/** The policy documents for already-resolved ids, skipping any record that no longer exists. */
async function readPoliciesByIds(table: PolicyReadTable, policyIds: readonly string[]): Promise<PolicyDocument[]> {
  const policies: PolicyDocument[] = [];
  for (const policyId of policyIds) {
    let key: TableKey;
    try {
      key = policyKey(policyId);
    } catch {
      continue;
    }
    const record = await table.get(key);
    if (record === undefined || record === null) {
      continue;
    }
    policies.push({
      policyId,
      version: typeof record.version === 'number' ? record.version : 0,
      settings: isObject(record.settings) ? record.settings : {},
    });
  }
  return policies;
}

/**
 * The device's effective `locationTracking`. When the caller already resolved
 * the assigned policy ids (the check-in's compliance step), they are reused
 * rather than resolved a second time.
 */
export async function locationTrackingEnabled(
  table: PolicyReadTable,
  deviceId: string,
  assignedPolicyIds?: readonly string[],
): Promise<boolean> {
  const policies =
    assignedPolicyIds === undefined
      ? await readAssignedPolicies(table, deviceId)
      : await readPoliciesByIds(table, assignedPolicyIds);
  return trackingFromPolicies(policies);
}

/** Options for `captureLocation`. */
export interface CaptureOptions {
  /** Capture whatever the stored `capturedAt` is (enrollment). Default `false`. */
  force?: boolean;
  /** The device's assigned policy ids, when the caller already resolved them. */
  assignedPolicyIds?: readonly string[];
}

/**
 * Capture the request's location for a device, when its policies enable it.
 *
 * In order, and stopping at the first that fails: the viewer headers carry
 * usable coordinates; unless `force`, the stored capture is not current (so a
 * fresh one costs no policy resolution); the effective `locationTracking` is
 * `true`. Only then is the folded item written. Returns whether it wrote.
 * Errors propagate: the caller decides how a failure is reported.
 */
export async function captureLocation(
  table: LocationTable,
  deviceId: string,
  headers: RouteRequest['headers'] | undefined,
  at: Date,
  options: CaptureOptions = {},
): Promise<boolean> {
  const capture = parseViewerLocation(headers, at);
  if (capture === null) {
    return false;
  }
  const key = deviceLocation(deviceId);
  const existing = await table.get(key);
  if (options.force !== true && isCaptureCurrent(existing, at)) {
    return false;
  }
  if (!(await locationTrackingEnabled(table, deviceId, options.assignedPolicyIds))) {
    return false;
  }
  await table.put(foldLocation(deviceId, existing, capture));
  return true;
}

/** The location view the admin device detail returns. */
export interface LocationView {
  latest: LocationCapture | null;
  history: LocationCapture[];
}

/** The admin view of a stored item: `{latest: null, history: []}` when none exists. */
export function locationView(item: Item | undefined | null): LocationView {
  if (item === undefined || item === null) {
    return { latest: null, history: [] };
  }
  return { latest: storedCapture(item), history: storedHistory(item) };
}
