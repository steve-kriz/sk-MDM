/**
 * The per-device event store behind the device detail's History.
 *
 * One item per action performed on a device, written at the moment it
 * happens, under `DEVICE#<deviceId>` / `EVENT#<occurredAt>#<eventId>`:
 *
 *   await recordDeviceEvent(table, {
 *     deviceId,
 *     source: 'admin',
 *     type: 'device.disabled',
 *     summary: 'Device disabled',
 *     actor,
 *     occurredAt: at,
 *   });
 *
 * `source` is `admin` (a person did it), `agent` (the device's agent did it)
 * or `system` (the backend observed or caused it). Items carry a `ttl` of
 * `occurredAt` + `DEVICE_EVENT_RETENTION_SECONDS`; the reader applies the same
 * cutoff because TTL deletion is lazy.
 *
 * Recording never fails the caller: a put that throws is logged with one
 * `console.warn` line and swallowed, so an action that succeeded is never
 * reported as failed because its History row could not be written.
 */
import { randomBytes } from 'node:crypto';
import { isoUtc, toUtcDate } from './audit.js';
import { deviceEvent, group as groupKey, type TableKey } from './db/keys.js';
import type { Item } from './db/table.js';

/** How long an event is kept: 30 days, by TTL and by the read-time cutoff. */
export const DEVICE_EVENT_RETENTION_SECONDS = 2592000;

/** The most events the device detail endpoint returns. */
export const MAX_DETAIL_DEVICE_EVENTS = 100;

/** Longest stored `summary`. */
export const MAX_DEVICE_EVENT_SUMMARY_LENGTH = 256;

/** Most `details` entries kept. */
export const MAX_DEVICE_EVENT_DETAILS = 8;

/** Longest stored `details` key. */
export const MAX_DEVICE_EVENT_DETAIL_KEY_LENGTH = 64;

/** Longest stored `details` value. */
export const MAX_DEVICE_EVENT_DETAIL_VALUE_LENGTH = 256;

/** Who caused an event. */
export type DeviceEventSource = 'admin' | 'agent' | 'system';

/** The storage operation `recordDeviceEvent` needs: the subset a fake must implement. */
export interface DeviceEventTable {
  put(item: Item): Promise<void>;
}

/** One event to record. */
export interface DeviceEventInput {
  deviceId: string;
  source: DeviceEventSource;
  type: string;
  summary: string;
  details?: Record<string, unknown>;
  actor?: string | null;
  occurredAt: Date | string;
  eventId?: string;
}

/** Only string-valued entries, the first 8, keys and values cut; `{}` when absent. */
function storedDetails(details: Record<string, unknown> | undefined): Record<string, string> {
  const stored: Record<string, string> = {};
  if (typeof details !== 'object' || details === null || Array.isArray(details)) {
    return stored;
  }
  let kept = 0;
  for (const [key, value] of Object.entries(details)) {
    if (kept >= MAX_DEVICE_EVENT_DETAILS) {
      break;
    }
    if (typeof value !== 'string') {
      continue;
    }
    stored[key.slice(0, MAX_DEVICE_EVENT_DETAIL_KEY_LENGTH)] = value.slice(0, MAX_DEVICE_EVENT_DETAIL_VALUE_LENGTH);
    kept += 1;
  }
  return stored;
}

/**
 * Put one event item. Never rejects: when building the item or the put
 * throws, one `console.warn` JSON line is written and the promise resolves.
 */
export async function recordDeviceEvent(table: DeviceEventTable, event: DeviceEventInput): Promise<void> {
  try {
    const occurredDate = event.occurredAt instanceof Date ? event.occurredAt : toUtcDate(event.occurredAt);
    const occurredAt = isoUtc(occurredDate);
    const eventId = event.eventId ?? randomBytes(16).toString('hex');
    const key: TableKey = deviceEvent(event.deviceId, occurredAt, eventId);
    const ttl = Math.floor(Date.parse(occurredAt) / 1000) + DEVICE_EVENT_RETENTION_SECONDS;
    await table.put({
      ...key,
      deviceId: event.deviceId,
      eventId,
      source: event.source,
      type: event.type,
      summary: String(event.summary).slice(0, MAX_DEVICE_EVENT_SUMMARY_LENGTH),
      details: storedDetails(event.details),
      actor: typeof event.actor === 'string' ? event.actor : null,
      occurredAt,
      recordedAt: isoUtc(new Date()),
      ttl,
    });
  } catch {
    console.warn(JSON.stringify({ msg: 'device event not recorded', deviceId: event.deviceId, type: event.type }));
  }
}

/**
 * The name a group is shown by in an event summary: the group record's string
 * `name`, else the `groupId` (no record, no string name, or the read failed).
 */
export async function deviceEventGroupName(
  table: { get(key: TableKey): Promise<Item | undefined> },
  groupId: string,
): Promise<string> {
  try {
    const record = await table.get(groupKey(groupId));
    if (record !== undefined && record !== null && typeof record.name === 'string') {
      return record.name;
    }
  } catch {
    // Fall back to the id.
  }
  return groupId;
}
