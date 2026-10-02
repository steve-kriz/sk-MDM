/**
 * The audit trail: one append-only item per thing that happened.
 *
 * Every writer in the backend goes through `appendAudit` rather than writing
 * an `AUDIT#...` item itself, so the stored shape is decided in exactly one
 * place:
 *
 *   await appendAudit(table, {
 *     action: 'device.enrolled',
 *     actor: `device:${deviceId}`,
 *     target: deviceId,
 *     detail: { hardwareUuid, platform, agentVersion },
 *     now,
 *   });
 *
 * `actor` is `device:<deviceId>` when an agent caused the entry and the admin's
 * user principal name when a person did. `detail` is optional and the attribute
 * is omitted entirely when it is not supplied, so a reader never has to tell an
 * absent detail from an empty one.
 *
 * Entries are partitioned by UTC day (`AUDIT#2026-10-02`) and sorted by `seq`,
 * which is the zero-padded epoch milliseconds plus eight random hex characters:
 * the padding makes lexicographic order match time order, and the random tail
 * keeps two entries written in the same millisecond from overwriting each
 * other.
 *
 * Never put a secret in `detail`: these items are read by every admin.
 */
import { randomBytes } from 'node:crypto';
import { audit as auditKey } from './db/keys.js';
import type { Item } from './db/table.js';

/** Random bytes appended to `seq`, rendered as 8 lower-case hex characters. */
export const SEQ_SUFFIX_BYTES = 4;

/** Width `epochMillis` is zero-padded to, so `seq` sorts lexicographically. */
export const SEQ_MILLIS_DIGITS = 13;

/** Shape of every `seq` this module builds. */
export const SEQ_PATTERN = /^[0-9]{13}-[0-9a-f]{8}$/;

/**
 * An instant, however the caller happens to hold it: a `Date`, epoch
 * milliseconds, an ISO-8601 string, or a clock function returning one of those.
 */
export type AuditInstant = Date | number | string;
export type AuditClock = () => AuditInstant;

/** The storage operation this module needs: the subset a fake must implement. */
export interface AuditTable {
  put(item: Item): Promise<void>;
}

/** One entry to append. */
export interface AuditEntry {
  /** What happened, e.g. `device.enrolled`, `group.created`. */
  action: string;
  /** Who caused it: `device:<deviceId>`, or the admin user principal name. */
  actor: string;
  /** What it happened to, e.g. the device or group id. */
  target: string;
  /** Extra context. Omitted from the item when absent. Never secrets. */
  detail?: Record<string, unknown>;
  /** Current time, or a clock returning it. */
  now: AuditClock | AuditInstant;
}

/** Normalise whatever a caller passed as `now` into a `Date`. */
export function toUtcDate(value: AuditClock | AuditInstant): Date {
  const instant = typeof value === 'function' ? value() : value;
  const date =
    instant instanceof Date ? new Date(instant.getTime()) : new Date(instant as string | number);
  if (Number.isNaN(date.getTime())) {
    throw new Error('invalid now: expected a Date, epoch milliseconds or an ISO-8601 string');
  }
  return date;
}

/** Render an instant the way every stored timestamp is written: `2026-10-02T09:00:00Z`. */
export function isoUtc(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** The UTC `YYYY-MM-DD` the entry is partitioned under. */
export function utcDay(date: Date): string {
  return date.toISOString().slice(0, 10);
}

/** `<epochMillis padded to 13>-<8 hex>`: time ordered, and unique within a millisecond. */
export function auditSeq(date: Date): string {
  const millis = String(date.getTime()).padStart(SEQ_MILLIS_DIGITS, '0');
  return `${millis}-${randomBytes(SEQ_SUFFIX_BYTES).toString('hex')}`;
}

/**
 * Append exactly one audit entry.
 *
 * @returns the item written, so a caller can log or assert on it
 */
export async function appendAudit(
  table: AuditTable,
  { action, actor, target, detail, now }: AuditEntry,
): Promise<Item> {
  const at = toUtcDate(now);
  const item: Item = {
    ...auditKey(utcDay(at), auditSeq(at)),
    action,
    actor,
    target,
    at: isoUtc(at),
  };
  if (detail !== undefined) {
    item.detail = detail;
  }
  await table.put(item);
  return item;
}
