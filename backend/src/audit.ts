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
 *
 * The read side is `queryAudit`, which walks the same partitions backwards --
 * newest UTC day first, newest `seq` first within a day -- and reads through
 * `keys.audit(dayUtc, seq)` exactly as the writer does. There is one audit key
 * shape and this module owns both ends of it.
 */
import { randomBytes } from 'node:crypto';
import { audit as auditKey } from './db/keys.js';
import { decodeCursor, encodeCursor, type Item, type QueryPage, type QueryRequest } from './db/table.js';

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

/** Milliseconds in one UTC day; the step the range walks day partitions with. */
const DAY_MILLIS = 86400000;

/** Entries returned when the caller names no `limit`. */
export const AUDIT_DEFAULT_LIMIT = 50;

/** The most entries one `queryAudit` page may hold. */
export const AUDIT_MAX_LIMIT = 200;

/**
 * The most day partitions one call reads before it stops and hands back a
 * cursor. A long range of mostly empty days therefore costs a bounded number
 * of queries per request; the caller simply pages on.
 */
export const AUDIT_MAX_DAYS_PER_PAGE = 31;

/** The storage operation the read side needs: the subset a fake must implement. */
export interface AuditQueryTable {
  query(request?: QueryRequest): Promise<QueryPage>;
}

/** An inclusive instant range, plus the usual paging controls. */
export interface AuditQuery {
  /** Start of the range, as an instant `toUtcDate` accepts. Its UTC day is included. */
  fromIso: AuditInstant;
  /** End of the range. Its UTC day is included. */
  toIso: AuditInstant;
  /** Page size. Clamped to 1..`AUDIT_MAX_LIMIT`; defaults to `AUDIT_DEFAULT_LIMIT`. */
  limit?: number;
  /** Cursor from a previous page, or `null`/`undefined` for the first. */
  cursor?: string | null;
}

/** One page of audit entries. `cursor` is `null` when the range is exhausted. */
export interface AuditPage {
  items: Item[];
  cursor: string | null;
}

/** Where a cursor resumes: the day partition, and the position inside it. */
interface AuditPosition {
  day: string;
  within: string | null;
}

/** Every UTC day in the inclusive range, newest first. */
function daysDescending(fromDay: string, toDay: string): string[] {
  const oldest = Date.parse(`${fromDay}T00:00:00Z`);
  const days: string[] = [];
  for (let at = Date.parse(`${toDay}T00:00:00Z`); at >= oldest; at -= DAY_MILLIS) {
    days.push(new Date(at).toISOString().slice(0, 10));
  }
  return days;
}

/** Keep `limit` inside the bounds this module pages with. */
function clampLimit(limit: number | undefined): number {
  if (typeof limit !== 'number' || !Number.isFinite(limit)) {
    return AUDIT_DEFAULT_LIMIT;
  }
  return Math.min(Math.max(Math.trunc(limit), 1), AUDIT_MAX_LIMIT);
}

/** Read a cursor back into a position, or `null` when it is not one of ours. */
function decodePosition(cursor: string): AuditPosition | null {
  const decoded = decodeCursor(cursor);
  const day = decoded.day;
  if (typeof day !== 'string' || day.length === 0) {
    return null;
  }
  return { day, within: typeof decoded.within === 'string' ? decoded.within : null };
}

/** `AUDIT#<day>` as the key builder writes it -- never assembled by hand here. */
function dayPartition(day: string): string {
  return auditKey(day, '').pk;
}

/**
 * Newest first across the assembled page: UTC day descending, then `seq`
 * descending. The store already returns each day that way; sorting the
 * assembled page keeps the order true when one page spans two days.
 */
function newestFirst(left: Item, right: Item): number {
  const leftPk = typeof left.pk === 'string' ? left.pk : '';
  const rightPk = typeof right.pk === 'string' ? right.pk : '';
  if (leftPk !== rightPk) {
    return leftPk < rightPk ? 1 : -1;
  }
  const leftSk = typeof left.sk === 'string' ? left.sk : '';
  const rightSk = typeof right.sk === 'string' ? right.sk : '';
  if (leftSk === rightSk) {
    return 0;
  }
  return leftSk < rightSk ? 1 : -1;
}

/**
 * Read the audit entries whose UTC day falls in an inclusive range.
 *
 *   const page = await queryAudit(table, {
 *     fromIso: '2026-10-01T00:00:00Z', toIso: '2026-10-03T23:59:59Z', limit: 50,
 *   });
 *   const next = await queryAudit(table, { fromIso, toIso, limit: 50, cursor: page.cursor });
 *
 * Entries come back newest first and a page may span several day partitions.
 * The returned cursor carries the day it stopped on and the position inside
 * it, so passing it back resumes exactly where the previous page ended: no
 * entry is lost and none is returned twice. A cursor from a different range is
 * not ours to resume and yields an empty, final page.
 *
 * @throws when `from` is after `to`, or either bound is not an instant.
 */
export async function queryAudit(
  table: AuditQueryTable,
  { fromIso, toIso, limit, cursor = null }: AuditQuery,
): Promise<AuditPage> {
  const from = toUtcDate(fromIso);
  const to = toUtcDate(toIso);
  if (from.getTime() > to.getTime()) {
    throw new Error('invalid range: from is after to');
  }

  const pageSize = clampLimit(limit);
  const days = daysDescending(utcDay(from), utcDay(to));

  let index = 0;
  let within: string | null = null;
  if (typeof cursor === 'string' && cursor.length > 0) {
    const position = decodePosition(cursor);
    const resumeAt = position === null ? -1 : days.indexOf(position.day);
    if (position === null || resumeAt === -1) {
      return { items: [], cursor: null };
    }
    index = resumeAt;
    within = position.within;
  }

  const items: Item[] = [];
  let daysRead = 0;
  while (items.length < pageSize && index < days.length && daysRead < AUDIT_MAX_DAYS_PER_PAGE) {
    const page = await table.query({
      KeyConditionExpression: '#pk = :pk',
      ExpressionAttributeNames: { '#pk': 'pk' },
      ExpressionAttributeValues: { ':pk': dayPartition(days[index] as string) },
      // Descending, so the newest `seq` of the day comes back first.
      ScanIndexForward: false,
      limit: pageSize - items.length,
      cursor: within,
    });
    items.push(...page.items);

    const next = page.cursor ?? null;
    if (next === null || next === within) {
      // The day is exhausted -- or its cursor did not move, which would page
      // forever -- so continue with the next older day.
      index += 1;
      within = null;
      daysRead += 1;
    } else {
      within = next;
    }
  }

  items.sort(newestFirst);
  const exhausted = index >= days.length;
  return {
    items,
    cursor: exhausted ? null : encodeCursor({ day: days[index] as string, within }),
  };
}
