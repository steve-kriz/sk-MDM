/**
 * Software installed, removed or updated on a device, derived at check-in by
 * comparing the stored INVENTORY software list with the newly posted one, and
 * recorded as `system` events in the device History (TASK-067's event store).
 *
 * An entry's identity is its name, trimmed and lower-cased; publisher is left
 * out because it can flip between collections. Each identity holds a set of
 * exact version strings per side:
 *
 *   - only posted: one `software.installed` per version;
 *   - only stored: one `software.removed` per version;
 *   - both, one version each, different: one `software.updated`;
 *   - both, any other difference: installed / removed per differing version.
 *
 * No baseline means no events: a missing or empty stored list, an unusable
 * stored `collectedAt`, an empty or failed posted collection, or a posted
 * `collectedAt` that is not strictly newer all derive nothing. Event ids are
 * deterministic, so a re-sent body overwrites the same items.
 */
import { createHash } from 'node:crypto';
import { isoUtc } from './audit.js';
import { recordDeviceEvent, type DeviceEventTable } from './deviceEvents.js';

/** The most individual software events one check-in writes. */
export const MAX_SOFTWARE_EVENTS_PER_CHECKIN = 20;

/** The posted inventory warnings that mean the software probe failed. */
const SOFTWARE_FAILURE_WARNINGS = ['software', 'software:timeout'];

/** The kinds of software change. */
export type SoftwareChangeType = 'software.installed' | 'software.removed' | 'software.updated';

/** One derived software change. */
export interface SoftwareChange {
  type: SoftwareChangeType;
  key: string;
  name: string;
  version?: string;
  from?: string;
  to?: string;
  publisher?: string;
}

/** The first entry seen for one key + version: its name and publisher. */
interface EntryInfo {
  name: string;
  publisher?: string;
}

/** Per key, per version (in first-seen order), the first entry carrying it. */
type SoftwareIndex = Map<string, Map<string, EntryInfo>>;

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Group the valid entries of a software list by key, then by version. */
function indexSoftware(list: unknown): SoftwareIndex {
  const index: SoftwareIndex = new Map();
  if (!Array.isArray(list)) {
    return index;
  }
  for (const entry of list) {
    if (!isObject(entry) || typeof entry.name !== 'string' || typeof entry.version !== 'string') {
      continue;
    }
    const name = entry.name.trim();
    const version = entry.version.trim();
    if (name === '' || version === '') {
      continue;
    }
    const key = name.toLowerCase();
    let versions = index.get(key);
    if (versions === undefined) {
      versions = new Map();
      index.set(key, versions);
    }
    if (versions.has(version)) {
      continue;
    }
    const publisher = typeof entry.publisher === 'string' ? entry.publisher.trim() : '';
    versions.set(version, publisher === '' ? { name } : { name, publisher });
  }
  return index;
}

function change(type: SoftwareChangeType, key: string, info: EntryInfo, fields: Partial<SoftwareChange>): SoftwareChange {
  return {
    type,
    key,
    name: info.name,
    ...fields,
    ...(info.publisher === undefined ? {} : { publisher: info.publisher }),
  };
}

const TYPE_ORDER: Record<SoftwareChangeType, number> = {
  'software.removed': 0,
  'software.updated': 1,
  'software.installed': 2,
};

function compareStrings(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** The version a change is ordered by: `to` for an update. */
function sortVersion(entry: SoftwareChange): string {
  return (entry.type === 'software.updated' ? entry.to : entry.version) ?? '';
}

/**
 * The software changes between a stored and a posted list, sorted by key,
 * then type (removed, updated, installed), then version (`to` for updated).
 */
export function softwareChanges(storedSoftware: unknown, postedSoftware: unknown): SoftwareChange[] {
  const stored = indexSoftware(storedSoftware);
  const posted = indexSoftware(postedSoftware);
  const changes: SoftwareChange[] = [];

  for (const [key, postedVersions] of posted) {
    const storedVersions = stored.get(key);
    if (storedVersions === undefined) {
      for (const [version, info] of postedVersions) {
        changes.push(change('software.installed', key, info, { version }));
      }
      continue;
    }
    const added = [...postedVersions.keys()].filter((version) => !storedVersions.has(version));
    const dropped = [...storedVersions.keys()].filter((version) => !postedVersions.has(version));
    if (added.length === 0 && dropped.length === 0) {
      continue;
    }
    if (storedVersions.size === 1 && postedVersions.size === 1) {
      const from = [...storedVersions.keys()][0] as string;
      const [to, info] = [...postedVersions.entries()][0] as [string, EntryInfo];
      changes.push(change('software.updated', key, info, { from, to }));
      continue;
    }
    for (const version of added) {
      changes.push(change('software.installed', key, postedVersions.get(version) as EntryInfo, { version }));
    }
    for (const version of dropped) {
      changes.push(change('software.removed', key, storedVersions.get(version) as EntryInfo, { version }));
    }
  }

  for (const [key, storedVersions] of stored) {
    if (posted.has(key)) {
      continue;
    }
    for (const [version, info] of storedVersions) {
      changes.push(change('software.removed', key, info, { version }));
    }
  }

  return changes.sort(
    (a, b) =>
      compareStrings(a.key, b.key) ||
      TYPE_ORDER[a.type] - TYPE_ORDER[b.type] ||
      compareStrings(sortVersion(a), sortVersion(b)),
  );
}

/** The first 32 lower-case hex characters of the sha256 of `input`. */
function eventIdOf(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex').slice(0, 32);
}

/** The History event fields for one change. */
function changeEvent(
  entry: SoftwareChange,
  collectedAt: string,
): { type: string; summary: string; details: Record<string, string>; eventId: string } {
  const publisher: Record<string, string> = entry.publisher === undefined ? {} : { publisher: entry.publisher };
  if (entry.type === 'software.updated') {
    const from = entry.from ?? '';
    const to = entry.to ?? '';
    return {
      type: entry.type,
      summary: `Updated ${entry.name} from ${from} to ${to}`,
      details: { name: entry.name, from, to, ...publisher },
      eventId: eventIdOf(`${entry.type}\n${collectedAt}\n${entry.key}\n${from}\n${to}`),
    };
  }
  const version = entry.version ?? '';
  const installed = entry.type === 'software.installed';
  return {
    type: entry.type,
    summary: `${installed ? 'Installed' : 'Removed'} ${entry.name} ${version}`,
    details: { name: entry.name, version, ...publisher },
    eventId: eventIdOf(
      installed
        ? `${entry.type}\n${collectedAt}\n${entry.key}\n\n${version}`
        : `${entry.type}\n${collectedAt}\n${entry.key}\n${version}\n`,
    ),
  };
}

/** Whether the posted inventory's warnings say the software probe failed. */
function softwareProbeFailed(postedInventory: Record<string, unknown>): boolean {
  const warnings = postedInventory.warnings;
  return Array.isArray(warnings) && warnings.some((warning) => SOFTWARE_FAILURE_WARNINGS.includes(warning));
}

/**
 * Derive and record the software changes of one check-in. Writes nothing
 * without a usable baseline (see the module comment). Each event is awaited in
 * turn; `recordDeviceEvent` never rejects, so a failed put is logged by it and
 * the remaining events are still attempted.
 *
 * @param storedItem the INVENTORY item read before the check-in overwrote it
 * @param postedInventory the posted `inventory` object
 * @param collectedAt the posted `collectedAt`, verbatim
 */
export async function recordSoftwareChanges(
  table: DeviceEventTable,
  deviceId: string,
  storedItem: Record<string, unknown> | undefined,
  postedInventory: Record<string, unknown>,
  collectedAt: string,
): Promise<void> {
  if (storedItem === undefined || storedItem === null) {
    return;
  }
  const storedSoftware = storedItem.software;
  if (!Array.isArray(storedSoftware) || storedSoftware.length === 0) {
    return;
  }
  const storedCollectedAt = storedItem.collectedAt;
  if (typeof storedCollectedAt !== 'string' || Number.isNaN(Date.parse(storedCollectedAt))) {
    return;
  }
  const postedSoftware = postedInventory.software;
  if (!Array.isArray(postedSoftware) || postedSoftware.length === 0 || softwareProbeFailed(postedInventory)) {
    return;
  }
  const postedTime = Date.parse(collectedAt);
  if (Number.isNaN(postedTime) || postedTime <= Date.parse(storedCollectedAt)) {
    return;
  }

  const changes = softwareChanges(storedSoftware, postedSoftware);
  if (changes.length === 0) {
    return;
  }
  const occurredAt = isoUtc(new Date(collectedAt));

  for (const entry of changes.slice(0, MAX_SOFTWARE_EVENTS_PER_CHECKIN)) {
    const event = changeEvent(entry, collectedAt);
    await recordDeviceEvent(table, {
      deviceId,
      source: 'system',
      type: event.type,
      summary: event.summary,
      details: event.details,
      actor: null,
      occurredAt,
      eventId: event.eventId,
    });
  }

  const rest = changes.slice(MAX_SOFTWARE_EVENTS_PER_CHECKIN);
  if (rest.length === 0) {
    return;
  }
  const count = (type: SoftwareChangeType): string => String(rest.filter((entry) => entry.type === type).length);
  const installed = count('software.installed');
  const removed = count('software.removed');
  const updated = count('software.updated');
  await recordDeviceEvent(table, {
    deviceId,
    source: 'system',
    type: 'software.more_changes',
    summary: `And ${rest.length} more software changes (${installed} installed, ${removed} removed, ${updated} updated)`,
    details: { installed, removed, updated },
    actor: null,
    occurredAt,
    eventId: eventIdOf(`software.more_changes\n${collectedAt}`),
  });
}
