/**
 * The fleet software view.
 *
 *   GET /admin/api/v1/software?search=<text>&sort=name|devices&offset=<n>&limit=<n>
 *   GET /admin/api/v1/software/devices?name=<exact>[&version=<exact>]
 *
 *   registerSoftwareRoutes(router, { verifier, table, now });
 *
 * Built at read time from what the check-in route stores: every device's
 * latest inventory carries `gsi1pk = "INVENTORY"`, so one `gsi1` query lists
 * every device's software. Nothing is pre-aggregated and nothing is scanned.
 *
 * The title list groups entries by exact, case-sensitive `name`, counting each
 * device once per title and once per version. The drill-down lists the devices
 * reporting one title (optionally one version of it), with their profile's
 * hostname, platform and last check-in.
 *
 * Each read follows the partition's cursor to the end, up to
 * `SOFTWARE_MAX_QUERY_PAGES` pages; stopping there with a cursor still pending
 * marks the answer `truncated`.
 */
import { GSI1_NAME, deviceProfile, inventoryListIndex } from '../db/keys.js';
import type { Item, QueryPage } from '../db/table.js';
import type { RouteResult, Router } from '../http/router.js';
import {
  jsonError,
  parseLimit,
  registerAdminRoute,
  type AdminDependencySource,
  type AdminRouteHandler,
  type AdminTable,
} from './router.js';

/** Sub-path of the fleet software title list. */
export const SOFTWARE_PATH = '/software';

/** Sub-path of the drill-down from a title to the devices that have it. */
export const SOFTWARE_DEVICES_PATH = '/software/devices';

/** The most query pages read from the `INVENTORY` partition per request. */
export const SOFTWARE_MAX_QUERY_PAGES = 50;

/** The longest `search` accepted, after trimming. */
const MAX_SEARCH_LENGTH = 200;

/** The longest `name` accepted by the drill-down. */
const MAX_NAME_LENGTH = 512;

/** The longest `version` accepted by the drill-down. */
const MAX_VERSION_LENGTH = 256;

/** The title orderings the list accepts. */
const SORT_VALUES = ['name', 'devices'] as const;

type SoftwareSort = (typeof SORT_VALUES)[number];

/** A decimal integer with no sign, fraction or exponent. */
const INTEGER_PATTERN = /^[0-9]+$/;

/** A non-empty string attribute, or `null`. */
function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/** `-1`/`0`/`1` for two strings in code-unit order, independent of locale. */
function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

/** The `offset` query parameter: `0` when absent or empty, `null` when invalid. */
function parseOffset(raw: string | undefined): number | null {
  if (raw === undefined || raw === '') {
    return 0;
  }
  if (!INTEGER_PATTERN.test(raw)) {
    return null;
  }
  const value = Number(raw);
  return Number.isSafeInteger(value) ? value : null;
}

/** The result of reading the partition to its end, or to the page cap. */
interface PartitionRead {
  items: Item[];
  truncated: boolean;
}

/**
 * Read every page of the `gsi1` `INVENTORY` partition, projecting only what
 * the software views use.
 *
 * A cursor equal to the one just sent would page forever and ends the read; a
 * cursor still pending after `SOFTWARE_MAX_QUERY_PAGES` pages ends it too, and
 * marks the read truncated.
 */
async function readInventories(table: AdminTable): Promise<PartitionRead> {
  // An empty id yields the partition's value without writing key text here.
  const { gsi1pk: partition } = inventoryListIndex('');
  const items: Item[] = [];
  let cursor: string | null = null;
  let pages = 0;
  do {
    const page: QueryPage = await table.query({
      IndexName: GSI1_NAME,
      KeyConditionExpression: '#gsi1pk = :gsi1pk',
      ProjectionExpression: '#deviceId, #software, #collectedAt',
      ExpressionAttributeNames: {
        '#gsi1pk': 'gsi1pk',
        '#deviceId': 'deviceId',
        '#software': 'software',
        '#collectedAt': 'collectedAt',
      },
      ExpressionAttributeValues: { ':gsi1pk': partition },
      cursor,
    });
    pages += 1;
    items.push(...(Array.isArray(page.items) ? page.items : []));
    const next = page.cursor ?? null;
    if (next === null || next === cursor) {
      return { items, truncated: false };
    }
    cursor = next;
  } while (pages < SOFTWARE_MAX_QUERY_PAGES);
  return { items, truncated: true };
}

/** One well-formed stored software entry. */
interface SoftwareEntry {
  name: string;
  version: string;
  publisher: string | null;
  installedAt: string | null;
}

/** The inventory's device id, or a per-item placeholder that can never be a real id. */
function inventoryDeviceId(item: Item, index: number): string {
  return stringOrNull(item.deviceId) ?? stringOrNull(item.gsi1sk) ?? `#${index}`;
}

/** The inventory's well-formed software entries; none when `software` is not an array. */
function softwareEntries(item: Item): SoftwareEntry[] {
  if (!Array.isArray(item.software)) {
    return [];
  }
  const entries: SoftwareEntry[] = [];
  for (const raw of item.software) {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      continue;
    }
    const entry = raw as Item;
    const name = stringOrNull(entry.name);
    const version = stringOrNull(entry.version);
    if (name === null || version === null) {
      continue;
    }
    entries.push({
      name,
      version,
      publisher: stringOrNull(entry.publisher),
      installedAt: stringOrNull(entry.installedAt),
    });
  }
  return entries;
}

/** One title as it is built up across inventories. */
interface TitleAccumulator {
  publisher: string | null;
  devices: Set<string>;
  versions: Map<string, Set<string>>;
}

/** One title in the response. */
interface SoftwareTitle {
  name: string;
  publisher: string | null;
  deviceCount: number;
  versions: Array<{ version: string; deviceCount: number }>;
}

/** Group every inventory's entries by exact name. */
function aggregateTitles(items: Item[]): SoftwareTitle[] {
  const titles = new Map<string, TitleAccumulator>();
  items.forEach((item, index) => {
    const deviceId = inventoryDeviceId(item, index);
    for (const entry of softwareEntries(item)) {
      let title = titles.get(entry.name);
      if (title === undefined) {
        title = { publisher: null, devices: new Set(), versions: new Map() };
        titles.set(entry.name, title);
      }
      if (entry.publisher !== null && (title.publisher === null || entry.publisher < title.publisher)) {
        title.publisher = entry.publisher;
      }
      title.devices.add(deviceId);
      let devices = title.versions.get(entry.version);
      if (devices === undefined) {
        devices = new Set();
        title.versions.set(entry.version, devices);
      }
      devices.add(deviceId);
    }
  });
  return [...titles.entries()].map(([name, title]) => ({
    name,
    publisher: title.publisher,
    deviceCount: title.devices.size,
    versions: [...title.versions.entries()]
      .map(([version, devices]) => ({ version, deviceCount: devices.size }))
      .sort((a, b) => b.deviceCount - a.deviceCount || compareStrings(a.version, b.version)),
  }));
}

/** Name lower-cased ascending, ties broken by name in code-unit order. */
function compareByName(a: SoftwareTitle, b: SoftwareTitle): number {
  return compareStrings(a.name.toLowerCase(), b.name.toLowerCase()) || compareStrings(a.name, b.name);
}

/**
 * `GET /admin/api/v1/software` -- the fleet's distinct software titles with
 * per-version device counts, searched, sorted and paged.
 *
 * `limit`, `offset`, `sort` and `search` are validated before anything is
 * read; an invalid value is 400 `invalid_request`.
 */
export const handleSoftwareList: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const limit = parseLimit(req.query?.limit);
  const offset = parseOffset(req.query?.offset);
  const rawSort = req.query?.sort;
  const sort: SoftwareSort | null =
    rawSort === undefined || rawSort === ''
      ? 'name'
      : SORT_VALUES.includes(rawSort as SoftwareSort)
        ? (rawSort as SoftwareSort)
        : null;
  const search = (req.query?.search ?? '').trim();
  if (limit === null || offset === null || sort === null || search.length > MAX_SEARCH_LENGTH) {
    return jsonError(400, 'invalid_request');
  }

  const read = await readInventories(deps.table);
  let titles = aggregateTitles(read.items);

  if (search !== '') {
    const needle = search.toLowerCase();
    titles = titles.filter(
      (title) =>
        title.name.toLowerCase().includes(needle) ||
        (title.publisher !== null && title.publisher.toLowerCase().includes(needle)),
    );
  }

  titles.sort(sort === 'devices' ? (a, b) => b.deviceCount - a.deviceCount || compareByName(a, b) : compareByName);

  return {
    statusCode: 200,
    body: {
      items: titles.slice(offset, offset + limit),
      total: titles.length,
      offset,
      limit,
      deviceCount: read.items.length,
      truncated: read.truncated,
    },
  };
};

/** One (device, version) row of the drill-down, before its profile is attached. */
interface DeviceVersion {
  deviceId: string;
  version: string;
  installedAt: string | null;
}

/** The profile of each id, read once per id; `undefined` when absent. */
async function profilesOf(table: AdminTable, deviceIds: Set<string>): Promise<Map<string, Item | undefined>> {
  const ids = [...deviceIds];
  const profiles = await Promise.all(
    ids.map(async (deviceId) => {
      let key;
      try {
        key = deviceProfile(deviceId);
      } catch {
        return undefined;
      }
      return table.get(key);
    }),
  );
  return new Map(ids.map((deviceId, index) => [deviceId, profiles[index]]));
}

/**
 * `GET /admin/api/v1/software/devices` -- the devices reporting one title,
 * one row per distinct (device, version).
 *
 * `name` and `version` are validated before anything is read; an invalid value
 * is 400 `invalid_request`. Paging, sort and search parameters are ignored.
 */
export const handleSoftwareDevices: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const name = req.query?.name;
  const rawVersion = req.query?.version;
  if (typeof name !== 'string' || name === '' || name.length > MAX_NAME_LENGTH) {
    return jsonError(400, 'invalid_request');
  }
  if (rawVersion !== undefined && rawVersion.length > MAX_VERSION_LENGTH) {
    return jsonError(400, 'invalid_request');
  }
  const version = rawVersion === undefined || rawVersion === '' ? null : rawVersion;

  const read = await readInventories(deps.table);

  const rows = new Map<string, DeviceVersion>();
  for (const item of read.items) {
    const deviceId = stringOrNull(item.deviceId) ?? stringOrNull(item.gsi1sk);
    if (deviceId === null) {
      continue;
    }
    for (const entry of softwareEntries(item)) {
      if (entry.name !== name || (version !== null && entry.version !== version)) {
        continue;
      }
      // `#` never occurs in a device id, so the pair key cannot collide.
      const key = `${deviceId}#${entry.version}`;
      const existing = rows.get(key);
      if (existing === undefined) {
        rows.set(key, { deviceId, version: entry.version, installedAt: entry.installedAt });
      } else if (existing.installedAt === null) {
        existing.installedAt = entry.installedAt;
      }
    }
  }

  const profiles = await profilesOf(deps.table, new Set([...rows.values()].map((row) => row.deviceId)));

  const items: Item[] = [];
  for (const row of rows.values()) {
    const profile = profiles.get(row.deviceId);
    if (profile === undefined || profile === null) {
      continue;
    }
    items.push({
      deviceId: row.deviceId,
      hostname: stringOrNull(profile.hostname),
      platform: stringOrNull(profile.platform),
      lastSeenAt: stringOrNull(profile.lastSeenAt),
      version: row.version,
      installedAt: row.installedAt,
    });
  }

  items.sort((a, b) => {
    const left = a.hostname as string | null;
    const right = b.hostname as string | null;
    if (left !== right) {
      if (left === null) {
        return 1;
      }
      if (right === null) {
        return -1;
      }
      const byHostname = compareStrings(left.toLowerCase(), right.toLowerCase());
      if (byHostname !== 0) {
        return byHostname;
      }
    }
    return (
      compareStrings(a.deviceId as string, b.deviceId as string) ||
      compareStrings(a.version as string, b.version as string)
    );
  });

  return {
    statusCode: 200,
    body: { name, version, items, truncated: read.truncated },
  };
};

/** Register the software routes on a router. Returns the router, so calls chain. */
export function registerSoftwareRoutes(router: Router, source: AdminDependencySource): Router {
  registerAdminRoute(router, 'GET', SOFTWARE_PATH, handleSoftwareList, source);
  return registerAdminRoute(router, 'GET', SOFTWARE_DEVICES_PATH, handleSoftwareDevices, source);
}
