/**
 * Configuration policies: the admin write side of the policy entity, plus the
 * compliance view the fleet reports back into.
 *
 *   POST   /admin/api/v1/policies                          -- create a policy
 *   GET    /admin/api/v1/policies                          -- list policies, by name
 *   POST   /admin/api/v1/policies/reindex                  -- list policies written before the index
 *   PUT    /admin/api/v1/policies/{policyId}                -- replace its settings
 *   DELETE /admin/api/v1/policies/{policyId}                -- delete it and its assignments
 *   POST   /admin/api/v1/policies/{policyId}/assignments    -- assign it to a group
 *   DELETE /admin/api/v1/policies/{policyId}/assignments    -- take that back
 *   GET    /admin/api/v1/policies/{policyId}/compliance     -- who is violating it
 *
 *   registerPolicyRoutes(router, { verifier, table, now, randomBytes });
 *
 * Every route is registered through `registerAdminRoute`, so it is reached only
 * by a verified admin (see `src/admin/router.ts`), and every dependency is
 * injected, so tests drive them with a stub verifier and a fake table.
 *
 * `settings` is a closed vocabulary: exactly the sixteen keys in
 * `POLICY_SETTING_KEYS`, each of its own type and range. A key this backend
 * does not know is refused rather than stored, because an agent cannot enforce
 * a setting it has never heard of -- storing it would produce a policy the UI
 * shows and no machine applies. Every offending key is named at once, prefixed
 * `settings.`, so one round trip tells the admin everything that is wrong.
 *
 * A policy record lives at `keys.policy(policyId)` and carries the
 * `keys.policyListIndex` attributes, written on create and on every `PUT` (a
 * `PUT` may rename it), which is what makes the list a query on one `gsi1`
 * partition rather than a scan. Records written before that index existed are
 * picked up once by `POST /policies/reindex`, the one route that scans.
 *
 * A policy is versioned, never edited in place from the agent's point of view:
 * `PUT` stores the new settings and increments `version`, so an agent's
 * compliance report can say which version it evaluated.
 *
 * Assignment is by group, never by device: the assignment item lives in the
 * policy's own partition (`policyAssignment`) and carries the `gsi1` attributes
 * that let a group's policies be read back (`policyAssignmentIndex`). Assigning
 * to a group that does not exist is refused, so an assignment never points at
 * nothing; the groups themselves are created by `src/admin/groups.ts` and are
 * only ever read here.
 *
 * Every successful write is audited through `appendAudit` (see `src/audit.ts`)
 * with the admin's own identity as the actor.
 */
import { appendAudit, isoUtc } from '../audit.js';
import {
  GSI1_NAME,
  deviceCompliance,
  group,
  policy as policyKey,
  policyAssignment,
  policyAssignmentIndex,
  policyListIndex,
  type TableKey,
} from '../db/keys.js';
import type { Item, QueryPage, ScanRequest } from '../db/table.js';
import type { RouteResult, Router } from '../http/router.js';
import { readPolicyGroupIds } from '../policies/resolve.js';
import { readGroupMemberIds } from './groups.js';
import {
  adminActor,
  adminDeleteTable,
  adminNow,
  adminRandomBytes,
  adminWriteTable,
  isUsableCursor,
  jsonError,
  parseLimit,
  readCursor,
  readJsonBody,
  registerAdminRoute,
  type AdminDependencySource,
  type AdminRouteHandler,
  type AdminTable,
  type AdminWriteTable,
} from './router.js';

/** Sub-path of the policy collection. */
export const POLICY_PATH = '/policies';

/** Sub-path of the one-off re-index of policies written before the list index. */
export const POLICY_REINDEX_PATH = '/policies/reindex';

/** Sub-path of one policy. */
export const POLICY_DETAIL_PATH = '/policies/{policyId}';

/** Sub-path of a policy's group assignments. */
export const POLICY_ASSIGNMENT_PATH = '/policies/{policyId}/assignments';

/** Sub-path of a policy's compliance view. */
export const POLICY_COMPLIANCE_PATH = '/policies/{policyId}/compliance';

/** Prefix of a generated policy id. */
export const POLICY_ID_PREFIX = 'pol-';

/** Length of the random part of a generated policy id, in bytes (16 hex characters). */
export const POLICY_ID_BYTES = 8;

/** The version every policy starts at. */
export const FIRST_POLICY_VERSION = 1;

/** The only settings keys a policy may carry. */
export const POLICY_SETTING_KEYS = [
  'firewallEnabled',
  'diskEncryptionRequired',
  'screenLockTimeoutSeconds',
  'osUpdateMaxAgeDays',
  'localAdminAllowlist',
  'firewallBlockedDomains',
  'firewallAllowedDomains',
  'antivirusEnabled',
  'antivirusScanFrequency',
  'locationTracking',
  'defenderRealTimeProtection',
  'defenderCloudProtection',
  'defenderNetworkProtection',
  'defenderRansomwareProtection',
  'defenderReputationProtection',
  'defenderDailySignatureUpdate',
] as const;

/**
 * The values `defenderRansomwareProtection` accepts. An absent key means not
 * required; the agent switches Microsoft Defender Controlled Folder Access on
 * in that mode and never downgrades block to audit.
 */
export const DEFENDER_RANSOMWARE_MODES = ['audit', 'block'] as const;

/**
 * The values `antivirusScanFrequency` accepts. An absent key means off; the
 * agent runs a background Microsoft Defender quick scan at the chosen interval.
 */
export const ANTIVIRUS_SCAN_FREQUENCIES = ['off', 'daily', 'weekly', 'monthly'] as const;

/**
 * What one entry of a domain list must look like: a hostname of at least two
 * labels, each label alphanumeric with inner hyphens, ending in an alphabetic
 * top-level label. No scheme, no wildcard, no IP address, no whitespace -- the
 * agent writes these names into the hosts file, so anything else is refused.
 */
export const DOMAIN_PATTERN = /^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;

/** Longest accepted domain entry, in characters. */
export const DOMAIN_MAX_LENGTH = 253;

/** Most entries a domain list may hold. */
export const DOMAIN_LIST_MAX_ENTRIES = 500;

/** Accepted range of `screenLockTimeoutSeconds`, both bounds inclusive. */
export const SCREEN_LOCK_TIMEOUT_SECONDS = { min: 60, max: 3600 } as const;

/** Accepted range of `osUpdateMaxAgeDays`, both bounds inclusive. */
export const OS_UPDATE_MAX_AGE_DAYS = { min: 1, max: 180 } as const;

/** The audit action recorded when a policy is created. */
export const POLICY_CREATED_ACTION = 'policy.created';

/** The audit action recorded when a policy's settings are replaced. */
export const POLICY_UPDATED_ACTION = 'policy.updated';

/** The audit action recorded when a policy and its assignments are deleted. */
export const POLICY_DELETED_ACTION = 'policy.deleted';

/** The audit action recorded when policies are re-indexed into the list. */
export const POLICY_REINDEXED_ACTION = 'policy.reindexed';

/** The fields a policy list item carries. */
export const POLICY_SUMMARY_FIELDS = ['policyId', 'name', 'version', 'settings', 'createdAt', 'updatedAt'] as const;

/** The audit action recorded when a policy is assigned to a group. */
export const POLICY_ASSIGNED_ACTION = 'policy.assigned';

/** The audit action recorded when an assignment is removed. */
export const POLICY_UNASSIGNED_ACTION = 'policy.unassigned';

/** What a settings key must hold, checked one key at a time. */
type SettingCheck = (value: unknown) => boolean;

/** True when a value is an integer inside an inclusive range. */
function inRange(value: unknown, { min, max }: { min: number; max: number }): boolean {
  return typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max;
}

/** True when a value is a list of at most 500 valid domain names. */
function isDomainList(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.length <= DOMAIN_LIST_MAX_ENTRIES &&
    value.every(
      (entry) => typeof entry === 'string' && entry.length <= DOMAIN_MAX_LENGTH && DOMAIN_PATTERN.test(entry),
    )
  );
}

const SETTING_CHECKS: Readonly<Record<(typeof POLICY_SETTING_KEYS)[number], SettingCheck>> = {
  firewallEnabled: (value) => typeof value === 'boolean',
  diskEncryptionRequired: (value) => typeof value === 'boolean',
  screenLockTimeoutSeconds: (value) => inRange(value, SCREEN_LOCK_TIMEOUT_SECONDS),
  osUpdateMaxAgeDays: (value) => inRange(value, OS_UPDATE_MAX_AGE_DAYS),
  localAdminAllowlist: (value) =>
    Array.isArray(value) && value.every((entry) => typeof entry === 'string'),
  firewallBlockedDomains: isDomainList,
  firewallAllowedDomains: isDomainList,
  antivirusEnabled: (value) => typeof value === 'boolean',
  antivirusScanFrequency: (value) =>
    typeof value === 'string' && (ANTIVIRUS_SCAN_FREQUENCIES as readonly string[]).includes(value),
  locationTracking: (value) => typeof value === 'boolean',
  defenderRealTimeProtection: (value) => typeof value === 'boolean',
  defenderCloudProtection: (value) => typeof value === 'boolean',
  defenderNetworkProtection: (value) => typeof value === 'boolean',
  defenderRansomwareProtection: (value) =>
    typeof value === 'string' && (DEFENDER_RANSOMWARE_MODES as readonly string[]).includes(value),
  defenderReputationProtection: (value) => typeof value === 'boolean',
  defenderDailySignatureUpdate: (value) => typeof value === 'boolean',
};

/** The string value of an attribute, or `null` when it is not a non-empty string. */
function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/** True for a plain JSON object: not a primitive, not null, not an array. */
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The settings paths that are unknown, of the wrong type or out of range.
 *
 * Reported as `settings.<key>`, in the order the body wrote them, so the
 * response points at the request the admin actually sent. A `settings` that is
 * not an object at all is reported as `settings` itself.
 */
export function offendingSettingsFields(settings: unknown): string[] {
  if (!isObject(settings)) {
    return ['settings'];
  }
  const fields: string[] = [];
  for (const [key, value] of Object.entries(settings)) {
    const check = SETTING_CHECKS[key as (typeof POLICY_SETTING_KEYS)[number]];
    if (check === undefined || !check(value)) {
      fields.push(`settings.${key}`);
    }
  }
  return fields;
}

/**
 * The group an assignment request names.
 *
 * `POST` carries it in the body; `DELETE` is the same path with no group
 * segment, so it is read from the body too, and from `?groupId=` as well since
 * not every client will send a body with a DELETE.
 */
function requestedGroupId(body: Record<string, unknown> | null, query: Record<string, string> | undefined): string | null {
  return stringOrNull(body?.groupId) ?? stringOrNull(query?.groupId);
}

/**
 * `POST /admin/api/v1/policies` -- create a policy.
 *
 * The id is generated here, so a caller can never choose one that collides with
 * an existing policy or carries the key separator. The new policy is at version
 * 1 and assigned to nothing: it reaches no device until it is.
 */
export const handlePolicyCreate: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body) ?? {};
  const name = stringOrNull(body.name);
  const fields = [...(name === null ? ['name'] : []), ...offendingSettingsFields(body.settings)];
  if (fields.length > 0) {
    return jsonError(400, 'invalid_request', { fields });
  }
  const settings = body.settings as Record<string, unknown>;

  const table = adminWriteTable(deps.table);
  const at = adminNow(deps);
  const createdAt = isoUtc(at);
  const policyId = `${POLICY_ID_PREFIX}${adminRandomBytes(deps)(POLICY_ID_BYTES).toString('hex')}`;

  await table.put({
    ...policyKey(policyId),
    ...policyListIndex(name as string),
    policyId,
    name,
    settings,
    version: FIRST_POLICY_VERSION,
    createdAt,
    updatedAt: createdAt,
  });

  await appendAudit(table, {
    action: POLICY_CREATED_ACTION,
    actor: adminActor(req.claims),
    target: policyId,
    detail: { name, version: FIRST_POLICY_VERSION },
    now: at,
  });

  return { statusCode: 201, body: { policyId, version: FIRST_POLICY_VERSION } };
};

/**
 * `PUT /admin/api/v1/policies/{policyId}` -- replace a policy's settings.
 *
 * The settings are replaced wholesale rather than merged, so the stored policy
 * is always exactly what the admin last submitted, and `version` moves on by
 * one so an agent's report can be matched to what it evaluated.
 */
export const handlePolicyUpdate: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body) ?? {};
  const name = body.name === undefined ? null : stringOrNull(body.name);
  const fields = [
    ...(body.name !== undefined && name === null ? ['name'] : []),
    ...offendingSettingsFields(body.settings),
  ];
  if (fields.length > 0) {
    return jsonError(400, 'invalid_request', { fields });
  }
  const settings = body.settings as Record<string, unknown>;

  const policyId = req.params?.policyId ?? '';
  // An id no key can be built from names no policy.
  let key: TableKey;
  try {
    key = policyKey(policyId);
  } catch {
    return jsonError(404, 'not_found');
  }

  const table = adminWriteTable(deps.table);
  const existing = await table.get(key);
  if (existing === undefined || existing === null) {
    return jsonError(404, 'not_found');
  }

  const at = adminNow(deps);
  const previousVersion = typeof existing.version === 'number' ? existing.version : 0;
  const version = previousVersion + 1;
  const storedName = name ?? stringOrNull(existing.name);

  // The list index is written again on every update: a rename moves the
  // policy's sort position, and a record written before the index existed
  // joins the list the first time it is edited.
  await table.put({
    ...key,
    ...policyListIndex(storedName ?? policyId),
    policyId,
    name: storedName,
    settings,
    version,
    createdAt: stringOrNull(existing.createdAt) ?? isoUtc(at),
    updatedAt: isoUtc(at),
  });

  await appendAudit(table, {
    action: POLICY_UPDATED_ACTION,
    actor: adminActor(req.claims),
    target: policyId,
    detail: { version },
    now: at,
  });

  return { statusCode: 200, body: { policyId, version } };
};

/**
 * `DELETE /admin/api/v1/policies/{policyId}` -- delete a policy and every one
 * of its group assignments.
 *
 * The body must carry `{"confirm": true}`, the same gate the destructive
 * commands use (see `src/admin/commandDispatch.ts`). The policy is looked up
 * before the confirmation is checked, so an unknown id is a 404 either way, and
 * nothing is deleted or audited unless the delete actually happens.
 *
 * The devices' `COMPLIANCE#<policyId>` items are left in place: the compliance
 * state ignores results for policies no longer assigned, so each device that
 * held the policy is recomputed at its next check-in.
 */
export const handlePolicyDelete: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const policyId = req.params?.policyId ?? '';
  // An id no key can be built from names no policy.
  let key: TableKey;
  try {
    key = policyKey(policyId);
  } catch {
    return jsonError(404, 'not_found');
  }

  const table = adminDeleteTable(deps.table);
  const existing = await table.get(key);
  if (existing === undefined || existing === null) {
    return jsonError(404, 'not_found');
  }

  const body = readJsonBody(req.body) ?? {};
  if (body.confirm !== true) {
    return jsonError(409, 'confirmation_required');
  }

  const at = adminNow(deps);
  const groupIds = await readPolicyGroupIds(table, policyId);
  let assignmentsRemoved = 0;
  for (const groupId of groupIds) {
    let assignmentKey: TableKey;
    try {
      assignmentKey = policyAssignment(policyId, groupId);
    } catch {
      continue;
    }
    await table.delete(assignmentKey);
    assignmentsRemoved += 1;
  }
  await table.delete(key);

  await appendAudit(table, {
    action: POLICY_DELETED_ACTION,
    actor: adminActor(req.claims),
    target: policyId,
    detail: { name: stringOrNull(existing.name), assignmentsRemoved },
    now: at,
  });

  return { statusCode: 200, body: { policyId, assignmentsRemoved } };
};

/** A policy record's id: its own attribute, else the `POLICY#` key it lives under. */
function policyIdOf(record: Item): string | null {
  const { pk: prefix } = policyKey('');
  const pk = typeof record.pk === 'string' ? record.pk : '';
  return stringOrNull(record.policyId) ?? (pk.startsWith(prefix) ? stringOrNull(pk.slice(prefix.length)) : null);
}

/** The fields a listed policy carries (`POLICY_SUMMARY_FIELDS`), and nothing else. */
export function policySummary(record: Item): Item {
  return {
    policyId: policyIdOf(record),
    name: stringOrNull(record.name),
    version: typeof record.version === 'number' ? record.version : null,
    settings: isObject(record.settings) ? record.settings : {},
    createdAt: stringOrNull(record.createdAt),
    updatedAt: stringOrNull(record.updatedAt),
  };
}

/**
 * `GET /admin/api/v1/policies` -- the policies, by name, in the same
 * `{items, cursor}` envelope and under the same `limit` rules as every other
 * admin list (see `handleGroupList` in `src/admin/groups.ts`).
 */
export const handlePolicyList: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const limit = parseLimit(req.query?.limit);
  const cursor = readCursor(req.query?.cursor);
  if (limit === null || !isUsableCursor(cursor)) {
    return jsonError(400, 'invalid_request');
  }

  const { gsi1pk } = policyListIndex('');
  const page = await deps.table.query({
    IndexName: GSI1_NAME,
    KeyConditionExpression: '#gsi1pk = :gsi1pk',
    ExpressionAttributeNames: { '#gsi1pk': 'gsi1pk' },
    ExpressionAttributeValues: { ':gsi1pk': gsi1pk },
    limit,
    cursor,
  });

  return { statusCode: 200, body: { items: page.items.map(policySummary), cursor: page.cursor } };
};

/**
 * The injected table as the re-index needs it.
 *
 * Scanning is not part of `AdminTable` -- no request path should ever need it
 * -- so the one place that assumption is made is here: a table client with no
 * `scan` is a wiring fault and becomes the router's 500 rather than a re-index
 * that silently reports nothing to do.
 */
interface AdminScanTable extends AdminWriteTable {
  scan(request?: ScanRequest): Promise<QueryPage>;
}

function adminScanTable(table: AdminTable): AdminScanTable {
  const writable = adminWriteTable(table);
  if (typeof (writable as Partial<AdminScanTable>).scan !== 'function') {
    throw new Error('re-indexing policies needs a table client with scan()');
  }
  return writable as AdminScanTable;
}

/**
 * Every policy record in the table, following the scan cursor to the end.
 *
 * The filter keeps exactly the `POLICY#<id>` / `PROFILE` items; assignments
 * share the partition but not the sort key, so they are never returned.
 */
async function scanPolicyRecords(table: AdminScanTable): Promise<Item[]> {
  const { pk: pkPrefix, sk } = policyKey('');
  const records: Item[] = [];
  let cursor: string | null = null;
  do {
    const page: QueryPage = await table.scan({
      FilterExpression: '#sk = :sk AND begins_with(#pk, :pkPrefix)',
      ExpressionAttributeNames: { '#pk': 'pk', '#sk': 'sk' },
      ExpressionAttributeValues: { ':sk': sk, ':pkPrefix': pkPrefix },
      cursor,
    });
    records.push(...page.items);
    const next = page.cursor ?? null;
    // A cursor that does not move would page forever; treat it as the end.
    cursor = next === cursor ? null : next;
  } while (cursor !== null);
  return records;
}

/**
 * `POST /admin/api/v1/policies/reindex` -- put policies written before the
 * list index existed into the list.
 *
 * Idempotent: only a record whose `gsi1` attributes are missing or stale is
 * written, so a second run reports `{reindexed: 0}` and writes nothing but its
 * audit entry. The record is written back whole, with only the two index
 * attributes added. A record with no name is listed under its id, so it can
 * still be found and renamed.
 */
export const handlePolicyReindex: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const table = adminScanTable(deps.table);
  const at = adminNow(deps);

  let reindexed = 0;
  for (const record of await scanPolicyRecords(table)) {
    const policyId = policyIdOf(record);
    if (policyId === null) {
      continue;
    }
    const index = policyListIndex(stringOrNull(record.name) ?? policyId);
    if (record.gsi1pk === index.gsi1pk && record.gsi1sk === index.gsi1sk) {
      continue;
    }
    await table.put({ ...record, ...index });
    reindexed += 1;
  }

  await appendAudit(table, {
    action: POLICY_REINDEXED_ACTION,
    actor: adminActor(req.claims),
    target: 'policies',
    detail: { reindexed },
    now: at,
  });

  return { statusCode: 200, body: { reindexed } };
};

/**
 * `POST /admin/api/v1/policies/{policyId}/assignments` -- assign a policy to a
 * group.
 *
 * Writing the same assignment twice leaves one item: the key is derived from
 * the policy and the group, so assigning is idempotent.
 */
export const handlePolicyAssign: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const groupId = requestedGroupId(readJsonBody(req.body), req.query);
  if (groupId === null) {
    return jsonError(400, 'invalid_request', { fields: ['groupId'] });
  }

  const policyId = req.params?.policyId ?? '';
  let key: TableKey;
  let index;
  try {
    key = policyAssignment(policyId, groupId);
    index = policyAssignmentIndex(groupId, policyId);
  } catch {
    return jsonError(404, 'not_found');
  }

  const table = adminWriteTable(deps.table);

  // An assignment to a group that does not exist would reach no device and
  // could never be found again from the group's side.
  const groupRecord = await table.get(group(groupId));
  if (groupRecord === undefined || groupRecord === null) {
    return jsonError(404, 'not_found');
  }

  const at = adminNow(deps);
  await table.put({
    ...key,
    ...index,
    policyId,
    groupId,
    assignedAt: isoUtc(at),
  });

  await appendAudit(table, {
    action: POLICY_ASSIGNED_ACTION,
    actor: adminActor(req.claims),
    target: policyId,
    detail: { groupId },
    now: at,
  });

  return { statusCode: 200, body: { policyId, groupId } };
};

/**
 * `DELETE /admin/api/v1/policies/{policyId}/assignments` -- take an assignment
 * back.
 *
 * Removing an assignment that is not there is not an error: the caller asked
 * for a state, and that state already holds.
 */
export const handlePolicyUnassign: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const groupId = requestedGroupId(readJsonBody(req.body), req.query);
  if (groupId === null) {
    return jsonError(400, 'invalid_request', { fields: ['groupId'] });
  }

  const policyId = req.params?.policyId ?? '';
  let key: TableKey;
  try {
    key = policyAssignment(policyId, groupId);
  } catch {
    return jsonError(404, 'not_found');
  }

  const table = adminDeleteTable(deps.table);
  const at = adminNow(deps);
  await table.delete(key);

  await appendAudit(table, {
    action: POLICY_UNASSIGNED_ACTION,
    actor: adminActor(req.claims),
    target: policyId,
    detail: { groupId },
    now: at,
  });

  return { statusCode: 200, body: { policyId, groupId } };
};

/** Every device that holds a policy: the members of every group it is assigned to. */
async function policyDeviceIds(table: AdminTable, policyId: string): Promise<string[]> {
  const groupIds = await readPolicyGroupIds(table, policyId);
  const deviceIds: string[] = [];
  for (const groupId of groupIds) {
    deviceIds.push(...(await readGroupMemberIds(table, groupId)));
  }
  return [...new Set(deviceIds)].sort();
}

/**
 * `GET /admin/api/v1/policies/{policyId}/compliance` -- how the fleet is doing
 * against one policy.
 *
 * One entry per device that holds the policy, not per device that answered: a
 * machine that has never reported is the one an admin most needs to see, so it
 * is listed with `compliant: null` rather than left out of the list.
 */
export const handlePolicyCompliance: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const policyId = req.params?.policyId ?? '';
  // An id no key can be built from names no policy.
  try {
    policyKey(policyId);
  } catch {
    return jsonError(404, 'not_found');
  }

  const deviceIds = await policyDeviceIds(deps.table, policyId);
  const items: Item[] = [];
  for (const deviceId of deviceIds) {
    let key: TableKey;
    try {
      key = deviceCompliance(deviceId, policyId);
    } catch {
      continue;
    }
    const result = await deps.table.get(key);
    items.push({
      deviceId,
      compliant: typeof result?.compliant === 'boolean' ? result.compliant : null,
      violations: Array.isArray(result?.violations)
        ? result.violations.filter((violation): violation is string => typeof violation === 'string')
        : [],
    });
  }

  return { statusCode: 200, body: { items } };
};

/** Register the policy routes on a router. Returns the router, so calls chain. */
export function registerPolicyRoutes(router: Router, source: AdminDependencySource): Router {
  registerAdminRoute(router, 'POST', POLICY_PATH, handlePolicyCreate, source);
  registerAdminRoute(router, 'GET', POLICY_PATH, handlePolicyList, source);
  registerAdminRoute(router, 'POST', POLICY_REINDEX_PATH, handlePolicyReindex, source);
  registerAdminRoute(router, 'PUT', POLICY_DETAIL_PATH, handlePolicyUpdate, source);
  registerAdminRoute(router, 'DELETE', POLICY_DETAIL_PATH, handlePolicyDelete, source);
  registerAdminRoute(router, 'POST', POLICY_ASSIGNMENT_PATH, handlePolicyAssign, source);
  registerAdminRoute(router, 'DELETE', POLICY_ASSIGNMENT_PATH, handlePolicyUnassign, source);
  return registerAdminRoute(router, 'GET', POLICY_COMPLIANCE_PATH, handlePolicyCompliance, source);
}
