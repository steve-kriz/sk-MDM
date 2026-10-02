/**
 * Configuration policies: the admin write side of the policy entity, plus the
 * compliance view the fleet reports back into.
 *
 *   POST   /admin/api/v1/policies                          -- create a policy
 *   PUT    /admin/api/v1/policies/{policyId}                -- replace its settings
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
 * `settings` is a closed vocabulary: exactly the five keys in
 * `POLICY_SETTING_KEYS`, each of its own type and range. A key this backend
 * does not know is refused rather than stored, because an agent cannot enforce
 * a setting it has never heard of -- storing it would produce a policy the UI
 * shows and no machine applies. Every offending key is named at once, prefixed
 * `settings.`, so one round trip tells the admin everything that is wrong.
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
  deviceCompliance,
  group,
  policy as policyKey,
  policyAssignment,
  policyAssignmentIndex,
  type TableKey,
} from '../db/keys.js';
import type { Item, RequestFields } from '../db/table.js';
import type { RouteResult, Router } from '../http/router.js';
import { readPolicyGroupIds } from '../policies/resolve.js';
import { readGroupMemberIds } from './groups.js';
import {
  adminActor,
  adminNow,
  adminRandomBytes,
  adminWriteTable,
  jsonError,
  readJsonBody,
  registerAdminRoute,
  type AdminDependencySource,
  type AdminRouteHandler,
  type AdminTable,
  type AdminWriteTable,
} from './router.js';

/** Sub-path of the policy collection. */
export const POLICY_PATH = '/policies';

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
] as const;

/** Accepted range of `screenLockTimeoutSeconds`, both bounds inclusive. */
export const SCREEN_LOCK_TIMEOUT_SECONDS = { min: 60, max: 3600 } as const;

/** Accepted range of `osUpdateMaxAgeDays`, both bounds inclusive. */
export const OS_UPDATE_MAX_AGE_DAYS = { min: 1, max: 180 } as const;

/** The audit action recorded when a policy is created. */
export const POLICY_CREATED_ACTION = 'policy.created';

/** The audit action recorded when a policy's settings are replaced. */
export const POLICY_UPDATED_ACTION = 'policy.updated';

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

const SETTING_CHECKS: Readonly<Record<(typeof POLICY_SETTING_KEYS)[number], SettingCheck>> = {
  firewallEnabled: (value) => typeof value === 'boolean',
  diskEncryptionRequired: (value) => typeof value === 'boolean',
  screenLockTimeoutSeconds: (value) => inRange(value, SCREEN_LOCK_TIMEOUT_SECONDS),
  osUpdateMaxAgeDays: (value) => inRange(value, OS_UPDATE_MAX_AGE_DAYS),
  localAdminAllowlist: (value) =>
    Array.isArray(value) && value.every((entry) => typeof entry === 'string'),
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
 * The injected table as the assignment delete needs it.
 *
 * Removing an item is not part of `AdminTable`, so the one place that
 * assumption is made is here: a table client with no `delete` is a wiring fault
 * and becomes the router's 500 rather than a silently skipped removal.
 */
interface AdminDeleteTable extends AdminWriteTable {
  delete(key: TableKey, fields?: RequestFields): Promise<void>;
}

function adminDeleteTable(table: AdminTable): AdminDeleteTable {
  const writable = adminWriteTable(table);
  if (typeof (writable as Partial<AdminDeleteTable>).delete !== 'function') {
    throw new Error('removing an assignment needs a table client with delete()');
  }
  return writable as AdminDeleteTable;
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

  await table.put({
    ...key,
    policyId,
    name: name ?? stringOrNull(existing.name),
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
  registerAdminRoute(router, 'PUT', POLICY_DETAIL_PATH, handlePolicyUpdate, source);
  registerAdminRoute(router, 'POST', POLICY_ASSIGNMENT_PATH, handlePolicyAssign, source);
  registerAdminRoute(router, 'DELETE', POLICY_ASSIGNMENT_PATH, handlePolicyUnassign, source);
  return registerAdminRoute(router, 'GET', POLICY_COMPLIANCE_PATH, handlePolicyCompliance, source);
}
