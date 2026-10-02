/**
 * Resolving which policies reach a device, and what its compliance adds up to.
 *
 * Three callers share this module, so the answer is the same wherever it is
 * asked: the agent's policy bundle (`src/routes/policies.ts`), the compliance
 * ingest at check-in (`src/routes/checkin.ts`) and the admin's per-policy
 * compliance view (`src/admin/policies.ts`).
 *
 * A policy reaches a device through a group: the policy is assigned to a group
 * (`policyAssignment`, written by `src/admin/policies.ts`) and the device holds
 * a membership in it (`groupMember`, written by `src/admin/groups.ts` and only
 * ever read here).
 *
 * The device-to-group direction has no index of its own -- a membership lives
 * in the group's partition -- so it is resolved by listing the groups from the
 * `gsi1` group list and point-reading this device's membership in each. That is
 * a query plus one small read per group, never a scan, and it reads items this
 * ticket does not own rather than mirroring a second copy of the membership.
 * A group with no `group(groupId)` record is therefore invisible here, exactly
 * as it is to the admin group list.
 *
 * Every read pages to the end: a cursor is followed until it comes back null,
 * so a device in many groups is never silently truncated to one page.
 */
import {
  GSI1_NAME,
  deviceCompliance,
  groupListIndex,
  groupMember,
  policy as policyKey,
  policyAssignment,
  policyAssignmentIndex,
} from '../db/keys.js';
import type { Item, QueryPage, QueryRequest, RequestFields } from '../db/table.js';
import type { Gsi1Key, TableKey } from '../db/keys.js';
import type { PolicyDocument } from './merge.js';

/** The compliance state of a device that reports a violation, or that reports nothing about a policy it holds. */
export const NONCOMPLIANT_STATE = 'noncompliant';

/** The compliance state of a device that reported every policy it holds, all passing. */
export const COMPLIANT_STATE = 'compliant';

/** The compliance state of a device that has reported nothing we can judge. */
export const UNKNOWN_STATE = 'unknown';

/** The only three values `complianceState` is ever stored as. */
export type ComplianceState =
  | typeof COMPLIANT_STATE
  | typeof NONCOMPLIANT_STATE
  | typeof UNKNOWN_STATE;

/** One stored compliance result, as the state rule needs it. */
export interface ComplianceResult {
  policyId: string;
  compliant: boolean;
}

/**
 * The storage operations this module needs: the structural read-only subset of
 * `TableClient` (see `src/db/table.ts`) a fake has to implement.
 */
export interface PolicyReadTable {
  get(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
  query(request?: QueryRequest): Promise<QueryPage>;
}

/** The string value of an attribute, or `null` when it is not a non-empty string. */
function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/** The id carried by a key written `<PREFIX>#<id>`. */
function idFromKey(value: unknown, prefix: string): string | null {
  const key = typeof value === 'string' ? value : '';
  if (!key.startsWith(prefix)) {
    return null;
  }
  const id = key.slice(prefix.length);
  return id.length > 0 ? id : null;
}

/** Every item a query matches, following the cursor to the end. */
async function queryAll(table: PolicyReadTable, request: QueryRequest): Promise<Item[]> {
  const items: Item[] = [];
  let cursor: string | null = null;
  do {
    const page: QueryPage = await table.query({ ...request, cursor });
    items.push(...page.items);
    const next = page.cursor ?? null;
    // A cursor that does not move would page forever; treat it as the end.
    cursor = next === cursor ? null : next;
  } while (cursor !== null);
  return items;
}

/** Ascending, de-duplicated ids. */
function sortedUnique(ids: readonly string[]): string[] {
  return [...new Set(ids)].sort();
}

/** Every group that has a `group(groupId)` record, from the `gsi1` group list. */
export async function readAllGroupIds(table: PolicyReadTable): Promise<string[]> {
  const { gsi1pk } = groupListIndex('');
  const items = await queryAll(table, {
    IndexName: GSI1_NAME,
    KeyConditionExpression: '#gsi1pk = :gsi1pk',
    ExpressionAttributeNames: { '#gsi1pk': 'gsi1pk' },
    ExpressionAttributeValues: { ':gsi1pk': gsi1pk },
  });
  const groupIds = items
    .map((item) => stringOrNull(item.groupId) ?? idFromKey(item.pk, 'GROUP#'))
    .filter((groupId): groupId is string => groupId !== null);
  return sortedUnique(groupIds);
}

/**
 * The groups this device holds a `groupMember` item for.
 *
 * Each group is checked with one point read, so a device that belongs to
 * nothing costs one small read per group and reads no policy or assignment.
 */
export async function readDeviceGroupIds(table: PolicyReadTable, deviceId: string): Promise<string[]> {
  const groupIds = await readAllGroupIds(table);
  const member: string[] = [];
  for (const groupId of groupIds) {
    let key: TableKey;
    try {
      key = groupMember(groupId, deviceId);
    } catch {
      // An id no key can be built from matches no membership.
      continue;
    }
    const membership = await table.get(key);
    if (membership !== undefined && membership !== null) {
      member.push(groupId);
    }
  }
  return member;
}

/** The policies assigned to one group, read through the `gsi1` assignment index. */
export async function readGroupPolicyIds(table: PolicyReadTable, groupId: string): Promise<string[]> {
  let partition: Gsi1Key;
  try {
    // An empty policy id yields the group's index partition and the `POLICY#`
    // prefix its assignments are listed under, without writing key text here.
    partition = policyAssignmentIndex(groupId, '');
  } catch {
    // An id no key can be built from matches nothing.
    return [];
  }

  const items = await queryAll(table, {
    IndexName: GSI1_NAME,
    KeyConditionExpression: '#gsi1pk = :gsi1pk AND begins_with(#gsi1sk, :policyPrefix)',
    ExpressionAttributeNames: { '#gsi1pk': 'gsi1pk', '#gsi1sk': 'gsi1sk' },
    ExpressionAttributeValues: { ':gsi1pk': partition.gsi1pk, ':policyPrefix': partition.gsi1sk },
  });

  const policyIds = items
    .map((item) => stringOrNull(item.policyId) ?? idFromKey(item.pk, 'POLICY#'))
    .filter((policyId): policyId is string => policyId !== null);
  return sortedUnique(policyIds);
}

/** The groups one policy is assigned to, from the policy's own partition. */
export async function readPolicyGroupIds(table: PolicyReadTable, policyId: string): Promise<string[]> {
  let partition: TableKey;
  try {
    // An empty group id yields the policy's partition key and the `ASSIGN#`
    // prefix its assignments are stored under.
    partition = policyAssignment(policyId, '');
  } catch {
    return [];
  }

  const items = await queryAll(table, {
    KeyConditionExpression: '#pk = :pk AND begins_with(#sk, :assignPrefix)',
    ExpressionAttributeNames: { '#pk': 'pk', '#sk': 'sk' },
    ExpressionAttributeValues: { ':pk': partition.pk, ':assignPrefix': partition.sk },
  });

  const groupIds = items
    .map((item) => stringOrNull(item.groupId) ?? idFromKey(item.sk, 'ASSIGN#'))
    .filter((groupId): groupId is string => groupId !== null);
  return sortedUnique(groupIds);
}

/**
 * Every policy id assigned to a device, each once, ascending.
 *
 * This is the set the bundle is built from and the set compliance is judged
 * against, so a report naming anything outside it is not this device's business.
 */
export async function readAssignedPolicyIds(table: PolicyReadTable, deviceId: string): Promise<string[]> {
  const groupIds = await readDeviceGroupIds(table, deviceId);
  const policyIds: string[] = [];
  for (const groupId of groupIds) {
    policyIds.push(...(await readGroupPolicyIds(table, groupId)));
  }
  return sortedUnique(policyIds);
}

/**
 * The policy documents assigned to a device, ascending by id.
 *
 * An assignment whose policy record has since been removed is skipped rather
 * than reported as an empty policy.
 */
export async function readAssignedPolicies(
  table: PolicyReadTable,
  deviceId: string,
): Promise<PolicyDocument[]> {
  const policyIds = await readAssignedPolicyIds(table, deviceId);
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
      settings:
        typeof record.settings === 'object' && record.settings !== null && !Array.isArray(record.settings)
          ? (record.settings as Record<string, unknown>)
          : {},
    });
  }
  return policies;
}

/** Every compliance result stored for a device, whatever is assigned to it now. */
export async function readComplianceResults(
  table: PolicyReadTable,
  deviceId: string,
): Promise<ComplianceResult[]> {
  let partition: TableKey;
  try {
    // An empty policy id yields the device's partition key and the
    // `COMPLIANCE#` prefix its results are stored under.
    partition = deviceCompliance(deviceId, '');
  } catch {
    return [];
  }

  const items = await queryAll(table, {
    KeyConditionExpression: '#pk = :pk AND begins_with(#sk, :compliancePrefix)',
    ExpressionAttributeNames: { '#pk': 'pk', '#sk': 'sk' },
    ExpressionAttributeValues: { ':pk': partition.pk, ':compliancePrefix': partition.sk },
  });

  const results: ComplianceResult[] = [];
  for (const item of items) {
    const policyId = stringOrNull(item.policyId) ?? idFromKey(item.sk, 'COMPLIANCE#');
    if (policyId === null) {
      continue;
    }
    results.push({ policyId, compliant: item.compliant === true });
  }
  return results;
}

/**
 * The device's compliance state, by one ordered rule:
 *
 *   1. a result for a currently assigned policy says `compliant: false`
 *                                                          -> `noncompliant`
 *   2. every assigned policy has a result, and there is at least one assigned
 *                                                          -> `compliant`
 *   3. some assigned policy has a result, but not all do    -> `noncompliant`
 *   4. nothing judgeable was ever reported                  -> `unknown`
 *
 * Step 3 is the one that matters: an agent that reports on four of its five
 * policies is not quietly compliant, it is a device we cannot vouch for. Step 4
 * keeps that honest in the other direction -- a device that has never reported,
 * and a device with no policy at all, are `unknown` rather than falsely clean.
 *
 * A result for a policy no longer assigned is ignored entirely, so unassigning
 * a policy cannot leave a device stuck non-compliant over it.
 */
export function computeComplianceState(
  assignedPolicyIds: readonly string[],
  results: readonly ComplianceResult[],
): ComplianceState {
  const assigned = new Set(assignedPolicyIds);
  const relevant = results.filter((result) => assigned.has(result.policyId));

  if (relevant.some((result) => !result.compliant)) {
    return NONCOMPLIANT_STATE;
  }

  const reported = new Set(relevant.map((result) => result.policyId));
  if (assigned.size > 0 && reported.size === assigned.size) {
    return COMPLIANT_STATE;
  }
  if (reported.size > 0) {
    return NONCOMPLIANT_STATE;
  }
  return UNKNOWN_STATE;
}
