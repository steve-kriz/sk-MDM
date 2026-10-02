/**
 * Merging a device's assigned policies into the settings it must apply.
 *
 *   const { effectiveSettings, conflicts } = mergePolicySettings(policies);
 *
 * This module is pure: it reads no storage, takes no clock and keeps no state,
 * so the merge rule can be exercised on its own.
 *
 * The rule is deliberately boring, because an admin has to be able to predict
 * it from the policy list alone: for every settings key, the policy with the
 * lexicographically smallest `policyId` wins. Nothing here knows which setting
 * is "stricter" -- a backend that silently picked the safer-looking value would
 * make the resulting configuration impossible to reason about, and would change
 * meaning every time a setting type was added.
 *
 * Nothing is invented either. `effectiveSettings` carries exactly the keys at
 * least one assigned policy set; a key no policy mentions is absent rather than
 * defaulted, so the agent can tell "no policy governs this" from "a policy set
 * it to the default". `conflicts` reports every key more than one policy set,
 * so the admin UI can show the contest the merge resolved; it is `[]` rather
 * than absent when there is none.
 */

/** One assigned policy, as the bundle carries it. */
export interface PolicyDocument {
  policyId: string;
  version: number;
  settings: Record<string, unknown>;
}

/** One policy that set a contested key but did not win it. */
export interface ConflictLoser {
  policyId: string;
  value: unknown;
}

/** One settings key more than one assigned policy tried to set. */
export interface PolicyConflict {
  key: string;
  winningPolicyId: string;
  value: unknown;
  losers: ConflictLoser[];
}

/** The merge result: what to apply, and what was contested on the way there. */
export interface MergedPolicies {
  effectiveSettings: Record<string, unknown>;
  conflicts: PolicyConflict[];
}

/** Lexicographic by policy id: the order the winner is taken from. */
function byPolicyId(left: { policyId: string }, right: { policyId: string }): number {
  if (left.policyId === right.policyId) {
    return 0;
  }
  return left.policyId < right.policyId ? -1 : 1;
}

/** True for a plain JSON object: not a primitive, not null, not an array. */
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Merge the settings of every assigned policy.
 *
 * `policies` may arrive in any order; it is sorted by `policyId` here, so the
 * result depends on the policies alone and never on the order storage happened
 * to return them in. The conflicts come back sorted by key, and each one's
 * losers sorted by policy id.
 */
export function mergePolicySettings(policies: readonly PolicyDocument[]): MergedPolicies {
  // Every value offered for a key, by ascending policy id: the head of each
  // list is that key's winner.
  const offered = new Map<string, ConflictLoser[]>();
  for (const policy of [...policies].sort(byPolicyId)) {
    const settings = isObject(policy.settings) ? policy.settings : {};
    for (const [key, value] of Object.entries(settings)) {
      const values = offered.get(key) ?? [];
      values.push({ policyId: policy.policyId, value });
      offered.set(key, values);
    }
  }

  const effectiveSettings: Record<string, unknown> = {};
  const conflicts: PolicyConflict[] = [];
  for (const key of [...offered.keys()].sort()) {
    const values = offered.get(key) ?? [];
    const winner = values[0];
    if (winner === undefined) {
      continue;
    }
    effectiveSettings[key] = winner.value;
    if (values.length > 1) {
      conflicts.push({
        key,
        winningPolicyId: winner.policyId,
        value: winner.value,
        losers: values.slice(1),
      });
    }
  }

  return { effectiveSettings, conflicts };
}
