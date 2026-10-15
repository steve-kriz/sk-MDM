/**
 * Key builders for the single-table DynamoDB layout.
 *
 * Every entity in the store lives in one table keyed by `pk`/`sk`, with one
 * global secondary index `gsi1` keyed by `gsi1pk`/`gsi1sk` (see
 * `src/infra/mdm-stack.ts`). These builders are the only place those strings
 * are written: callers never concatenate key strings by hand.
 *
 *   const key = deviceCommand('dev-7', 'cmd-1');
 *   // -> { pk: 'DEVICE#dev-7', sk: 'CMD#cmd-1' }
 *
 * `#` separates a prefix from an id, so an id may never contain one: an id
 * that does is rejected rather than silently producing a key that collides
 * with another entity's.
 */

/** The character separating a key prefix from the id it carries. */
export const KEY_SEPARATOR = '#';

/** Name of the global secondary index declared by the stack. */
export const GSI1_NAME = 'gsi1';

/** A primary key: the table's partition and sort key attributes. */
export interface TableKey {
  pk: string;
  sk: string;
}

/** The `gsi1` index attributes written onto an item so it is listed. */
export interface Gsi1Key {
  gsi1pk: string;
  gsi1sk: string;
}

/**
 * Return `value` unchanged, or throw when it cannot be used as a key id.
 *
 * Shared by every builder so the rejection message is identical wherever an
 * id reaches the storage layer.
 */
export function assertValidId(value: string): string {
  if (typeof value !== 'string' || value.includes(KEY_SEPARATOR)) {
    throw new Error(`invalid id: ${String(value)}`);
  }
  return value;
}

/** `DEVICE#<deviceId>` / `PROFILE` -- the device's identity record. */
export function deviceProfile(deviceId: string): TableKey {
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: 'PROFILE' };
}

/** `DEVICE#<deviceId>` / `INVENTORY` -- the last reported hardware inventory. */
export function deviceInventory(deviceId: string): TableKey {
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: 'INVENTORY' };
}

/** `DEVICE#<deviceId>` / `POSTURE` -- the last reported compliance posture. */
export function devicePosture(deviceId: string): TableKey {
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: 'POSTURE' };
}

/** `DEVICE#<deviceId>` / `SIGNEDINUSER` -- the Entra user last verified as signed in on the device. */
export function deviceSignedInUser(deviceId: string): TableKey {
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: 'SIGNEDINUSER' };
}

/** `DEVICE#<deviceId>` / `SETTINGS` -- the device's admin settings, such as analytics collection on/off. */
export function deviceSettings(deviceId: string): TableKey {
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: 'SETTINGS' };
}

/**
 * `DEVICE#<deviceId>` / `HEARTBEAT` -- the device's heartbeat setting
 * (on/off and frequency). A separate item from `SETTINGS`, because both admin
 * routes write their whole item with `put`.
 */
export function deviceHeartbeatSettings(deviceId: string): TableKey {
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: 'HEARTBEAT' };
}

/** The sort key prefix every per-device login history record is stored under. */
export const LOGIN_USER_SK_PREFIX = 'LOGINUSER#';

/** A login-history username key: the SHA-256 hex of the normalised username. */
const LOGIN_USER_KEY_PATTERN = /^[0-9a-f]{64}$/;

/**
 * `DEVICE#<deviceId>` / `LOGINUSER#<usernameKey>` -- one OS user ever reported
 * as signed in on the device, `{deviceId, username, firstSeenAt, lastSeenAt,
 * loginCount}`. No `ttl`. `usernameKey` is 64 lower-case hex characters, or
 * the empty string to build the prefix for a query.
 */
export function deviceLoginUser(deviceId: string, usernameKey: string): TableKey {
  if (typeof usernameKey !== 'string' || (usernameKey !== '' && !LOGIN_USER_KEY_PATTERN.test(usernameKey))) {
    throw new Error(`invalid id: ${String(usernameKey)}`);
  }
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: `${LOGIN_USER_SK_PREFIX}${usernameKey}` };
}

/** `DEVICE#<deviceId>` / `CMD#<commandId>` -- one queued or completed command. */
export function deviceCommand(deviceId: string, commandId: string): TableKey {
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: `CMD#${assertValidId(commandId)}` };
}

/**
 * `DEVICE#<deviceId>` / `CMDSEQ` -- the device's command sequence counter,
 * `{next}`, advanced with `ADD next :1` each time a library command is queued.
 * The sort key does not begin with `CMD#`, so command queries never return it.
 */
export function deviceCommandSeq(deviceId: string): TableKey {
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: 'CMDSEQ' };
}

/** `SCRIPT#<scriptId>` / `PROFILE` -- one saved command in the command library. */
export function script(scriptId: string): TableKey {
  return { pk: `SCRIPT#${assertValidId(scriptId)}`, sk: 'PROFILE' };
}

/**
 * `APPLICATION#<applicationId>` / `PROFILE` -- one approved installer in the
 * application safe list. An empty id is rejected as well as one carrying `#`.
 */
export function application(applicationId: string): TableKey {
  if (applicationId === '') {
    throw new Error('invalid id: ');
  }
  return { pk: `APPLICATION#${assertValidId(applicationId)}`, sk: 'PROFILE' };
}

/**
 * `UNIQUENAME#<nameKey>` / `SCRIPT` -- the guard item that keeps command
 * library names unique ignoring case. `nameKey` is a hex digest of the
 * lower-cased name, so a name containing `#` never becomes a key id.
 */
export function scriptNameGuard(nameKey: string): TableKey {
  return { pk: `UNIQUENAME#${assertValidId(nameKey)}`, sk: 'SCRIPT' };
}

/**
 * `RATELIMIT#SCRIPTGENERATE#<actorKey>` / `MINUTE#<minute>` -- one admin's
 * script-generate counter for one UTC minute (TASK-053), `{count, ttl}`,
 * advanced with `ADD count :1`. `actorKey` is the SHA-256 hex of the
 * lower-cased actor and `minute` is `YYYYMMDDHHmm`. It carries no `gsi1`
 * attributes, so it never appears in an index query.
 */
export function scriptGenerateRateLimit(actorKey: string, minute: string): TableKey {
  return { pk: `RATELIMIT#SCRIPTGENERATE#${assertValidId(actorKey)}`, sk: `MINUTE#${assertValidId(minute)}` };
}

/** `CONFIG` / `COMMANDS` -- the fleet-wide command settings, `{onFailure}`. */
export function commandSettings(): TableKey {
  return { pk: 'CONFIG', sk: 'COMMANDS' };
}

/** `CONFIG` / `ASSIGNMENT` -- the fleet-wide default group per ownership, `{officehq, byoc}`. */
export function defaultAssignmentSettings(): TableKey {
  return { pk: 'CONFIG', sk: 'ASSIGNMENT' };
}

/**
 * `HWUUID#<hardwareUuid>` / `POINTER` -- the device a hardware uuid belongs to.
 *
 * A re-enrolling machine presents the same hardware uuid, so this pointer item
 * (`{pk, sk, deviceId, createdAt}`) is what re-binds it to its existing device
 * record instead of creating a second one.
 */
export function deviceByHardware(hardwareUuid: string): TableKey {
  return { pk: `HWUUID#${assertValidId(hardwareUuid)}`, sk: 'POINTER' };
}

/** `GROUP#<groupId>` / `PROFILE` -- the group's own record. */
export function group(groupId: string): TableKey {
  return { pk: `GROUP#${assertValidId(groupId)}`, sk: 'PROFILE' };
}

/** `GROUP#<groupId>` / `MEMBER#<deviceId>` -- one device's membership. */
export function groupMember(groupId: string, deviceId: string): TableKey {
  return { pk: `GROUP#${assertValidId(groupId)}`, sk: `MEMBER#${assertValidId(deviceId)}` };
}

/**
 * `DEVICE#<deviceId>` / `COMPLIANCE#<policyId>` -- the last compliance result
 * the device reported for one policy.
 *
 * One item per policy rather than one per check-in: a later report for the same
 * policy overwrites the earlier one, so the device's partition never grows with
 * its check-in history.
 */
export function deviceCompliance(deviceId: string, policyId: string): TableKey {
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: `COMPLIANCE#${assertValidId(policyId)}` };
}

/**
 * `DEVICE#<deviceId>` / `AVFINDING#<findingId>` -- one antivirus threat
 * detection the device reported.
 *
 * One item per finding: a later report of the same finding overwrites the
 * earlier one, keeping its `firstReportedAt`.
 */
export function deviceAntivirusFinding(deviceId: string, findingId: string): TableKey {
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: `AVFINDING#${assertValidId(findingId)}` };
}

/**
 * `DEVICE#<deviceId>` / `AVSCAN` -- the latest scheduled antivirus scan result
 * the device reported. Overwritten by every check-in carrying a valid
 * `antivirusScan`; no `ttl`.
 */
export function deviceAntivirusScan(deviceId: string): TableKey {
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: 'AVSCAN' };
}

/**
 * `DEVICE#<deviceId>` / `AVSTATUS` -- the latest full antivirus status the
 * device reported. Overwritten by every check-in carrying an object
 * `antivirusStatus`; no `ttl`.
 */
export function deviceAntivirusStatus(deviceId: string): TableKey {
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: 'AVSTATUS' };
}

/**
 * `DEVICE#<deviceId>` / `DEFENDERHARDENING` -- what the agent's Defender
 * protections hardener did to each required protection in its last pass.
 * Overwritten by every check-in carrying an object `defenderHardening`; no
 * `ttl`. Never read to compute `complianceState`.
 */
export function deviceDefenderHardening(deviceId: string): TableKey {
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: 'DEFENDERHARDENING' };
}

/**
 * `DEVICE#<deviceId>` / `ANALYTICS` -- the latest endpoint analytics snapshot
 * (boot and performance) the device reported. Overwritten by every check-in
 * carrying analytics; no `ttl`.
 */
export function deviceAnalytics(deviceId: string): TableKey {
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: 'ANALYTICS' };
}

/**
 * `DEVICE#<deviceId>` / `BOOTHISTORY` -- the device's bounded boot history,
 * newest boot first. No `ttl`.
 */
export function deviceBootHistory(deviceId: string): TableKey {
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: 'BOOTHISTORY' };
}

/**
 * `DEVICE#<deviceId>` / `LOCATION` -- the device's latest coarse location as
 * top-level fields, plus a bounded `history` of captures, newest first. Only
 * written while a policy enables `locationTracking`. No `ttl`.
 */
export function deviceLocation(deviceId: string): TableKey {
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: 'LOCATION' };
}

/** The sort key prefix every application crash/hang event item is stored under. */
export const APP_CRASH_SK_PREFIX = 'APPCRASH#';

/**
 * `DEVICE#<deviceId>` / `APPCRASH#<occurredAt>#<eventId>` -- one application
 * crash or hang event. The sort key orders a device's events by when they
 * occurred; the items carry a `ttl` attribute so DynamoDB expires them.
 */
export function deviceAppCrash(deviceId: string, occurredAt: string, eventId: string): TableKey {
  return {
    pk: `DEVICE#${assertValidId(deviceId)}`,
    sk: `${APP_CRASH_SK_PREFIX}${assertValidId(occurredAt)}#${assertValidId(eventId)}`,
  };
}

/** Sort-key prefix of the per-device agent error items. */
export const AGENT_ERROR_SK_PREFIX = 'AGENTERROR#';

/**
 * `DEVICE#<deviceId>` / `AGENTERROR#<signature>` -- one distinct warn or error
 * record the device's agent reported, accumulated across check-ins. The
 * signature is the first 32 hex characters of sha256(level\ncomponent\nmessage);
 * the items carry a `ttl` attribute so DynamoDB expires them.
 */
export function deviceAgentError(deviceId: string, signature: string): TableKey {
  return {
    pk: `DEVICE#${assertValidId(deviceId)}`,
    sk: `${AGENT_ERROR_SK_PREFIX}${assertValidId(signature)}`,
  };
}

/** Sort-key prefix of the per-device History event items. */
export const DEVICE_EVENT_SK_PREFIX = 'EVENT#';

/**
 * `DEVICE#<deviceId>` / `EVENT#<occurredAt>#<eventId>` -- one action performed
 * on the device, shown in its History. The sort key orders a device's events
 * by when they occurred; the items carry a `ttl` attribute so DynamoDB expires
 * them. `deviceEvent(id, '', '')` yields the partition key, for queries.
 */
export function deviceEvent(deviceId: string, occurredAt: string, eventId: string): TableKey {
  return {
    pk: `DEVICE#${assertValidId(deviceId)}`,
    sk: `${DEVICE_EVENT_SK_PREFIX}${assertValidId(occurredAt)}#${assertValidId(eventId)}`,
  };
}

/** `POLICY#<policyId>` / `PROFILE` -- the policy document. */
export function policy(policyId: string): TableKey {
  return { pk: `POLICY#${assertValidId(policyId)}`, sk: 'PROFILE' };
}

/** `POLICY#<policyId>` / `ASSIGN#<groupId>` -- the policy's assignment to a group. */
export function policyAssignment(policyId: string, groupId: string): TableKey {
  return { pk: `POLICY#${assertValidId(policyId)}`, sk: `ASSIGN#${assertValidId(groupId)}` };
}

/** `ENROLLTOKEN#<tokenId>` / `PROFILE` -- one enrollment token. */
export function enrollmentToken(tokenId: string): TableKey {
  return { pk: `ENROLLTOKEN#${assertValidId(tokenId)}`, sk: 'PROFILE' };
}

/**
 * `NONCE#<deviceId>` / `<nonce>` -- a replay-protection nonce.
 *
 * These items carry a `ttl` attribute so DynamoDB expires them; nothing here
 * deletes them.
 */
export function nonce(deviceId: string, nonceValue: string): TableKey {
  return { pk: `NONCE#${assertValidId(deviceId)}`, sk: assertValidId(nonceValue) };
}

/** An agent sign-in session id: 32 random bytes as 64 lower-case hex characters. */
export const AGENT_SIGNIN_SESSION_ID_PATTERN = /^[0-9a-f]{64}$/;

/**
 * `AGENTSIGNIN#<sessionId>` / `PROFILE` -- one MDM-brokered agent sign-in
 * session (spec Amendment A).
 *
 * The id arrives from an unauthenticated URL, so it is held to the exact shape
 * the backend issues rather than only to `assertValidId`. These items carry a
 * `ttl` attribute so DynamoDB expires them.
 */
export function agentSignInSession(sessionId: string): TableKey {
  if (typeof sessionId !== 'string' || !AGENT_SIGNIN_SESSION_ID_PATTERN.test(sessionId)) {
    throw new Error(`invalid id: ${String(sessionId)}`);
  }
  return { pk: `AGENTSIGNIN#${assertValidId(sessionId)}`, sk: 'PROFILE' };
}

/**
 * `AUDIT#<YYYY-MM-DD>` / `<seq>` -- one audit entry inside a UTC day, which
 * keeps a day's entries in one partition and ordered by `seq`.
 */
export function audit(dayUtc: string, seq: string | number): TableKey {
  const sequence = typeof seq === 'number' ? String(seq) : seq;
  return { pk: `AUDIT#${assertValidId(dayUtc)}`, sk: assertValidId(sequence) };
}

/**
 * The platforms an agent build is published for: the GOOS/GOARCH pairs the
 * agent is cross-compiled to, spelled the way the release record names them.
 */
export const AGENT_RELEASE_PLATFORMS = [
  'windows-amd64',
  'windows-arm64',
  'darwin-amd64',
  'darwin-arm64',
] as const;

/** One of the four platforms an agent release may be published for. */
export type AgentReleasePlatform = (typeof AGENT_RELEASE_PLATFORMS)[number];

/**
 * `AGENTRELEASE` / `<platform>` -- the agent build the fleet is being moved to
 * on one platform.
 *
 * One item per platform, in one partition, so a check-in reads the build for
 * the device's platform with a single get. A platform outside the published
 * set is rejected the way every other id is, rather than writing a release
 * nothing will ever look for.
 */
export function agentRelease(platform: string): TableKey {
  if (!AGENT_RELEASE_PLATFORMS.includes(platform as AgentReleasePlatform)) {
    throw new Error(`invalid id: ${String(platform)}`);
  }
  return { pk: 'AGENTRELEASE', sk: platform };
}

/**
 * Index attributes putting a device into the `gsi1` device list, sorted by
 * the ISO-8601 instant it was last seen.
 */
export function deviceListIndex(lastSeenIso: string): Gsi1Key {
  return { gsi1pk: 'DEVICE', gsi1sk: lastSeenIso };
}

/**
 * Index attributes putting a group into the `gsi1` group list, sorted by name.
 *
 * The counterpart of `deviceListIndex`: the group records share one partition
 * (`GROUP`, distinct from a group's own `GROUP#<groupId>` partition) so the
 * admin group list is a query, never a scan.
 */
export function groupListIndex(name: string): Gsi1Key {
  return { gsi1pk: 'GROUP', gsi1sk: name };
}

/**
 * Index attributes putting a policy into the `gsi1` policy list, sorted by name.
 *
 * The counterpart of `groupListIndex`: the policy records share one partition
 * (`POLICY`, distinct from a policy's own `POLICY#<policyId>` partition) so the
 * admin policy list is a query, never a scan. A policy is renamed by `PUT`, so
 * every write of the record writes these attributes again.
 */
export function policyListIndex(name: string): Gsi1Key {
  return { gsi1pk: 'POLICY', gsi1sk: name };
}

/**
 * Index attributes putting a saved command into the `gsi1` command library
 * list (`SCRIPT`, distinct from a script's own `SCRIPT#<scriptId>` partition),
 * so the library is listed with a query, never a scan. Written again on every
 * `PUT`, since a rename moves its sort position.
 */
export function scriptListIndex(name: string): Gsi1Key {
  return { gsi1pk: 'SCRIPT', gsi1sk: name };
}

/**
 * Index attributes putting an application into the `gsi1` application list
 * (`APPLICATION`, distinct from an application's own `APPLICATION#<id>`
 * partition), sorted by name, so the safe list is a query, never a scan.
 */
export function applicationListIndex(name: string): Gsi1Key {
  return { gsi1pk: 'APPLICATION', gsi1sk: name };
}

/**
 * Index attributes putting a device's analytics snapshot into the `gsi1`
 * `ANALYTICS` partition, so one query lists every device's latest snapshot.
 */
export function analyticsListIndex(deviceId: string): Gsi1Key {
  return { gsi1pk: 'ANALYTICS', gsi1sk: assertValidId(deviceId) };
}

/**
 * Index attributes putting a device's inventory into the `gsi1` `INVENTORY`
 * partition, so one query lists every device's latest inventory (the fleet
 * software view).
 */
export function inventoryListIndex(deviceId: string): Gsi1Key {
  return { gsi1pk: 'INVENTORY', gsi1sk: assertValidId(deviceId) };
}

/**
 * Index attributes putting an application crash event into the `gsi1`
 * `APPCRASH` partition, sorted by when it occurred across the fleet. DynamoDB
 * TTL deletion is lazy, so readers still filter on `gsi1sk >= <cutoff ISO>`.
 */
export function appCrashListIndex(occurredAt: string, deviceId: string): Gsi1Key {
  return { gsi1pk: 'APPCRASH', gsi1sk: `${assertValidId(occurredAt)}#${assertValidId(deviceId)}` };
}

/**
 * Index attributes putting an enrollment token into the `gsi1` `ENROLLTOKEN`
 * partition, sorted by when it was minted, so the admin token list is a query
 * (newest first with `ScanIndexForward: false`), never a scan.
 */
export function enrollmentTokenListIndex(createdAtIso: string, tokenId: string): Gsi1Key {
  return { gsi1pk: 'ENROLLTOKEN', gsi1sk: `${assertValidId(createdAtIso)}#${assertValidId(tokenId)}` };
}

/** Index attributes listing a device under its group in `gsi1`. */
export function groupIndex(groupId: string, deviceId: string): Gsi1Key {
  return { gsi1pk: `GROUP#${assertValidId(groupId)}`, gsi1sk: `DEVICE#${assertValidId(deviceId)}` };
}

/**
 * Index attributes listing a policy under the group it is assigned to in `gsi1`.
 *
 * An assignment item is keyed by its policy (`policyAssignment`), so this is
 * what lets the other direction -- "which policies does this group carry" --
 * be a query rather than a scan. It shares the `GROUP#<groupId>` partition with
 * `groupIndex`; the two are told apart by their sort key prefix, so a group's
 * policies are read with `begins_with(gsi1sk, 'POLICY#')`.
 */
export function policyAssignmentIndex(groupId: string, policyId: string): Gsi1Key {
  return { gsi1pk: `GROUP#${assertValidId(groupId)}`, gsi1sk: `POLICY#${assertValidId(policyId)}` };
}
