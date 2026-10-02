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

/** `DEVICE#<deviceId>` / `CMD#<commandId>` -- one queued or completed command. */
export function deviceCommand(deviceId: string, commandId: string): TableKey {
  return { pk: `DEVICE#${assertValidId(deviceId)}`, sk: `CMD#${assertValidId(commandId)}` };
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

/**
 * `AUDIT#<YYYY-MM-DD>` / `<seq>` -- one audit entry inside a UTC day, which
 * keeps a day's entries in one partition and ordered by `seq`.
 */
export function audit(dayUtc: string, seq: string | number): TableKey {
  const sequence = typeof seq === 'number' ? String(seq) : seq;
  return { pk: `AUDIT#${assertValidId(dayUtc)}`, sk: assertValidId(sequence) };
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

/** Index attributes listing a device under its group in `gsi1`. */
export function groupIndex(groupId: string, deviceId: string): Gsi1Key {
  return { gsi1pk: `GROUP#${assertValidId(groupId)}`, gsi1sk: `DEVICE#${assertValidId(deviceId)}` };
}
