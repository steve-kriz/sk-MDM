/**
 * Best-effort "last seen" bookkeeping for device-authenticated agent routes.
 *
 *   await recordDeviceContact(deps.table, deviceId, toDate(clock()));
 *
 * Called by the command lease, command result, policy bundle and user-session
 * routes once their own work is done and they are about to answer 200. It
 * refreshes the device profile's `lastSeenAt` and its `gsi1` device-list index
 * entry with the server's instant (never a time the agent sent).
 *
 * The update is conditional: it never creates a stub profile for a device
 * deleted mid-request, and never moves `lastSeenAt` backwards when two
 * requests finish out of order (ISO strings in `isoUtc` format compare
 * lexicographically in time order).
 *
 * It never throws. A failed condition is ignored silently; any other error is
 * logged as one `console.warn` line, so a bookkeeping failure cannot turn an
 * already-completed request (e.g. a poll that has leased commands) into a 500.
 *
 * The check-in route keeps its own unconditional update and does not use this.
 */
import { isoUtc } from '../audit.js';
import { deviceListIndex, deviceProfile, type TableKey } from '../db/keys.js';
import { CONDITIONAL_CHECK_FAILED, type Item, type RequestFields } from '../db/table.js';

/** The refresh's update expression. */
export const LAST_SEEN_UPDATE_EXPRESSION = 'SET lastSeenAt = :lastSeenAt, gsi1pk = :gsi1pk, gsi1sk = :gsi1sk';

/** The refresh's guard: the profile exists and its `lastSeenAt` is not later than this instant. */
export const LAST_SEEN_CONDITION =
  'attribute_exists(pk) AND (attribute_not_exists(lastSeenAt) OR lastSeenAt <= :lastSeenAt)';

/** The one table operation the refresh needs. */
export interface DeviceContactTable {
  update(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
}

/** True when a thrown value is DynamoDB's failed-condition rejection. */
function isConditionalCheckFailure(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === CONDITIONAL_CHECK_FAILED
  );
}

/**
 * Refresh `deviceId`'s `lastSeenAt` and device-list index to `at`.
 * Never throws; see the module comment for the failure handling.
 */
export async function recordDeviceContact(
  table: DeviceContactTable,
  deviceId: string,
  at: Date,
): Promise<void> {
  try {
    const lastSeenAt = isoUtc(at);
    const { gsi1pk, gsi1sk } = deviceListIndex(lastSeenAt);
    await table.update(deviceProfile(deviceId), {
      UpdateExpression: LAST_SEEN_UPDATE_EXPRESSION,
      ConditionExpression: LAST_SEEN_CONDITION,
      ExpressionAttributeValues: {
        ':lastSeenAt': lastSeenAt,
        ':gsi1pk': gsi1pk,
        ':gsi1sk': gsi1sk,
      },
    });
  } catch (error) {
    if (isConditionalCheckFailure(error)) {
      return;
    }
    console.warn(JSON.stringify({ msg: 'last-seen update failed', deviceId }));
  }
}
