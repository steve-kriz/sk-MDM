/**
 * Authentication for the signed device API.
 *
 * Every `/api/v1/devices/...` request carries four headers -- the device id,
 * an epoch-seconds timestamp, a nonce and a `v1=` HMAC over the canonical
 * string from `src/contract/signing.ts`. `verifyDeviceRequest` checks all of
 * them against the stored device profile and burns the nonce, so a captured
 * request cannot be replayed.
 *
 *   const result = await verifyDeviceRequest(req, { table, now, pepper });
 *   if (!result.ok) return { statusCode: result.status, body: result.body };
 *
 * `POST /api/v1/enroll` is NOT authenticated here: at enroll time the agent
 * has no device id and no device secret, so that route is authenticated by its
 * enrollment token alone.
 *
 * The checks run in a fixed order and the first failure returns immediately:
 *
 *   1. all four headers present   -> 401 missing_auth_headers
 *      (plus the timestamp's format -> 401 invalid_timestamp, since the
 *       timestamp is part of the string that is signed)
 *   2. device profile found       -> 401 unknown_device
 *   3. stored secret decrypts     -> 500 device_secret_unreadable
 *   4. signature valid            -> 401 bad_signature
 *   5. timestamp within skew      -> 401 stale_timestamp
 *   6. device not revoked         -> 403 device_revoked
 *   7. nonce unused               -> 401 replayed_nonce
 *
 * The signature is checked before revocation and before the clock, so probing
 * cannot tell an unauthenticated caller whether a device id exists or has been
 * revoked. No failing path writes a nonce item, so a failure can never burn a
 * nonce the legitimate agent still needs.
 *
 * The table client and the clock are injected and no AWS client is
 * constructed here, so nothing in the tests opens a DynamoDB connection.
 */
import { decryptDeviceSecret } from '../crypto/deviceSecret.js';
import { verifySignature } from '../contract/signing.js';
import { deviceProfile, nonce as nonceKey, type TableKey } from '../db/keys.js';
import type { Item, WriteOutcome } from '../db/table.js';
import type { RouterRequest } from './router.js';

/** The device id header, lower-cased; lookups are case-insensitive. */
export const DEVICE_ID_HEADER = 'x-mdm-device-id';
/** The epoch-seconds timestamp header, lower-cased. */
export const TIMESTAMP_HEADER = 'x-mdm-timestamp';
/** The replay-protection nonce header, lower-cased. */
export const NONCE_HEADER = 'x-mdm-nonce';
/** The `v1=` signature header, lower-cased. */
export const SIGNATURE_HEADER = 'x-mdm-signature';

/** How far the agent's clock may differ from ours, in seconds. Inclusive. */
export const DEFAULT_SKEW_SECONDS = 300;

/** How long a burned nonce is remembered, in seconds. */
export const DEFAULT_NONCE_TTL_SECONDS = 900;

/** The device profile's `status` value that refuses every request. */
export const REVOKED_STATUS = 'revoked';

/** A decimal count of epoch seconds: no sign, fraction, padding or text. */
const TIMESTAMP_PATTERN = /^[0-9]{1,11}$/;

/** Injected clock. Returns an integer number of epoch *seconds*. */
export type EpochSecondsClock = () => number;

/**
 * The storage operations this module needs: the structural subset of
 * `TableClient` (see `src/db/table.ts`) a fake has to implement.
 */
export interface DeviceAuthTable {
  get(key: TableKey): Promise<Item | undefined>;
  putIfAbsent(item: Item): Promise<WriteOutcome>;
}

export interface DeviceAuthOptions {
  /** Table client. Required; never created here. */
  table: DeviceAuthTable;
  /** Current time as integer epoch seconds. */
  now: EpochSecondsClock;
  /** The 64-character hex pepper key, from `getPepper()`. */
  pepper: string;
  /** Accepted clock difference in seconds; the bound itself is accepted. */
  skewSeconds?: number;
  /** Lifetime written onto the nonce item's `ttl`, in seconds. */
  nonceTtlSeconds?: number;
}

/** An authenticated request: the device it came from. */
export interface DeviceAuthSuccess {
  ok: true;
  deviceId: string;
}

/** A refused request, shaped so a route can return it unchanged. */
export interface DeviceAuthFailure {
  ok: false;
  status: number;
  body: { error: string };
}

export type DeviceAuthResult = DeviceAuthSuccess | DeviceAuthFailure;

function failure(status: number, error: string): DeviceAuthFailure {
  return { ok: false, status, body: { error } };
}

/**
 * Index the request's headers by lower-cased name, so a hand-built request
 * keyed `X-MDM-Device-Id` reads the same as the Function URL event's
 * lower-cased `x-mdm-device-id`.
 */
function lowerCaseHeaders(headers: RouterRequest['headers'] | undefined): Map<string, string> {
  const indexed = new Map<string, string>();
  for (const [name, value] of Object.entries(headers ?? {})) {
    if (typeof value === 'string') {
      indexed.set(name.toLowerCase(), value);
    }
  }
  return indexed;
}

/** A present, non-empty header value, or `''` when it is absent or empty. */
function headerValue(headers: Map<string, string>, name: string): string {
  return headers.get(name) ?? '';
}

/** The stored device record as this module reads it. */
interface DeviceRecord extends Item {
  secretEnc?: unknown;
  status?: unknown;
}

/**
 * Authenticate one signed device request.
 *
 * @param req the router request object, `{method, path, query, headers, body}`
 * @returns `{ok:true, deviceId}` when every check passes, otherwise the status
 *   and body the route should return
 */
export async function verifyDeviceRequest(
  req: RouterRequest,
  {
    table,
    now,
    pepper,
    skewSeconds = DEFAULT_SKEW_SECONDS,
    nonceTtlSeconds = DEFAULT_NONCE_TTL_SECONDS,
  }: DeviceAuthOptions,
): Promise<DeviceAuthResult> {
  // 1. All four headers, before any table read.
  const headers = lowerCaseHeaders(req?.headers);
  const deviceId = headerValue(headers, DEVICE_ID_HEADER);
  const timestampText = headerValue(headers, TIMESTAMP_HEADER);
  const nonceValue = headerValue(headers, NONCE_HEADER);
  const signature = headerValue(headers, SIGNATURE_HEADER);

  if (deviceId === '' || timestampText === '' || nonceValue === '' || signature === '') {
    return failure(401, 'missing_auth_headers');
  }

  // The timestamp is one of the seven signed lines, so its format is settled
  // here rather than at the skew check: a value that is not a decimal count of
  // seconds is a malformed request, not a mis-signed one.
  if (!TIMESTAMP_PATTERN.test(timestampText)) {
    return failure(401, 'invalid_timestamp');
  }
  const timestamp = Number(timestampText);

  // 2. The device profile. An id that cannot even form a key is unknown.
  let record: DeviceRecord | undefined;
  try {
    record = (await table.get(deviceProfile(deviceId))) as DeviceRecord | undefined;
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('invalid id')) {
      return failure(401, 'unknown_device');
    }
    throw error;
  }
  if (record === undefined || record === null) {
    return failure(401, 'unknown_device');
  }

  // 3. The stored secret. A record we cannot read is our fault, not the
  // caller's, and must never be reported as a bad signature.
  const secretEnc = record.secretEnc;
  let secretHex: string;
  try {
    if (typeof secretEnc !== 'string' || secretEnc.length === 0) {
      return failure(500, 'device_secret_unreadable');
    }
    secretHex = decryptDeviceSecret(secretEnc, pepper, deviceId);
  } catch {
    return failure(500, 'device_secret_unreadable');
  }

  // 4. The signature over the canonical string.
  const signed = verifySignature(
    secretHex,
    {
      method: req.method,
      path: req.path,
      query: req.query,
      body: req.body,
      timestamp,
      nonce: nonceValue,
      deviceId,
    },
    signature,
  );
  if (!signed) {
    return failure(401, 'bad_signature');
  }

  // 5. Clock skew, in either direction. The bound itself is still fresh.
  const currentTime = now();
  if (Math.abs(currentTime - timestamp) > skewSeconds) {
    return failure(401, 'stale_timestamp');
  }

  // 6. Revocation.
  if (record.status === REVOKED_STATUS) {
    return failure(403, 'device_revoked');
  }

  // 7. The nonce, burned with a conditional write so a replay loses the race.
  const outcome = await table.putIfAbsent({
    ...nonceKey(deviceId, nonceValue),
    ttl: currentTime + nonceTtlSeconds,
  });
  if (!outcome?.written) {
    return failure(401, 'replayed_nonce');
  }

  return { ok: true, deviceId };
}
