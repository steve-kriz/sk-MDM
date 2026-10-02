/**
 * Device request signing: the HMAC scheme that authenticates every
 * `/api/v1/devices/...` operation.
 *
 * `POST /api/v1/enroll` is NOT signed this way — at enroll time the agent has
 * no device id and no device secret, so that operation is authenticated by the
 * `X-MDM-Enrollment-Token` header alone.
 *
 * The agent builds the same canonical string in
 * `agent/internal/contract/signing.go`; the two implementations are pinned
 * against each other by `contract/testdata/signing-vectors.json`.
 *
 * Canonical string (seven lines joined by "\n"):
 *
 *   METHOD              upper-cased HTTP method
 *   path                request path, exactly as sent
 *   canonicalQuery      decoded query pairs sorted by key then value, "k=v" joined by "&"
 *   sha256hex(body)     lower-case SHA-256 of the UTF-8 body bytes; empty body
 *                       hashes the zero-byte input
 *   timestamp           decimal epoch seconds, no padding and no sign
 *   nonce               the X-MDM-Nonce value
 *   deviceId            the X-MDM-Device-Id value
 *
 * The signature header is `v1=` followed by 64 lower-case hex characters.
 */
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

/** Prefix every signature header must carry. */
const SIGNATURE_PREFIX = 'v1=';

/** The request facts that go into the canonical string. */
export interface SigningParts {
  /** HTTP method; upper-cased before signing. */
  method: string;
  /** Request path, e.g. `/api/v1/devices/dev-001/commands`. */
  path: string;
  /**
   * Query pairs. Accepts the raw query string (with or without a leading `?`)
   * or the decoded `query` map the router hands to a route handler.
   */
  query?: string | Record<string, string | string[]> | null | undefined;
  /** Request body. `null`, `undefined` and `''` all hash as zero bytes. */
  body?: string | Uint8Array | null | undefined;
  /** Epoch seconds, as sent in `X-MDM-Timestamp`. */
  timestamp: number;
  /** The `X-MDM-Nonce` value. */
  nonce: string;
  /** The `X-MDM-Device-Id` value. */
  deviceId: string;
}

/** Compare two strings by their UTF-8 bytes, so JS and Go sort identically. */
function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

/** Flatten the query into decoded (key, value) pairs, keeping repeated keys. */
function queryPairs(query: SigningParts['query']): Array<[string, string]> {
  if (query === undefined || query === null) {
    return [];
  }

  if (typeof query === 'string') {
    const text = query.startsWith('?') ? query.slice(1) : query;
    if (text.length === 0) {
      return [];
    }
    return [...new URLSearchParams(text)];
  }

  const pairs: Array<[string, string]> = [];
  for (const [key, value] of Object.entries(query)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        pairs.push([key, item]);
      }
      continue;
    }
    pairs.push([key, value]);
  }
  return pairs;
}

/** Sort the query pairs by key then value and render them as `k=v&k=v`. */
export function canonicalQuery(query: SigningParts['query']): string {
  const pairs = queryPairs(query);
  pairs.sort((left, right) => {
    const byKey = compareUtf8(left[0], right[0]);
    return byKey !== 0 ? byKey : compareUtf8(left[1], right[1]);
  });
  return pairs.map(([key, value]) => `${key}=${value}`).join('&');
}

/** The body as raw bytes; a missing body is zero bytes, never the string "null". */
function bodyBytes(body: SigningParts['body']): Buffer {
  if (body === undefined || body === null) {
    return Buffer.alloc(0);
  }
  if (typeof body === 'string') {
    return Buffer.from(body, 'utf8');
  }
  return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
}

/** Lower-case SHA-256 hex of the body's UTF-8 bytes. */
export function bodyHash(body: SigningParts['body']): string {
  return createHash('sha256').update(bodyBytes(body)).digest('hex');
}

/** Build the seven-line canonical string that is actually signed. */
export function canonicalString(parts: SigningParts): string {
  return [
    parts.method.toUpperCase(),
    parts.path,
    canonicalQuery(parts.query),
    bodyHash(parts.body),
    String(Math.trunc(parts.timestamp)),
    parts.nonce,
    parts.deviceId,
  ].join('\n');
}

/**
 * Sign the canonical string with the device secret.
 *
 * @param secretHex device secret as lower-case hex, as issued by enrollment
 * @returns the `X-MDM-Signature` value: `v1=` plus 64 lower-case hex characters
 */
export function signRequest(secretHex: string, parts: SigningParts): string {
  const key = Buffer.from(secretHex, 'hex');
  const mac = createHmac('sha256', key).update(canonicalString(parts), 'utf8').digest('hex');
  return `${SIGNATURE_PREFIX}${mac}`;
}

/**
 * Check an `X-MDM-Signature` header against the request.
 *
 * Returns false — never throws — for a header with the wrong prefix, the wrong
 * length, non-hex characters or a signature made with a different secret.
 */
export function verifySignature(secretHex: string, parts: SigningParts, header: string): boolean {
  if (typeof header !== 'string' || !header.startsWith(SIGNATURE_PREFIX)) {
    return false;
  }

  const presented = header.slice(SIGNATURE_PREFIX.length);
  let expected: string;
  try {
    expected = signRequest(secretHex, parts).slice(SIGNATURE_PREFIX.length);
  } catch {
    return false;
  }

  // Compare the hex text itself: equal length is already public information,
  // and a non-hex remainder simply fails to match.
  if (presented.length !== expected.length) {
    return false;
  }
  return timingSafeEqual(Buffer.from(presented, 'utf8'), Buffer.from(expected, 'utf8'));
}
