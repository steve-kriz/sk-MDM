/**
 * PKCE: the proof that ties an authorization code to the browser that asked
 * for it (RFC 7636).
 *
 *   const {verifier, challenge} = createPkcePair();
 *   // -> verifier: 64 unreserved characters, kept in sessionStorage
 *   //    challenge: base64url(SHA-256(verifier)), sent to Entra
 *
 * The console is a public client: it has no secret, so the code exchange is
 * authenticated by the verifier alone. The verifier is generated here, held
 * only until the redirect comes back, and sent exactly once.
 *
 * SHA-256 is implemented in this module rather than taken from `crypto.subtle`
 * or `node:crypto` for two reasons: `crypto.subtle.digest` is asynchronous,
 * which would make `createPkcePair` a promise for no benefit, and `node:crypto`
 * is an import a browser cannot resolve. The implementation is the plain FIPS
 * 180-4 one, so `node --test` can check it against `node:crypto` directly.
 */

/** The characters RFC 7636 allows in a verifier: the unreserved set. */
export const UNRESERVED = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

/** How long a generated verifier is; RFC 7636 allows 43..128. */
export const VERIFIER_LENGTH = 64;

/** How long a generated `state` value is. */
export const STATE_LENGTH = 32;

const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const K = Uint32Array.from([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(value, bits) {
  return ((value >>> bits) | (value << (32 - bits))) >>> 0;
}

/** FIPS 180-4 SHA-256 over a byte array, returning 32 bytes. */
export function sha256(bytes) {
  const input = Uint8Array.from(bytes);
  const h = Uint32Array.from([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);

  // Message, 0x80, zeros, then the bit length as a 64-bit big-endian integer.
  const blocks = Math.ceil((input.length + 9) / 64);
  const padded = new Uint8Array(blocks * 64);
  padded.set(input);
  padded[input.length] = 0x80;
  const view = new DataView(padded.buffer);
  const bitLength = input.length * 8;
  view.setUint32(padded.length - 8, Math.floor(bitLength / 0x100000000));
  view.setUint32(padded.length - 4, bitLength >>> 0);

  const w = new Uint32Array(64);
  for (let offset = 0; offset < padded.length; offset += 64) {
    for (let i = 0; i < 16; i += 1) {
      w[i] = view.getUint32(offset + i * 4);
    }
    for (let i = 16; i < 64; i += 1) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i += 1) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }

    const next = [a, b, c, d, e, f, g, hh];
    for (let i = 0; i < 8; i += 1) {
      h[i] = (h[i] + next[i]) >>> 0;
    }
  }

  const digest = new Uint8Array(32);
  const digestView = new DataView(digest.buffer);
  for (let i = 0; i < 8; i += 1) {
    digestView.setUint32(i * 4, h[i]);
  }
  return digest;
}

/** base64url of a byte array, with no `=` padding. */
export function base64url(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : undefined;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : undefined;
    out += BASE64URL[b0 >>> 2];
    out += BASE64URL[((b0 & 0x03) << 4) | ((b1 ?? 0) >>> 4)];
    if (b1 === undefined) {
      break;
    }
    out += BASE64URL[((b1 & 0x0f) << 2) | ((b2 ?? 0) >>> 6)];
    if (b2 === undefined) {
      break;
    }
    out += BASE64URL[b2 & 0x3f];
  }
  return out;
}

/** UTF-8 bytes of a string. `TextEncoder` is a global in Node and every browser. */
function utf8Bytes(text) {
  return new TextEncoder().encode(text);
}

/**
 * The bytes to draw a secret from.
 *
 * `source` is a function that returns bytes (`node:crypto`'s `randomBytes` and
 * a fixed test source both fit), a byte array, or nothing -- in which case the
 * platform's own CSPRNG is used. A source that returns fewer bytes than asked
 * for is cycled, so a fixed source stays deterministic and a short one is never
 * silently truncated to nothing.
 */
function takeBytes(source, length) {
  let supplied = typeof source === 'function' ? source(length) : source;
  if (supplied === undefined || supplied === null) {
    supplied = globalThis.crypto.getRandomValues(new Uint8Array(length));
  }
  const bytes = Uint8Array.from(supplied);
  if (bytes.length === 0) {
    throw new Error('random source returned no bytes');
  }
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    out[i] = bytes[i % bytes.length];
  }
  return out;
}

/** A string of `length` characters drawn from the unreserved set. */
function unreservedString(bytes) {
  let out = '';
  for (const byte of bytes) {
    out += UNRESERVED[byte % UNRESERVED.length];
  }
  return out;
}

/** The code challenge for a verifier: unpadded base64url of its SHA-256. */
export function challengeFor(verifier) {
  return base64url(sha256(utf8Bytes(verifier)));
}

/**
 * A verifier and its challenge.
 *
 * The verifier is 64 characters of the unreserved set -- inside RFC 7636's
 * 43..128 -- and the challenge is the `S256` transform of it.
 */
export function createPkcePair(randomBytes) {
  const verifier = unreservedString(takeBytes(randomBytes, VERIFIER_LENGTH));
  return { verifier, challenge: challengeFor(verifier) };
}

/** An opaque `state` value, drawn from the same alphabet as a verifier. */
export function createState(randomBytes) {
  return unreservedString(takeBytes(randomBytes, STATE_LENGTH));
}
