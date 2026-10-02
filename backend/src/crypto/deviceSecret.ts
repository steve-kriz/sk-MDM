/**
 * Envelope encryption for the per-device HMAC secret.
 *
 * The device secret is the key the agent signs requests with (see
 * `src/contract/signing.ts`), so the backend must be able to read it back --
 * it cannot be stored as a hash. It is stored on the device profile item under
 * `secretEnc`, encrypted with AES-256-GCM under the pepper key the stack keeps
 * in Secrets Manager (`PEPPER_SECRET_ARN`, see `src/crypto/pepper.ts`).
 *
 *   const secretEnc = encryptDeviceSecret(secretHex, pepperKeyHex, deviceId);
 *   const secretHex = decryptDeviceSecret(secretEnc, pepperKeyHex, deviceId);
 *
 * The device id is the additional authenticated data, so a `secretEnc` lifted
 * from one device's item and pasted onto another's fails to decrypt rather
 * than handing out a working key. Layout of the decoded value:
 *
 *   iv(12) || ciphertext(32) || authTag(16)   = 60 bytes = 80 base64 characters
 *
 * Every failure -- wrong pepper, wrong device id, a flipped byte, a truncated
 * value -- throws. Callers map that onto their own error; this module never
 * returns a partially trusted result.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

/** The only cipher used here. */
export const CIPHER_ALGORITHM = 'aes-256-gcm';

/** Length of the random GCM nonce, in bytes. */
export const IV_BYTES = 12;

/** Length of the GCM authentication tag, in bytes. */
export const AUTH_TAG_BYTES = 16;

/** Length of a device secret and of the pepper key, in bytes (64 hex chars). */
export const KEY_BYTES = 32;

/** Length of the base64 `secretEnc` attribute: 12 + 32 + 16 bytes. */
export const SECRET_ENC_LENGTH = 80;

/** A 64-character hex string, in either case. */
const HEX_KEY_PATTERN = /^[0-9a-fA-F]{64}$/;

/** Unpadded standard base64, exactly as `encryptDeviceSecret` emits it. */
const SECRET_ENC_PATTERN = /^[A-Za-z0-9+/]{80}$/;

/** Decode a 64-character hex key, or throw naming which key was wrong. */
function hexKey(value: string, label: string): Buffer {
  if (typeof value !== 'string' || !HEX_KEY_PATTERN.test(value)) {
    throw new Error(`invalid ${label}: expected 64 hex characters`);
  }
  return Buffer.from(value, 'hex');
}

/** The additional authenticated data binding a ciphertext to one device. */
function additionalData(deviceId: string): Buffer {
  if (typeof deviceId !== 'string' || deviceId.length === 0) {
    throw new Error('invalid deviceId: expected a non-empty string');
  }
  return Buffer.from(deviceId, 'utf8');
}

/**
 * Encrypt a device secret for storage.
 *
 * @param secretHex 64-character hex device secret, as issued by enrollment
 * @param pepperKeyHex 64-character hex pepper key from `getPepper()`
 * @param deviceId the device the secret belongs to; bound in as GCM AAD
 * @returns the 80-character base64 `secretEnc` attribute value
 */
export function encryptDeviceSecret(secretHex: string, pepperKeyHex: string, deviceId: string): string {
  const secret = hexKey(secretHex, 'device secret');
  const key = hexKey(pepperKeyHex, 'pepper key');
  const aad = additionalData(deviceId);

  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(CIPHER_ALGORITHM, key, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(secret), cipher.final()]);
  return Buffer.concat([iv, ciphertext, cipher.getAuthTag()]).toString('base64');
}

/**
 * Decrypt a stored device secret.
 *
 * @param secretEnc the 80-character base64 `secretEnc` attribute
 * @param pepperKeyHex 64-character hex pepper key from `getPepper()`
 * @param deviceId the device the item belongs to; must match the AAD used to encrypt
 * @returns the original 64-character lower-case hex device secret
 * @throws when the value is malformed, or when the key, the device id or the
 *   ciphertext does not match the authentication tag
 */
export function decryptDeviceSecret(secretEnc: string, pepperKeyHex: string, deviceId: string): string {
  if (typeof secretEnc !== 'string' || !SECRET_ENC_PATTERN.test(secretEnc)) {
    throw new Error(`invalid secretEnc: expected ${SECRET_ENC_LENGTH} base64 characters`);
  }
  const key = hexKey(pepperKeyHex, 'pepper key');
  const aad = additionalData(deviceId);

  const decoded = Buffer.from(secretEnc, 'base64');
  if (decoded.length !== IV_BYTES + KEY_BYTES + AUTH_TAG_BYTES) {
    throw new Error('invalid secretEnc: wrong length');
  }
  const iv = decoded.subarray(0, IV_BYTES);
  const ciphertext = decoded.subarray(IV_BYTES, IV_BYTES + KEY_BYTES);
  const authTag = decoded.subarray(IV_BYTES + KEY_BYTES);

  const decipher = createDecipheriv(CIPHER_ALGORITHM, key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(authTag);
  // `final()` throws when the tag does not match, which is the only check that
  // matters here: a wrong pepper or a wrong device id both land on it.
  const secret = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return secret.toString('hex');
}
