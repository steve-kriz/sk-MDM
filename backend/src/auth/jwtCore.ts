/**
 * The JWT core shared by every Entra ID token verifier.
 *
 * `createJwtCore` owns the JWKS cache (with its TTL and the single refetch on
 * an unknown `kid`), the RS256 signature check and the `iss`, `aud`, `exp` and
 * `nbf` checks. A verifier built on it adds only its own authorisation rule:
 * `createTokenVerifier` (`entra.ts`) requires the admin role or group,
 * `createUserTokenVerifier` (`userToken.ts`) requires the agent scope.
 *
 * Every failure is a plain `{status, error}` object, never an Error, so a
 * caller can map it straight onto a route result.
 */
import {
  createPublicKey,
  verify as verifySignature,
  type JsonWebKeyInput,
  type KeyObject,
} from 'node:crypto';

/** Leeway applied to `exp` and `nbf`, in seconds. The bound is inclusive. */
export const CLOCK_SKEW_SECONDS = 60;

/** The only signature algorithm accepted. */
export const SIGNING_ALGORITHM = 'RS256';

/** Default JWKS cache lifetime, in seconds. */
export const DEFAULT_CACHE_TTL_SECONDS = 3600;

/** A single JSON Web Key as published by the tenant's JWKS endpoint. */
export interface JsonWebKey {
  kty?: string;
  kid?: string;
  use?: string;
  alg?: string;
  n?: string;
  e?: string;
  [claim: string]: unknown;
}

/** A JWKS document: `{ keys: [...] }`. A bare array of keys is also accepted. */
export interface JwksDocument {
  keys: JsonWebKey[];
}

/** Injected JWKS source. Rejecting surfaces as a 503, never as a bad token. */
export type JwksFetcher = () => Promise<JwksDocument | JsonWebKey[]>;

/** Injected clock. Returns an integer number of epoch *seconds*. */
export type EpochSecondsClock = () => number;

/** The decoded payload of a verified token. */
export interface TokenClaims {
  iss?: unknown;
  aud?: unknown;
  exp?: unknown;
  nbf?: unknown;
  roles?: unknown;
  groups?: unknown;
  [claim: string]: unknown;
}

/**
 * Why a token was refused. Rejections are plain objects, not Errors, so a
 * caller can map one straight onto a `RouteResult`.
 */
export interface VerifyFailure {
  status: number;
  error: string;
}

export interface JwtCoreOptions {
  /** Entra tenant id; fixes the expected issuer. */
  tenantId: string;
  /** Application (client) id; the expected `aud`. */
  clientId: string;
  /** Returns the tenant's JWKS. */
  jwksFetcher: JwksFetcher;
  /** Current time as integer epoch seconds. */
  now: EpochSecondsClock;
  /** How long a fetched JWKS is reused, in seconds. */
  cacheTtlSeconds?: number;
}

export interface JwtCore {
  /**
   * Resolve the claims of a token whose signature, issuer, audience and
   * validity window all check out, or reject with a VerifyFailure.
   */
  verify(token: string): Promise<TokenClaims>;
}

export function failure(status: number, error: string): VerifyFailure {
  return { status, error };
}

/** Narrow an unknown throwable to a VerifyFailure. */
export function isVerifyFailure(value: unknown): value is VerifyFailure {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as VerifyFailure).status === 'number' &&
    typeof (value as VerifyFailure).error === 'string'
  );
}

function decodeSegment(segment: string): Buffer {
  return Buffer.from(segment, 'base64url');
}

/** Parse one base64url JSON segment, or null when it is not a JSON object. */
export function decodeJsonSegment(segment: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(decodeSegment(segment).toString('utf8'));
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return null;
    }
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Keys from a JWKS document, tolerating a bare array of keys. */
export function readKeyList(document: JwksDocument | JsonWebKey[] | null | undefined): JsonWebKey[] | null {
  if (Array.isArray(document)) {
    return document;
  }
  if (typeof document === 'object' && document !== null && Array.isArray(document.keys)) {
    return document.keys;
  }
  return null;
}

/**
 * Import every usable RSA signing key, indexed by `kid`. A key that cannot be
 * imported is skipped rather than poisoning the whole set: it simply reads as
 * an unknown `kid` later on.
 */
export function importKeys(keys: JsonWebKey[]): Map<string, KeyObject> {
  const imported = new Map<string, KeyObject>();
  for (const key of keys) {
    if (typeof key !== 'object' || key === null) {
      continue;
    }
    const { kid, kty } = key;
    if (typeof kid !== 'string' || kid.length === 0 || kty !== 'RSA') {
      continue;
    }
    if (imported.has(kid)) {
      continue;
    }
    try {
      imported.set(kid, createPublicKey({ key: key as JsonWebKeyInput['key'], format: 'jwk' }));
    } catch {
      // Unusable key material; leave it out of the set.
    }
  }
  return imported;
}

export function createJwtCore({
  tenantId,
  clientId,
  jwksFetcher,
  now,
  cacheTtlSeconds = DEFAULT_CACHE_TTL_SECONDS,
}: JwtCoreOptions): JwtCore {
  const expectedIssuer = `https://login.microsoftonline.com/${tenantId}/v2.0`;

  let cachedKeys: Map<string, KeyObject> | null = null;
  let cachedAt = 0;

  /** Fetch the JWKS and replace the cache. Any failure is a 503. */
  async function fetchKeys(): Promise<Map<string, KeyObject>> {
    let document: JwksDocument | JsonWebKey[];
    try {
      document = await jwksFetcher();
    } catch {
      throw failure(503, 'jwks_unavailable');
    }
    const keys = readKeyList(document);
    if (keys === null) {
      // A JWKS that is not a key set is an endpoint fault, not a bad token.
      throw failure(503, 'jwks_unavailable');
    }
    cachedKeys = importKeys(keys);
    cachedAt = now();
    return cachedKeys;
  }

  /** The cached key set, refreshed once its TTL has elapsed. */
  async function loadKeys(): Promise<Map<string, KeyObject>> {
    if (cachedKeys !== null && now() - cachedAt < cacheTtlSeconds) {
      return cachedKeys;
    }
    return fetchKeys();
  }

  /**
   * Resolve the signing key for `kid`, allowing at most one refetch so a
   * key-rotation storm cannot drive unbounded traffic at the JWKS endpoint.
   */
  async function resolveKey(kid: string): Promise<KeyObject> {
    const keys = await loadKeys();
    const cached = keys.get(kid);
    if (cached !== undefined) {
      return cached;
    }
    const refreshed = await fetchKeys();
    const rotated = refreshed.get(kid);
    if (rotated !== undefined) {
      return rotated;
    }
    throw failure(401, 'unknown_key');
  }

  async function verify(token: string): Promise<TokenClaims> {
    if (typeof token !== 'string') {
      throw failure(401, 'invalid_token');
    }
    const segments = token.split('.');
    if (segments.length !== 3) {
      throw failure(401, 'invalid_token');
    }
    const [encodedHeader, encodedPayload, encodedSignature] = segments as [string, string, string];

    const header = decodeJsonSegment(encodedHeader);
    const payload = decodeJsonSegment(encodedPayload);
    if (header === null || payload === null || encodedSignature.length === 0) {
      throw failure(401, 'invalid_token');
    }
    if (header.alg !== SIGNING_ALGORITHM) {
      throw failure(401, 'invalid_token');
    }

    const kid = typeof header.kid === 'string' ? header.kid : '';
    const key = await resolveKey(kid);

    let signatureValid = false;
    try {
      signatureValid = verifySignature(
        'RSA-SHA256',
        Buffer.from(`${encodedHeader}.${encodedPayload}`, 'utf8'),
        key,
        decodeSegment(encodedSignature),
      );
    } catch {
      signatureValid = false;
    }
    if (!signatureValid) {
      throw failure(401, 'invalid_token');
    }

    const claims = payload as TokenClaims;

    if (claims.iss !== expectedIssuer) {
      throw failure(401, 'invalid_issuer');
    }
    if (claims.aud !== clientId) {
      throw failure(401, 'invalid_audience');
    }

    const currentTime = now();

    // exp/nbf are epoch *seconds*; the clock is injected in the same unit.
    const exp = claims.exp;
    if (typeof exp !== 'number' || !Number.isFinite(exp) || currentTime - exp > CLOCK_SKEW_SECONDS) {
      throw failure(401, 'token_expired');
    }
    const nbf = claims.nbf;
    if (typeof nbf === 'number' && Number.isFinite(nbf) && nbf - currentTime > CLOCK_SKEW_SECONDS) {
      throw failure(401, 'token_not_yet_valid');
    }

    return claims;
  }

  return { verify };
}
