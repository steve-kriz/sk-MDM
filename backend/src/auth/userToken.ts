/**
 * Microsoft Entra ID access token validation for a user signed in on an agent.
 *
 * `createUserTokenVerifier` returns a `verify(token)` that resolves the decoded
 * claims of a valid agent-scoped user token. It shares the JWKS cache, the
 * RS256 signature check and the `iss`/`aud`/`exp`/`nbf` checks with the admin
 * verifier (`jwtCore.ts`), then requires:
 *
 *   - the space-separated `scp` claim to hold the exact element `MDM.Agent`;
 *   - `tid` to equal the configured tenant;
 *   - `oid` to be a non-empty string.
 *
 * No role or group is required: any user of the tenant may sign in on a device.
 * Failures are the same plain `{status, error}` objects the admin verifier
 * rejects with.
 */
import {
  DEFAULT_CACHE_TTL_SECONDS,
  createJwtCore,
  failure,
  type EpochSecondsClock,
  type JwksFetcher,
  type TokenClaims,
} from './jwtCore.js';

/** The delegated scope the agent's sign-in asks for. */
export const AGENT_SCOPE_NAME = 'MDM.Agent';

/** `scp` absent, or not holding the exact element `MDM.Agent`. */
export const MISSING_SCOPE = 'missing_scope';

/** `oid` missing or empty, or `tid` naming another tenant. */
export const INVALID_SUBJECT = 'invalid_subject';

export interface UserTokenVerifierOptions {
  /** Entra tenant id; fixes the expected issuer and `tid`. */
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

export interface UserTokenVerifier {
  /** Resolve the claims of a valid agent user token, or reject with a VerifyFailure. */
  verify(token: string): Promise<TokenClaims>;
}

/** True when the space-separated scope string holds `scope` as a whole element. */
function hasScope(scp: unknown, scope: string): boolean {
  if (typeof scp !== 'string') {
    return false;
  }
  return scp.split(' ').includes(scope);
}

export function createUserTokenVerifier({
  tenantId,
  clientId,
  jwksFetcher,
  now,
  cacheTtlSeconds = DEFAULT_CACHE_TTL_SECONDS,
}: UserTokenVerifierOptions): UserTokenVerifier {
  const core = createJwtCore({ tenantId, clientId, jwksFetcher, now, cacheTtlSeconds });

  async function verify(token: string): Promise<TokenClaims> {
    const claims = await core.verify(token);

    if (!hasScope(claims.scp, AGENT_SCOPE_NAME)) {
      throw failure(401, MISSING_SCOPE);
    }
    if (claims.tid !== tenantId) {
      throw failure(401, INVALID_SUBJECT);
    }
    if (typeof claims.oid !== 'string' || claims.oid.length === 0) {
      throw failure(401, INVALID_SUBJECT);
    }

    return claims;
  }

  return { verify };
}

/** The delegated scope the Applications page's sign-in asks for. */
export const APP_USER_SCOPE_NAME = 'MDM.User';

/**
 * The verifier for a user signed in on the Applications page (`/applications`).
 *
 * The same JWT core checks as every other verifier, then: the space-separated
 * `scp` must hold the exact element `MDM.User` (403 `missing_scope` otherwise,
 * including a token carrying only `MDM.Admin`), `tid` must equal the configured
 * tenant and `oid` must be non-empty (401 `invalid_subject` otherwise). No role
 * or group is required.
 */
export function createAppUserTokenVerifier({
  tenantId,
  clientId,
  jwksFetcher,
  now,
  cacheTtlSeconds = DEFAULT_CACHE_TTL_SECONDS,
}: UserTokenVerifierOptions): UserTokenVerifier {
  const core = createJwtCore({ tenantId, clientId, jwksFetcher, now, cacheTtlSeconds });

  async function verify(token: string): Promise<TokenClaims> {
    const claims = await core.verify(token);

    if (!hasScope(claims.scp, APP_USER_SCOPE_NAME)) {
      throw failure(403, MISSING_SCOPE);
    }
    if (claims.tid !== tenantId) {
      throw failure(401, INVALID_SUBJECT);
    }
    if (typeof claims.oid !== 'string' || claims.oid.length === 0) {
      throw failure(401, INVALID_SUBJECT);
    }

    return claims;
  }

  return { verify };
}
