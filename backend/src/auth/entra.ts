/**
 * Microsoft Entra ID access token validation for the admin API.
 *
 * `createTokenVerifier` returns a `verify(token)` that resolves the decoded
 * claims of a valid admin token and rejects with a `{status, error}` failure
 * otherwise. Every outside dependency is injected -- the JWKS arrives through
 * `jwksFetcher` and the clock through `now()` -- so the verifier runs offline
 * and deterministically under test.
 *
 *   const verifier = createTokenVerifier({
 *     tenantId, clientId, jwksFetcher, now: () => Math.floor(Date.now() / 1000),
 *   });
 *   const claims = await verifier.verify(bearerToken);
 *
 * The JWKS cache, the RS256 signature check and the `iss`/`aud`/`exp`/`nbf`
 * checks live in the shared `jwtCore.ts`; this module adds the admin rule.
 */
import {
  CLOCK_SKEW_SECONDS,
  DEFAULT_CACHE_TTL_SECONDS,
  SIGNING_ALGORITHM,
  createJwtCore,
  failure,
  isVerifyFailure,
  type EpochSecondsClock,
  type JsonWebKey,
  type JwksDocument,
  type JwksFetcher,
  type TokenClaims,
  type VerifyFailure,
} from './jwtCore.js';

export { CLOCK_SKEW_SECONDS, DEFAULT_CACHE_TTL_SECONDS, SIGNING_ALGORITHM, isVerifyFailure };
export type { EpochSecondsClock, JsonWebKey, JwksDocument, JwksFetcher, TokenClaims, VerifyFailure };

/**
 * The app role that grants admin, independently of group membership. Entra
 * keeps app-role and exposed-scope values in one namespace, so this cannot be
 * `MDM.Admin`: that value is the delegated scope the console signs in with
 * (`ADMIN_SCOPE_NAME` in ui/config.ts).
 */
export const ADMIN_ROLE = 'MDM.Administrator';

export interface TokenVerifierOptions {
  /** Entra tenant id; fixes the expected issuer. */
  tenantId: string;
  /** Application (client) id; the expected `aud`. */
  clientId: string;
  /** Returns the tenant's JWKS. */
  jwksFetcher: JwksFetcher;
  /** Current time as integer epoch seconds. */
  now: EpochSecondsClock;
  /** Optional group whose members are admins. Empty string disables it. */
  adminGroupId?: string;
  /** How long a fetched JWKS is reused, in seconds. */
  cacheTtlSeconds?: number;
}

export interface TokenVerifier {
  /** Resolve the claims of a valid admin token, or reject with a VerifyFailure. */
  verify(token: string): Promise<TokenClaims>;
}

function readStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === 'string') : [];
}

export function createTokenVerifier({
  tenantId,
  clientId,
  jwksFetcher,
  now,
  adminGroupId = '',
  cacheTtlSeconds = DEFAULT_CACHE_TTL_SECONDS,
}: TokenVerifierOptions): TokenVerifier {
  const configuredGroupId = typeof adminGroupId === 'string' ? adminGroupId : '';
  const core = createJwtCore({ tenantId, clientId, jwksFetcher, now, cacheTtlSeconds });

  async function verify(token: string): Promise<TokenClaims> {
    const claims = await core.verify(token);

    const roles = readStringArray(claims.roles);
    const groups = readStringArray(claims.groups);
    const isAdmin =
      roles.includes(ADMIN_ROLE) || (configuredGroupId.length > 0 && groups.includes(configuredGroupId));
    if (!isAdmin) {
      throw failure(403, 'not_admin');
    }

    return claims;
  }

  return { verify };
}
