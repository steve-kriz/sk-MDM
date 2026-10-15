/**
 * `POST /api/v1/agent-auth/enrollment-token` -- spec Amendment B.
 *
 * The Entra access token the agent redeems after the brokered sign-in
 * (`agentSignIn.ts`) is used for exactly this one call and is never stored:
 * it mints a single-use enrollment token, which the agent writes to its config
 * and presents to `POST /api/v1/enroll` in `X-MDM-Enrollment-Token`.
 *
 *   POST /api/v1/agent-auth/enrollment-token   Authorization: Bearer <access token>   {}
 *   -> 201 {"tokenId":"<16 hex>","token":"<16 hex>.<64 hex>","expiresAt":null}
 *
 * The route is public (no device credential exists yet). Checks, in order,
 * the first failure answering:
 *
 *   1. Entra not configured (or no verifier) -> 500 not_configured
 *   2. no / blank `Authorization: Bearer`    -> 401 user_token_missing
 *   3. verifier rejects with 503             -> 503 jwks_unavailable
 *   4. any other rejection                   -> 401 invalid_user_token
 *
 * The verifier is `createUserTokenVerifier` (scope `MDM.Agent`, configured
 * tenant and audience). The minted record has the admin route's shape and
 * hashing (`mintEnrollmentToken`), with `maxUses: 1`, no expiry (it stays
 * usable until it enrolls a device or an admin revokes it),
 * `label: "sign-in <upn>"`, `createdBy: "user:<upn or oid>"` and
 * `enrolledBy: {oid, upn, name}`, which the enroll route copies onto the
 * device. It is audited as `enrollment_token.created` with
 * `detail.source: "agent-sign-in"`. Neither the bearer nor the minted token is
 * ever logged, stored or audited; the token appears only in the 201 body.
 */
import { randomBytes as cryptoRandomBytes } from 'node:crypto';
import { mintEnrollmentToken, type MintTable, type TokenEnrolledBy } from '../admin/enrollmentTokens.js';
import { isVerifyFailure, type TokenClaims } from '../auth/jwtCore.js';
import type { RouteHandler, RouteRequest, RouteResult, Router } from '../http/router.js';
import { agentAuthConfig, type AgentAuthEnv } from './userSession.js';

/** Where the agent exchanges its user token for an enrollment token. */
export const AGENT_ENROLLMENT_TOKEN_PATH = '/api/v1/agent-auth/enrollment-token';

/** A sign-in token enrolls one device. */
export const SIGN_IN_TOKEN_MAX_USES = 1;

/** `detail.source` of the audit entry, telling these mints from the admin's. */
export const SIGN_IN_TOKEN_SOURCE = 'agent-sign-in';

/** The authorization scheme, compared case-insensitively. */
const BEARER_SCHEME = 'bearer ';

/** Verifies the signed-in user's Entra token; `createUserTokenVerifier` fits. */
export interface AgentUserVerifier {
  verify(token: string): Promise<TokenClaims>;
}

/** Current time: a `Date`, an ISO string, or integer epoch seconds. */
export type AgentEnrollmentTokenClock = () => Date | string | number;

export interface AgentEnrollmentTokenDependencies {
  /** Table client. Required; never created here. */
  table: MintTable;
  /** The user token verifier. Without one the route answers 500 not_configured. */
  userVerifier?: AgentUserVerifier;
  /** Current time. Defaults to the system clock. */
  now?: AgentEnrollmentTokenClock;
  /** Random source for the token. Defaults to `crypto.randomBytes`. */
  randomBytes?: (size: number) => Buffer;
  /** Environment holding the Entra ids. Defaults to `process.env`. */
  env?: AgentAuthEnv;
}

/** Dependencies, or something that resolves them when the request arrives. */
export type AgentEnrollmentTokenDependencySource =
  | AgentEnrollmentTokenDependencies
  | (() => AgentEnrollmentTokenDependencies | Promise<AgentEnrollmentTokenDependencies>);

const NO_STORE = { 'cache-control': 'no-store' };

function failure(statusCode: number, error: string): RouteResult {
  return { statusCode, headers: { ...NO_STORE }, body: { error } };
}

function toDate(instant: Date | string | number): Date {
  if (instant instanceof Date) {
    return new Date(instant.getTime());
  }
  if (typeof instant === 'string') {
    return new Date(instant);
  }
  return new Date(instant * 1000);
}

/** The bearer token, or `null` when the header is absent or not `Bearer <non-blank>`. */
function readBearer(headers: RouteRequest['headers'] | undefined): string | null {
  for (const [name, value] of Object.entries(headers ?? {})) {
    if (name.toLowerCase() !== 'authorization' || typeof value !== 'string') {
      continue;
    }
    if (value.length <= BEARER_SCHEME.length || value.slice(0, BEARER_SCHEME.length).toLowerCase() !== BEARER_SCHEME) {
      return null;
    }
    const token = value.slice(BEARER_SCHEME.length).trim();
    return token.length > 0 ? token : null;
  }
  return null;
}

/** A non-empty string claim, or `null`. */
function claimOrNull(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/**
 * Build the mint handler.
 *
 * @param source the dependencies, or a function resolving them per request
 */
export function createAgentEnrollmentTokenHandler(source: AgentEnrollmentTokenDependencySource): RouteHandler {
  return async function handleAgentEnrollmentToken(req: RouteRequest): Promise<RouteResult> {
    const deps = typeof source === 'function' ? await source() : source;
    const env = deps.env ?? process.env;
    const verifier = deps.userVerifier;

    // 1. Entra must be configured for any user token to be verifiable.
    if (agentAuthConfig(env) === null || verifier === undefined) {
      return failure(500, 'not_configured');
    }

    // 2. The bearer. The body carries nothing and is not read.
    const bearer = readBearer(req?.headers);
    if (bearer === null) {
      return failure(401, 'user_token_missing');
    }

    // 3./4. The token itself. The reason is not echoed: the agent only needs
    // to know whether to retry later or to sign in again.
    let claims: TokenClaims;
    try {
      claims = await verifier.verify(bearer);
    } catch (rejection) {
      if (isVerifyFailure(rejection) && rejection.status === 503) {
        return failure(503, 'jwks_unavailable');
      }
      return failure(401, 'invalid_user_token');
    }

    const enrolledBy: TokenEnrolledBy = {
      oid: claims.oid as string,
      upn: claimOrNull(claims.preferred_username),
      name: claimOrNull(claims.name),
    };
    const who = enrolledBy.upn ?? enrolledBy.oid;
    const at = toDate((deps.now ?? ((): Date => new Date()))());
    const minted = await mintEnrollmentToken(deps.table, {
      label: `sign-in ${who}`,
      maxUses: SIGN_IN_TOKEN_MAX_USES,
      expiry: null,
      createdBy: `user:${who}`,
      actor: `user:${who}`,
      at,
      randomBytes: deps.randomBytes ?? cryptoRandomBytes,
      enrolledBy,
      auditDetail: { source: SIGN_IN_TOKEN_SOURCE },
    });

    return {
      statusCode: 201,
      headers: { ...NO_STORE },
      body: { tokenId: minted.tokenId, token: minted.token, expiresAt: minted.expiresAt },
    };
  };
}

/** Register the route on a router. Returns the router, so calls chain. */
export function registerAgentEnrollmentTokenRoute(
  router: Router,
  source: AgentEnrollmentTokenDependencySource,
): Router {
  return router.add('POST', AGENT_ENROLLMENT_TOKEN_PATH, createAgentEnrollmentTokenHandler(source));
}

/** Dependencies supplied at start-up by `bootstrap`. */
let configuredDependencies: AgentEnrollmentTokenDependencies | null = null;

/** Supply the mint route's storage and user token verifier. */
export function configureAgentEnrollmentTokenRoute(dependencies: AgentEnrollmentTokenDependencies): void {
  configuredDependencies = dependencies;
}

/** The configured dependencies, or a thrown error when start-up skipped them. */
export function resolveAgentEnrollmentTokenDependencies(): AgentEnrollmentTokenDependencies {
  if (configuredDependencies === null) {
    throw new Error(
      'agent enrollment-token route is not configured: call configureAgentEnrollmentTokenRoute() at start-up',
    );
  }
  return configuredDependencies;
}
