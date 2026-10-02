/**
 * The production `JwksFetcher` for `createTokenVerifier`: reads the Entra
 * tenant's v2.0 signing keys over `fetch`.
 *
 * A non-2xx answer or a failed request rejects, which the verifier reports as
 * `503 jwks_unavailable` rather than as a bad token.
 */
import type { JsonWebKey, JwksDocument, JwksFetcher } from '../auth/entra.js';

/** The subset of `fetch` this module uses, so tests can inject a fake. */
export type FetchLike = (url: string) => Promise<{
  ok?: boolean;
  status: number;
  json(): Promise<unknown>;
}>;

/** The tenant's JWKS endpoint. */
export function jwksUrl(tenantId: string): string {
  return `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/discovery/v2.0/keys`;
}

export function createJwksFetcher(tenantId: string, fetchImpl: FetchLike = globalThis.fetch as unknown as FetchLike): JwksFetcher {
  const url = jwksUrl(tenantId);
  return async (): Promise<JwksDocument | JsonWebKey[]> => {
    const response = await fetchImpl(url);
    if (response.status < 200 || response.status > 299) {
      throw new Error(`JWKS request failed with status ${response.status}`);
    }
    return (await response.json()) as JwksDocument | JsonWebKey[];
  };
}
