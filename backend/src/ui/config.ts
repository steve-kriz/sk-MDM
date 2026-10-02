/**
 * The public client configuration the admin console boots from.
 *
 *   GET /admin/config.json
 *   -> {"tenantId":"t-1","clientId":"c-9","redirectUri":"https://admin.example.com/","scope":"api://c-9/MDM.Admin"}
 *
 * Sign-in happens entirely in the browser: the SPA runs the authorization-code
 * flow with PKCE against Entra ID itself, so the Lambda never holds a session,
 * never sets a cookie and never sees a client secret. All it publishes is the
 * handful of values a public client needs to start that flow -- which is why
 * this payload is built by hand, key by key, rather than by filtering an
 * environment: a server-side value such as `ENTRA_ADMIN_GROUP_ID` or
 * `PEPPER_SECRET_ARN` cannot leak into a response it is never read into.
 *
 * `redirectUri` is derived from the request's own `Host` header rather than
 * configured, so the console works behind whatever hostname the Function URL
 * (or a fronting domain) answers on, with no redeploy.
 */

/** The environment this module reads: `process.env`, or a fake in a test. */
export type ConfigEnv = Record<string, string | undefined>;

/** The whole of what `GET /admin/config.json` answers with. */
export interface AdminClientConfig {
  tenantId: string;
  clientId: string;
  redirectUri: string;
  scope: string;
}

/** The exact key set of the published configuration; nothing else is ever added. */
export const CONFIG_KEYS = ['tenantId', 'clientId', 'redirectUri', 'scope'] as const;

/** The scope name exposed by the admin API's app registration. */
export const ADMIN_SCOPE_NAME = 'MDM.Admin';

/** The access-token scope the console asks for; its `aud` is the client id the verifier requires. */
export function adminScope(clientId: string): string {
  return `api://${clientId}/${ADMIN_SCOPE_NAME}`;
}

/** A configured value, or `null` when it is absent or the empty string. */
function configured(value: string | undefined): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/**
 * Build the client configuration, or `null` when Entra is not configured --
 * which the route answers as 500 `not_configured`, because a console that
 * cannot sign in is a deployment fault, not a bad request.
 */
export function adminClientConfig(env: ConfigEnv, host: string): AdminClientConfig | null {
  const tenantId = configured(env.ENTRA_TENANT_ID);
  const clientId = configured(env.ENTRA_CLIENT_ID);
  if (tenantId === null || clientId === null) {
    return null;
  }
  return {
    tenantId,
    clientId,
    redirectUri: `https://${host}/`,
    scope: adminScope(clientId),
  };
}
