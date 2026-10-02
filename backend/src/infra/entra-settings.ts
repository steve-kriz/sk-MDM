/**
 * Resolves the Entra tenant and client ids that `MdmStack` needs at synth time.
 *
 * Precedence, per key: a non-empty process-env value, then a non-empty string
 * CDK-context value, then the same-named key of the deploy secret (trimmed).
 * Pure: no AWS calls; the secret is loaded beforehand by `loadDeploySecrets`.
 */
import { DEFAULT_DEPLOY_SECRET_ID, type DeploySecrets } from './deploy-secrets.js';

export interface ResolveEntraSettingsOptions {
  env: Record<string, string | undefined>;
  context: (key: string) => unknown;
  secret: DeploySecrets;
}

export interface EntraSettings {
  entraTenantId: string;
  entraClientId: string;
}

function resolve(
  { env, context, secret }: ResolveEntraSettingsOptions,
  envName: string,
  contextKey: string,
): string {
  const fromEnv = env[envName];
  if (fromEnv !== undefined && fromEnv !== '') {
    return fromEnv;
  }
  const fromContext = context(contextKey);
  if (typeof fromContext === 'string' && fromContext !== '') {
    return fromContext;
  }
  // `get`, not `require`: `require` throws the loader's message, not this one.
  const fromSecret = secret.get(envName)?.trim();
  if (fromSecret !== undefined && fromSecret !== '') {
    return fromSecret;
  }
  throw new Error(
    `${envName} not found in secret ${DEFAULT_DEPLOY_SECRET_ID}, environment or CDK context`,
  );
}

export function resolveEntraSettings(options: ResolveEntraSettingsOptions): EntraSettings {
  const entraTenantId = resolve(options, 'ENTRA_TENANT_ID', 'entraTenantId');
  const entraClientId = resolve(options, 'ENTRA_CLIENT_ID', 'entraClientId');
  return { entraTenantId, entraClientId };
}
