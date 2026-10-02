#!/usr/bin/env node
/**
 * CDK entry point. Run through `cdk` from the `backend` directory, which reads
 * `backend/cdk.json` and executes `node dist/infra/app.js`.
 *
 * `ENTRA_TENANT_ID` / `ENTRA_CLIENT_ID` default to the same-named keys of the
 * Secrets Manager secret `prod/sk-mdm`, loaded at synth time. Per key, a
 * non-empty environment variable wins, then CDK context
 * (`cdk deploy -c entraTenantId=...`), then the secret. `ENTRA_ADMIN_GROUP_ID`
 * is read from the environment, falling back to CDK context.
 */
import { App } from 'aws-cdk-lib';

import { createSecretsManagerClient, loadDeploySecrets } from './deploy-secrets.js';
import { resolveEntraSettings } from './entra-settings.js';
import { MdmStack } from './mdm-stack.js';

const app = new App();

function setting(envName: string, contextKey: string): string | undefined {
  const fromEnv = process.env[envName];
  if (fromEnv !== undefined && fromEnv !== '') {
    return fromEnv;
  }
  const fromContext: unknown = app.node.tryGetContext(contextKey);
  return typeof fromContext === 'string' && fromContext !== '' ? fromContext : undefined;
}

const secret = await loadDeploySecrets({ secretsClient: createSecretsManagerClient() });
const { entraTenantId, entraClientId } = resolveEntraSettings({
  env: process.env,
  context: (key) => app.node.tryGetContext(key),
  secret,
});

new MdmStack(app, 'MdmStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
  entraTenantId,
  entraClientId,
  entraAdminGroupId: setting('ENTRA_ADMIN_GROUP_ID', 'entraAdminGroupId'),
});

app.synth();
