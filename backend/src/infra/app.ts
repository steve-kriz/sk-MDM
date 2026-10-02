#!/usr/bin/env node
/**
 * CDK entry point. Run through `cdk` from the `backend` directory, which reads
 * `backend/cdk.json` and executes `node dist/infra/app.js`.
 *
 * The Entra values are required by `MdmStack`, so they are supplied here from
 * the environment, falling back to CDK context (`cdk deploy -c entraTenantId=...`).
 */
import { App } from 'aws-cdk-lib';

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

new MdmStack(app, 'MdmStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
  // `MdmStack` throws if either is missing; the cast keeps that single check in
  // the stack rather than duplicating the message here.
  entraTenantId: setting('ENTRA_TENANT_ID', 'entraTenantId') as string,
  entraClientId: setting('ENTRA_CLIENT_ID', 'entraClientId') as string,
  entraAdminGroupId: setting('ENTRA_ADMIN_GROUP_ID', 'entraAdminGroupId'),
  // Optional: the stack defaults to `prod/sk-mdm` / `ENTRA_CLIENT_SECRET`.
  graphSecretName: setting('GRAPH_SECRET_NAME', 'graphSecretName'),
  graphSecretKey: setting('GRAPH_SECRET_KEY', 'graphSecretKey'),
});

app.synth();
