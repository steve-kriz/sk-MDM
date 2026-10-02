/**
 * Production wiring, run once per cold start.
 *
 * Every route resolves its dependencies per request through a module-level
 * setter (`configureEnrollRoute`, `configureCheckInRoute`,
 * `configurePolicyBundleRoute`, `configureAdminRoutes`, `setCommandRouteDeps`).
 * `bootstrap` reads the Lambda environment the stack sets, builds the real
 * clients from the injected factories, awaits the pepper and calls every one
 * of those setters. `src/index.ts` never calls it itself, so tests keep
 * configuring the routes with fakes; `src/lambda.ts` calls it before routing.
 *
 * The factories return SDK-shaped clients (`send(command)` taking an AWS SDK
 * v3 Command). Neither is ever handed to a consumer directly: the document
 * client is wrapped by `createSdkDocumentClientAdapter` and the secrets client
 * by `createSecretsClientAdapter`, so a real Command always reaches the SDK.
 */
import { createTokenVerifier } from './auth/entra.js';
import { createUserTokenVerifier } from './auth/userToken.js';
import { createSdkDocumentClientAdapter, type SdkDocumentClient } from './aws/documentClient.js';
import { createJwksFetcher, type FetchLike } from './aws/jwks.js';
import { createSecretsClientAdapter, type SdkSecretsClient } from './aws/secrets.js';
import { createPepperProvider } from './crypto/pepper.js';
import { createTableClient, type TableClient } from './db/table.js';
import {
  configureAdminRoutes,
  configureCheckInRoute,
  configureEnrollRoute,
  configurePolicyBundleRoute,
  configureUserSessionRoute,
  setCommandRouteDeps,
} from './index.js';
import type { TokenVerifier } from './auth/entra.js';

/** The Lambda environment variables bootstrap cannot run without, in the order they are checked. */
export const REQUIRED_ENV = ['TABLE_NAME', 'PEPPER_SECRET_ARN', 'ENTRA_TENANT_ID', 'ENTRA_CLIENT_ID'] as const;

export type BootstrapEnv = Record<string, string | undefined>;

/**
 * What bootstrap is built from. Later wiring (a Graph client, an installer
 * bucket) adds optional fields here; nothing beyond these is required.
 */
export interface BootstrapOptions {
  /** The Lambda environment, normally `process.env`. */
  env: BootstrapEnv;
  /** Builds the SDK-shaped DynamoDB document client. */
  createDocumentClient: () => SdkDocumentClient;
  /** Builds the SDK-shaped Secrets Manager client. */
  createSecretsClient: () => SdkSecretsClient;
  /** The `fetch` the JWKS fetcher uses. */
  fetchImpl?: FetchLike | typeof globalThis.fetch;
}

/** What bootstrap configured the routes with. */
export interface BootstrapResult {
  table: TableClient;
  verifier: TokenVerifier;
}

/** Current time as integer epoch seconds. */
function epochSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function readEnv(env: BootstrapEnv): Record<(typeof REQUIRED_ENV)[number], string> {
  const values = {} as Record<(typeof REQUIRED_ENV)[number], string>;
  for (const name of REQUIRED_ENV) {
    const value = env[name];
    if (value === undefined || value === '') {
      throw new Error(`missing environment variable ${name}`);
    }
    values[name] = value;
  }
  return values;
}

export async function bootstrap({
  env,
  createDocumentClient,
  createSecretsClient,
  fetchImpl = globalThis.fetch,
}: BootstrapOptions): Promise<BootstrapResult> {
  const {
    TABLE_NAME: tableName,
    PEPPER_SECRET_ARN: secretArn,
    ENTRA_TENANT_ID: tenantId,
    ENTRA_CLIENT_ID: clientId,
  } = readEnv(env);

  const table = createTableClient({
    documentClient: createSdkDocumentClientAdapter(createDocumentClient()),
    tableName,
  });
  const getPepper = createPepperProvider({
    secretsClient: createSecretsClientAdapter(createSecretsClient()),
    secretArn,
  });
  const pepper = await getPepper();

  const jwksFetcher = createJwksFetcher(tenantId, fetchImpl as FetchLike);
  const verifier = createTokenVerifier({
    tenantId,
    clientId,
    jwksFetcher,
    now: epochSeconds,
    adminGroupId: env.ENTRA_ADMIN_GROUP_ID ?? '',
  });
  // TASK-031: the agent user token verifier shares the tenant, client and JWKS fetcher.
  const userVerifier = createUserTokenVerifier({ tenantId, clientId, jwksFetcher, now: epochSeconds });

  configureEnrollRoute({ table, pepper });
  configureCheckInRoute({ table, pepper });
  configurePolicyBundleRoute({ table, pepper });
  configureAdminRoutes({ verifier, table });
  setCommandRouteDeps({ table, pepper, now: epochSeconds });
  configureUserSessionRoute({ table, pepper, now: epochSeconds, userVerifier });

  return { table, verifier };
}
