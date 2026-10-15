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
import { BedrockRuntimeClient } from '@aws-sdk/client-bedrock-runtime';
import { CloudWatchLogsClient } from '@aws-sdk/client-cloudwatch-logs';
import { LambdaClient } from '@aws-sdk/client-lambda';
import { S3Client, type S3ClientConfig } from '@aws-sdk/client-s3';
import { createTokenVerifier } from './auth/entra.js';
import { createAppUserTokenVerifier, createUserTokenVerifier } from './auth/userToken.js';
import { createSdkDocumentClientAdapter, type SdkDocumentClient } from './aws/documentClient.js';
import { createLambdaHasherInvoker } from './aws/hasherInvoker.js';
import { createCloudWatchHeartbeatLog } from './aws/heartbeatLog.js';
import { createJwksFetcher, type FetchLike } from './aws/jwks.js';
import { createBedrockScriptGenerator } from './aws/scriptGenerator.js';
import { createSecretsClientAdapter, type SdkSecretsClient } from './aws/secrets.js';
import { createPepperProvider } from './crypto/pepper.js';
import { createTableClient, type TableClient } from './db/table.js';
import {
  configureAdminRoutes,
  configureAgentEnrollmentTokenRoute,
  configureAgentSignInRoutes,
  configureApplicationRoutes,
  configureCheckInRoute,
  configureDownloadRoute,
  configureEnrollRoute,
  configureHeartbeatRoute,
  configurePolicyBundleRoute,
  configureUserSessionRoute,
  setCommandRouteDeps,
} from './index.js';
import { createS3InstallerStore } from './storage/installers.js';
import type { TokenVerifier } from './auth/entra.js';

/** The Lambda environment variables bootstrap cannot run without, in the order they are checked. */
export const REQUIRED_ENV = ['TABLE_NAME', 'PEPPER_SECRET_ARN', 'ENTRA_TENANT_ID', 'ENTRA_CLIENT_ID'] as const;

/**
 * Options every S3 client bootstrap builds starts from. Checksums are calculated
 * only when an operation requires them, so a presigned PUT (TASK-049 uploads)
 * never carries SDK default checksum parameters the browser's upload cannot
 * satisfy.
 */
export const S3_CLIENT_OPTIONS: S3ClientConfig = { requestChecksumCalculation: 'WHEN_REQUIRED' };

export type BootstrapEnv = Record<string, string | undefined>;

/**
 * What bootstrap is built from. Later wiring (an installer bucket) adds optional fields here; nothing beyond these is required.
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
  /** Builds the SDK-shaped S3 client the installer store wraps. Defaults to `new S3Client({ ...S3_CLIENT_OPTIONS })`. */
  createS3Client?: () => S3Client;
  /**
   * Builds the SDK-shaped CloudWatch Logs client the heartbeat log wraps.
   * Defaults to `new CloudWatchLogsClient({})`; called only when
   * `HEARTBEAT_LOG_GROUP` is set.
   */
  createLogsClient?: () => CloudWatchLogsClient;
  /**
   * Builds the SDK-shaped Lambda client the URL hasher invoker wraps (TASK-050).
   * Defaults to `new LambdaClient({})`; called only when `HASHER_FUNCTION_NAME` is set.
   */
  createLambdaClient?: () => LambdaClient;
  /**
   * Builds the SDK-shaped Bedrock Runtime client the script generator wraps (TASK-053).
   * Defaults to `new BedrockRuntimeClient({})`; called only when `BEDROCK_MODEL_ID` is set.
   */
  createBedrockRuntimeClient?: () => BedrockRuntimeClient;
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
  createS3Client = (): S3Client => new S3Client({ ...S3_CLIENT_OPTIONS }),
  createLogsClient = (): CloudWatchLogsClient => new CloudWatchLogsClient({}),
  createLambdaClient = (): LambdaClient => new LambdaClient({}),
  createBedrockRuntimeClient = (): BedrockRuntimeClient => new BedrockRuntimeClient({}),
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
  // The Secrets Manager adapter the pepper is read through.
  const secretsClient = createSecretsClientAdapter(createSecretsClient());
  const getPepper = createPepperProvider({ secretsClient, secretArn });
  const pepper = await getPepper();

  const jwksFetcher = createJwksFetcher(tenantId, fetchImpl as FetchLike);
  const verifier = createTokenVerifier({
    tenantId,
    clientId,
    jwksFetcher,
    now: epochSeconds,
    adminGroupId: env.ENTRA_ADMIN_GROUP_ID ?? '',
  });
  // The agent user token verifier shares the tenant, client and JWKS fetcher.
  // Amendment B: it is used only to mint a single-use enrollment token.
  const userVerifier = createUserTokenVerifier({ tenantId, clientId, jwksFetcher, now: epochSeconds });
  // TASK-049: the Applications page's MDM.User token verifier, same tenant, client and JWKS fetcher.
  const appUserVerifier = createAppUserTokenVerifier({ tenantId, clientId, jwksFetcher, now: epochSeconds });

  // Not a required variable: without a log group the heartbeat routes answer
  // 503 heartbeat_not_configured (when a heartbeat is on) and every other route still runs.
  const heartbeatLogGroup = env.HEARTBEAT_LOG_GROUP ?? '';
  const heartbeatLog =
    heartbeatLogGroup.length > 0
      ? createCloudWatchHeartbeatLog({ client: createLogsClient(), logGroupName: heartbeatLogGroup })
      : undefined;

  // Not a required variable: without a bucket the download route answers
  // 500 not_configured and every other route still runs. The one store is
  // shared with check-in (TASK-048), which reads the published agent build
  // through it only when a bucket is configured.
  const installerBucket = env.INSTALLER_BUCKET ?? '';
  const installers = createS3InstallerStore({ bucket: installerBucket, client: createS3Client() });
  // TASK-049: the admin and application routes share that one store, only when a bucket is configured.
  const configuredInstallers = installerBucket.length > 0 ? installers : undefined;

  // TASK-050: not a required variable either. Without the hasher function a
  // URL-source create or Retry answers 500 not_configured; uploads still work.
  const hasherFunctionName = env.HASHER_FUNCTION_NAME ?? '';
  const hasher =
    hasherFunctionName.length > 0
      ? createLambdaHasherInvoker({ client: createLambdaClient(), functionName: hasherFunctionName })
      : undefined;

  // TASK-053: not a required variable. Without a model id the generate route
  // answers 503 not_configured and every other route still runs.
  const bedrockModelId = env.BEDROCK_MODEL_ID ?? '';
  const scriptGenerator =
    bedrockModelId.length > 0
      ? createBedrockScriptGenerator({ client: createBedrockRuntimeClient(), modelId: bedrockModelId })
      : undefined;

  configureEnrollRoute({ table, pepper });
  configureCheckInRoute({ table, pepper, ...(installerBucket.length > 0 ? { installers } : {}) });
  configurePolicyBundleRoute({ table, pepper });
  configureAdminRoutes({
    verifier,
    table,
    ...(heartbeatLog === undefined ? {} : { heartbeatLog }),
    installers: configuredInstallers,
    hasher,
    scriptGenerator,
  });
  setCommandRouteDeps({ table, pepper, now: epochSeconds });
  configureDownloadRoute({ bucket: installerBucket, installers });
  // Amendment B: device HMAC only; the agent reports the OS console user.
  configureUserSessionRoute({ table, pepper, now: epochSeconds });
  // Amendment A: the MDM-brokered agent sign-in sessions.
  configureAgentSignInRoutes({ table });
  configureAgentEnrollmentTokenRoute({ table, userVerifier });
  // TASK-049: the signed-in Applications page and the agent's download details.
  configureApplicationRoutes({
    table,
    pepper,
    now: epochSeconds,
    userVerifier: appUserVerifier,
    installers: configuredInstallers,
  });
  // TASK-044: device HMAC; samples go to CloudWatch Logs when the heartbeat is on.
  configureHeartbeatRoute({
    table,
    pepper,
    now: epochSeconds,
    ...(heartbeatLog === undefined ? {} : { heartbeatLog }),
  });

  return { table, verifier };
}
