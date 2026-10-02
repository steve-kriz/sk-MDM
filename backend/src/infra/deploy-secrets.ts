/**
 * Deploy-time secrets: a read-only key/value lookup over the AWS Secrets
 * Manager secret `prod/sk-mdm` (or another secret id), for the CDK app or a
 * deploy script to call at synth/deploy time.
 *
 *   const secrets = await loadDeploySecrets({
 *     secretsClient: createSecretsManagerClient('ap-southeast-2'),
 *   });
 *   const value = secrets.require('SOME_KEY');
 *
 * The secret's `SecretString` must be a flat JSON object whose values are all
 * strings. `SecretBinary` is deliberately not accepted, and neither is a bare
 * string response.
 *
 * The Secrets Manager client is injected, in the same two shapes
 * `src/crypto/pepper.ts` accepts:
 *
 *   getSecretValue({ SecretId })                     -- preferred
 *   send({ operation: 'GetSecretValue', SecretId })  -- used when there is no
 *                                                      getSecretValue method
 *
 * Importing this module builds no client and makes no network call. Every
 * error message names the secret id; no error message and no log ever
 * contains a secret value. This module is not used by the Lambda at runtime.
 */
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';

import { createSecretsClientAdapter } from '../aws/secrets.js';
import {
  GET_SECRET_VALUE,
  type GetSecretValueRequest,
  type SecretsClient,
  type SecretsResponse,
} from '../crypto/pepper.js';

/** The secret read when no `secretId` is given. */
export const DEFAULT_DEPLOY_SECRET_ID = 'prod/sk-mdm';

export interface LoadDeploySecretsOptions {
  /** The Secrets Manager client. Required; never constructed here. */
  secretsClient: SecretsClient;
  /** Name or ARN of the secret. Defaults to `DEFAULT_DEPLOY_SECRET_ID`. */
  secretId?: string;
}

/** The resolved, frozen lookup over one secret's key/value pairs. */
export interface DeploySecrets {
  /** The id of the secret the values were read from. */
  readonly secretId: string;
  /** The value of `key`, or `undefined` when the key is absent. */
  get(key: string): string | undefined;
  /** The value of `key`; throws when the key is absent or empty. */
  require(key: string): string;
  /** Every key in the secret, sorted. */
  keys(): string[];
}

/** Fetch the raw response through whichever shape the client offers. */
async function fetchSecret(secretsClient: SecretsClient, secretId: string): Promise<SecretsResponse> {
  try {
    if (typeof secretsClient.getSecretValue === 'function') {
      return await secretsClient.getSecretValue({ SecretId: secretId });
    }
    return await secretsClient.send!({ operation: GET_SECRET_VALUE, SecretId: secretId });
  } catch (error: unknown) {
    const name =
      typeof error === 'object' && error !== null && typeof (error as { name?: unknown }).name === 'string'
        ? (error as { name: string }).name
        : 'UnknownError';
    throw new Error(`deploy secret ${secretId}: GetSecretValue failed (${name})`, { cause: error });
  }
}

/** Pull the non-empty `SecretString` out of the response, or throw. */
function readSecretString(response: SecretsResponse, secretId: string): string {
  if (
    typeof response === 'object' &&
    response !== null &&
    typeof response.SecretString === 'string' &&
    response.SecretString.length > 0
  ) {
    return response.SecretString;
  }
  throw new Error(`deploy secret ${secretId}: no SecretString in GetSecretValue response`);
}

/** Parse the secret string into a flat string-to-string map, or throw. */
function parseSecretValues(raw: string, secretId: string): Map<string, string> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // The parser's own message can quote the input, so it is not passed on.
    throw new Error(`deploy secret ${secretId}: SecretString is not a JSON object`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`deploy secret ${secretId}: SecretString is not a JSON object`);
  }
  const values = new Map<string, string>();
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (typeof value !== 'string') {
      throw new Error(`deploy secret ${secretId}: value of key ${key} is not a string`);
    }
    values.set(key, value);
  }
  return values;
}

/** Read and parse the secret into a frozen `DeploySecrets` lookup. */
export async function loadDeploySecrets({
  secretsClient,
  secretId = DEFAULT_DEPLOY_SECRET_ID,
}: LoadDeploySecretsOptions): Promise<DeploySecrets> {
  if (
    typeof secretsClient?.getSecretValue !== 'function' &&
    typeof secretsClient?.send !== 'function'
  ) {
    throw new Error('invalid secretsClient: expected getSecretValue() or send()');
  }
  if (typeof secretId !== 'string' || secretId.length === 0) {
    throw new Error('invalid secretId: expected a non-empty string');
  }

  const response = await fetchSecret(secretsClient, secretId);
  const values = parseSecretValues(readSecretString(response, secretId), secretId);
  const sortedKeys = [...values.keys()].sort();

  return Object.freeze({
    secretId,
    get(key: string): string | undefined {
      return values.get(key);
    },
    require(key: string): string {
      const value = values.get(key);
      if (value === undefined || value.length === 0) {
        throw new Error(`deploy secret ${secretId}: required key ${key} is missing or empty`);
      }
      return value;
    },
    keys(): string[] {
      return [...sortedKeys];
    },
  });
}

/**
 * A real Secrets Manager client in the injected shape. Construction is
 * synchronous and resolves no credentials; those are only looked up when a
 * call is made.
 */
export function createSecretsManagerClient(region?: string): SecretsClient & {
  getSecretValue(request: GetSecretValueRequest): Promise<SecretsResponse>;
} {
  return createSecretsClientAdapter(new SecretsManagerClient(region ? { region } : {}));
}
