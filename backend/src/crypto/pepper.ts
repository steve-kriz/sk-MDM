/**
 * The pepper key: the AES key every device secret is encrypted under.
 *
 * The stack stores a random secret string in Secrets Manager and publishes its
 * ARN to the Lambda as `PEPPER_SECRET_ARN` (see `src/infra/mdm-stack.ts`). The
 * key material actually used is the SHA-256 of that secret string, rendered as
 * 64 lower-case hex characters, so the stored secret may be any length or
 * character set while the key is always exactly 32 bytes.
 *
 *   const getPepper = createPepperProvider({ secretsClient, secretArn: process.env.PEPPER_SECRET_ARN });
 *   const pepper = await getPepper();  // or: provider.getPepper()
 *
 * The Secrets Manager client is injected and no AWS client is constructed
 * here, so tests inject a recording fake and nothing opens a connection. The
 * injected client only has to offer one of two shapes:
 *
 *   getSecretValue({ SecretId })                     -- preferred, SDK v2 style
 *   send({ operation: 'GetSecretValue', SecretId })  -- used when there is no
 *                                                      getSecretValue method
 *
 * and resolve `{ SecretString }`, `{ SecretBinary }`, or the secret string
 * itself. The value is fetched at most once per provider: the in-flight
 * promise is cached, so concurrent callers share the single call. A failed
 * fetch is not cached, so a later call retries.
 */
import { createHash } from 'node:crypto';

/** The Secrets Manager operation this module issues. */
export const GET_SECRET_VALUE = 'GetSecretValue';

/** The request body of a `GetSecretValue` call. */
export interface GetSecretValueRequest {
  SecretId: string;
}

/** One command handed to a client that exposes only `send`. */
export interface SecretsCommand extends GetSecretValueRequest {
  operation: typeof GET_SECRET_VALUE;
}

/** The parts of a `GetSecretValue` response this module reads. */
export interface GetSecretValueResult {
  SecretString?: string;
  SecretBinary?: string | Uint8Array;
  [field: string]: unknown;
}

/** What a fetch may resolve: a response object or the bare secret string. */
export type SecretsResponse = GetSecretValueResult | string | undefined;

/** The injected Secrets Manager client. Never created here. */
export interface SecretsClient {
  getSecretValue?(request: GetSecretValueRequest): Promise<SecretsResponse>;
  send?(command: SecretsCommand): Promise<SecretsResponse>;
}

export interface PepperProviderOptions {
  /** The Secrets Manager client. Required; never constructed here. */
  secretsClient: SecretsClient;
  /** ARN (or name) of the pepper secret, from `PEPPER_SECRET_ARN`. */
  secretArn: string;
}

/**
 * The provider. Callable directly -- `await provider()` -- and also exposing
 * `getPepper()`, so either destructuring style reads naturally at the call
 * site.
 */
export interface PepperProvider {
  (): Promise<string>;
  /** Resolve the 64-character lower-case hex pepper key. */
  getPepper(): Promise<string>;
}

/** Pull the secret string out of whatever the injected client resolved. */
function readSecretString(response: SecretsResponse): string {
  if (typeof response === 'string') {
    return response;
  }
  if (typeof response !== 'object' || response === null) {
    throw new Error('pepper secret unavailable: empty GetSecretValue response');
  }
  if (typeof response.SecretString === 'string' && response.SecretString.length > 0) {
    return response.SecretString;
  }
  const binary = response.SecretBinary;
  if (typeof binary === 'string' && binary.length > 0) {
    return Buffer.from(binary, 'base64').toString('utf8');
  }
  if (binary instanceof Uint8Array && binary.byteLength > 0) {
    return Buffer.from(binary.buffer, binary.byteOffset, binary.byteLength).toString('utf8');
  }
  throw new Error('pepper secret unavailable: no SecretString in GetSecretValue response');
}

export function createPepperProvider({ secretsClient, secretArn }: PepperProviderOptions): PepperProvider {
  if (typeof secretArn !== 'string' || secretArn.length === 0) {
    throw new Error('invalid secretArn: expected a non-empty string');
  }

  let pending: Promise<string> | null = null;

  async function fetchPepper(): Promise<string> {
    let response: SecretsResponse;
    if (typeof secretsClient?.getSecretValue === 'function') {
      response = await secretsClient.getSecretValue({ SecretId: secretArn });
    } else if (typeof secretsClient?.send === 'function') {
      response = await secretsClient.send({ operation: GET_SECRET_VALUE, SecretId: secretArn });
    } else {
      throw new Error('invalid secretsClient: expected getSecretValue() or send()');
    }
    return createHash('sha256').update(readSecretString(response), 'utf8').digest('hex');
  }

  const provider = ((): Promise<string> => {
    if (pending === null) {
      // Cache the promise, not the value, so concurrent callers share one
      // call; drop it again on failure so a transient error can be retried.
      pending = fetchPepper().catch((error: unknown) => {
        pending = null;
        throw error;
      });
    }
    return pending;
  }) as PepperProvider;

  provider.getPepper = provider;
  return provider;
}
