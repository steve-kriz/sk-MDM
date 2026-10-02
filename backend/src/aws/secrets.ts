/**
 * The adapter that fits a real Secrets Manager client to the injected
 * `SecretsClient` interface of `src/crypto/pepper.ts`.
 *
 *   const getPepper = createPepperProvider({
 *     secretsClient: createSecretsClientAdapter(new SecretsManagerClient({})),
 *     secretArn,
 *   });
 *
 * Without it `createPepperProvider` would fall back to sending a plain
 * `{ operation, SecretId }` object, which a real SDK v3 client rejects; the
 * adapter exposes `getSecretValue` and sends a genuine `GetSecretValueCommand`.
 */
import { GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import type { GetSecretValueRequest, SecretsClient, SecretsResponse } from '../crypto/pepper.js';

/** An SDK-shaped client: `send` takes an AWS SDK v3 Command instance. */
export interface SdkSecretsClient {
  send(command: unknown): Promise<unknown>;
}

/** Fit an SDK-shaped Secrets Manager client to the `SecretsClient` interface. */
export function createSecretsClientAdapter(sdkClient: SdkSecretsClient): SecretsClient & {
  getSecretValue(request: GetSecretValueRequest): Promise<SecretsResponse>;
} {
  return {
    async getSecretValue({ SecretId }: GetSecretValueRequest): Promise<SecretsResponse> {
      return (await sdkClient.send(new GetSecretValueCommand({ SecretId }))) as SecretsResponse;
    },
  };
}
