/**
 * The deployed Lambda's entry point (bundled to `dist-lambda/index.mjs`).
 *
 * It runs `bootstrap` once per cold start -- memoised as one promise, so
 * concurrent first invocations share it -- and then hands every event to the
 * `handler` of `src/index.ts`. A failed bootstrap is not cached: that
 * invocation answers 503 `service_unavailable`, one line is logged, and the
 * next invocation retries.
 */
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { createSdkDocumentClient } from './aws/documentClient.js';
import { bootstrap, type BootstrapOptions } from './bootstrap.js';
import { handler as routeHandler, type FunctionUrlEvent, type FunctionUrlResponse } from './index.js';

export type LambdaOptions = BootstrapOptions;

export type LambdaHandler = (event: FunctionUrlEvent) => Promise<FunctionUrlResponse>;

/** The production wiring: the real environment, AWS clients and `fetch`. */
export const defaultLambdaOptions: LambdaOptions = {
  env: process.env,
  createDocumentClient: createSdkDocumentClient,
  createSecretsClient: () => new SecretsManagerClient({}),
  fetchImpl: globalThis.fetch,
};

function serviceUnavailable(): FunctionUrlResponse {
  return {
    statusCode: 503,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ error: 'service_unavailable' }),
  };
}

export function createLambdaHandler(options: LambdaOptions): LambdaHandler {
  let ready: Promise<unknown> | null = null;

  function ensureBootstrapped(): Promise<unknown> {
    if (ready === null) {
      ready = bootstrap(options).catch((error: unknown) => {
        ready = null;
        throw error;
      });
    }
    return ready;
  }

  return async (event: FunctionUrlEvent): Promise<FunctionUrlResponse> => {
    try {
      await ensureBootstrapped();
    } catch (error) {
      const text = error instanceof Error ? error.message : String(error);
      console.error(`[bootstrap] failed: ${text.replace(/[\r\n]+/g, ' ')}`);
      return serviceUnavailable();
    }
    return routeHandler(event);
  };
}

export const handler: LambdaHandler = createLambdaHandler(defaultLambdaOptions);
