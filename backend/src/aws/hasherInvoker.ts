/**
 * Start the hasher Lambda asynchronously (TASK-050).
 *
 *   const hasher = createLambdaHasherInvoker({ client: new LambdaClient({}), functionName });
 *   await hasher.invoke({ applicationId, url, hashRunId });
 *
 * One `InvokeCommand` with `InvocationType: 'Event'`: Lambda queues the event
 * and answers 202 at once, so the API Lambda never waits for (or downloads)
 * the installer. Any other `StatusCode`, or a failed send, rejects. The client
 * is injected, the same shape as the S3 client of `src/storage/installers.ts`.
 */
import { InvokeCommand } from '@aws-sdk/client-lambda';
import type { HasherEvent } from '../hashing/urlHasher.js';

/** The status Lambda answers an accepted asynchronous invocation with. */
export const ASYNC_INVOKE_ACCEPTED = 202;

/** Starts a hashing run. */
export interface HasherInvoker {
  invoke(event: HasherEvent): Promise<void>;
}

/** An SDK-shaped Lambda client (a `LambdaClient` satisfies it): only `send` is used. */
export interface HasherLambdaClient {
  send(command: InvokeCommand): Promise<unknown>;
}

export interface LambdaHasherInvokerOptions {
  /** The SDK-shaped Lambda client. */
  client: HasherLambdaClient;
  /** The hasher function's name. */
  functionName: string;
}

export function createLambdaHasherInvoker({ client, functionName }: LambdaHasherInvokerOptions): HasherInvoker {
  return {
    async invoke(event: HasherEvent): Promise<void> {
      const command = new InvokeCommand({
        FunctionName: functionName,
        InvocationType: 'Event',
        Payload: new TextEncoder().encode(JSON.stringify(event)),
      });
      const response = (await client.send(command)) as
        | { StatusCode?: unknown }
        | undefined;
      const status = response?.StatusCode;
      if (status !== ASYNC_INVOKE_ACCEPTED) {
        throw new Error(`hasher invoke answered status ${String(status)}`);
      }
    },
  };
}
