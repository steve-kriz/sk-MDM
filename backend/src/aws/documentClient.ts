/**
 * The real DynamoDB document client, and the adapter that fits it to the
 * injected `DocumentClient` interface of `src/db/table.ts`.
 *
 *   const table = createTableClient({
 *     documentClient: createSdkDocumentClientAdapter(createSdkDocumentClient()),
 *     tableName,
 *   });
 *
 * `createTableClient` sends plain `{ operation, input }` requests; an AWS SDK
 * v3 client only accepts Command instances. The adapter maps each operation to
 * its `@aws-sdk/lib-dynamodb` command class and passes the input through
 * unchanged. Errors from the SDK propagate unchanged, so a failed condition
 * still reaches `putIfAbsent` as a `ConditionalCheckFailedException`.
 */
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DeleteCommand,
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';
import type { DocumentClient, DocumentCommand, DocumentOperation, DocumentResult } from '../db/table.js';

/** An SDK-shaped client: `send` takes an AWS SDK v3 Command instance. */
export interface SdkDocumentClient {
  send(command: unknown): Promise<unknown>;
}

type CommandFactory = (input: Record<string, unknown>) => unknown;

/** Each document operation and the lib-dynamodb command that carries it. */
const COMMANDS: Readonly<Record<DocumentOperation, CommandFactory>> = {
  Get: (input) => new GetCommand(input as unknown as ConstructorParameters<typeof GetCommand>[0]),
  Put: (input) => new PutCommand(input as unknown as ConstructorParameters<typeof PutCommand>[0]),
  Update: (input) => new UpdateCommand(input as unknown as ConstructorParameters<typeof UpdateCommand>[0]),
  Query: (input) => new QueryCommand(input as unknown as ConstructorParameters<typeof QueryCommand>[0]),
  Delete: (input) => new DeleteCommand(input as unknown as ConstructorParameters<typeof DeleteCommand>[0]),
};

/** Build the production document client. Undefined attribute values are dropped, not rejected. */
export function createSdkDocumentClient(): DynamoDBDocumentClient {
  return DynamoDBDocumentClient.from(new DynamoDBClient({}), {
    marshallOptions: { removeUndefinedValues: true },
  });
}

/** Fit an SDK-shaped document client to the `DocumentClient` interface `createTableClient` takes. */
export function createSdkDocumentClientAdapter(sdkClient: SdkDocumentClient): DocumentClient {
  return {
    async send({ operation, input }: DocumentCommand): Promise<DocumentResult | undefined> {
      const factory = Object.prototype.hasOwnProperty.call(COMMANDS, operation) ? COMMANDS[operation] : undefined;
      if (factory === undefined) {
        throw new Error(`unsupported DynamoDB operation: ${String(operation)}`);
      }
      return (await sdkClient.send(factory(input))) as DocumentResult | undefined;
    },
  };
}
