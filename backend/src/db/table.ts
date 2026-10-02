/**
 * Thin wrapper over an injected DynamoDB document client.
 *
 * `createTableClient` owns exactly two things: it stamps `TableName` onto
 * every request, and it turns DynamoDB's pagination token into an opaque
 * cursor string. It never constructs an AWS client -- the client arrives
 * through `documentClient` -- so callers under test inject a fake with a
 * recording `send` and no AWS SDK is needed to exercise the storage layer.
 *
 *   const table = createTableClient({ documentClient, tableName: 'mdm' });
 *   const item = await table.get(deviceProfile('dev-7'));
 *   const page = await table.query({ IndexName: 'gsi1', KeyConditionExpression: '#p = :p',
 *     ExpressionAttributeNames: { '#p': 'gsi1pk' }, ExpressionAttributeValues: { ':p': 'DEVICE' },
 *     limit: 25, cursor });
 *
 * Everything other than `TableName`, `Key`/`Item` and the pagination fields is
 * passed straight through, so callers write ordinary DynamoDB expressions.
 * Errors from the client propagate unchanged, with one exception: a losing
 * `putIfAbsent` race resolves to `{ written: false }` rather than throwing.
 */
import type { TableKey } from './keys.js';

/** A document-shaped DynamoDB item: plain JavaScript values, not attribute maps. */
export type Item = Record<string, unknown>;

/** Extra request fields merged into a command's input. */
export type RequestFields = Record<string, unknown>;

/** The document operations this wrapper issues. */
export type DocumentOperation = 'Get' | 'Put' | 'Update' | 'Query' | 'Delete';

/**
 * One request handed to the injected client. Shaped like an AWS SDK v3
 * command -- the request body lives under `input` -- so wiring a real
 * `DynamoDBDocumentClient` needs only a map from `operation` to its command
 * class.
 */
export interface DocumentCommand {
  readonly operation: DocumentOperation;
  readonly input: RequestFields;
}

/** The parts of a DynamoDB response this wrapper reads. */
export interface DocumentResult {
  Item?: Item;
  Items?: Item[];
  Attributes?: Item;
  LastEvaluatedKey?: Item;
  [field: string]: unknown;
}

/** The injected client: anything that can send a command. */
export interface DocumentClient {
  send(command: DocumentCommand): Promise<DocumentResult | undefined>;
}

export interface TableClientOptions {
  /** The DynamoDB document client. Required; never created here. */
  documentClient: DocumentClient;
  /** The single table's name, stamped onto every request. */
  tableName: string;
}

/** Outcome of a conditional put: `false` means the item already existed. */
export interface WriteOutcome {
  written: boolean;
}

/** A query request: ordinary DynamoDB fields plus opaque pagination. */
export interface QueryRequest extends RequestFields {
  /** Maximum number of items in the page. */
  limit?: number;
  /** Cursor returned by a previous `query`, or `null`/`undefined` for the first page. */
  cursor?: string | null;
}

/** One page of query results. `cursor` is `null` when the page is the last. */
export interface QueryPage {
  items: Item[];
  cursor: string | null;
}

export interface TableClient {
  /** Read one item, or `undefined` when it does not exist. */
  get(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
  /** Write one item, overwriting any existing item with the same key. */
  put(item: Item, fields?: RequestFields): Promise<void>;
  /** Write one item only if its key is free. Resolves `{written:false}` on a lost race. */
  putIfAbsent(item: Item, fields?: RequestFields): Promise<WriteOutcome>;
  /** Apply an update expression; resolves the returned attributes. */
  update(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
  /** Run a query and return one page plus the cursor for the next. */
  query(request?: QueryRequest): Promise<QueryPage>;
  /** Remove one item. Deleting a missing item is not an error in DynamoDB. */
  delete(key: TableKey, fields?: RequestFields): Promise<void>;
}

/** The condition that makes a put succeed only when the key is free. */
export const PUT_IF_ABSENT_CONDITION = 'attribute_not_exists(pk)';

/** The error name DynamoDB rejects a failed `ConditionExpression` with. */
export const CONDITIONAL_CHECK_FAILED = 'ConditionalCheckFailedException';

/** Encode a `LastEvaluatedKey` as the opaque cursor handed back to callers. */
export function encodeCursor(lastEvaluatedKey: Item): string {
  return Buffer.from(JSON.stringify(lastEvaluatedKey), 'utf8').toString('base64');
}

/**
 * Decode a cursor produced by `encodeCursor` back into an `ExclusiveStartKey`.
 * Anything that is not such a cursor is rejected: the value is opaque to
 * callers, so a malformed one is a bug, never a request to start over.
 */
export function decodeCursor(cursor: string): Item {
  if (typeof cursor !== 'string' || cursor.length === 0) {
    throw new Error('invalid cursor');
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(cursor, 'base64').toString('utf8'));
  } catch {
    throw new Error('invalid cursor');
  }
  if (typeof decoded !== 'object' || decoded === null || Array.isArray(decoded)) {
    throw new Error('invalid cursor');
  }
  return decoded as Item;
}

/** True when a thrown value is DynamoDB's failed-condition rejection. */
function isConditionalCheckFailure(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === CONDITIONAL_CHECK_FAILED
  );
}

export function createTableClient({ documentClient, tableName }: TableClientOptions): TableClient {
  /** Send one command, with `TableName` stamped on last so it cannot be overridden. */
  async function send(operation: DocumentOperation, input: RequestFields): Promise<DocumentResult> {
    const result = await documentClient.send({ operation, input: { ...input, TableName: tableName } });
    return result ?? {};
  }

  async function get(key: TableKey, fields: RequestFields = {}): Promise<Item | undefined> {
    const result = await send('Get', { ...fields, Key: key });
    return result.Item;
  }

  async function put(item: Item, fields: RequestFields = {}): Promise<void> {
    await send('Put', { ...fields, Item: item });
  }

  async function putIfAbsent(item: Item, fields: RequestFields = {}): Promise<WriteOutcome> {
    try {
      await send('Put', { ...fields, Item: item, ConditionExpression: PUT_IF_ABSENT_CONDITION });
    } catch (error) {
      if (isConditionalCheckFailure(error)) {
        return { written: false };
      }
      throw error;
    }
    return { written: true };
  }

  async function update(key: TableKey, fields: RequestFields = {}): Promise<Item | undefined> {
    // ALL_NEW by default so an update reads back what it wrote; a caller that
    // wants something else simply passes its own ReturnValues.
    const result = await send('Update', { ReturnValues: 'ALL_NEW', ...fields, Key: key });
    return result.Attributes;
  }

  async function query(request: QueryRequest = {}): Promise<QueryPage> {
    const { limit, cursor, ...fields } = request;
    const input: RequestFields = { ...fields };
    if (limit !== undefined) {
      input.Limit = limit;
    }
    if (cursor !== undefined && cursor !== null) {
      input.ExclusiveStartKey = decodeCursor(cursor);
    }
    const result = await send('Query', input);
    const lastEvaluatedKey = result.LastEvaluatedKey;
    return {
      items: result.Items ?? [],
      cursor: lastEvaluatedKey === undefined || lastEvaluatedKey === null ? null : encodeCursor(lastEvaluatedKey),
    };
  }

  async function remove(key: TableKey, fields: RequestFields = {}): Promise<void> {
    await send('Delete', { ...fields, Key: key });
  }

  return { get, put, putIfAbsent, update, query, delete: remove };
}
