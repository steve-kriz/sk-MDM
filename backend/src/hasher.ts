/**
 * The hasher Lambda's entry point (bundled to `dist-hasher/index.mjs`, TASK-050).
 *
 * The API Lambda invokes it asynchronously with `{applicationId, url,
 * hashRunId}` when a URL-source application is registered or its hash is
 * retried. It streams the URL through `hashUrl`, then records the outcome with
 * exactly one conditional `table.update` on `application(applicationId)`:
 *
 *   attribute_exists(pk) AND hashRunId = :runId
 *
 * so a deleted application is never brought back and a stale run never
 * overwrites a newer Retry. A failed condition is logged on one line and the
 * invocation resolves. The hasher never reads the table: the event carries
 * everything it needs. A malformed event writes nothing and resolves.
 *
 * Nothing is built at import time: the production table client is created on
 * the first invocation, so importing the bundle without `TABLE_NAME` is safe.
 */
import { createSdkDocumentClient, createSdkDocumentClientAdapter } from './aws/documentClient.js';
import { isoUtc } from './audit.js';
import { application as applicationKey, type TableKey } from './db/keys.js';
import { CONDITIONAL_CHECK_FAILED, createTableClient, type Item, type RequestFields } from './db/table.js';
import { hashOutcomeUpdate, hashUrl, type HasherEvent, type HashFetch } from './hashing/urlHasher.js';

/** The one table operation the hasher uses. */
export interface HasherTable {
  update(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
}

export interface HasherHandlerOptions {
  table: HasherTable;
  fetch: HashFetch;
  /** Current time. Defaults to the system clock. */
  now?: () => Date;
  /** Deadline passed to `hashUrl`. Defaults to its own `HASH_DEADLINE_MS`. */
  deadlineMs?: number;
}

export type HasherHandler = (event: unknown) => Promise<void>;

/** The event's three fields, or `null` when any is missing or not a string. */
function readEvent(event: unknown): HasherEvent | null {
  if (typeof event !== 'object' || event === null) {
    return null;
  }
  const { applicationId, url, hashRunId } = event as Record<string, unknown>;
  if (typeof applicationId !== 'string' || typeof url !== 'string' || typeof hashRunId !== 'string') {
    return null;
  }
  return { applicationId, url, hashRunId };
}

/** The application key, or `null` when the id cannot form one. */
function keyOf(applicationId: string): TableKey | null {
  try {
    return applicationKey(applicationId);
  } catch {
    return null;
  }
}

function isConditionalCheckFailure(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === CONDITIONAL_CHECK_FAILED
  );
}

/** One log line, with no line breaks from the logged values. */
function oneLine(text: string): string {
  return text.replace(/[\r\n]+/g, ' ');
}

export function createHasherHandler({ table, fetch, now, deadlineMs }: HasherHandlerOptions): HasherHandler {
  const clock = now ?? ((): Date => new Date());
  return async (raw: unknown): Promise<void> => {
    const event = readEvent(raw);
    if (event === null) {
      console.error('[hasher] malformed event ignored');
      return;
    }
    const key = keyOf(event.applicationId);
    if (key === null) {
      console.error('[hasher] event with an invalid applicationId ignored');
      return;
    }

    const result = await hashUrl(event.url, {
      fetch,
      ...(deadlineMs === undefined ? {} : { deadlineMs }),
    });

    try {
      await table.update(key, { ...hashOutcomeUpdate(event.hashRunId, result, isoUtc(clock())) });
    } catch (error) {
      if (isConditionalCheckFailure(error)) {
        console.log(oneLine(`[hasher] ${event.applicationId}: outcome not stored (application deleted or run superseded)`));
        return;
      }
      throw error;
    }
  };
}

let productionHandler: HasherHandler | null = null;

/** The production handler, built on the first invocation from the Lambda environment. */
function productionHasher(): HasherHandler {
  if (productionHandler === null) {
    const tableName = process.env.TABLE_NAME ?? '';
    if (tableName === '') {
      throw new Error('missing environment variable TABLE_NAME');
    }
    const table = createTableClient({
      documentClient: createSdkDocumentClientAdapter(createSdkDocumentClient()),
      tableName,
    });
    productionHandler = createHasherHandler({ table, fetch: globalThis.fetch as unknown as HashFetch });
  }
  return productionHandler;
}

/** The deployed hasher Lambda's handler (`index.handler`). */
export const handler: HasherHandler = async (event: unknown): Promise<void> => productionHasher()(event);
