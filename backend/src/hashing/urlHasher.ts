/**
 * Compute the SHA-256 of a URL-source application's installer (TASK-050).
 *
 *   const result = await hashUrl('https://example.com/setup.msi', { fetch });
 *   // -> { ok: true, sha256: '<64 lowercase hex>' } or { ok: false, error: 'http_404' }
 *
 * Runs in the hasher Lambda (`src/hasher.ts`), never in the API Lambda. The
 * body is streamed into `createHash('sha256')` chunk by chunk and never
 * buffered whole, so an installer of up to `HASH_MAX_BYTES` fits in a small
 * Lambda. Redirects are followed by hand (`redirect: 'manual'`) so every hop
 * can be required to be https. `hashUrl` never rejects: every failure is one
 * of the error codes below.
 *
 *   invalid_url, fetch_failed, http_<status>, redirect_not_https,
 *   too_many_redirects, too_large, empty_body, timeout
 *
 * This module also builds the conditional DynamoDB update the hasher writes
 * its outcome with, so the write rule lives beside the codes it records.
 */
import { createHash } from 'node:crypto';

/** Largest installer hashed, in bytes: the agent's `MaxApplicationBytes` (2 GiB). */
export const HASH_MAX_BYTES = 2147483648;

/** The hasher's own deadline, in milliseconds: below the 900 s Lambda timeout. */
export const HASH_DEADLINE_MS = 840000;

/** Most redirects followed before giving up. */
export const HASH_MAX_REDIRECTS = 5;

/** The condition every hasher write carries: the record still exists and this run is still the latest. */
export const HASH_OUTCOME_CONDITION = 'attribute_exists(pk) AND hashRunId = :runId';

/** The asynchronous invocation event the API Lambda sends the hasher. */
export interface HasherEvent {
  applicationId: string;
  url: string;
  hashRunId: string;
}

/** The headers `hashUrl` reads from a response. */
export interface HashResponseHeaders {
  get(name: string): string | null | undefined;
}

/** The parts of a `fetch` response `hashUrl` uses. The body is iterated, never read whole. */
export interface HashResponse {
  status: number;
  headers: HashResponseHeaders;
  body?: unknown;
}

/** The request options `hashUrl` passes to `fetch`. */
export interface HashFetchInit {
  redirect: 'manual';
  signal: AbortSignal;
}

/** A `fetch`-shaped function; `globalThis.fetch` satisfies it. */
export type HashFetch = (url: string, init: HashFetchInit) => Promise<HashResponse>;

export interface HashUrlOptions {
  fetch: HashFetch;
  /** Largest accepted body, in bytes. Defaults to `HASH_MAX_BYTES`. */
  maxBytes?: number;
  /** Deadline for the whole run, in milliseconds. Defaults to `HASH_DEADLINE_MS`. */
  deadlineMs?: number;
  /** Most redirects followed. Defaults to `HASH_MAX_REDIRECTS`. */
  maxRedirects?: number;
}

export type HashResult = { ok: true; sha256: string } | { ok: false; error: string };

/** The redirect statuses that are followed. */
const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

/** Thrown internally to end a run with one error code. */
class HashFailure extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

function failure(error: string): HashResult {
  return { ok: false, error };
}

/** True when a body can be iterated chunk by chunk. */
function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { [Symbol.asyncIterator]?: unknown })[Symbol.asyncIterator] === 'function'
  );
}

/** Best effort: cancel a response body that will not be read (or read no further). */
function cancelBody(body: unknown): void {
  if (typeof body !== 'object' || body === null) {
    return;
  }
  const cancel = (body as { cancel?: unknown }).cancel;
  if (typeof cancel !== 'function') {
    return;
  }
  try {
    const outcome: unknown = cancel.call(body);
    if (outcome instanceof Promise) {
      outcome.catch(() => undefined);
    }
  } catch {
    // A body that cannot be cancelled is simply left alone.
  }
}

/** One body chunk as bytes. */
function chunkBytes(chunk: unknown): Uint8Array {
  if (chunk instanceof Uint8Array) {
    return chunk;
  }
  if (typeof chunk === 'string') {
    return Buffer.from(chunk, 'utf8');
  }
  if (chunk instanceof ArrayBuffer) {
    return new Uint8Array(chunk);
  }
  throw new HashFailure('fetch_failed');
}

/** The `https:` URL `value` names, or `null`. */
function parseHttps(value: string, base?: string): URL | null {
  try {
    const parsed = base === undefined ? new URL(value) : new URL(value, base);
    return parsed.protocol === 'https:' ? parsed : null;
  } catch {
    return null;
  }
}

/** Stream a 2xx body into the hash, enforcing the size limit. */
async function hashBody(body: unknown, maxBytes: number, signal: AbortSignal): Promise<string> {
  if (!isAsyncIterable(body)) {
    throw new HashFailure('empty_body');
  }
  const hash = createHash('sha256');
  let total = 0;
  const iterator = body[Symbol.asyncIterator]();
  try {
    for (;;) {
      const next = await iterator.next();
      if (next.done === true) {
        break;
      }
      if (signal.aborted) {
        throw new HashFailure('timeout');
      }
      const bytes = chunkBytes(next.value);
      total += bytes.byteLength;
      if (total > maxBytes) {
        try {
          const ended = iterator.return?.();
          if (ended instanceof Promise) {
            ended.catch(() => undefined);
          }
        } catch {
          // Ending the iteration early is best effort.
        }
        cancelBody(body);
        throw new HashFailure('too_large');
      }
      hash.update(bytes);
    }
  } catch (error) {
    if (error instanceof HashFailure) {
      throw error;
    }
    throw new HashFailure(signal.aborted ? 'timeout' : 'fetch_failed');
  }
  if (total === 0) {
    throw new HashFailure('empty_body');
  }
  return hash.digest('hex');
}

/** Follow redirects and hash the final body. Throws `HashFailure`. */
async function run(
  start: URL,
  fetchImpl: HashFetch,
  maxBytes: number,
  maxRedirects: number,
  signal: AbortSignal,
): Promise<string> {
  let current = start;
  let redirects = 0;
  for (;;) {
    let response: HashResponse;
    try {
      response = await fetchImpl(current.href, { redirect: 'manual', signal });
    } catch {
      throw new HashFailure(signal.aborted ? 'timeout' : 'fetch_failed');
    }
    if (signal.aborted) {
      cancelBody(response.body);
      throw new HashFailure('timeout');
    }
    const status = response.status;

    if (REDIRECT_STATUSES.has(status)) {
      cancelBody(response.body);
      const location = response.headers.get('location');
      if (typeof location !== 'string' || location.length === 0) {
        throw new HashFailure(`http_${status}`);
      }
      let next: URL;
      try {
        next = new URL(location, current.href);
      } catch {
        throw new HashFailure(`http_${status}`);
      }
      if (next.protocol !== 'https:') {
        throw new HashFailure('redirect_not_https');
      }
      if (redirects >= maxRedirects) {
        throw new HashFailure('too_many_redirects');
      }
      redirects += 1;
      current = next;
      continue;
    }

    if (status < 200 || status > 299) {
      cancelBody(response.body);
      throw new HashFailure(`http_${status}`);
    }

    const length = response.headers.get('content-length');
    if (typeof length === 'string' && length.trim().length > 0) {
      const declared = Number(length);
      if (Number.isFinite(declared) && declared > maxBytes) {
        cancelBody(response.body);
        throw new HashFailure('too_large');
      }
    }

    return hashBody(response.body, maxBytes, signal);
  }
}

/**
 * Hash the installer at `url`. Resolves `{ok:true, sha256}` or
 * `{ok:false, error}`; never rejects.
 */
export async function hashUrl(url: string, options: HashUrlOptions): Promise<HashResult> {
  const maxBytes = options.maxBytes ?? HASH_MAX_BYTES;
  const deadlineMs = options.deadlineMs ?? HASH_DEADLINE_MS;
  const maxRedirects = options.maxRedirects ?? HASH_MAX_REDIRECTS;

  const start = typeof url === 'string' ? parseHttps(url) : null;
  if (start === null) {
    return failure('invalid_url');
  }

  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  // The deadline settles the run even when a fetch ignores its abort signal.
  const deadline = new Promise<HashResult>((resolve) => {
    timer = setTimeout(() => {
      controller.abort();
      resolve(failure('timeout'));
    }, deadlineMs);
  });

  const work = run(start, options.fetch, maxBytes, maxRedirects, controller.signal).then(
    (sha256): HashResult => ({ ok: true, sha256 }),
    (error: unknown): HashResult => failure(error instanceof HashFailure ? error.code : 'fetch_failed'),
  );

  try {
    return await Promise.race([work, deadline]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

/** The fields of a `table.update` call. */
export interface HashOutcomeUpdate {
  UpdateExpression: string;
  ConditionExpression: string;
  ExpressionAttributeValues: Record<string, unknown>;
}

/**
 * The conditional update that records a run's outcome. A success sets
 * `sha256`, `hashStatus: 'ready'`, `hashError: null` and `hashedAt`; a failure
 * sets `hashStatus: 'failed'`, `hashError` and `hashedAt` and leaves `sha256`
 * untouched (it is `null` while a URL application is not ready).
 */
export function hashOutcomeUpdate(hashRunId: string, result: HashResult, hashedAt: string): HashOutcomeUpdate {
  if (result.ok) {
    return {
      UpdateExpression: 'SET sha256 = :sha256, hashStatus = :hashStatus, hashError = :hashError, hashedAt = :hashedAt',
      ConditionExpression: HASH_OUTCOME_CONDITION,
      ExpressionAttributeValues: {
        ':sha256': result.sha256,
        ':hashStatus': 'ready',
        ':hashError': null,
        ':hashedAt': hashedAt,
        ':runId': hashRunId,
      },
    };
  }
  return {
    UpdateExpression: 'SET hashStatus = :hashStatus, hashError = :hashError, hashedAt = :hashedAt',
    ConditionExpression: HASH_OUTCOME_CONDITION,
    ExpressionAttributeValues: {
      ':hashStatus': 'failed',
      ':hashError': result.error,
      ':hashedAt': hashedAt,
      ':runId': hashRunId,
    },
  };
}
