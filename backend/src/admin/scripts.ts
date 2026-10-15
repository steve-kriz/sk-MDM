/**
 * The command library: saved scripts an admin queues onto devices.
 *
 *   GET    /admin/api/v1/scripts              -- list, by name ignoring case (?platform=windows|darwin)
 *   GET    /admin/api/v1/scripts/{scriptId}   -- one saved command
 *   POST   /admin/api/v1/scripts              -- save a new command
 *   PUT    /admin/api/v1/scripts/{scriptId}   -- replace a saved command
 *   DELETE /admin/api/v1/scripts/{scriptId}   -- delete it
 *
 *   registerScriptRoutes(router, { verifier, table, now, randomBytes });
 *
 * Every route is registered through `registerAdminRoute`, so it is reached only
 * by a verified admin (see `src/admin/router.ts`).
 *
 * A record lives at `keys.script(scriptId)` and carries the
 * `keys.scriptListIndex` attributes, written on create and on every `PUT`, so
 * the library is listed with a query on one `gsi1` partition, never a scan.
 *
 * Names are unique ignoring case. The mechanism is a guard item at
 * `keys.scriptNameGuard(<sha256 of the lower-cased name>)`, claimed with
 * `putIfAbsent` before the record is written: a name may contain `#`, so the
 * raw name never becomes a key id.
 *
 * `platform` is derived from the interpreter (`cmd`/`powershell` -> windows,
 * `bash`/`zsh` -> darwin); a value the client sends is ignored.
 *
 * Queuing a saved command copies its script text onto the queued command (see
 * `src/admin/commandDispatch.ts`), so editing or deleting a library entry never
 * changes anything already queued.
 *
 * Audit entries carry the `name` and `interpreter`, never the script body.
 *
 *   POST   /admin/api/v1/scripts/generate     -- AI-generate a script from a plain-English request (TASK-053)
 *
 * Generate only answers `{script}`: it writes no `SCRIPT#` record and no name
 * guard and queues nothing. Its only table writes are the per-admin, per-minute
 * rate-limit counter and, on success, one `script.generated` audit entry that
 * carries the interpreter and prompt length, never the prompt, the description
 * or the generated script.
 */
import { createHash } from 'node:crypto';
import { appendAudit, isoUtc } from '../audit.js';
import type { ScriptGenerateRequest } from '../aws/scriptGenerator.js';
import {
  GSI1_NAME,
  script as scriptKey,
  scriptGenerateRateLimit,
  scriptListIndex,
  scriptNameGuard,
  type TableKey,
} from '../db/keys.js';
import type { Item, QueryPage, RequestFields, WriteOutcome } from '../db/table.js';
import type { RouteResult, Router } from '../http/router.js';
import {
  adminActor,
  adminDeleteTable,
  adminNow,
  adminRandomBytes,
  adminUpdateTable,
  jsonError,
  readJsonBody,
  registerAdminRoute,
  type AdminDeleteTable,
  type AdminDependencySource,
  type AdminRouteHandler,
  type AdminTable,
} from './router.js';

/** Sub-path of the command library. */
export const SCRIPT_PATH = '/scripts';

/** Sub-path of one saved command. */
export const SCRIPT_DETAIL_PATH = '/scripts/{scriptId}';

/** Prefix of a generated script id. */
export const SCRIPT_ID_PREFIX = 'scr-';

/** Length of the random part of a generated script id, in bytes (16 hex characters). */
export const SCRIPT_ID_BYTES = 8;

/** The interpreters a saved command may name. */
export const LIBRARY_INTERPRETERS = ['cmd', 'powershell', 'bash', 'zsh'] as const;

/** The platforms a saved command runs on. */
export const SCRIPT_PLATFORMS = ['windows', 'darwin'] as const;

/** The platform each interpreter runs on. */
export const INTERPRETER_PLATFORMS: Readonly<Record<(typeof LIBRARY_INTERPRETERS)[number], (typeof SCRIPT_PLATFORMS)[number]>> = {
  cmd: 'windows',
  powershell: 'windows',
  bash: 'darwin',
  zsh: 'darwin',
};

/** Longest accepted name, in characters. */
export const SCRIPT_NAME_MAX_LENGTH = 100;

/** Longest accepted description, in characters. */
export const SCRIPT_DESCRIPTION_MAX_LENGTH = 500;

/** Largest accepted script body, in UTF-8 bytes. */
export const SCRIPT_MAX_BYTES = 65536;

/** Accepted range of `timeoutSeconds`, both bounds inclusive. */
export const SCRIPT_TIMEOUT_SECONDS = { min: 1, max: 3600 } as const;

/** The timeout stored when a request names none. */
export const DEFAULT_SCRIPT_TIMEOUT_SECONDS = 300;

/** The audit action recorded when a command is saved to the library. */
export const SCRIPT_CREATED_ACTION = 'script.created';

/** The audit action recorded when a saved command is replaced. */
export const SCRIPT_UPDATED_ACTION = 'script.updated';

/** The audit action recorded when a saved command is deleted. */
export const SCRIPT_DELETED_ACTION = 'script.deleted';

/** Sub-path of the AI script generator (TASK-053). */
export const SCRIPT_GENERATE_PATH = '/scripts/generate';

/** Longest accepted generate request, in characters after trimming. */
export const SCRIPT_GENERATE_PROMPT_MAX_LENGTH = 4000;

/** How long the AI call may run before it is aborted, in milliseconds (below the Lambda's 30 s timeout). */
export const SCRIPT_GENERATE_TIMEOUT_MS = 20000;

/** Most generate calls one admin may make in one UTC minute. */
export const SCRIPT_GENERATE_RATE_LIMIT_PER_MINUTE = 10;

/** How long a rate-limit counter outlives the end of its minute, in seconds. */
export const SCRIPT_GENERATE_COUNTER_TTL_GRACE_SECONDS = 120;

/** The audit action recorded when a script is generated. */
export const SCRIPT_GENERATED_ACTION = 'script.generated';

/** The audit target of a generate entry. */
export const SCRIPT_GENERATOR_TARGET = 'script-generator';

const INTERPRETERS: ReadonlySet<string> = new Set(LIBRARY_INTERPRETERS);
const PLATFORMS: ReadonlySet<string> = new Set(SCRIPT_PLATFORMS);

/** What the library routes need of the table: delete, plus the guard's conditional put. */
interface ScriptTable extends AdminDeleteTable {
  putIfAbsent(item: Item, fields?: RequestFields): Promise<WriteOutcome>;
}

/** The injected table as the library needs it; a client without `putIfAbsent` is a wiring fault. */
function scriptTable(table: AdminTable): ScriptTable {
  const deletable = adminDeleteTable(table);
  if (typeof (deletable as Partial<ScriptTable>).putIfAbsent !== 'function') {
    throw new Error('the command library needs a table client with putIfAbsent()');
  }
  return deletable as ScriptTable;
}

/** A validated library body, ready to store. */
export interface ScriptFields {
  name: string;
  description: string | null;
  interpreter: (typeof LIBRARY_INTERPRETERS)[number];
  platform: (typeof SCRIPT_PLATFORMS)[number];
  script: string;
  timeoutSeconds: number;
}

/**
 * Validate a create or replace body: the fields, or every offending field name
 * in the order `name`, `description`, `interpreter`, `script`, `timeoutSeconds`.
 */
export function readScriptFields(body: Record<string, unknown>): { fields: ScriptFields } | { offending: string[] } {
  const offending: string[] = [];

  const name = body.name;
  if (typeof name !== 'string' || name.length < 1 || name.length > SCRIPT_NAME_MAX_LENGTH || name.trim().length === 0) {
    offending.push('name');
  }

  const description = body.description;
  if (
    description !== undefined &&
    description !== null &&
    (typeof description !== 'string' || description.length > SCRIPT_DESCRIPTION_MAX_LENGTH)
  ) {
    offending.push('description');
  }

  const interpreter = body.interpreter;
  if (typeof interpreter !== 'string' || !INTERPRETERS.has(interpreter)) {
    offending.push('interpreter');
  }

  const text = body.script;
  const bytes = typeof text === 'string' ? Buffer.byteLength(text, 'utf8') : 0;
  if (typeof text !== 'string' || bytes < 1 || bytes > SCRIPT_MAX_BYTES) {
    offending.push('script');
  }

  const timeout = body.timeoutSeconds;
  if (
    timeout !== undefined &&
    !(
      typeof timeout === 'number' &&
      Number.isInteger(timeout) &&
      timeout >= SCRIPT_TIMEOUT_SECONDS.min &&
      timeout <= SCRIPT_TIMEOUT_SECONDS.max
    )
  ) {
    offending.push('timeoutSeconds');
  }

  if (offending.length > 0) {
    return { offending };
  }

  const shell = interpreter as (typeof LIBRARY_INTERPRETERS)[number];
  return {
    fields: {
      name: name as string,
      description: typeof description === 'string' ? description : null,
      interpreter: shell,
      platform: INTERPRETER_PLATFORMS[shell],
      script: text as string,
      timeoutSeconds: typeof timeout === 'number' ? timeout : DEFAULT_SCRIPT_TIMEOUT_SECONDS,
    },
  };
}

/** The guard key for a name: the SHA-256 hex of the lower-cased name. */
function nameGuardKey(name: string): TableKey {
  return scriptNameGuard(createHash('sha256').update(name.toLowerCase(), 'utf8').digest('hex'));
}

/** A string attribute, or `null`. */
function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

/** The public shape of a stored script: the record without its key and index attributes. */
export function scriptRecord(item: Item): Item {
  return {
    scriptId: stringOrNull(item.scriptId),
    name: stringOrNull(item.name),
    description: stringOrNull(item.description),
    interpreter: stringOrNull(item.interpreter),
    platform: stringOrNull(item.platform),
    script: stringOrNull(item.script),
    timeoutSeconds: typeof item.timeoutSeconds === 'number' ? item.timeoutSeconds : DEFAULT_SCRIPT_TIMEOUT_SECONDS,
    createdAt: stringOrNull(item.createdAt),
    createdBy: stringOrNull(item.createdBy),
    updatedAt: stringOrNull(item.updatedAt),
    updatedBy: stringOrNull(item.updatedBy),
  };
}

/** The key of the script a request names, or `null` when no key can be built from it. */
function requestedScriptKey(scriptId: string): TableKey | null {
  try {
    return scriptKey(scriptId);
  } catch {
    return null;
  }
}

/**
 * Read one saved command by id, or `null` when it does not exist (or the id
 * cannot form a key). Shared with the queue routes in `commandDispatch.ts`.
 */
export async function readScript(table: AdminTable, scriptId: string): Promise<Item | null> {
  const key = requestedScriptKey(scriptId);
  if (key === null) {
    return null;
  }
  const item = await table.get(key);
  return item === undefined || item === null ? null : item;
}

/** Every library record, following the `gsi1` query cursor to the end. */
async function readAllScripts(table: AdminTable): Promise<Item[]> {
  const { gsi1pk } = scriptListIndex('');
  const records: Item[] = [];
  let cursor: string | null = null;
  do {
    const page: QueryPage = await table.query({
      IndexName: GSI1_NAME,
      KeyConditionExpression: '#gsi1pk = :gsi1pk',
      ExpressionAttributeNames: { '#gsi1pk': 'gsi1pk' },
      ExpressionAttributeValues: { ':gsi1pk': gsi1pk },
      cursor,
    });
    records.push(...page.items);
    const next = page.cursor ?? null;
    // A cursor that does not move would page forever; treat it as the end.
    cursor = next === cursor ? null : next;
  } while (cursor !== null);
  return records;
}

/** Ascending by name ignoring case; ties by name, then by id, so the order is stable. */
function byNameIgnoringCase(left: Item, right: Item): number {
  const leftName = String(left.name ?? '');
  const rightName = String(right.name ?? '');
  const a = leftName.toLowerCase();
  const b = rightName.toLowerCase();
  if (a !== b) {
    return a < b ? -1 : 1;
  }
  if (leftName !== rightName) {
    return leftName < rightName ? -1 : 1;
  }
  const leftId = String(left.scriptId ?? '');
  const rightId = String(right.scriptId ?? '');
  return leftId === rightId ? 0 : leftId < rightId ? -1 : 1;
}

/** `GET /admin/api/v1/scripts` -- the library, by name ignoring case, optionally for one platform. */
export const handleScriptList: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const platform = req.query?.platform;
  if (platform !== undefined && !PLATFORMS.has(platform)) {
    return jsonError(400, 'invalid_request');
  }
  const items = (await readAllScripts(deps.table))
    .map(scriptRecord)
    .filter((record) => platform === undefined || record.platform === platform)
    .sort(byNameIgnoringCase);
  return { statusCode: 200, body: { items } };
};

/** `GET /admin/api/v1/scripts/{scriptId}` -- one saved command. */
export const handleScriptGet: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const record = await readScript(deps.table, req.params?.scriptId ?? '');
  if (record === null) {
    return jsonError(404, 'not_found');
  }
  return { statusCode: 200, body: scriptRecord(record) };
};

/** `POST /admin/api/v1/scripts` -- save a new command. */
export const handleScriptCreate: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const read = readScriptFields(readJsonBody(req.body) ?? {});
  if ('offending' in read) {
    return jsonError(400, 'invalid_request', { fields: read.offending });
  }
  const { fields } = read;

  const table = scriptTable(deps.table);
  const at = adminNow(deps);
  const actor = adminActor(req.claims);
  const scriptId = `${SCRIPT_ID_PREFIX}${adminRandomBytes(deps)(SCRIPT_ID_BYTES).toString('hex')}`;

  // The name is claimed first: a lost claim is a duplicate and writes nothing.
  const claim = await table.putIfAbsent({ ...nameGuardKey(fields.name), scriptId, name: fields.name });
  if (!claim.written) {
    return jsonError(409, 'name_taken');
  }

  const stamp = isoUtc(at);
  const item: Item = {
    ...scriptKey(scriptId),
    ...scriptListIndex(fields.name),
    scriptId,
    ...fields,
    createdAt: stamp,
    createdBy: actor,
    updatedAt: stamp,
    updatedBy: actor,
  };
  await table.put(item);

  await appendAudit(table, {
    action: SCRIPT_CREATED_ACTION,
    actor,
    target: scriptId,
    detail: { name: fields.name, interpreter: fields.interpreter },
    now: at,
  });

  return { statusCode: 201, body: scriptRecord(item) };
};

/** `PUT /admin/api/v1/scripts/{scriptId}` -- replace a saved command. */
export const handleScriptUpdate: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const read = readScriptFields(readJsonBody(req.body) ?? {});
  if ('offending' in read) {
    return jsonError(400, 'invalid_request', { fields: read.offending });
  }
  const { fields } = read;

  const scriptId = req.params?.scriptId ?? '';
  const key = requestedScriptKey(scriptId);
  if (key === null) {
    return jsonError(404, 'not_found');
  }
  const table = scriptTable(deps.table);
  const existing = await table.get(key);
  if (existing === undefined || existing === null) {
    return jsonError(404, 'not_found');
  }

  const at = adminNow(deps);
  const actor = adminActor(req.claims);
  const previousName = stringOrNull(existing.name) ?? '';
  const renamed = previousName.toLowerCase() !== fields.name.toLowerCase();

  // A rename claims the new name before anything else is written; keeping the
  // same name in another case keeps the guard it already holds.
  if (renamed) {
    const claim = await table.putIfAbsent({ ...nameGuardKey(fields.name), scriptId, name: fields.name });
    if (!claim.written) {
      return jsonError(409, 'name_taken');
    }
  }

  const item: Item = {
    ...key,
    ...scriptListIndex(fields.name),
    scriptId,
    ...fields,
    createdAt: stringOrNull(existing.createdAt) ?? isoUtc(at),
    createdBy: stringOrNull(existing.createdBy) ?? actor,
    updatedAt: isoUtc(at),
    updatedBy: actor,
  };
  await table.put(item);

  if (renamed && previousName.length > 0) {
    await table.delete(nameGuardKey(previousName));
  }

  await appendAudit(table, {
    action: SCRIPT_UPDATED_ACTION,
    actor,
    target: scriptId,
    detail: { name: fields.name, interpreter: fields.interpreter },
    now: at,
  });

  return { statusCode: 200, body: scriptRecord(item) };
};

/** `DELETE /admin/api/v1/scripts/{scriptId}` -- delete a saved command; queued copies are untouched. */
export const handleScriptDelete: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const scriptId = req.params?.scriptId ?? '';
  const key = requestedScriptKey(scriptId);
  if (key === null) {
    return jsonError(404, 'not_found');
  }
  const table = scriptTable(deps.table);
  const existing = await table.get(key);
  if (existing === undefined || existing === null) {
    return jsonError(404, 'not_found');
  }

  const at = adminNow(deps);
  await table.delete(key);
  const name = stringOrNull(existing.name);
  if (name !== null && name.length > 0) {
    await table.delete(nameGuardKey(name));
  }

  await appendAudit(table, {
    action: SCRIPT_DELETED_ACTION,
    actor: adminActor(req.claims),
    target: scriptId,
    detail: { name, interpreter: stringOrNull(existing.interpreter) },
    now: at,
  });

  return { statusCode: 204, rawBody: '', headers: {} };
};

/**
 * Validate a generate body: the generator request, or every offending field
 * name in the order `prompt`, `description`, `interpreter`, `timeoutSeconds`.
 * A missing `timeoutSeconds` becomes 300; a missing or empty `description`
 * becomes `null`.
 */
export function readGenerateFields(body: Record<string, unknown>): { request: ScriptGenerateRequest } | { offending: string[] } {
  const offending: string[] = [];

  const prompt = typeof body.prompt === 'string' ? body.prompt.trim() : null;
  if (prompt === null || prompt.length < 1 || prompt.length > SCRIPT_GENERATE_PROMPT_MAX_LENGTH) {
    offending.push('prompt');
  }

  const description = body.description;
  if (
    description !== undefined &&
    description !== null &&
    (typeof description !== 'string' || description.length > SCRIPT_DESCRIPTION_MAX_LENGTH)
  ) {
    offending.push('description');
  }

  const interpreter = body.interpreter;
  if (typeof interpreter !== 'string' || !INTERPRETERS.has(interpreter)) {
    offending.push('interpreter');
  }

  const timeout = body.timeoutSeconds;
  if (
    timeout !== undefined &&
    !(
      typeof timeout === 'number' &&
      Number.isInteger(timeout) &&
      timeout >= SCRIPT_TIMEOUT_SECONDS.min &&
      timeout <= SCRIPT_TIMEOUT_SECONDS.max
    )
  ) {
    offending.push('timeoutSeconds');
  }

  if (offending.length > 0) {
    return { offending };
  }

  const shell = interpreter as (typeof LIBRARY_INTERPRETERS)[number];
  return {
    request: {
      prompt: prompt as string,
      interpreter: shell,
      platform: INTERPRETER_PLATFORMS[shell],
      timeoutSeconds: typeof timeout === 'number' ? timeout : DEFAULT_SCRIPT_TIMEOUT_SECONDS,
      description: typeof description === 'string' && description.length > 0 ? description : null,
    },
  };
}

/** A fence line that opens generated output: three backticks and an optional language tag. */
const OPENING_FENCE = /^```[\w+-]*$/;

/**
 * Clean the model's output: trim it; when the first line is an opening fence and
 * the last line is exactly three backticks, drop both; trim again. Backticks
 * anywhere else are kept.
 */
export function cleanGeneratedScript(raw: string): string {
  const trimmed = raw.trim();
  const lines = trimmed.split('\n');
  if (lines.length >= 2) {
    const first = (lines[0] ?? '').replace(/\r$/, '');
    const last = lines[lines.length - 1];
    if (OPENING_FENCE.test(first) && last === '```') {
      return lines.slice(1, -1).join('\n').trim();
    }
  }
  return trimmed;
}

/** `YYYYMMDDHHmm` of an instant, in UTC. */
function utcMinuteStamp(at: Date): string {
  return isoUtc(at).slice(0, 16).replace(/[-T:]/g, '');
}

/**
 * Count one generate call against the admin's current UTC minute (`ADD count :1`)
 * and say whether it is within the limit. The counter expires 120 s after the
 * end of its minute.
 */
async function withinGenerateRateLimit(table: AdminTable, actor: string, at: Date): Promise<boolean> {
  const updatable = adminUpdateTable(table);
  const actorKey = createHash('sha256').update(actor.toLowerCase(), 'utf8').digest('hex');
  const minuteStartSeconds = Math.floor(at.getTime() / 60000) * 60;
  const ttl = minuteStartSeconds + 60 + SCRIPT_GENERATE_COUNTER_TTL_GRACE_SECONDS;
  const attributes = await updatable.update(scriptGenerateRateLimit(actorKey, utcMinuteStamp(at)), {
    UpdateExpression: 'ADD #count :one SET #ttl = :ttl',
    ExpressionAttributeNames: { '#count': 'count', '#ttl': 'ttl' },
    ExpressionAttributeValues: { ':one': 1, ':ttl': ttl },
    ReturnValues: 'ALL_NEW',
  });
  const count = attributes?.count;
  return typeof count === 'number' && count <= SCRIPT_GENERATE_RATE_LIMIT_PER_MINUTE;
}

/** The `name` of a thrown value, the only part of a provider error ever logged. */
function errorName(error: unknown): string {
  const name = (error as { name?: unknown } | null | undefined)?.name;
  return typeof name === 'string' && name.length > 0 ? name : 'Error';
}

/** Marks the timer winning the race against the generator. */
const TIMED_OUT = Symbol('timed out');

/** `POST /admin/api/v1/scripts/generate` -- AI-generate a script; nothing is saved or queued. */
export const handleScriptGenerate: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const read = readGenerateFields(readJsonBody(req.body) ?? {});
  if ('offending' in read) {
    return jsonError(400, 'invalid_request', { fields: read.offending });
  }
  const { request } = read;

  const generator = deps.scriptGenerator;
  if (generator === undefined) {
    return jsonError(503, 'not_configured');
  }

  const at = adminNow(deps);
  const actor = adminActor(req.claims);
  if (!(await withinGenerateRateLimit(deps.table, actor, at))) {
    return jsonError(429, 'rate_limited');
  }

  // The signal is aborted at 20 s, and the timer also wins the race, so the
  // route answers 504 even if the provider ignores the abort.
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timedOut = new Promise<typeof TIMED_OUT>((resolve) => {
    timer = setTimeout(() => {
      controller.abort();
      resolve(TIMED_OUT);
    }, SCRIPT_GENERATE_TIMEOUT_MS);
  });
  let raw: unknown;
  try {
    raw = await Promise.race([generator.generate(request, controller.signal), timedOut]);
  } catch (error) {
    if (controller.signal.aborted) {
      console.error(`script generate ai_timeout: ${errorName(error)}`);
      return jsonError(504, 'ai_timeout');
    }
    console.error(`script generate ai_failed: ${errorName(error)}`);
    return jsonError(502, 'ai_failed');
  } finally {
    clearTimeout(timer);
  }
  if (raw === TIMED_OUT) {
    console.error('script generate ai_timeout: TimeoutError');
    return jsonError(504, 'ai_timeout');
  }

  const script = cleanGeneratedScript(typeof raw === 'string' ? raw : '');
  if (script.length === 0) {
    return jsonError(502, 'empty_result');
  }
  if (Buffer.byteLength(script, 'utf8') > SCRIPT_MAX_BYTES) {
    console.error('script generate ai_failed: OversizedResult');
    return jsonError(502, 'ai_failed');
  }

  await appendAudit(adminUpdateTable(deps.table), {
    action: SCRIPT_GENERATED_ACTION,
    actor,
    target: SCRIPT_GENERATOR_TARGET,
    detail: { interpreter: request.interpreter, promptLength: request.prompt.length },
    now: at,
  });

  return { statusCode: 200, body: { script } };
};

/** Register the library routes on a router. Returns the router, so calls chain. */
export function registerScriptRoutes(router: Router, source: AdminDependencySource): Router {
  registerAdminRoute(router, 'GET', SCRIPT_PATH, handleScriptList, source);
  registerAdminRoute(router, 'POST', SCRIPT_PATH, handleScriptCreate, source);
  registerAdminRoute(router, 'POST', SCRIPT_GENERATE_PATH, handleScriptGenerate, source);
  registerAdminRoute(router, 'GET', SCRIPT_DETAIL_PATH, handleScriptGet, source);
  registerAdminRoute(router, 'PUT', SCRIPT_DETAIL_PATH, handleScriptUpdate, source);
  return registerAdminRoute(router, 'DELETE', SCRIPT_DETAIL_PATH, handleScriptDelete, source);
}
