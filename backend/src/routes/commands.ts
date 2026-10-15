/**
 * The agent-facing command queue: lease work, report the outcome.
 *
 *   GET  /api/v1/devices/{deviceId}/commands
 *   POST /api/v1/devices/{deviceId}/commands/{commandId}/result
 *
 * Both routes are authorised server-side: the device id resolved by
 * `verifyDeviceRequest` must equal the one in the path, so a device can only
 * ever reach items under its own partition (see `src/db/keys.ts`). A mismatch
 * is refused before any command item is read.
 *
 *   registerCommandRoutes(router, { table, now, pepper });
 *
 * Every dependency -- the table client, the clock and the authenticator --
 * is injected, so tests drive these handlers with fakes and nothing opens a
 * DynamoDB connection.
 *
 * Every 200 answer also refreshes the device profile's last-seen (see
 * `./deviceContact.ts`) after the route's own writes; a failed refresh never
 * changes the response.
 *
 * Time units follow the stored item, which is written by the admin-facing
 * enqueue route: `issuedAt` and `expiresAt` are epoch *milliseconds* and are
 * echoed to the agent unchanged, while `leaseExpiresAt` and `finishedAt` --
 * the fields this module writes -- are epoch *seconds*, the unit of the
 * injected `now()`.
 *
 * Leasing is a conditional update, never a read-then-write: a command is
 * handed out only while it is `pending` or while its previous lease has
 * lapsed, so two concurrent polls cannot both win the same command and a
 * crashed agent's work returns to the queue when its lease expires.
 *
 * Ordered queues (TASK-045): the lease reads every `CMD#` item of the device
 * (following the cursor), drops terminal ones, and walks the rest in
 * `(seq ?? -Infinity, issuedAt)` order. A command still out on an unexpired
 * lease stops the walk, so a machine never runs command N+1 while N is out. A
 * command stored without `expiresAt` (a library command) never expires and is
 * sent with `expiresAt = issuedAt + NO_EXPIRY_WIRE_MILLIS`. When the fleet
 * setting is `stop`, each sequenced command leased gets
 * `payload.stopOnFailure: true`, stored and returned; a `failed` result for
 * such a command marks every later-`seq` pending/leased command `skipped`.
 */
import type { Command, CommandLeaseResponse, CommandResultRequest } from '../contract/types.js';
import { readCommandSettings } from '../admin/commandSettings.js';
import { deviceCommand, type TableKey } from '../db/keys.js';
import { CONDITIONAL_CHECK_FAILED, type Item, type QueryPage, type QueryRequest, type RequestFields, type WriteOutcome } from '../db/table.js';
import { verifyDeviceRequest, type DeviceAuthResult, type EpochSecondsClock } from '../http/deviceAuth.js';
import type { RouteRequest, RouteResult, Router, RouterRequest } from '../http/router.js';
import { recordDeviceContact } from './deviceContact.js';

/** Commands returned by one poll when the request does not ask for a number. */
export const DEFAULT_MAX_COMMANDS = 5;

/** The most commands one poll may ask for; a larger `max` is refused. */
export const MAX_MAX_COMMANDS = 25;

/** How long a lease is held before the command returns to the queue, in seconds. */
export const LEASE_SECONDS = 300;

/** The most result output bytes kept on the command item; the rest is dropped. */
export const MAX_OUTPUT_BYTES = 8192;

/** Status of a command waiting to be leased. */
export const PENDING_STATUS = 'pending';
/** Status of a command leased to an agent until its `leaseExpiresAt`. */
export const LEASED_STATUS = 'leased';
/** Status of a command whose `expiresAt` passed before it was leased. */
export const EXPIRED_STATUS = 'expired';

/** Status of a pending command an admin cancelled. */
export const CANCELLED_STATUS = 'cancelled';
/** Status of a command passed over because an earlier one failed under the `stop` setting. */
export const SKIPPED_STATUS = 'skipped';

/** The terminal statuses a result may report, and that a stored command may already hold. */
export const TERMINAL_STATUSES: readonly CommandResultRequest['status'][] = ['succeeded', 'failed'];

/**
 * Every status the lease never hands out and never lets block a later
 * command. Kept apart from `isFinished`, which decides the result route's
 * repeat handling and is deliberately unchanged.
 */
export const LEASE_TERMINAL_STATUSES: readonly string[] = [
  'succeeded',
  'failed',
  EXPIRED_STATUS,
  CANCELLED_STATUS,
  SKIPPED_STATUS,
];

/**
 * The wire `expiresAt` of a command stored without one: `issuedAt` plus
 * 3650 days, in milliseconds, so the agent contract keeps a required number.
 */
export const NO_EXPIRY_WIRE_MILLIS = 315360000000;

/**
 * The condition a command item must satisfy to be leased: it is waiting, or
 * its previous lease has lapsed. Substituting the names and values below
 * reads `status = 'pending' OR (status = 'leased' AND leaseExpiresAt <= <now>)`.
 */
export const LEASE_CONDITION =
  '#status = :pending OR (#status = :leased AND leaseExpiresAt <= :now)';

/** A decimal count with no sign, fraction or padding; what `max` must look like. */
const MAX_PATTERN = /^[0-9]{1,3}$/;

/** The result-body fields validated before the command is looked up, in report order. */
export const RESULT_FIELDS = ['exitCode', 'output', 'finishedAt'] as const;

/**
 * The storage operations this module needs: the structural subset of
 * `TableClient` (see `src/db/table.ts`) a fake has to implement. `putIfAbsent`
 * is here only because `verifyDeviceRequest` burns a nonce with it.
 */
export interface CommandTable {
  get(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
  put?(item: Item, fields?: RequestFields): Promise<void>;
  putIfAbsent(item: Item, fields?: RequestFields): Promise<WriteOutcome>;
  update(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
  query(request?: QueryRequest): Promise<QueryPage>;
}

/** The authenticator these routes call; injectable so tests need no signed request. */
export type DeviceVerifier = (
  req: RouterRequest,
  options: { table: CommandTable; now: EpochSecondsClock; pepper: string },
) => Promise<DeviceAuthResult>;

export interface CommandRouteDeps {
  /** Table client. Required; never created here. */
  table: CommandTable;
  /** Current time as integer epoch seconds. */
  now: EpochSecondsClock;
  /** The 64-character hex pepper key, from `getPepper()`. Unused when `verifyDevice` is injected. */
  pepper?: string;
  /** Overrides the device authenticator; defaults to `verifyDeviceRequest`. */
  verifyDevice?: DeviceVerifier;
}

/** Dependencies, or a function resolving them when the request arrives. */
export type CommandRouteDepsSource = CommandRouteDeps | (() => CommandRouteDeps);

function jsonError(statusCode: number, error: string, extra?: Record<string, unknown>): RouteResult {
  return { statusCode, body: { error, ...(extra ?? {}) } };
}

/** True when a thrown value is DynamoDB's failed-condition rejection. */
function isConditionalCheckFailure(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === CONDITIONAL_CHECK_FAILED
  );
}

function resolveDeps(source: CommandRouteDepsSource): CommandRouteDeps {
  return typeof source === 'function' ? source() : source;
}

/**
 * Authenticate the request and confirm it is about its own device.
 *
 * Returns the device id, or the result the route must return: an
 * authentication failure unchanged, or a 403 when the path names another
 * device. No command item is read before this passes.
 */
async function authoriseDevice(
  req: RouteRequest,
  deps: CommandRouteDeps,
): Promise<{ ok: true; deviceId: string } | { ok: false; result: RouteResult }> {
  const verify: DeviceVerifier = deps.verifyDevice ?? verifyDeviceRequest;
  const auth = await verify(req, { table: deps.table, now: deps.now, pepper: deps.pepper ?? '' });
  if (!auth.ok) {
    return { ok: false, result: { statusCode: auth.status, body: auth.body } };
  }
  if (auth.deviceId !== (req.params.deviceId ?? '')) {
    return { ok: false, result: jsonError(403, 'device_mismatch') };
  }
  return { ok: true, deviceId: auth.deviceId };
}

/** The `max` query parameter, or `null` when it is not a count this route accepts. */
function parseMax(raw: string | undefined): number | null {
  if (raw === undefined || raw === '') {
    return DEFAULT_MAX_COMMANDS;
  }
  if (!MAX_PATTERN.test(raw)) {
    return null;
  }
  const max = Number(raw);
  if (max < 1 || max > MAX_MAX_COMMANDS) {
    return null;
  }
  return max;
}

/** The command's id: the stored attribute, else the `CMD#` sort key it was written under. */
function commandIdOf(item: Item): string {
  if (typeof item.commandId === 'string' && item.commandId.length > 0) {
    return item.commandId;
  }
  const sk = typeof item.sk === 'string' ? item.sk : '';
  return sk.startsWith('CMD#') ? sk.slice('CMD#'.length) : sk;
}

/** True when the command's deadline (epoch milliseconds) has passed. */
function hasExpired(item: Item, nowSeconds: number): boolean {
  const expiresAt = item.expiresAt;
  return typeof expiresAt === 'number' && expiresAt <= nowSeconds * 1000;
}

/** The `seq` a command carries, or `null` when it has none (a legacy or raw-dispatch command). */
function seqOf(item: Item): number | null {
  return typeof item.seq === 'number' && Number.isFinite(item.seq) ? item.seq : null;
}

/** A command's `issuedAt` in epoch milliseconds, or 0 when it has none. */
function issuedAtOf(item: Item): number {
  return typeof item.issuedAt === 'number' && Number.isFinite(item.issuedAt) ? item.issuedAt : 0;
}

/**
 * Run order: `(seq ?? -Infinity, issuedAt)` ascending -- commands without
 * `seq` first by `issuedAt`, then sequenced commands by `seq`.
 */
export function byRunOrder(left: Item, right: Item): number {
  const leftSeq = seqOf(left) ?? Number.NEGATIVE_INFINITY;
  const rightSeq = seqOf(right) ?? Number.NEGATIVE_INFINITY;
  if (leftSeq !== rightSeq) {
    return leftSeq < rightSeq ? -1 : 1;
  }
  return issuedAtOf(left) - issuedAtOf(right);
}

/** Every `CMD#` item of the device, following the query cursor until it is `null`. */
async function readAllCommands(table: CommandTable, deviceId: string): Promise<Item[]> {
  // An empty command id yields the partition key and the `CMD#` prefix every
  // command of this device is stored under, without writing key text here.
  const { pk, sk: commandPrefix } = deviceCommand(deviceId, '');
  const items: Item[] = [];
  let cursor: string | null = null;
  do {
    const page: QueryPage = await table.query({
      KeyConditionExpression: '#pk = :pk AND begins_with(#sk, :commandPrefix)',
      ExpressionAttributeNames: { '#pk': 'pk', '#sk': 'sk' },
      ExpressionAttributeValues: { ':pk': pk, ':commandPrefix': commandPrefix },
      cursor,
    });
    items.push(...page.items);
    const next = page.cursor ?? null;
    // A cursor that does not move would page forever; treat it as the end.
    cursor = next === cursor ? null : next;
  } while (cursor !== null);
  return items;
}

/** True when the stored command has already reported an outcome. */
function isFinished(item: Item): boolean {
  return TERMINAL_STATUSES.includes(item.status as CommandResultRequest['status']);
}

/**
 * True when the stored state looks leasable. The authority is the conditional
 * update below; this only avoids issuing a write that is certain to fail, so a
 * live lease is never touched.
 */
function isLeasable(item: Item, nowSeconds: number): boolean {
  if (item.status === PENDING_STATUS) {
    return true;
  }
  if (item.status !== LEASED_STATUS) {
    return false;
  }
  const leaseExpiresAt = item.leaseExpiresAt;
  return typeof leaseExpiresAt === 'number' && leaseExpiresAt <= nowSeconds;
}

/** Take the first `MAX_OUTPUT_BYTES` bytes, never splitting a UTF-8 sequence. */
function truncateOutput(output: string): string {
  const bytes = Buffer.from(output, 'utf8');
  if (bytes.length <= MAX_OUTPUT_BYTES) {
    return output;
  }
  let end = MAX_OUTPUT_BYTES;
  // Step back over a sequence the cut would split, so re-encoding the result
  // can never grow it past the cap with replacement characters.
  while (end > 0) {
    const byte = bytes[end] ?? 0;
    if (byte < 0x80 || byte >= 0xc0) {
      break;
    }
    end -= 1;
  }
  return bytes.subarray(0, end).toString('utf8');
}

/** The posted body as an object; `undefined` when it is absent or not JSON object text. */
function parseBody(body: string | null): Record<string, unknown> | undefined {
  if (typeof body !== 'string' || body.length === 0) {
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return undefined;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return undefined;
  }
  return parsed as Record<string, unknown>;
}

/** The result fields that are absent or of the wrong type, in `RESULT_FIELDS` order. */
function offendingFields(body: Record<string, unknown>): string[] {
  const offending: string[] = [];
  if (!Number.isInteger(body.exitCode)) {
    offending.push('exitCode');
  }
  if (typeof body.output !== 'string') {
    offending.push('output');
  }
  if (!Number.isInteger(body.finishedAt)) {
    offending.push('finishedAt');
  }
  return offending;
}

/** `GET /api/v1/devices/{deviceId}/commands` -- lease up to `max` commands. */
export function createLeaseHandler(source: CommandRouteDepsSource) {
  return async function leaseCommands(req: RouteRequest): Promise<RouteResult> {
    const deps = resolveDeps(source);

    // The request shape is settled before the device is authenticated, so a
    // malformed poll never burns the nonce the agent still needs.
    const max = parseMax(req.query?.max);
    if (max === null) {
      return jsonError(400, 'invalid_request');
    }

    const authorised = await authoriseDevice(req, deps);
    if (!authorised.ok) {
      return authorised.result;
    }
    const deviceId = authorised.deviceId;

    const now = deps.now();
    const leaseExpiresAt = now + LEASE_SECONDS;

    const queue = (await readAllCommands(deps.table, deviceId))
      .filter((item) => !LEASE_TERMINAL_STATUSES.includes(item.status as string))
      .sort(byRunOrder);

    // The fleet setting is read once, and only when a sequenced command is
    // about to be leased: legacy commands never carry `stopOnFailure`.
    let stopOnFailure: boolean | null = null;

    const commands: Command[] = [];
    for (const item of queue) {
      if (commands.length >= max) {
        break;
      }

      const commandId = commandIdOf(item);
      const key = deviceCommand(deviceId, commandId);

      // A command past its deadline is never handed out; it is retired so a
      // later poll does not consider it again. A command with no `expiresAt`
      // never reaches here.
      if (hasExpired(item, now)) {
        await expireCommand(deps, key);
        continue;
      }

      // A command still out on a live lease holds the queue: nothing after it
      // is leased or returned until it reports or its lease lapses.
      if (item.status === LEASED_STATUS && !isLeasable(item, now)) {
        break;
      }
      if (!isLeasable(item, now)) {
        continue;
      }

      const sequenced = seqOf(item) !== null;
      if (sequenced && stopOnFailure === null) {
        stopOnFailure = (await readCommandSettings(deps.table)).onFailure === 'stop';
      }
      const flag = sequenced && stopOnFailure === true;

      const leased = await leaseCommand(deps, key, now, leaseExpiresAt, flag);
      if (!leased) {
        continue;
      }

      const storedPayload = (item.payload ?? {}) as Record<string, unknown>;
      const issuedAt = item.issuedAt as number;
      // Both instants are echoed exactly as the queue stored them, which is
      // where their epoch-milliseconds unit is decided; a command stored with
      // no deadline is sent with a far one so the wire shape never changes.
      commands.push({
        commandId,
        type: typeof item.type === 'string' ? item.type : '',
        payload: flag ? { ...storedPayload, stopOnFailure: true } : storedPayload,
        issuedAt,
        expiresAt: typeof item.expiresAt === 'number' ? item.expiresAt : issuedAt + NO_EXPIRY_WIRE_MILLIS,
      });
    }

    // Only after every lease is written: a failed last-seen refresh never
    // strands the commands this poll has already leased.
    await recordDeviceContact(deps.table, deviceId, new Date(now * 1000));

    const body: CommandLeaseResponse = { commands };
    return { statusCode: 200, body };
  };
}

/** Stamp the lease, or report that another poll (or a result) got there first. */
async function leaseCommand(
  deps: CommandRouteDeps,
  key: TableKey,
  now: number,
  leaseExpiresAt: number,
  stopOnFailure = false,
): Promise<boolean> {
  // Under the `stop` setting the flag is written onto the stored payload in
  // the same update, so the result route reads what the agent was told.
  const names: Record<string, string> = { '#status': 'status' };
  const values: Record<string, unknown> = {
    ':leased': LEASED_STATUS,
    ':pending': PENDING_STATUS,
    ':leaseExpiresAt': leaseExpiresAt,
    ':now': now,
  };
  let updateExpression = 'SET #status = :leased, leaseExpiresAt = :leaseExpiresAt';
  if (stopOnFailure) {
    updateExpression += ', #payload.#stopOnFailure = :stopOnFailure';
    names['#payload'] = 'payload';
    names['#stopOnFailure'] = 'stopOnFailure';
    values[':stopOnFailure'] = true;
  }
  try {
    await deps.table.update(key, {
      UpdateExpression: updateExpression,
      ConditionExpression: LEASE_CONDITION,
      ExpressionAttributeNames: names,
      ExpressionAttributeValues: values,
    });
    return true;
  } catch (error) {
    if (isConditionalCheckFailure(error)) {
      return false;
    }
    throw error;
  }
}

/** Retire a command whose deadline passed, without disturbing a finished one. */
async function expireCommand(deps: CommandRouteDeps, key: TableKey): Promise<void> {
  try {
    await deps.table.update(key, {
      UpdateExpression: 'SET #status = :expired',
      ConditionExpression: '#status = :pending OR #status = :leased',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: {
        ':expired': EXPIRED_STATUS,
        ':pending': PENDING_STATUS,
        ':leased': LEASED_STATUS,
      },
    });
  } catch (error) {
    if (!isConditionalCheckFailure(error)) {
      throw error;
    }
  }
}

/** `POST /api/v1/devices/{deviceId}/commands/{commandId}/result` -- record an outcome. */
export function createResultHandler(source: CommandRouteDepsSource) {
  return async function recordResult(req: RouteRequest): Promise<RouteResult> {
    const deps = resolveDeps(source);

    // 1. The body, before the device is authenticated and before any lookup:
    // a malformed result is a malformed request whatever it names.
    const body = parseBody(req.body) ?? {};
    const fields = offendingFields(body);
    const statusValid = TERMINAL_STATUSES.includes(body.status as CommandResultRequest['status']);
    if (!statusValid || fields.length > 0) {
      return jsonError(400, 'invalid_request', fields.length > 0 ? { fields } : undefined);
    }
    // Every field is now known to be present and of the contract's type.
    const posted: CommandResultRequest = {
      status: body.status as CommandResultRequest['status'],
      exitCode: body.exitCode as number,
      output: body.output as string,
      finishedAt: body.finishedAt as number,
    };

    // 2. The device the path names.
    const authorised = await authoriseDevice(req, deps);
    if (!authorised.ok) {
      return authorised.result;
    }
    const deviceId = authorised.deviceId;
    const commandId = req.params.commandId ?? '';

    // 3. The command itself. An id that cannot even form a key is unknown.
    let key: TableKey;
    try {
      key = deviceCommand(deviceId, commandId);
    } catch {
      return jsonError(404, 'unknown_command');
    }
    const item = await deps.table.get(key);
    if (item === undefined || item === null) {
      return jsonError(404, 'unknown_command');
    }

    // 4. A repeat of a result we already recorded: accepted, and the command
    // is left untouched; only the device's last-seen is refreshed.
    if (isFinished(item)) {
      await recordDeviceContact(deps.table, deviceId, new Date(deps.now() * 1000));
      return { statusCode: 200, body: { ok: true } };
    }

    // 5. A command no agent ever leased cannot have been run.
    if (item.status === PENDING_STATUS) {
      return jsonError(409, 'command_not_leased');
    }

    await deps.table.update(key, {
      UpdateExpression:
        'SET #status = :status, #output = :output, exitCode = :exitCode, finishedAt = :finishedAt',
      ExpressionAttributeNames: { '#status': 'status', '#output': 'output' },
      ExpressionAttributeValues: {
        ':status': posted.status,
        ':output': truncateOutput(posted.output),
        ':exitCode': posted.exitCode,
        ':finishedAt': posted.finishedAt,
      },
    });

    // 6. A failure of a command leased under the `stop` setting passes over
    // everything queued after it. The flag stored at lease time decides.
    const payload = item.payload as Record<string, unknown> | undefined;
    const failedSeq = seqOf(item);
    if (posted.status === 'failed' && payload?.stopOnFailure === true && failedSeq !== null) {
      await skipLaterCommands(deps, deviceId, commandId, failedSeq);
    }

    await recordDeviceContact(deps.table, deviceId, new Date(deps.now() * 1000));

    return { statusCode: 200, body: { ok: true } };
  };
}

/**
 * Mark every `pending` or `leased` command of the device with a higher `seq`
 * as `skipped`, each through a conditional update so a command that finished
 * in the meantime is left alone.
 */
async function skipLaterCommands(
  deps: CommandRouteDeps,
  deviceId: string,
  failedCommandId: string,
  failedSeq: number,
): Promise<void> {
  for (const item of await readAllCommands(deps.table, deviceId)) {
    const seq = seqOf(item);
    if (seq === null || seq <= failedSeq) {
      continue;
    }
    if (item.status !== PENDING_STATUS && item.status !== LEASED_STATUS) {
      continue;
    }
    try {
      await deps.table.update(deviceCommand(deviceId, commandIdOf(item)), {
        UpdateExpression: 'SET #status = :skipped, skippedBecause = :because',
        ConditionExpression: '#status = :pending OR #status = :leased',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: {
          ':skipped': SKIPPED_STATUS,
          ':because': failedCommandId,
          ':pending': PENDING_STATUS,
          ':leased': LEASED_STATUS,
        },
      });
    } catch (error) {
      if (!isConditionalCheckFailure(error)) {
        throw error;
      }
    }
  }
}

/** Register both agent command routes on `router`. */
export function registerCommandRoutes(router: Router, source: CommandRouteDepsSource): Router {
  return router
    .add('GET', '/api/v1/devices/{deviceId}/commands', createLeaseHandler(source))
    .add('POST', '/api/v1/devices/{deviceId}/commands/{commandId}/result', createResultHandler(source));
}
