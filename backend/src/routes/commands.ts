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
 */
import { deviceCommand, type TableKey } from '../db/keys.js';
import { CONDITIONAL_CHECK_FAILED, type Item, type QueryPage, type QueryRequest, type RequestFields, type WriteOutcome } from '../db/table.js';
import { verifyDeviceRequest, type DeviceAuthResult, type EpochSecondsClock } from '../http/deviceAuth.js';
import type { RouteRequest, RouteResult, Router, RouterRequest } from '../http/router.js';

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

/** The terminal statuses a result may report, and that a stored command may already hold. */
export const TERMINAL_STATUSES = ['succeeded', 'failed'] as const;

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

/** One command as the agent sees it. `issuedAt` and `expiresAt` are epoch milliseconds. */
export interface LeasedCommand {
  commandId: string;
  type: string;
  payload: unknown;
  issuedAt: unknown;
  expiresAt: unknown;
}

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

/** True when the stored command has already reported an outcome. */
function isFinished(item: Item): boolean {
  return TERMINAL_STATUSES.includes(item.status as (typeof TERMINAL_STATUSES)[number]);
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

    // An empty command id yields the partition key and the `CMD#` prefix every
    // command of this device is stored under, without writing key text here.
    const { pk, sk: commandPrefix } = deviceCommand(deviceId, '');
    const page = await deps.table.query({
      KeyConditionExpression: '#pk = :pk AND begins_with(#sk, :commandPrefix)',
      ExpressionAttributeNames: { '#pk': 'pk', '#sk': 'sk' },
      ExpressionAttributeValues: { ':pk': pk, ':commandPrefix': commandPrefix },
    });

    const commands: LeasedCommand[] = [];
    for (const item of page.items) {
      if (commands.length >= max) {
        break;
      }
      if (isFinished(item) || item.status === EXPIRED_STATUS) {
        continue;
      }

      const commandId = commandIdOf(item);
      const key = deviceCommand(deviceId, commandId);

      // A command past its deadline is never handed out; it is retired so a
      // later poll does not consider it again.
      if (hasExpired(item, now)) {
        await expireCommand(deps, key);
        continue;
      }

      if (!isLeasable(item, now)) {
        continue;
      }

      const leased = await leaseCommand(deps, key, now, leaseExpiresAt);
      if (!leased) {
        continue;
      }

      commands.push({
        commandId,
        type: typeof item.type === 'string' ? item.type : '',
        payload: item.payload ?? {},
        issuedAt: item.issuedAt,
        expiresAt: item.expiresAt,
      });
    }

    return { statusCode: 200, body: { commands } };
  };
}

/** Stamp the lease, or report that another poll (or a result) got there first. */
async function leaseCommand(
  deps: CommandRouteDeps,
  key: TableKey,
  now: number,
  leaseExpiresAt: number,
): Promise<boolean> {
  try {
    await deps.table.update(key, {
      UpdateExpression: 'SET #status = :leased, leaseExpiresAt = :leaseExpiresAt',
      ConditionExpression: LEASE_CONDITION,
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: {
        ':leased': LEASED_STATUS,
        ':pending': PENDING_STATUS,
        ':leaseExpiresAt': leaseExpiresAt,
        ':now': now,
      },
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
    const status = body.status;
    const fields = offendingFields(body);
    const statusValid = TERMINAL_STATUSES.includes(status as (typeof TERMINAL_STATUSES)[number]);
    if (!statusValid || fields.length > 0) {
      return jsonError(400, 'invalid_request', fields.length > 0 ? { fields } : undefined);
    }

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

    // 4. A repeat of a result we already recorded: accepted, written nowhere.
    if (isFinished(item)) {
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
        ':status': status,
        ':output': truncateOutput(body.output as string),
        ':exitCode': body.exitCode,
        ':finishedAt': body.finishedAt,
      },
    });

    return { statusCode: 200, body: { ok: true } };
  };
}

/** Register both agent command routes on `router`. */
export function registerCommandRoutes(router: Router, source: CommandRouteDepsSource): Router {
  return router
    .add('GET', '/api/v1/devices/{deviceId}/commands', createLeaseHandler(source))
    .add('POST', '/api/v1/devices/{deviceId}/commands/{commandId}/result', createResultHandler(source));
}
