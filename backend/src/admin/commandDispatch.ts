/**
 * Queueing work for the fleet: the admin write side of the command queue.
 *
 *   POST /admin/api/v1/devices/{deviceId}/commands -- queue one command
 *   POST /admin/api/v1/groups/{groupId}/commands   -- fan one out to a group
 *
 *   registerCommandDispatchRoutes(router, { verifier, table, now, randomBytes });
 *
 * Both routes write the item the agent later leases, so this module decides
 * its shape: `status: 'pending'`, and `issuedAt`/`expiresAt` as epoch
 * *milliseconds* -- the unit `src/routes/commands.ts` compares against and
 * echoes to the agent unchanged. A command that no agent collects within
 * `COMMAND_TTL_MILLIS` is retired by that route rather than run late.
 *
 * A request is settled completely before anything is written, in one order for
 * both routes:
 *
 *   1. type supported   -> 400 unsupported_command_type
 *   2. payload complete -> 400 invalid_request, naming every missing field
 *   3. confirmed        -> 409 confirmation_required
 *
 * so a refused fan-out leaves the group exactly as it was: zero command items,
 * never a partially dispatched fleet. The confirmation gate is what stands
 * between a stray click and a restarted fleet, which is why it is a field in
 * the body (`{confirm: true}`) rather than anything a browser might replay.
 *
 * The group route queues one command per member, each with its own
 * `commandId`, and audits each one, so the trail answers "what was sent to
 * this device" as well as "what did the admin do".
 *
 * The command library adds four routes (TASK-045):
 *
 *   POST /admin/api/v1/devices/{deviceId}/scripts                     -- queue a saved command
 *   POST /admin/api/v1/groups/{groupId}/scripts                       -- queue it on every member
 *   POST /admin/api/v1/devices/{deviceId}/commands/{commandId}/move   -- reorder a pending command
 *   POST /admin/api/v1/devices/{deviceId}/commands/{commandId}/cancel -- cancel a pending command
 *
 * A queued library command is an ordinary `run_script` item that also carries
 * a per-device `seq` (from the `CMDSEQ` counter), its `scriptId`/`scriptName`
 * provenance and a copy of the script, and has **no** `expiresAt`: it waits for
 * the machine however long it is offline. Every refusal check runs before the
 * counter is touched, so a refused request never advances it.
 *
 *   POST /admin/api/v1/devices/{deviceId}/applications -- queue an application install (TASK-049)
 *
 * queues a sequenced, never-expiring `install_application` item the same way.
 */
import { appendAudit } from '../audit.js';
import { deviceCommand, deviceCommandSeq, deviceProfile, group, type TableKey } from '../db/keys.js';
import { CONDITIONAL_CHECK_FAILED, type Item, type QueryPage, type TransactWriteItem, type WriteOutcome } from '../db/table.js';
import type { RouteResult, Router } from '../http/router.js';
import { readGroupMemberIds } from './groups.js';
import { applicationHashStatus, readApplication } from './applications.js';
import { readScript } from './scripts.js';
import {
  adminActor,
  adminNow,
  adminRandomBytes,
  adminUpdateTable,
  adminWriteTable,
  jsonError,
  readJsonBody,
  registerAdminRoute,
  type AdminDependencies,
  type AdminDependencySource,
  type AdminRequest,
  type AdminRouteHandler,
  type AdminTable,
  type AdminUpdateTable,
  type AdminWriteTable,
} from './router.js';

/** Sub-path of a device's command collection. */
export const DEVICE_COMMAND_PATH = '/devices/{deviceId}/commands';

/** Sub-path of a group's command collection. */
export const GROUP_COMMAND_PATH = '/groups/{groupId}/commands';

/** The command types this API accepts; anything else is refused. */
export const COMMAND_TYPES = [
  'run_script',
  'restart',
  'lock',
  'install_package',
  'uninstall_package',
  'collect_logs',
] as const;

/** The types destructive enough to need `{confirm: true}` in the body. */
export const CONFIRM_REQUIRED_TYPES = ['restart', 'run_script'] as const;

/** The interpreters a `run_script` command may name. */
export const SCRIPT_INTERPRETERS = ['powershell', 'zsh', 'cmd', 'bash'] as const;

/** How long a queued command stays collectable: 24 hours, in milliseconds. */
export const COMMAND_TTL_MILLIS = 86400000;

/** Status of a command waiting to be leased. */
export const PENDING_STATUS = 'pending';

/** Prefix of a generated command id. */
export const COMMAND_ID_PREFIX = 'cmd-';

/** Length of the random part of a generated command id, in bytes (16 hex characters). */
export const COMMAND_ID_BYTES = 8;

/** The audit action recorded when a command is queued. */
export const COMMAND_QUEUED_ACTION = 'command.queued';

const SUPPORTED_TYPES: ReadonlySet<string> = new Set(COMMAND_TYPES);
const CONFIRMED_TYPES: ReadonlySet<string> = new Set(CONFIRM_REQUIRED_TYPES);
const INTERPRETERS: ReadonlySet<string> = new Set(SCRIPT_INTERPRETERS);

/** A validated request: what to queue, once every check has passed. */
interface CommandRequest {
  type: string;
  payload: Record<string, unknown>;
}

/** True when a value is a non-empty string. */
function isNonEmptyString(value: unknown): boolean {
  return typeof value === 'string' && value.length > 0;
}

/** The payload fields the type requires but the body does not carry, in report order. */
export function offendingPayloadFields(type: string, payload: Record<string, unknown>): string[] {
  const fields: string[] = [];
  if (type === 'run_script') {
    if (typeof payload.interpreter !== 'string' || !INTERPRETERS.has(payload.interpreter)) {
      fields.push('payload.interpreter');
    }
    if (!isNonEmptyString(payload.script)) {
      fields.push('payload.script');
    }
  }
  if (type === 'install_package' || type === 'uninstall_package') {
    if (!isNonEmptyString(payload.packageId)) {
      fields.push('payload.packageId');
    }
  }
  return fields;
}

/**
 * Settle the request: the validated command, or the result the route must
 * return. Nothing is read or written until this passes.
 */
function readCommandRequest(req: AdminRequest): { command: CommandRequest } | { refusal: RouteResult } {
  const body = readJsonBody(req.body) ?? {};

  // 1. The type, which decides every check after it.
  const type = body.type;
  if (typeof type !== 'string' || !SUPPORTED_TYPES.has(type)) {
    return { refusal: jsonError(400, 'unsupported_command_type') };
  }

  // 2. The payload the type requires, reporting every missing field at once.
  const rawPayload = body.payload;
  const payload: Record<string, unknown> =
    typeof rawPayload === 'object' && rawPayload !== null && !Array.isArray(rawPayload)
      ? (rawPayload as Record<string, unknown>)
      : {};
  const fields = offendingPayloadFields(type, payload);
  if (fields.length > 0) {
    return { refusal: jsonError(400, 'invalid_request', { fields }) };
  }

  // 3. The explicit confirmation a destructive type needs.
  if (CONFIRMED_TYPES.has(type) && body.confirm !== true) {
    return { refusal: jsonError(409, 'confirmation_required') };
  }

  return { command: { type, payload } };
}

/** A generated command id: unique per command, so a fan-out never collides. */
function newCommandId(deps: AdminDependencies): string {
  return `${COMMAND_ID_PREFIX}${adminRandomBytes(deps)(COMMAND_ID_BYTES).toString('hex')}`;
}

/**
 * Write one pending command for one device and audit it.
 *
 * @returns the command id, or `null` when the device id cannot form a key
 */
async function queueCommand(
  table: AdminWriteTable,
  deps: AdminDependencies,
  options: {
    deviceId: string;
    command: CommandRequest;
    actor: string;
    at: Date;
    groupId?: string;
  },
): Promise<string | null> {
  const { deviceId, command, actor, at, groupId } = options;
  const commandId = newCommandId(deps);

  let key;
  try {
    key = deviceCommand(deviceId, commandId);
  } catch {
    return null;
  }

  // Epoch milliseconds, the unit the agent-facing queue reads these two
  // instants in.
  const issuedAt = at.getTime();
  const item: Item = {
    ...key,
    commandId,
    deviceId,
    type: command.type,
    payload: command.payload,
    status: PENDING_STATUS,
    issuedAt,
    expiresAt: issuedAt + COMMAND_TTL_MILLIS,
    issuedBy: actor,
  };
  if (groupId !== undefined) {
    item.groupId = groupId;
  }
  await table.put(item);

  await appendAudit(table, {
    action: COMMAND_QUEUED_ACTION,
    actor,
    target: deviceId,
    detail: groupId === undefined
      ? { commandId, type: command.type }
      : { commandId, type: command.type, groupId },
    now: at,
  });

  return commandId;
}

/**
 * `POST /admin/api/v1/devices/{deviceId}/commands` -- queue one command.
 *
 * 202, not 201: the command is accepted onto the queue, and whether the device
 * ever runs it is the agent's story, told through the command's own status.
 */
export const handleDeviceCommandCreate: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const read = readCommandRequest(req);
  if ('refusal' in read) {
    return read.refusal;
  }

  const deviceId = req.params?.deviceId ?? '';
  const table = adminWriteTable(deps.table);
  const at = adminNow(deps);

  const commandId = await queueCommand(table, deps, {
    deviceId,
    command: read.command,
    actor: adminActor(req.claims),
    at,
  });
  // A device id that cannot even form a key names no device.
  if (commandId === null) {
    return jsonError(404, 'not_found');
  }

  return { statusCode: 202, body: { commandId } };
};

/**
 * `POST /admin/api/v1/groups/{groupId}/commands` -- queue the same command for
 * every member of a group.
 *
 * The group is known when it has a record or at least one member; anything
 * else is a 404 and writes nothing. An empty but real group is accepted and
 * queues nothing, which is the honest answer to "send this to nobody".
 */
export const handleGroupCommandCreate: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  // Every check of the single-device route runs first, so a refused fan-out
  // writes nothing even when the group has members.
  const read = readCommandRequest(req);
  if ('refusal' in read) {
    return read.refusal;
  }

  const groupId = req.params?.groupId ?? '';
  const deviceIds = await readGroupMemberIds(deps.table, groupId);
  if (deviceIds.length === 0 && !(await groupExists(deps, groupId))) {
    return jsonError(404, 'not_found');
  }

  const table = adminWriteTable(deps.table);
  const at = adminNow(deps);
  const actor = adminActor(req.claims);

  let queued = 0;
  for (const deviceId of deviceIds) {
    const commandId = await queueCommand(table, deps, {
      deviceId,
      command: read.command,
      actor,
      at,
      groupId,
    });
    if (commandId !== null) {
      queued += 1;
    }
  }

  return { statusCode: 202, body: { queued } };
};

/** True when the group's own record exists. */
async function groupExists(deps: AdminDependencies, groupId: string): Promise<boolean> {
  let key;
  try {
    key = group(groupId);
  } catch {
    return false;
  }
  const record = await deps.table.get(key);
  return record !== undefined && record !== null;
}

/** Sub-path that queues a library command on one device. */
export const DEVICE_SCRIPT_PATH = '/devices/{deviceId}/scripts';

/** Sub-path that queues a library command on every member of a group. */
export const GROUP_SCRIPT_PATH = '/groups/{groupId}/scripts';

/** Sub-path that moves a pending command up or down its device's queue. */
export const COMMAND_MOVE_PATH = '/devices/{deviceId}/commands/{commandId}/move';

/** Sub-path that cancels a pending command. */
export const COMMAND_CANCEL_PATH = '/devices/{deviceId}/commands/{commandId}/cancel';

/** Status of a pending command an admin cancelled. */
export const CANCELLED_STATUS = 'cancelled';

/** The directions a queued command can be moved in. */
export const MOVE_DIRECTIONS = ['up', 'down'] as const;

/** The audit action recorded when a pending command is cancelled. */
export const COMMAND_CANCELLED_ACTION = 'command.cancelled';

/** The audit action recorded when two pending commands swap places. */
export const COMMAND_MOVED_ACTION = 'command.moved';

/** What a move additionally needs: the atomic two-item `seq` swap. */
interface MoveTable extends AdminUpdateTable {
  transactWrite(items: TransactWriteItem[]): Promise<WriteOutcome>;
}

/** The injected table as a move needs it; a client without `transactWrite` is a wiring fault. */
function moveTable(table: AdminTable): MoveTable {
  const updatable = adminUpdateTable(table);
  if (typeof (updatable as Partial<MoveTable>).transactWrite !== 'function') {
    throw new Error('moving a queued command needs a table client with transactWrite()');
  }
  return updatable as MoveTable;
}

/** True when a thrown value is DynamoDB's failed-condition rejection. */
function isConditionalCheckFailure(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === CONDITIONAL_CHECK_FAILED
  );
}

/**
 * Settle the body both library queue routes take: a non-empty string
 * `scriptId` (400 otherwise), then `{confirm: true}` (409 otherwise).
 */
function readScriptQueueRequest(req: AdminRequest): { scriptId: string } | { refusal: RouteResult } {
  const body = readJsonBody(req.body) ?? {};
  const scriptId = body.scriptId;
  if (typeof scriptId !== 'string' || scriptId.length === 0) {
    return { refusal: jsonError(400, 'invalid_request', { fields: ['scriptId'] }) };
  }
  if (body.confirm !== true) {
    return { refusal: jsonError(409, 'confirmation_required') };
  }
  return { scriptId };
}

/** The device's stored profile, or `null` when it has none (or the id cannot form a key). */
async function readDeviceProfile(table: AdminTable, deviceId: string): Promise<Item | null> {
  let key: TableKey;
  try {
    key = deviceProfile(deviceId);
  } catch {
    return null;
  }
  const profile = await table.get(key);
  return profile === undefined || profile === null ? null : profile;
}

/** Advance the device's `CMDSEQ` counter by one (`ADD next :1`) and return the new value. */
async function nextCommandSeq(table: AdminUpdateTable, deviceId: string): Promise<number> {
  const attributes = await table.update(deviceCommandSeq(deviceId), {
    UpdateExpression: 'ADD #next :one',
    ExpressionAttributeNames: { '#next': 'next' },
    ExpressionAttributeValues: { ':one': 1 },
    ReturnValues: 'ALL_NEW',
  });
  const next = attributes?.next;
  if (typeof next !== 'number' || !Number.isFinite(next)) {
    throw new Error('the command sequence counter returned no value');
  }
  return next;
}

/**
 * Queue one copy of a saved command on one device whose platform has already
 * been checked: allocate its `seq`, write the pending item and audit it.
 */
async function queueLibraryCommand(
  table: AdminUpdateTable,
  deps: AdminDependencies,
  options: { deviceId: string; script: Item; actor: string; at: Date; groupId?: string },
): Promise<{ commandId: string; seq: number }> {
  const { deviceId, script, actor, at, groupId } = options;
  const commandId = newCommandId(deps);
  const key = deviceCommand(deviceId, commandId);
  const seq = await nextCommandSeq(table, deviceId);

  // The script text is copied here, so a later edit or delete of the library
  // entry never changes what this machine runs. No `expiresAt`: a library
  // command waits for its machine however long that takes.
  const item: Item = {
    ...key,
    commandId,
    deviceId,
    type: 'run_script',
    payload: {
      interpreter: script.interpreter,
      script: script.script,
      timeoutSeconds: script.timeoutSeconds,
    },
    status: PENDING_STATUS,
    issuedAt: at.getTime(),
    issuedBy: actor,
    seq,
    scriptId: script.scriptId,
    scriptName: script.name,
  };
  if (groupId !== undefined) {
    item.groupId = groupId;
  }
  await table.put(item);

  const detail: Record<string, unknown> = { commandId, type: 'run_script', scriptId: script.scriptId, seq };
  if (groupId !== undefined) {
    detail.groupId = groupId;
  }
  await appendAudit(table, { action: COMMAND_QUEUED_ACTION, actor, target: deviceId, detail, now: at });

  return { commandId, seq };
}

/**
 * `POST /admin/api/v1/devices/{deviceId}/scripts` -- queue a saved command on
 * one device. Checks, in order: `scriptId` (400), confirmation (409), device
 * profile (404 `not_found`), script (404 `script_not_found`), platform (409
 * `platform_mismatch`); only then is the counter advanced and the item written.
 */
export const handleDeviceScriptQueue: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const read = readScriptQueueRequest(req);
  if ('refusal' in read) {
    return read.refusal;
  }

  const deviceId = req.params?.deviceId ?? '';
  const profile = await readDeviceProfile(deps.table, deviceId);
  if (profile === null) {
    return jsonError(404, 'not_found');
  }
  const script = await readScript(deps.table, read.scriptId);
  if (script === null) {
    return jsonError(404, 'script_not_found');
  }
  if (script.platform !== profile.platform) {
    return jsonError(409, 'platform_mismatch');
  }

  const table = adminUpdateTable(deps.table);
  const queued = await queueLibraryCommand(table, deps, {
    deviceId,
    script,
    actor: adminActor(req.claims),
    at: adminNow(deps),
  });
  return { statusCode: 202, body: queued };
};

/**
 * `POST /admin/api/v1/groups/{groupId}/scripts` -- queue a saved command on
 * every member whose platform matches it. A member on the other platform, or
 * with no profile, gets nothing and is counted in `skipped.wrongPlatform`.
 */
export const handleGroupScriptQueue: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const read = readScriptQueueRequest(req);
  if ('refusal' in read) {
    return read.refusal;
  }

  const groupId = req.params?.groupId ?? '';
  const deviceIds = await readGroupMemberIds(deps.table, groupId);
  if (deviceIds.length === 0 && !(await groupExists(deps, groupId))) {
    return jsonError(404, 'not_found');
  }
  const script = await readScript(deps.table, read.scriptId);
  if (script === null) {
    return jsonError(404, 'script_not_found');
  }

  // Every member is classified before anything is written.
  const targets: string[] = [];
  let wrongPlatform = 0;
  for (const deviceId of deviceIds) {
    const profile = await readDeviceProfile(deps.table, deviceId);
    if (profile === null || profile.platform !== script.platform) {
      wrongPlatform += 1;
    } else {
      targets.push(deviceId);
    }
  }

  const table = adminUpdateTable(deps.table);
  const at = adminNow(deps);
  const actor = adminActor(req.claims);
  let queued = 0;
  for (const deviceId of targets) {
    await queueLibraryCommand(table, deps, { deviceId, script, actor, at, groupId });
    queued += 1;
  }

  return { statusCode: 202, body: { queued, skipped: { wrongPlatform } } };
};

/** Sub-path that queues an application install on one device. */
export const DEVICE_APPLICATION_PATH = '/devices/{deviceId}/applications';

/** The command type an application install is queued as; deliberately not in `COMMAND_TYPES`. */
export const INSTALL_APPLICATION_TYPE = 'install_application';

/** How long the agent lets an installer run, in seconds. */
export const INSTALL_APPLICATION_TIMEOUT_SECONDS = 3600;

/**
 * `POST /admin/api/v1/devices/{deviceId}/applications` -- queue an install of
 * a safe-list application on one device. Checks, in order: `applicationId`
 * (400), device profile (404 `not_found`), application (404
 * `application_not_found`), platform (409 `platform_mismatch`), hash status
 * (409 `application_not_ready` until the hash is ready, TASK-050); only then is
 * the counter advanced and the item written. The item is sequenced and never
 * expires, like a library command; the agent fetches fresh download details
 * when it runs, so no presigned URL is stored on it.
 */
export const handleDeviceApplicationQueue: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body) ?? {};
  const applicationId = body.applicationId;
  if (typeof applicationId !== 'string' || applicationId.length === 0) {
    return jsonError(400, 'invalid_request', { fields: ['applicationId'] });
  }

  const deviceId = req.params?.deviceId ?? '';
  const profile = await readDeviceProfile(deps.table, deviceId);
  if (profile === null) {
    return jsonError(404, 'not_found');
  }
  const app = await readApplication(deps.table, applicationId);
  if (app === null) {
    return jsonError(404, 'application_not_found');
  }
  if (app.platform !== profile.platform) {
    return jsonError(409, 'platform_mismatch');
  }
  if (applicationHashStatus(app) !== 'ready') {
    return jsonError(409, 'application_not_ready');
  }

  const table = adminUpdateTable(deps.table);
  const at = adminNow(deps);
  const actor = adminActor(req.claims);
  const commandId = newCommandId(deps);
  const key = deviceCommand(deviceId, commandId);
  const seq = await nextCommandSeq(table, deviceId);

  await table.put({
    ...key,
    commandId,
    deviceId,
    type: INSTALL_APPLICATION_TYPE,
    payload: {
      applicationId,
      applicationName: app.name,
      timeoutSeconds: INSTALL_APPLICATION_TIMEOUT_SECONDS,
    },
    status: PENDING_STATUS,
    issuedAt: at.getTime(),
    issuedBy: actor,
    seq,
    applicationId,
    scriptName: app.name,
  });

  await appendAudit(table, {
    action: COMMAND_QUEUED_ACTION,
    actor,
    target: deviceId,
    detail: { commandId, type: INSTALL_APPLICATION_TYPE, applicationId, seq },
    now: at,
  });

  return { statusCode: 202, body: { commandId, seq } };
};

/** Every command stored for a device, following the query cursor to the end. */
async function readDeviceCommands(table: AdminTable, deviceId: string): Promise<Item[]> {
  const { pk, sk: commandPrefix } = deviceCommand(deviceId, '');
  const commands: Item[] = [];
  let cursor: string | null = null;
  do {
    const page: QueryPage = await table.query({
      KeyConditionExpression: '#pk = :pk AND begins_with(#sk, :commandPrefix)',
      ExpressionAttributeNames: { '#pk': 'pk', '#sk': 'sk' },
      ExpressionAttributeValues: { ':pk': pk, ':commandPrefix': commandPrefix },
      cursor,
    });
    commands.push(...page.items);
    const next = page.cursor ?? null;
    // A cursor that does not move would page forever; treat it as the end.
    cursor = next === cursor ? null : next;
  } while (cursor !== null);
  return commands;
}

/** The command a move or cancel names, with its key, or `null` when it does not exist. */
async function readNamedCommand(
  table: AdminTable,
  deviceId: string,
  commandId: string,
): Promise<{ key: TableKey; item: Item } | null> {
  let key: TableKey;
  try {
    key = deviceCommand(deviceId, commandId);
  } catch {
    return null;
  }
  const item = await table.get(key);
  return item === undefined || item === null ? null : { key, item };
}

/** The command's id: the stored attribute, else the `CMD#` sort key it was written under. */
function storedCommandId(item: Item): string {
  if (typeof item.commandId === 'string' && item.commandId.length > 0) {
    return item.commandId;
  }
  const sk = typeof item.sk === 'string' ? item.sk : '';
  return sk.startsWith('CMD#') ? sk.slice('CMD#'.length) : sk;
}

/** The `seq` a command carries, or `null` when it has none. */
function seqOf(item: Item): number | null {
  return typeof item.seq === 'number' && Number.isFinite(item.seq) ? item.seq : null;
}

/** One write of the swap: the new `seq`, only while the item is pending at the `seq` it was read with. */
function seqSwapWrite(key: TableKey, readSeq: number, newSeq: number): TransactWriteItem {
  return {
    Update: {
      Key: key,
      UpdateExpression: 'SET #seq = :newSeq',
      ConditionExpression: '#status = :pending AND #seq = :readSeq',
      ExpressionAttributeNames: { '#seq': 'seq', '#status': 'status' },
      ExpressionAttributeValues: { ':newSeq': newSeq, ':readSeq': readSeq, ':pending': PENDING_STATUS },
    },
  };
}

/**
 * `POST /admin/api/v1/devices/{deviceId}/commands/{commandId}/move` -- swap a
 * pending command's `seq` with the nearest pending sequenced command in the
 * given direction, in one TransactWrite. At the edge, or for a command with
 * no `seq`, nothing is written. A lost race with a lease is 409 `not_pending`.
 */
export const handleCommandMove: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body) ?? {};
  const direction = body.direction;
  if (direction !== 'up' && direction !== 'down') {
    return jsonError(400, 'invalid_request', { fields: ['direction'] });
  }

  const deviceId = req.params?.deviceId ?? '';
  const commandId = req.params?.commandId ?? '';
  const named = await readNamedCommand(deps.table, deviceId, commandId);
  if (named === null) {
    return jsonError(404, 'not_found');
  }
  if (named.item.status !== PENDING_STATUS) {
    return jsonError(409, 'not_pending');
  }
  const targetSeq = seqOf(named.item);
  if (targetSeq === null) {
    return { statusCode: 200, body: { commandId, moved: false } };
  }

  // The nearest pending, sequenced neighbour in that direction; anything not
  // pending is stepped over.
  let neighbour: { item: Item; seq: number } | null = null;
  for (const item of await readDeviceCommands(deps.table, deviceId)) {
    const seq = seqOf(item);
    if (seq === null || item.status !== PENDING_STATUS || storedCommandId(item) === commandId) {
      continue;
    }
    const onSide = direction === 'up' ? seq < targetSeq : seq > targetSeq;
    if (!onSide) {
      continue;
    }
    if (neighbour === null || (direction === 'up' ? seq > neighbour.seq : seq < neighbour.seq)) {
      neighbour = { item, seq };
    }
  }
  if (neighbour === null) {
    return { statusCode: 200, body: { commandId, moved: false } };
  }

  const table = moveTable(deps.table);
  const neighbourKey = deviceCommand(deviceId, storedCommandId(neighbour.item));
  const outcome = await table.transactWrite([
    seqSwapWrite(named.key, targetSeq, neighbour.seq),
    seqSwapWrite(neighbourKey, neighbour.seq, targetSeq),
  ]);
  if (!outcome.written) {
    return jsonError(409, 'not_pending');
  }

  await appendAudit(table, {
    action: COMMAND_MOVED_ACTION,
    actor: adminActor(req.claims),
    target: deviceId,
    detail: { commandId, direction },
    now: adminNow(deps),
  });

  return { statusCode: 200, body: { commandId, moved: true } };
};

/**
 * `POST /admin/api/v1/devices/{deviceId}/commands/{commandId}/cancel` --
 * cancel a pending command through a conditional update; anything else, or a
 * lost race with a lease, is 409 `not_pending`.
 */
export const handleCommandCancel: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const deviceId = req.params?.deviceId ?? '';
  const commandId = req.params?.commandId ?? '';
  const named = await readNamedCommand(deps.table, deviceId, commandId);
  if (named === null) {
    return jsonError(404, 'not_found');
  }
  if (named.item.status !== PENDING_STATUS) {
    return jsonError(409, 'not_pending');
  }

  const table = adminUpdateTable(deps.table);
  try {
    await table.update(named.key, {
      UpdateExpression: 'SET #status = :cancelled',
      ConditionExpression: '#status = :pending',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: { ':cancelled': CANCELLED_STATUS, ':pending': PENDING_STATUS },
    });
  } catch (error) {
    if (isConditionalCheckFailure(error)) {
      return jsonError(409, 'not_pending');
    }
    throw error;
  }

  await appendAudit(table, {
    action: COMMAND_CANCELLED_ACTION,
    actor: adminActor(req.claims),
    target: deviceId,
    detail: { commandId },
    now: adminNow(deps),
  });

  return { statusCode: 200, body: { commandId, status: CANCELLED_STATUS } };
};

/** Register every dispatch route on a router. Returns the router, so calls chain. */
export function registerCommandDispatchRoutes(router: Router, source: AdminDependencySource): Router {
  registerAdminRoute(router, 'POST', DEVICE_COMMAND_PATH, handleDeviceCommandCreate, source);
  registerAdminRoute(router, 'POST', GROUP_COMMAND_PATH, handleGroupCommandCreate, source);
  registerAdminRoute(router, 'POST', DEVICE_SCRIPT_PATH, handleDeviceScriptQueue, source);
  registerAdminRoute(router, 'POST', GROUP_SCRIPT_PATH, handleGroupScriptQueue, source);
  registerAdminRoute(router, 'POST', DEVICE_APPLICATION_PATH, handleDeviceApplicationQueue, source);
  registerAdminRoute(router, 'POST', COMMAND_MOVE_PATH, handleCommandMove, source);
  return registerAdminRoute(router, 'POST', COMMAND_CANCEL_PATH, handleCommandCancel, source);
}
