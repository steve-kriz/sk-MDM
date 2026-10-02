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
 */
import { appendAudit } from '../audit.js';
import { deviceCommand, group } from '../db/keys.js';
import type { Item } from '../db/table.js';
import type { RouteResult, Router } from '../http/router.js';
import { readGroupMemberIds } from './groups.js';
import {
  adminActor,
  adminNow,
  adminRandomBytes,
  adminWriteTable,
  jsonError,
  readJsonBody,
  registerAdminRoute,
  type AdminDependencies,
  type AdminDependencySource,
  type AdminRequest,
  type AdminRouteHandler,
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
export const SCRIPT_INTERPRETERS = ['powershell', 'zsh'] as const;

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

/** Register both dispatch routes on a router. Returns the router, so calls chain. */
export function registerCommandDispatchRoutes(router: Router, source: AdminDependencySource): Router {
  registerAdminRoute(router, 'POST', DEVICE_COMMAND_PATH, handleDeviceCommandCreate, source);
  return registerAdminRoute(router, 'POST', GROUP_COMMAND_PATH, handleGroupCommandCreate, source);
}
