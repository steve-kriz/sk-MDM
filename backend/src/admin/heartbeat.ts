/**
 * The per-device heartbeat setting and its CloudWatch history.
 *
 *   POST /admin/api/v1/devices/{deviceId}/heartbeat   {"enabled": true, "intervalSeconds": 300}
 *   -> {"deviceId","heartbeatEnabled","intervalSeconds","updatedAt","updatedBy"}
 *
 *   GET  /admin/api/v1/devices/{deviceId}/heartbeats
 *   -> {"deviceId","items":[<newest HEARTBEAT_HISTORY_LIMIT snapshots, newest first>]}
 *
 *   registerHeartbeatAdminRoutes(router, { verifier, table, now, heartbeatLog });
 *
 * The setting is its own item, `DEVICE#<id>` / `HEARTBEAT`, written whole with
 * `put` -- never the TASK-040 `SETTINGS` item, whose route also writes whole
 * items. The agent learns it from the check-in response (on) and from each
 * heartbeat response (off, or a new frequency); see `src/routes/heartbeat.ts`.
 *
 * The set route checks the body, then the device, then writes and appends one
 * `device.heartbeat.changed` audit item -- the order of
 * `handleAnalyticsCollectionSet`. The history route reads the device's log
 * stream through the injected `heartbeatLog`: none configured is 503
 * `heartbeat_not_configured`, a failed read 503 `heartbeat_store_unavailable`.
 */
import { appendAudit, isoUtc } from '../audit.js';
import { HEARTBEAT_INTERVAL_OPTIONS_SECONDS } from '../config/intervals.js';
import { recordDeviceEvent } from '../deviceEvents.js';
import { deviceHeartbeatSettings, deviceProfile, type TableKey } from '../db/keys.js';
import type { RouteResult, Router } from '../http/router.js';
import {
  adminActor,
  adminNow,
  adminWriteTable,
  jsonError,
  readJsonBody,
  registerAdminRoute,
  type AdminDependencySource,
  type AdminRouteHandler,
} from './router.js';

/** Sub-path of the per-device heartbeat on/off and frequency setting. */
export const HEARTBEAT_SETTING_PATH = '/devices/{deviceId}/heartbeat';

/** Sub-path of the per-device heartbeat history. */
export const HEARTBEAT_HISTORY_PATH = '/devices/{deviceId}/heartbeats';

/** Audit action of a change to a device's heartbeat setting. */
export const HEARTBEAT_CHANGED_ACTION = 'device.heartbeat.changed';

/** The most snapshots the history route returns. */
export const HEARTBEAT_HISTORY_LIMIT = 100;

/** A thrown value's `name` when it is a non-empty string (e.g. `AccessDeniedException`), else `unknown`. */
function errorName(error: unknown): string {
  const name = typeof error === 'object' && error !== null ? (error as { name?: unknown }).name : undefined;
  return typeof name === 'string' && name.length > 0 ? name : 'unknown';
}

/** True for a number that is one of the allowed heartbeat frequencies. */
function isIntervalOption(value: unknown): value is number {
  return typeof value === 'number' && HEARTBEAT_INTERVAL_OPTIONS_SECONDS.includes(value);
}

/** `POST /devices/{deviceId}/heartbeat`. */
export const handleHeartbeatSet: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body);
  const posted = body !== null && !Array.isArray(body) ? body : {};
  const enabled = posted.enabled;
  const intervalSeconds = posted.intervalSeconds;
  const fields: string[] = [];
  if (typeof enabled !== 'boolean') {
    fields.push('enabled');
  }
  if (!isIntervalOption(intervalSeconds)) {
    fields.push('intervalSeconds');
  }
  if (fields.length > 0) {
    return jsonError(400, 'invalid_request', { fields });
  }

  const deviceId = req.params?.deviceId ?? '';
  let profileKey: TableKey;
  let heartbeatKey: TableKey;
  try {
    profileKey = deviceProfile(deviceId);
    heartbeatKey = deviceHeartbeatSettings(deviceId);
  } catch {
    return jsonError(404, 'not_found');
  }

  const table = adminWriteTable(deps.table);

  const profile = await table.get(profileKey);
  if (profile === undefined || profile === null) {
    return jsonError(404, 'not_found');
  }

  const at = adminNow(deps);
  const updatedAt = isoUtc(at);
  const updatedBy = adminActor(req.claims);
  await table.put({
    ...heartbeatKey,
    deviceId,
    heartbeatEnabled: enabled as boolean,
    intervalSeconds: intervalSeconds as number,
    updatedAt,
    updatedBy,
  });

  await appendAudit(table, {
    action: HEARTBEAT_CHANGED_ACTION,
    actor: updatedBy,
    target: deviceId,
    detail: { enabled, intervalSeconds },
    now: at,
  });

  await recordDeviceEvent(table, {
    deviceId,
    source: 'admin',
    type: 'heartbeat.changed',
    summary: enabled === true ? `Heartbeat turned on (every ${String(intervalSeconds)} seconds)` : 'Heartbeat turned off',
    actor: updatedBy,
    occurredAt: at,
  });

  return {
    statusCode: 200,
    body: { deviceId, heartbeatEnabled: enabled, intervalSeconds, updatedAt, updatedBy },
  };
};

/** `GET /devices/{deviceId}/heartbeats`. */
export const handleHeartbeatHistory: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const deviceId = req.params?.deviceId ?? '';
  let profileKey: TableKey;
  try {
    profileKey = deviceProfile(deviceId);
  } catch {
    return jsonError(404, 'not_found');
  }

  const profile = await deps.table.get(profileKey);
  if (profile === undefined || profile === null) {
    return jsonError(404, 'not_found');
  }

  if (deps.heartbeatLog === undefined) {
    return jsonError(503, 'heartbeat_not_configured');
  }

  let items: Record<string, unknown>[];
  try {
    items = await deps.heartbeatLog.read(deviceId, HEARTBEAT_HISTORY_LIMIT);
  } catch (error) {
    console.warn(JSON.stringify({ msg: 'heartbeat history read failed', deviceId, error: errorName(error) }));
    return jsonError(503, 'heartbeat_store_unavailable');
  }

  return { statusCode: 200, body: { deviceId, items } };
};

/** Register both heartbeat routes on a router. Returns the router, so calls chain. */
export function registerHeartbeatAdminRoutes(router: Router, source: AdminDependencySource): Router {
  registerAdminRoute(router, 'POST', HEARTBEAT_SETTING_PATH, handleHeartbeatSet, source);
  return registerAdminRoute(router, 'GET', HEARTBEAT_HISTORY_PATH, handleHeartbeatHistory, source);
}
