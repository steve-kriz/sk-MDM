/**
 * The fleet-wide command setting: what a failed queued command does to the
 * rest of that machine's queue.
 *
 *   GET /admin/api/v1/settings/commands  -- {onFailure}
 *   PUT /admin/api/v1/settings/commands  -- {onFailure: 'continue' | 'stop'}
 *
 *   registerCommandSettingsRoutes(router, { verifier, table, now });
 *
 * Stored at `keys.commandSettings()` (`CONFIG` / `COMMANDS`). When the item is
 * absent the value is `continue`. `readCommandSettings` is shared with the
 * agent-facing lease route (`src/routes/commands.ts`), which flags sequenced
 * commands with `stopOnFailure` when the setting is `stop`.
 */
import { appendAudit } from '../audit.js';
import { commandSettings, type TableKey } from '../db/keys.js';
import type { Item, RequestFields } from '../db/table.js';
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

/** Sub-path of the command settings. */
export const COMMAND_SETTINGS_PATH = '/settings/commands';

/** The values `onFailure` may take. */
export const ON_FAILURE_VALUES = ['continue', 'stop'] as const;

/** One `onFailure` value. */
export type OnFailure = (typeof ON_FAILURE_VALUES)[number];

/** The value when nothing is stored. */
export const DEFAULT_ON_FAILURE: OnFailure = 'continue';

/** The audit action recorded when the setting is saved. */
export const COMMAND_SETTINGS_UPDATED_ACTION = 'settings.commands.updated';

/** The read the setting needs: a single `get`. */
export interface CommandSettingsTable {
  get(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
}

/** True when a value is one of `ON_FAILURE_VALUES`. */
function isOnFailure(value: unknown): value is OnFailure {
  return typeof value === 'string' && (ON_FAILURE_VALUES as readonly string[]).includes(value);
}

/** The stored command settings, with the default applied when absent or unreadable. */
export async function readCommandSettings(table: CommandSettingsTable): Promise<{ onFailure: OnFailure }> {
  const item = await table.get(commandSettings());
  return { onFailure: isOnFailure(item?.onFailure) ? item.onFailure : DEFAULT_ON_FAILURE };
}

/** `GET /admin/api/v1/settings/commands` -- the current setting. */
export const handleCommandSettingsGet: AdminRouteHandler = async (_req, deps): Promise<RouteResult> => {
  return { statusCode: 200, body: await readCommandSettings(deps.table) };
};

/** `PUT /admin/api/v1/settings/commands` -- save the setting; a bad value stores nothing. */
export const handleCommandSettingsPut: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body) ?? {};
  const onFailure = body.onFailure;
  if (!isOnFailure(onFailure)) {
    return jsonError(400, 'invalid_request', { fields: ['onFailure'] });
  }

  const table = adminWriteTable(deps.table);
  const at = adminNow(deps);
  await table.put({ ...commandSettings(), onFailure });

  await appendAudit(table, {
    action: COMMAND_SETTINGS_UPDATED_ACTION,
    actor: adminActor(req.claims),
    target: 'settings.commands',
    detail: { onFailure },
    now: at,
  });

  return { statusCode: 200, body: { onFailure } };
};

/** Register the command settings routes on a router. Returns the router, so calls chain. */
export function registerCommandSettingsRoutes(router: Router, source: AdminDependencySource): Router {
  registerAdminRoute(router, 'GET', COMMAND_SETTINGS_PATH, handleCommandSettingsGet, source);
  return registerAdminRoute(router, 'PUT', COMMAND_SETTINGS_PATH, handleCommandSettingsPut, source);
}
