/**
 * Publishing an agent build: the record a check-in turns into an update offer.
 *
 *   POST /admin/api/v1/agent-release
 *
 *   registerAgentReleaseRoutes(router, { verifier, table, now });
 *
 * One item per platform, replaced on every publish, so the fleet is moved by
 * writing where it should be rather than by tracking where each device is: the
 * check-in route compares the device's reported agent version with the version
 * stored here and advertises the build only to the devices that are not on it
 * yet (see `src/routes/checkin.ts`).
 *
 * Everything the agent will act on is validated before anything is written.
 * The agent downloads the `url` and refuses the bytes whose SHA-256 is not
 * `sha256`, so a record with a plaintext url, a digest that is not 64 hex
 * characters or a version that is not `major.minor.patch` is a record that
 * would either be refused on every device or, worse, fetched over a transport
 * nobody authenticated. Every offending field is named at once, so an admin
 * fixes one request rather than four.
 */
import { appendAudit, isoUtc } from '../audit.js';
import { AGENT_RELEASE_PLATFORMS, agentRelease } from '../db/keys.js';
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

/** Sub-path of the agent release record. */
export const AGENT_RELEASE_PATH = '/agent-release';

/** The audit action recorded when a build is published. */
export const AGENT_RELEASE_PUBLISHED_ACTION = 'agent_release.published';

/** `1.3.0` -- the only version shape a release may carry. */
const VERSION_PATTERN = /^[0-9]+\.[0-9]+\.[0-9]+$/;

/** The SHA-256 of the build, lower-case hex. */
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

/** The only url scheme a build may be fetched over. */
const DOWNLOAD_SCHEME = 'https:';

/** True when the value is an `https` url the agent could fetch. */
function isHttpsUrl(value: unknown): boolean {
  if (typeof value !== 'string' || value.length === 0) {
    return false;
  }
  try {
    return new URL(value).protocol === DOWNLOAD_SCHEME;
  } catch {
    return false;
  }
}

/** True when the value is a published platform. */
function isPublishedPlatform(value: unknown): boolean {
  return typeof value === 'string' && AGENT_RELEASE_PLATFORMS.includes(value as never);
}

/**
 * Name every field of the body that is missing or wrong, in report order.
 *
 * The order is the order the fields are documented in, so two bad requests
 * never report the same two faults differently.
 */
export function offendingReleaseFields(body: Record<string, unknown>): string[] {
  const fields: string[] = [];
  if (typeof body.version !== 'string' || !VERSION_PATTERN.test(body.version)) {
    fields.push('version');
  }
  if (!isPublishedPlatform(body.platform)) {
    fields.push('platform');
  }
  if (!isHttpsUrl(body.url)) {
    fields.push('url');
  }
  if (typeof body.sha256 !== 'string' || !SHA256_PATTERN.test(body.sha256)) {
    fields.push('sha256');
  }
  return fields;
}

/**
 * `POST /admin/api/v1/agent-release` -- publish the build for one platform.
 *
 * The write replaces whatever was stored for that platform: there is one
 * current build per platform and no history, because a device that is behind
 * is moved to the current build, never to the one before it.
 */
export const handleAgentReleasePublish: AdminRouteHandler = async (req, deps): Promise<RouteResult> => {
  const body = readJsonBody(req.body) ?? {};

  const fields = offendingReleaseFields(body);
  if (fields.length > 0) {
    return jsonError(400, 'invalid_request', { fields });
  }
  // Every part is now known to be present and of the documented shape.
  const version = body.version as string;
  const platform = body.platform as string;
  const url = body.url as string;
  const sha256 = body.sha256 as string;

  const at = adminNow(deps);
  const table = adminWriteTable(deps.table);
  await table.put({
    ...agentRelease(platform),
    platform,
    version,
    url,
    sha256,
    publishedAt: isoUtc(at),
  });

  await appendAudit(table, {
    action: AGENT_RELEASE_PUBLISHED_ACTION,
    actor: adminActor(req.claims),
    target: platform,
    detail: { version, url },
    now: at,
  });

  return { statusCode: 201, body: { platform, version } };
};

/** Register the agent release route on a router. Returns the router, so calls chain. */
export function registerAgentReleaseRoutes(router: Router, source: AdminDependencySource): Router {
  return registerAdminRoute(router, 'POST', AGENT_RELEASE_PATH, handleAgentReleasePublish, source);
}
