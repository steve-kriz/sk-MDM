/**
 * `GET /api/v1/devices/{deviceId}/policies` -- the agent's policy bundle.
 *
 * One request answers "what should this machine be configured as right now":
 * every policy assigned to every group the device belongs to, merged into the
 * `effectiveSettings` the agent applies, plus the `conflicts` that merge
 * resolved so an admin can see why a value won (see `src/policies/merge.ts`).
 *
 *   registerPolicyBundleRoute(router, { table, now, pepper });
 *
 * This is an agent route, not an admin one: it is registered on the application
 * router in `src/index.ts` and authenticated by `verifyDeviceRequest` (see
 * `src/http/deviceAuth.ts`), exactly like the check-in and command routes.
 *
 * The checks run in a fixed order and the first failure returns immediately,
 * having read no policy, assignment or membership item:
 *
 *   1. `verifyDeviceRequest`        -> its own `{status, body}`, unchanged
 *   2. path device == signed device -> 403 device_mismatch
 *
 * so a device can only ever learn its own configuration. The bundle is never
 * written: it is derived from stored policies on every request rather than
 * cached, so unassigning a policy takes effect on the next poll. The only write
 * is the best-effort last-seen refresh of the device profile on a 200 answer
 * (see `./deviceContact.ts`), which never changes the response.
 *
 * A device with no membership, or whose groups carry no assignment, is a
 * perfectly ordinary answer: 200 with an empty bundle. It is never a 404, since
 * "no policy governs this machine" is a configuration, not a missing resource.
 *
 * Every dependency -- the table client, the clock and the authenticator -- is
 * injected, so tests drive this handler with fakes and nothing opens a
 * DynamoDB connection.
 */
import { isoUtc } from '../audit.js';
import type { PolicyBundleResponse } from '../contract/types.js';
import type { TableKey } from '../db/keys.js';
import type { Item, QueryPage, QueryRequest, RequestFields, WriteOutcome } from '../db/table.js';
import { verifyDeviceRequest, type DeviceAuthResult, type EpochSecondsClock } from '../http/deviceAuth.js';
import type { RouteHandler, RouteRequest, RouteResult, Router, RouterRequest } from '../http/router.js';
import { mergePolicySettings } from '../policies/merge.js';
import { readAssignedPolicies } from '../policies/resolve.js';
import { recordDeviceContact } from './deviceContact.js';

/** Path this route is registered on. */
export const POLICY_BUNDLE_PATH = '/api/v1/devices/{deviceId}/policies';

/**
 * The storage operations this route needs: the structural subset of
 * `TableClient` (see `src/db/table.ts`) a fake has to implement. `putIfAbsent`
 * is here only because `verifyDeviceRequest` burns a nonce with it; `update`
 * only refreshes the device's last-seen.
 */
export interface PolicyBundleTable {
  get(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
  putIfAbsent(item: Item, fields?: RequestFields): Promise<WriteOutcome>;
  query(request?: QueryRequest): Promise<QueryPage>;
  update(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
}

/** Current time: integer epoch seconds, or any instant a `Date` can be built from. */
export type PolicyBundleClock = () => number | string | Date;

/** The authenticator this route calls; injectable so tests need no signed request. */
export type DeviceVerifier = (
  req: RouterRequest,
  options: { table: PolicyBundleTable; now: EpochSecondsClock; pepper: string },
) => Promise<DeviceAuthResult>;

/** The pepper key, or anything that resolves it (a `PepperProvider` fits). */
export type PepperSource = string | (() => string | Promise<string>);

export interface PolicyBundleDependencies {
  /** Table client. Required; never created here. */
  table: PolicyBundleTable;
  /** Current time. Defaults to the system clock, in epoch seconds. */
  now?: PolicyBundleClock;
  /** The 64-character hex pepper key, or `getPepper`. Unused when `verifyDevice` is injected. */
  pepper?: PepperSource;
  /** Overrides the device authenticator; defaults to `verifyDeviceRequest`. */
  verifyDevice?: DeviceVerifier;
}

/** Dependencies, or something that resolves them when the request arrives. */
export type PolicyBundleDependencySource =
  | PolicyBundleDependencies
  | (() => PolicyBundleDependencies | Promise<PolicyBundleDependencies>);

function failure(statusCode: number, error: string): RouteResult {
  return { statusCode, body: { error } };
}

/** Normalise whatever the injected clock returned into a `Date`; a number is epoch seconds. */
function toDate(instant: number | string | Date): Date {
  if (instant instanceof Date) {
    return new Date(instant.getTime());
  }
  if (typeof instant === 'string') {
    return new Date(instant);
  }
  return new Date(instant * 1000);
}

async function resolvePepper(pepper: PepperSource | undefined): Promise<string> {
  if (pepper === undefined) {
    return '';
  }
  return typeof pepper === 'function' ? await pepper() : pepper;
}

/**
 * Authenticate the request and confirm it is about its own device.
 *
 * Returns the device id, or the result the route must return: an
 * authentication failure unchanged, or a 403 when the path names another
 * device. Nothing is read before this passes.
 */
async function authoriseDevice(
  req: RouteRequest,
  deps: PolicyBundleDependencies,
  now: EpochSecondsClock,
): Promise<{ ok: true; deviceId: string } | { ok: false; result: RouteResult }> {
  const verify: DeviceVerifier = deps.verifyDevice ?? verifyDeviceRequest;
  const auth = await verify(req, {
    table: deps.table,
    now,
    pepper: await resolvePepper(deps.pepper),
  });
  if (!auth.ok) {
    return { ok: false, result: { statusCode: auth.status, body: auth.body } };
  }
  if (auth.deviceId !== (req.params?.deviceId ?? '')) {
    return { ok: false, result: failure(403, 'device_mismatch') };
  }
  return { ok: true, deviceId: auth.deviceId };
}

/**
 * Build the policy bundle route handler.
 *
 * @param source the dependencies, or a function resolving them on first use
 */
export function createPolicyBundleHandler(source: PolicyBundleDependencySource): RouteHandler {
  async function dependencies(): Promise<PolicyBundleDependencies> {
    return typeof source === 'function' ? await source() : source;
  }

  return async function handlePolicyBundle(req: RouteRequest): Promise<RouteResult> {
    const deps = await dependencies();
    const clock: PolicyBundleClock = deps.now ?? ((): number => Math.floor(Date.now() / 1000));
    const nowSeconds: EpochSecondsClock = () => Math.floor(toDate(clock()).getTime() / 1000);

    // 1. The signed device, and 2. that it is the device the path names.
    const authorised = await authoriseDevice(req, deps, nowSeconds);
    if (!authorised.ok) {
      return authorised.result;
    }
    const deviceId = authorised.deviceId;

    const policies = await readAssignedPolicies(deps.table, deviceId);
    const { effectiveSettings, conflicts } = mergePolicySettings(policies);

    // `generatedAt` is the server's own instant, so an agent can tell how fresh
    // the merge it is applying is.
    const body: PolicyBundleResponse = {
      deviceId,
      generatedAt: isoUtc(toDate(clock())),
      policies,
      effectiveSettings,
      conflicts,
    };

    await recordDeviceContact(deps.table, deviceId, toDate(clock()));

    return { statusCode: 200, body };
  };
}

/** Register the route on a router. Returns the router, so calls chain. */
export function registerPolicyBundleRoute(router: Router, source: PolicyBundleDependencySource): Router {
  return router.add('GET', POLICY_BUNDLE_PATH, createPolicyBundleHandler(source));
}

/**
 * Dependencies supplied at start-up.
 *
 * Nothing in this package constructs an AWS client, so the route is registered
 * at import time and the deployment hands it a table client and a pepper
 * provider by calling `configurePolicyBundleRoute` before the first request.
 */
let configured: PolicyBundleDependencies | null = null;

/** Supply the policy bundle route's storage, clock and pepper. */
export function configurePolicyBundleRoute(dependencies: PolicyBundleDependencies): void {
  configured = dependencies;
}

/** The configured dependencies, or a thrown error when start-up skipped them. */
export function resolvePolicyBundleDependencies(): PolicyBundleDependencies {
  if (configured === null) {
    throw new Error('policy bundle route is not configured: call configurePolicyBundleRoute() at start-up');
  }
  return configured;
}
