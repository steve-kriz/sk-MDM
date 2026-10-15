/**
 * `GET /downloads/{platform}` -- the public installer download link.
 *
 * The landing page links each platform to a stable URL here; the route checks
 * the installer object exists and answers `302` to a short-lived presigned S3
 * GET URL, so the bucket stays private and no long-lived public URL exists.
 *
 *   unknown slug (case-sensitive)  -> 404 not_found (the store is not called)
 *   object absent                  -> 404 installer_not_available
 *   not configured / empty bucket  -> 500 not_configured
 *   store error                    -> thrown; the router answers 500 internal_error
 *
 * The route is public: it reads no authorization or device signature header.
 * Its store is injected and no AWS client is constructed here; start-up calls
 * `configureDownloadRoute({ bucket, installers })` before the first request.
 *
 *   GET /api/v1/downloads
 *   -> {"versions":{"windows-x64":"1.2.3","windows-arm64":null,...}}
 *
 * is its public companion: the version each platform's installer was published
 * as, which the landing page shows next to the link. The version is read from
 * the `OfficeHQ-MDM-<version>-<arch>` file name scripts/publish-installers.mjs
 * puts in the object's `Content-Disposition`; `null` means nothing (readable)
 * is published for that platform.
 */
import type { RouteHandler, RouteResult, Router } from '../http/router.js';

/** Path this route is registered on. */
export const DOWNLOAD_PATH = '/downloads/{platform}';

/** The platform slugs a download is offered for, in landing-page order. */
export const DOWNLOAD_PLATFORMS = ['windows-x64', 'windows-arm64', 'macos-amd64', 'macos-arm64'] as const;

export type DownloadPlatform = (typeof DOWNLOAD_PLATFORMS)[number];

/** How long a presigned download URL stays valid, in seconds. */
export const DOWNLOAD_URL_TTL_SECONDS = 300;

const INSTALLER_KEYS: Record<DownloadPlatform, string> = {
  'windows-x64': 'installers/windows-x64.msi',
  'windows-arm64': 'installers/windows-arm64.msi',
  'macos-amd64': 'installers/macos-amd64.pkg',
  'macos-arm64': 'installers/macos-arm64.pkg',
};

/** True when `slug` is exactly one of `DOWNLOAD_PLATFORMS`. */
export function isDownloadPlatform(slug: unknown): slug is DownloadPlatform {
  return typeof slug === 'string' && (DOWNLOAD_PLATFORMS as readonly string[]).includes(slug);
}

/** The fixed "latest" object key a platform's installer is published to. */
export function installerKey(slug: DownloadPlatform): string {
  return INSTALLER_KEYS[slug];
}

/**
 * The fixed object key each agent release platform's raw binary is published
 * to by scripts/publish-installers.mjs; check-in presigns it for self-update.
 */
const AGENT_BUILD_KEYS: Record<string, string> = {
  'windows-amd64': 'agent/windows-amd64/mdmagent.exe',
  'windows-arm64': 'agent/windows-arm64/mdmagent.exe',
  'darwin-amd64': 'agent/darwin-amd64/mdmagent',
  'darwin-arm64': 'agent/darwin-arm64/mdmagent',
};

/** The object key of a platform's published agent binary; throws on an unknown platform. */
export function agentBuildKey(platform: string): string {
  if (typeof platform !== 'string' || !Object.prototype.hasOwnProperty.call(AGENT_BUILD_KEYS, platform)) {
    throw new Error(`invalid id: ${platform}`);
  }
  return AGENT_BUILD_KEYS[platform] as string;
}

/** Path the published installer versions are answered on. */
export const DOWNLOAD_VERSIONS_PATH = '/api/v1/downloads';

/** `OfficeHQ-MDM-1.2.3-x64.msi` -> `1.2.3`. */
const PUBLISHED_FILE_VERSION = /OfficeHQ-MDM-([0-9]+\.[0-9]+\.[0-9]+)-/;

/**
 * The version in a published installer's `Content-Disposition` file name, or
 * `null` when the header is absent or names no version.
 */
export function versionFromContentDisposition(value: string | undefined): string | null {
  if (typeof value !== 'string') {
    return null;
  }
  const match = PUBLISHED_FILE_VERSION.exec(value);
  return match === null ? null : (match[1] ?? null);
}

/** The installer storage operations this route needs: the subset a fake must implement. */
export interface InstallerStore {
  exists(key: string): Promise<boolean>;
  presignGet(key: string, ttlSeconds: number): Promise<string>;
  /** The published version of the object at `key`, or `null`; a store without it answers `null` everywhere. */
  version?(key: string): Promise<string | null>;
  /** The published agent build at `key` from its object metadata, or `null` when absent or malformed. */
  agentBuild?(key: string): Promise<{ version: string; sha256: string } | null>;
  /** A presigned PutObject URL for `key`, valid for `ttlSeconds` (application uploads). */
  presignPut?(key: string, ttlSeconds: number): Promise<string>;
  /** The size in bytes of the object at `key`, or `null` when it does not exist. */
  objectSize?(key: string): Promise<number | null>;
}

export interface DownloadDependencies {
  /** The installer bucket's name; empty means the route is not configured. */
  bucket: string | undefined;
  /** The installer store; absent means the route is not configured. */
  installers?: InstallerStore;
}

/** Dependencies, or something that resolves them when the request arrives. */
export type DownloadDependencySource =
  | DownloadDependencies
  | (() => DownloadDependencies | Promise<DownloadDependencies>);

function failure(statusCode: number, error: string): RouteResult {
  return { statusCode, body: { error } };
}

/**
 * Build the download route handler.
 *
 * @param source the dependencies, or a function resolving them per request
 */
export function createDownloadHandler(source: DownloadDependencySource): RouteHandler {
  async function dependencies(): Promise<DownloadDependencies | undefined> {
    return typeof source === 'function' ? await source() : source;
  }

  return async function handleDownload(req): Promise<RouteResult> {
    const slug = req?.params?.platform;
    if (!isDownloadPlatform(slug)) {
      return failure(404, 'not_found');
    }

    const deps = await dependencies();
    const installers = deps?.installers;
    if (typeof deps?.bucket !== 'string' || deps.bucket === '' || !installers) {
      return failure(500, 'not_configured');
    }

    const key = installerKey(slug);
    if (!(await installers.exists(key))) {
      return failure(404, 'installer_not_available');
    }

    const location = await installers.presignGet(key, DOWNLOAD_URL_TTL_SECONDS);
    return {
      statusCode: 302,
      headers: { location, 'cache-control': 'no-store' },
      rawBody: '',
    };
  };
}

/**
 * Build the `GET /api/v1/downloads` handler: every platform's published
 * version, read in parallel, `null` where none is published.
 */
export function createDownloadVersionsHandler(source: DownloadDependencySource): RouteHandler {
  return async function handleDownloadVersions(): Promise<RouteResult> {
    const deps = typeof source === 'function' ? await source() : source;
    const installers = deps?.installers;
    if (typeof deps?.bucket !== 'string' || deps.bucket === '' || !installers) {
      return failure(500, 'not_configured');
    }

    const read = await Promise.all(
      DOWNLOAD_PLATFORMS.map(async (slug) =>
        installers.version === undefined ? null : await installers.version(installerKey(slug)),
      ),
    );
    const versions = Object.fromEntries(DOWNLOAD_PLATFORMS.map((slug, i) => [slug, read[i] ?? null]));
    return { statusCode: 200, headers: { 'cache-control': 'no-store' }, body: { versions } };
  };
}

/** Register the download route and its versions route on a router. Returns the router, so calls chain. */
export function registerDownloadRoute(router: Router, source: DownloadDependencySource): Router {
  return router
    .add('GET', DOWNLOAD_PATH, createDownloadHandler(source))
    .add('GET', DOWNLOAD_VERSIONS_PATH, createDownloadVersionsHandler(source));
}

/** Dependencies supplied at start-up by `configureDownloadRoute`. */
let configured: DownloadDependencies | null = null;

/** Supply the download route's bucket and installer store. */
export function configureDownloadRoute(dependencies: DownloadDependencies): void {
  configured = dependencies;
}

/**
 * The configured dependencies. When start-up skipped them both fields are
 * `undefined`, and the route answers `500 not_configured` rather than throwing.
 */
export function resolveDownloadDependencies(): DownloadDependencies {
  return configured ?? { bucket: undefined, installers: undefined };
}
