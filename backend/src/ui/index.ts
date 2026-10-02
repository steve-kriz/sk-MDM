/**
 * The admin console, served by the same Lambda as the API.
 *
 *   GET /                     -- the single page the console boots from
 *   GET /assets/{file}        -- its stylesheet and browser modules
 *   GET /assets/views/{file}  -- the per-screen view modules
 *   GET /admin/config.json    -- the public client configuration
 *
 *   registerUiRoutes(router);
 *
 * Nothing here is behind the token verifier: the page, its scripts and the
 * client configuration are public by construction, and every call that reads
 * or writes fleet data is made by the browser against `/admin/api/v1/*`, which
 * is. There is no server-side session, no `/auth/*` route and no cookie; the
 * browser performs the whole OIDC authorization-code flow with PKCE itself.
 *
 * Static files are returned through `rawBody` (see `src/http/router.ts`), which
 * is what keeps HTML HTML: a route that returns `body` is JSON-serialised and
 * answered as `application/json`, exactly as every API route still is, while a
 * route that returns `rawBody` owns its own content-type.
 *
 * The files themselves live next to this module once built -- `dist/ui/public`
 * and `dist/ui/views`, copied there by `scripts/copy-ui.mjs` during
 * `npm run build` -- so they travel inside the Lambda's code asset and are
 * resolved relative to `import.meta.url` rather than to a working directory.
 * `/assets/public/{file}` serves the same directory as `/assets/{file}` so a
 * view module's own `../public/html.js` import resolves in the browser exactly
 * as it does on disk.
 *
 * An asset name is matched against the directory listing taken at cold start,
 * so a request can only ever name a file that was shipped: `..`, an absolute
 * path and an unknown name are all simply 404 `not_found`, the same JSON body
 * the router answers an unmatched path with.
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { RouteRequest, RouteResult, Router } from '../http/router.js';
import { adminClientConfig } from './config.js';

/** Path of the single page. */
export const INDEX_PATH = '/';

/** Path pattern of a browser module or stylesheet. */
export const ASSET_PATH = '/assets/{file}';

/** Path pattern of a browser module addressed the way a view module imports it. */
export const PUBLIC_ASSET_PATH = '/assets/public/{file}';

/** Path pattern of a per-screen view module. */
export const VIEW_ASSET_PATH = '/assets/views/{file}';

/** Path of the public client configuration. */
export const CONFIG_PATH = '/admin/config.json';

/** The file `GET /` answers with. */
export const INDEX_FILE = 'index.html';

/** Where the browser modules and the stylesheet live, next to this module. */
export const PUBLIC_DIR = fileURLToPath(new URL('./public/', import.meta.url));

/** Where the per-screen view modules live, next to this module. */
export const VIEWS_DIR = fileURLToPath(new URL('./views/', import.meta.url));

/** The media type each servable extension is answered with. */
export const CONTENT_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
};

/**
 * The headers every page and script response carries.
 *
 * `default-src 'self'` is the whole point: the console loads no third-party
 * script and no inline one. `connect-src` additionally names Entra's own
 * endpoint, which is where -- and the only place where -- the browser exchanges
 * its authorization code.
 */
export const SECURITY_HEADERS: Record<string, string> = {
  'content-security-policy':
    "default-src 'self'; connect-src 'self' https://login.microsoftonline.com; img-src 'self' data:; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
};

/** A file name that could have been shipped: no path, no traversal, no surprises. */
const ASSET_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/** Read a directory's names once, at cold start; a missing directory serves nothing. */
function listNames(directory: string): ReadonlySet<string> {
  try {
    return new Set(readdirSync(directory));
  } catch {
    return new Set();
  }
}

const SHIPPED: Record<string, ReadonlySet<string>> = {
  [PUBLIC_DIR]: listNames(PUBLIC_DIR),
  [VIEWS_DIR]: listNames(VIEWS_DIR),
};

/** Contents already read, so a warm Lambda reads each file from disk once. */
const cache = new Map<string, string>();

/** The extension of a file name, lower-cased, including the dot. */
function extensionOf(name: string): string {
  const dot = name.lastIndexOf('.');
  return dot === -1 ? '' : name.slice(dot).toLowerCase();
}

/** The contents of a shipped file, or `null` when nothing of that name shipped. */
function readAsset(directory: string, name: string): string | null {
  if (!ASSET_NAME.test(name) || !(SHIPPED[directory] ?? new Set<string>()).has(name)) {
    return null;
  }
  const key = `${directory}${name}`;
  const cached = cache.get(key);
  if (cached !== undefined) {
    return cached;
  }
  let text: string;
  try {
    text = readFileSync(join(directory, name), 'utf8');
  } catch {
    return null;
  }
  cache.set(key, text);
  return text;
}

/** The 404 every unknown asset gets: the same JSON body an unmatched path gets. */
function notFound(): RouteResult {
  return { statusCode: 404, body: { error: 'not_found' } };
}

/** Serve one file from one directory, with its own media type and the security headers. */
export function serveAsset(directory: string, name: string): RouteResult {
  const contentType = CONTENT_TYPES[extensionOf(name)];
  if (contentType === undefined) {
    return notFound();
  }
  const text = readAsset(directory, name);
  if (text === null) {
    return notFound();
  }
  return {
    statusCode: 200,
    headers: { 'content-type': contentType, ...SECURITY_HEADERS },
    rawBody: text,
  };
}

/** `GET /` -- the page the console boots from. */
export function handleIndex(): RouteResult {
  return serveAsset(PUBLIC_DIR, INDEX_FILE);
}

/**
 * `GET /admin/config.json` -- the public values the browser needs to sign in.
 *
 * `redirectUri` follows the hostname the request arrived on, so the console
 * works behind any domain that reaches this Lambda.
 */
export function handleConfig(request: RouteRequest): RouteResult {
  const host = request.headers?.host ?? '';
  const config = adminClientConfig(process.env, host);
  if (config === null) {
    return { statusCode: 500, body: { error: 'not_configured' } };
  }
  return { statusCode: 200, body: config };
}

/** Register the console's routes on a router. Returns the router, so calls chain. */
export function registerUiRoutes(router: Router): Router {
  router.add('GET', INDEX_PATH, () => handleIndex());
  router.add('GET', ASSET_PATH, (request) => serveAsset(PUBLIC_DIR, request.params.file ?? ''));
  router.add('GET', PUBLIC_ASSET_PATH, (request) => serveAsset(PUBLIC_DIR, request.params.file ?? ''));
  router.add('GET', VIEW_ASSET_PATH, (request) => serveAsset(VIEWS_DIR, request.params.file ?? ''));
  return router.add('GET', CONFIG_PATH, (request) => handleConfig(request));
}
