/**
 * Agent sign-in brokered by the MDM site (spec Amendment A).
 *
 * The unenrolled agent cannot rely on a localhost listener, so the browser
 * only ever talks to this site and to Microsoft:
 *
 *   POST /api/v1/agent-auth/sessions                  {"codeChallenge":"<43 base64url>","codeChallengeMethod":"S256"}
 *   -> 201 {"sessionId":"<64 hex>","signInUrl":"https://<host>/agent/signin/<id>","expiresAt":"<ISO>"}
 *
 *   GET  /agent/signin/{sessionId}                    -> 302 to Entra authorize (PKCE S256, state=<sessionId>)
 *   GET  /agent/callback?code=&state=                 -> stores the code, 200 "Signed in" page
 *   GET  /api/v1/agent-auth/sessions/{sessionId}      -> {"status":"pending"}
 *                                                        {"status":"complete","code":"…","redirectUri":"…"}  (session deleted)
 *                                                        {"status":"failed","error":"access_denied"|"sign_in_failed"} (deleted)
 *
 * Every route is public. The authorization code held here is useless without
 * the PKCE verifier, which never leaves the device; the agent redeems the code
 * at Entra itself as a public client. No client secret exists anywhere.
 *
 * Rules the handlers keep:
 *
 * - `<host>` is `publicHost(env, Host header)`, as the admin config uses. The
 *   callback URL is fixed on the session when it is created, so the authorize
 *   redirect and the `redirectUri` the agent redeems with can never differ.
 * - A session id is validated against `^[0-9a-f]{64}$` before any key is built.
 * - A session whose `expiresAt` is at or before now is treated as unknown,
 *   whether or not DynamoDB's TTL sweep has removed it yet.
 * - The first callback wins: the code (or failure) is written only while the
 *   session is still `pending`, with a conditional write, so a later callback
 *   answers 400 and overwrites nothing.
 * - Reading a `complete` or `failed` session deletes it, again conditionally,
 *   so the code is handed out at most once.
 * - Entra not configured -> 500 `not_configured` on every route.
 * - The code is never logged, audited or written into a page.
 */
import { randomBytes as cryptoRandomBytes } from 'node:crypto';
import { agentSignInSession, AGENT_SIGNIN_SESSION_ID_PATTERN, type TableKey } from '../db/keys.js';
import { CONDITIONAL_CHECK_FAILED, type Item, type RequestFields } from '../db/table.js';
import type { RouteHandler, RouteRequest, RouteResult, Router } from '../http/router.js';
import { publicHost } from '../ui/config.js';
import { SECURITY_HEADERS } from '../ui/index.js';
import { agentAuthConfig, type AgentAuthConfig, type AgentAuthEnv } from './userSession.js';

/** Where the agent creates a sign-in session. */
export const AGENT_SIGNIN_SESSIONS_PATH = '/api/v1/agent-auth/sessions';

/** Where the agent polls its sign-in session. */
export const AGENT_SIGNIN_SESSION_PATH = '/api/v1/agent-auth/sessions/{sessionId}';

/** The browser entry point the agent opens. */
export const AGENT_SIGNIN_PAGE_PATH = '/agent/signin/{sessionId}';

/** The redirect URI registered with Entra. */
export const AGENT_CALLBACK_PATH = '/agent/callback';

/** How long a sign-in session lives, in seconds: 24 hours. */
export const AGENT_SIGNIN_LIFETIME_SECONDS = 24 * 60 * 60;

/** Random bytes in a session id (64 hex characters). */
export const AGENT_SIGNIN_SESSION_ID_BYTES = 32;

/** An S256 PKCE challenge: base64url of a SHA-256 digest, unpadded. */
const CODE_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** The only challenge method accepted. */
const CODE_CHALLENGE_METHOD = 'S256';

/** The Entra authorize endpoint, per tenant. */
const AUTHORIZE_BASE = 'https://login.microsoftonline.com';

/** Session states. */
type SessionStatus = 'pending' | 'complete' | 'failed';

/** Failure reasons the agent may be told. */
type SignInError = 'access_denied' | 'sign_in_failed';

/** The storage operations these routes need: the subset a fake must implement. */
export interface AgentSignInTable {
  get(key: TableKey, fields?: RequestFields): Promise<Item | undefined>;
  put(item: Item, fields?: RequestFields): Promise<void>;
  delete(key: TableKey, fields?: RequestFields): Promise<void>;
}

/** Current time: a `Date`, an ISO string, or integer epoch seconds. */
export type AgentSignInClock = () => Date | string | number;

export interface AgentSignInDependencies {
  /** Table client. Required; never created here. */
  table: AgentSignInTable;
  /** Current time. Defaults to the system clock. */
  now?: AgentSignInClock;
  /** Random source for the session id. Defaults to `crypto.randomBytes`. */
  randomBytes?: (size: number) => Buffer;
  /** Environment holding the Entra ids and `PUBLIC_HOST`. Defaults to `process.env`. */
  env?: AgentAuthEnv;
}

/** Dependencies, or something that resolves them when the request arrives. */
export type AgentSignInDependencySource =
  | AgentSignInDependencies
  | (() => AgentSignInDependencies | Promise<AgentSignInDependencies>);

/** One handler per route. */
export interface AgentSignInHandlers {
  create: RouteHandler;
  signIn: RouteHandler;
  callback: RouteHandler;
  poll: RouteHandler;
}

/** The stored session as these routes read it. */
interface SessionRecord extends Item {
  status?: unknown;
  codeChallenge?: unknown;
  redirectUri?: unknown;
  expiresAt?: unknown;
  code?: unknown;
  error?: unknown;
  errorDetail?: unknown;
}

/** The longest Microsoft error detail kept on a session. */
const ERROR_DETAIL_MAX = 500;

/**
 * `<error>: <error_description>` from an Entra error redirect, on one line and
 * bounded. Entra's descriptions carry an AADSTS code and trace ids, never the
 * authorization code, so they are safe to keep, log and hand to the agent.
 */
function errorDetail(error: string, description: unknown): string {
  const text = typeof description === 'string' && description.length > 0 ? `${error}: ${description}` : error;
  return text.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/ {2,}/g, ' ').trim().slice(0, ERROR_DETAIL_MAX);
}

/** The failure page, naming Microsoft's error so the user can report it. */
function failedPage(error: string, description: unknown): PageText {
  const aadsts = typeof description === 'string' ? /AADSTS[0-9]+/.exec(description)?.[0] : undefined;
  const reference = `${error.slice(0, 64)}${aadsts === undefined ? '' : ` (${aadsts})`}`;
  return { title: FAILED.title, message: `${FAILED.message} Microsoft reported: ${reference}.` };
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

const NO_STORE = { 'cache-control': 'no-store' };

function json(statusCode: number, body: unknown): RouteResult {
  return { statusCode, headers: { ...NO_STORE }, body };
}

function failure(statusCode: number, error: string): RouteResult {
  return json(statusCode, { error });
}

const NOT_CONFIGURED = (): RouteResult => failure(500, 'not_configured');
const NOT_FOUND = (): RouteResult => failure(404, 'not_found');

/** Escape text for HTML element content and attribute values. */
export function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** A page's fixed wording. Pages are static: no request value is ever put in one. */
interface PageText {
  title: string;
  message: string;
}

const SIGNED_IN: PageText = {
  title: 'Signed in',
  message: 'You can close this tab. This device will finish setting itself up on its own.',
};

const DECLINED: PageText = {
  title: 'Sign-in was declined',
  message: 'You can close this tab. To try again, open "Sign in to OfficeHQ MDM" on the device.',
};

const FAILED: PageText = {
  title: 'Sign-in failed',
  message: 'You can close this tab. To try again, open "Sign in to OfficeHQ MDM" on the device.',
};

const LINK_EXPIRED: PageText = {
  title: 'Sign-in link not found',
  message:
    'This sign-in link is unknown or has expired. Open "Sign in to OfficeHQ MDM" on the device to get a new one.',
};

const BAD_CALLBACK: PageText = {
  title: 'Sign-in could not be completed',
  message:
    'This sign-in response is not valid, has expired or was already used. Open "Sign in to OfficeHQ MDM" on the device to start again.',
};

/** A small branded HTML page with the console's stylesheet, the logo and no script. */
function page(statusCode: number, text: PageText): RouteResult {
  const title = escapeHtml(text.title);
  const message = escapeHtml(text.message);
  const html = [
    '<!doctype html>',
    '<html lang="en">',
    '  <head>',
    '    <meta charset="utf-8" />',
    '    <meta name="viewport" content="width=device-width, initial-scale=1" />',
    `    <title>${title} - OfficeHQ MDM</title>`,
    '    <link rel="stylesheet" href="/assets/public/styles.css" />',
    '  </head>',
    '  <body>',
    '    <main class="signin-page">',
    '      <img class="signin-logo" src="/assets/public/logo.svg" alt="OfficeHQ" />',
    `      <h1>${title}</h1>`,
    `      <p>${message}</p>`,
    '    </main>',
    '  </body>',
    '</html>',
    '',
  ].join('\n');
  return {
    statusCode,
    headers: { 'content-type': 'text/html; charset=utf-8', ...SECURITY_HEADERS, ...NO_STORE },
    rawBody: html,
  };
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toDate(instant: Date | string | number): Date {
  if (instant instanceof Date) {
    return new Date(instant.getTime());
  }
  if (typeof instant === 'string') {
    return new Date(instant);
  }
  return new Date(instant * 1000);
}

function isSessionId(value: unknown): value is string {
  return typeof value === 'string' && AGENT_SIGNIN_SESSION_ID_PATTERN.test(value);
}

function isConditionalCheckFailure(error: unknown): boolean {
  return typeof error === 'object' && error !== null && (error as { name?: unknown }).name === CONDITIONAL_CHECK_FAILED;
}

/** The JSON object body, or `null` when the body is absent, unparseable or not an object. */
function readObject(body: string | null | undefined): Record<string, unknown> | null {
  if (typeof body !== 'string' || body.length === 0) {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(body);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function callbackUri(env: AgentAuthEnv, req: RouteRequest): string {
  return `https://${publicHost(env, req.headers?.host ?? '')}${AGENT_CALLBACK_PATH}`;
}

/** Status of a live session, or `null` when the item is absent, malformed or expired. */
function liveStatus(session: SessionRecord | undefined, now: Date): SessionStatus | null {
  if (session === undefined) {
    return null;
  }
  const expiresAt = typeof session.expiresAt === 'string' ? Date.parse(session.expiresAt) : Number.NaN;
  if (!Number.isFinite(expiresAt) || expiresAt <= now.getTime()) {
    return null;
  }
  const status = session.status;
  return status === 'pending' || status === 'complete' || status === 'failed' ? status : null;
}

/** The conditional-write fields requiring the stored session to still have `status`. */
function whileStatus(status: SessionStatus): RequestFields {
  return {
    ConditionExpression: '#status = :status',
    ExpressionAttributeNames: { '#status': 'status' },
    ExpressionAttributeValues: { ':status': status },
  };
}

/** Space-separated, `%20`-encoded query string in the given key order. */
function queryString(params: [string, string][]): string {
  return params.map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`).join('&');
}

function authorizeUrl(config: AgentAuthConfig, redirectUri: string, sessionId: string, challenge: string): string {
  const query = queryString([
    ['client_id', config.clientId],
    ['response_type', 'code'],
    ['redirect_uri', redirectUri],
    ['scope', config.scopes.join(' ')],
    ['state', sessionId],
    ['code_challenge', challenge],
    ['code_challenge_method', CODE_CHALLENGE_METHOD],
    ['prompt', 'select_account'],
  ]);
  return `${AUTHORIZE_BASE}/${encodeURIComponent(config.tenantId)}/oauth2/v2.0/authorize?${query}`;
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/**
 * Build the four route handlers.
 *
 * @param source the dependencies, or a function resolving them per request
 */
export function createAgentSignInHandlers(source: AgentSignInDependencySource): AgentSignInHandlers {
  async function context(): Promise<{
    table: AgentSignInTable;
    now: Date;
    randomBytes: (size: number) => Buffer;
    env: AgentAuthEnv;
  }> {
    const deps = typeof source === 'function' ? await source() : source;
    const clock: AgentSignInClock = deps.now ?? ((): Date => new Date());
    return {
      table: deps.table,
      now: toDate(clock()),
      randomBytes: deps.randomBytes ?? cryptoRandomBytes,
      env: deps.env ?? process.env,
    };
  }

  /** `POST /api/v1/agent-auth/sessions` */
  async function create(req: RouteRequest): Promise<RouteResult> {
    const { table, now, randomBytes, env } = await context();
    if (agentAuthConfig(env) === null) {
      return NOT_CONFIGURED();
    }
    const body = readObject(req.body);
    if (
      body === null ||
      typeof body.codeChallenge !== 'string' ||
      !CODE_CHALLENGE_PATTERN.test(body.codeChallenge) ||
      body.codeChallengeMethod !== CODE_CHALLENGE_METHOD
    ) {
      return failure(400, 'invalid_request');
    }

    const sessionId = randomBytes(AGENT_SIGNIN_SESSION_ID_BYTES).toString('hex');
    const expires = new Date(now.getTime() + AGENT_SIGNIN_LIFETIME_SECONDS * 1000);
    const redirectUri = callbackUri(env, req);
    await table.put({
      ...agentSignInSession(sessionId),
      sessionId,
      status: 'pending',
      codeChallenge: body.codeChallenge,
      codeChallengeMethod: CODE_CHALLENGE_METHOD,
      redirectUri,
      createdAt: now.toISOString(),
      expiresAt: expires.toISOString(),
      ttl: Math.floor(expires.getTime() / 1000),
    });

    const host = publicHost(env, req.headers?.host ?? '');
    return json(201, {
      sessionId,
      signInUrl: `https://${host}/agent/signin/${sessionId}`,
      expiresAt: expires.toISOString(),
    });
  }

  /** `GET /agent/signin/{sessionId}` */
  async function signIn(req: RouteRequest): Promise<RouteResult> {
    const { table, now, env } = await context();
    const config = agentAuthConfig(env);
    if (config === null) {
      return NOT_CONFIGURED();
    }
    const sessionId = req.params?.sessionId;
    if (!isSessionId(sessionId)) {
      return page(404, LINK_EXPIRED);
    }
    const session = (await table.get(agentSignInSession(sessionId))) as SessionRecord | undefined;
    if (liveStatus(session, now) !== 'pending' || typeof session?.codeChallenge !== 'string') {
      return page(404, LINK_EXPIRED);
    }
    const redirectUri = typeof session.redirectUri === 'string' ? session.redirectUri : callbackUri(env, req);
    return {
      statusCode: 302,
      headers: { location: authorizeUrl(config, redirectUri, sessionId, session.codeChallenge), ...NO_STORE },
      rawBody: '',
    };
  }

  /** `GET /agent/callback?code=&state=` (or `?error=&state=`) */
  async function callback(req: RouteRequest): Promise<RouteResult> {
    const { table, now, env } = await context();
    if (agentAuthConfig(env) === null) {
      return NOT_CONFIGURED();
    }
    const query = req.query ?? {};
    const state = query.state;
    if (!isSessionId(state)) {
      return page(400, BAD_CALLBACK);
    }
    const session = (await table.get(agentSignInSession(state))) as SessionRecord | undefined;
    if (session === undefined || liveStatus(session, now) !== 'pending') {
      return page(400, BAD_CALLBACK);
    }

    let update: Item;
    let shown: PageText;
    const error = query.error;
    if (typeof error === 'string' && error.length > 0) {
      const reason: SignInError = error === 'access_denied' ? 'access_denied' : 'sign_in_failed';
      const detail = errorDetail(error, query.error_description);
      update = { status: 'failed', error: reason, errorDetail: detail };
      shown = reason === 'access_denied' ? DECLINED : failedPage(error, query.error_description);
      // The only diagnosis there is for a failed sign-in: Entra's own error.
      console.warn(JSON.stringify({ msg: 'agent sign-in failed', detail }));
    } else {
      const code = query.code;
      if (typeof code !== 'string' || code.length === 0) {
        return page(400, BAD_CALLBACK);
      }
      update = { status: 'complete', code };
      shown = SIGNED_IN;
    }

    // First callback wins: written only while the session is still pending.
    try {
      await table.put({ ...session, ...update, completedAt: now.toISOString() }, whileStatus('pending'));
    } catch (rejection) {
      if (isConditionalCheckFailure(rejection)) {
        return page(400, BAD_CALLBACK);
      }
      throw rejection;
    }
    return page(200, shown);
  }

  /** `GET /api/v1/agent-auth/sessions/{sessionId}` */
  async function poll(req: RouteRequest): Promise<RouteResult> {
    const { table, now, env } = await context();
    if (agentAuthConfig(env) === null) {
      return NOT_CONFIGURED();
    }
    const sessionId = req.params?.sessionId;
    if (!isSessionId(sessionId)) {
      return NOT_FOUND();
    }
    const key = agentSignInSession(sessionId);
    const session = (await table.get(key)) as SessionRecord | undefined;
    const status = liveStatus(session, now);
    if (session === undefined || status === null) {
      return NOT_FOUND();
    }
    if (status === 'pending') {
      return json(200, { status: 'pending' });
    }

    let body: Record<string, unknown>;
    if (status === 'complete') {
      if (typeof session.code !== 'string') {
        return NOT_FOUND();
      }
      const redirectUri = typeof session.redirectUri === 'string' ? session.redirectUri : callbackUri(env, req);
      body = { status: 'complete', code: session.code, redirectUri };
    } else {
      body = { status: 'failed', error: session.error === 'access_denied' ? 'access_denied' : 'sign_in_failed' };
      if (typeof session.errorDetail === 'string' && session.errorDetail.length > 0) {
        body.detail = session.errorDetail;
      }
    }

    // Handed out once: only the read that deletes the session answers with it.
    try {
      await table.delete(key, whileStatus(status));
    } catch (rejection) {
      if (isConditionalCheckFailure(rejection)) {
        return NOT_FOUND();
      }
      throw rejection;
    }
    return json(200, body);
  }

  return { create, signIn, callback, poll };
}

/** Register the four routes on a router. Returns the router, so calls chain. */
export function registerAgentSignInRoutes(router: Router, source: AgentSignInDependencySource): Router {
  const handlers = createAgentSignInHandlers(source);
  return router
    .add('POST', AGENT_SIGNIN_SESSIONS_PATH, handlers.create)
    .add('GET', AGENT_SIGNIN_SESSION_PATH, handlers.poll)
    .add('GET', AGENT_SIGNIN_PAGE_PATH, handlers.signIn)
    .add('GET', AGENT_CALLBACK_PATH, handlers.callback);
}

/** Dependencies supplied at start-up by `bootstrap`. */
let configuredDependencies: AgentSignInDependencies | null = null;

/** Supply the sign-in routes' storage (and, in tests, clock, random source and environment). */
export function configureAgentSignInRoutes(dependencies: AgentSignInDependencies): void {
  configuredDependencies = dependencies;
}

/** The configured dependencies, or a thrown error when start-up skipped them. */
export function resolveAgentSignInDependencies(): AgentSignInDependencies {
  if (configuredDependencies === null) {
    throw new Error('agent sign-in routes are not configured: call configureAgentSignInRoutes() at start-up');
  }
  return configuredDependencies;
}
