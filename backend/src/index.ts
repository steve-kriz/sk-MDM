/**
 * Lambda Function URL entry point.
 *
 * This module owns the single application router; later tickets register their
 * routes on the exported `router` and need no change here.
 */
import { createRouter, type Router, type RouterRequest, type RouterResponse } from './http/router.js';

/** The subset of the Lambda Function URL (payload format 2.0) event we use. */
export interface FunctionUrlEvent {
  requestContext: {
    http: {
      method: string;
      path: string;
    };
  };
  rawQueryString?: string;
  headers?: Record<string, string | undefined>;
  body?: string | null;
  isBase64Encoded?: boolean;
}

export interface FunctionUrlResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
}

/** The application router. Register routes with `router.add(method, pattern, handler)`. */
export const router: Router = createRouter();

function parseQuery(rawQueryString: string | undefined): Record<string, string> {
  const query: Record<string, string> = {};
  if (!rawQueryString) {
    return query;
  }
  for (const [key, value] of new URLSearchParams(rawQueryString)) {
    query[key] = value;
  }
  return query;
}

function normaliseHeaders(headers: Record<string, string | undefined> | undefined): Record<string, string> {
  const normalised: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers ?? {})) {
    if (value !== undefined) {
      normalised[key.toLowerCase()] = value;
    }
  }
  return normalised;
}

function decodeBody(event: FunctionUrlEvent): string | null {
  const body = event.body;
  if (body === undefined || body === null) {
    return null;
  }
  if (event.isBase64Encoded === true) {
    return Buffer.from(body, 'base64').toString('utf8');
  }
  return body;
}

/** Translate a Function URL event into the router's request shape. */
export function toRouterRequest(event: FunctionUrlEvent): RouterRequest {
  return {
    method: event.requestContext.http.method,
    path: event.requestContext.http.path,
    query: parseQuery(event.rawQueryString),
    headers: normaliseHeaders(event.headers),
    body: decodeBody(event),
  };
}

export async function handler(event: FunctionUrlEvent): Promise<FunctionUrlResponse> {
  let response: RouterResponse;
  try {
    response = await router.handle(toRouterRequest(event));
  } catch (error) {
    // The router handles route errors itself; this only fires on a malformed event.
    const text = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
    console.error(`[handler] request could not be adapted: ${text.replace(/[\r\n]+/g, ' ')}`);
    return {
      statusCode: 500,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ error: 'internal_error' }),
    };
  }

  return {
    statusCode: response.statusCode,
    headers: { ...response.headers, 'content-type': 'application/json' },
    body: response.body,
  };
}

export { createRouter } from './http/router.js';
export type {
  RouteHandler,
  RouteRequest,
  RouteResult,
  Router,
  RouterRequest,
  RouterResponse,
} from './http/router.js';
