/**
 * Minimal HTTP router shared by every API route in the backend.
 *
 * Patterns are plain paths split on "/". A segment written `{name}` is a
 * placeholder: it matches any single non-empty segment and is handed to the
 * route handler as `params.name`.
 *
 *   router.add('GET', '/api/v1/devices/{deviceId}/policies', handler)
 *   -> handler receives params.deviceId === 'dev-7' for '/api/v1/devices/dev-7/policies'
 */

/** Request handed to the router by the Lambda Function URL adapter. */
export interface RouterRequest {
  method: string;
  path: string;
  query: Record<string, string>;
  headers: Record<string, string>;
  body: string | null;
}

/** Request handed to a route handler: a RouterRequest plus the path params. */
export interface RouteRequest extends RouterRequest {
  params: Record<string, string>;
}

/** What a route handler returns. `body` is serialised to JSON by the router. */
export interface RouteResult {
  statusCode: number;
  headers?: Record<string, string>;
  body?: unknown;
}

/** What `handle()` returns: an HTTP response with a JSON string body. */
export interface RouterResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
}

export type RouteHandler = (request: RouteRequest) => RouteResult | Promise<RouteResult>;

export interface Router {
  add(method: string, pattern: string, handler: RouteHandler): Router;
  handle(request: RouterRequest): Promise<RouterResponse>;
}

interface Route {
  method: string;
  segments: string[];
  handler: RouteHandler;
}

const JSON_HEADERS: Record<string, string> = { 'content-type': 'application/json' };

function splitPath(path: string): string[] {
  return path.split('/').filter((segment) => segment.length > 0);
}

function isPlaceholder(segment: string): boolean {
  return segment.length > 2 && segment.startsWith('{') && segment.endsWith('}');
}

/** Match a request path against a route's segments, returning its params. */
function matchSegments(routeSegments: string[], pathSegments: string[]): Record<string, string> | null {
  if (routeSegments.length !== pathSegments.length) {
    return null;
  }
  const params: Record<string, string> = {};
  for (let i = 0; i < routeSegments.length; i += 1) {
    const routeSegment = routeSegments[i] as string;
    const pathSegment = pathSegments[i] as string;
    if (isPlaceholder(routeSegment)) {
      params[routeSegment.slice(1, -1)] = decodeURIComponent(pathSegment);
      continue;
    }
    if (routeSegment !== pathSegment) {
      return null;
    }
  }
  return params;
}

function jsonResponse(statusCode: number, body: unknown, headers?: Record<string, string>): RouterResponse {
  return {
    statusCode,
    headers: { ...JSON_HEADERS, ...(headers ?? {}) },
    body: JSON.stringify(body === undefined ? {} : body),
  };
}

/** Collapse an unknown throwable into a single-line log message (never returned to the caller). */
function describeError(error: unknown): string {
  const text = error instanceof Error ? `${error.name}: ${error.message}` : String(error);
  return text.replace(/[\r\n]+/g, ' ');
}

export function createRouter(): Router {
  const routes: Route[] = [];

  const router: Router = {
    add(method: string, pattern: string, handler: RouteHandler): Router {
      routes.push({
        method: method.toUpperCase(),
        segments: splitPath(pattern),
        handler,
      });
      return router;
    },

    async handle(request: RouterRequest): Promise<RouterResponse> {
      const method = request.method.toUpperCase();
      const pathSegments = splitPath(request.path);

      let pathMatched = false;

      for (const route of routes) {
        const params = matchSegments(route.segments, pathSegments);
        if (params === null) {
          continue;
        }
        pathMatched = true;
        if (route.method !== method) {
          continue;
        }
        try {
          const result = await route.handler({ ...request, method, params });
          return jsonResponse(result.statusCode, result.body, result.headers);
        } catch (error) {
          // Log once, with no stack text in the response body.
          console.error(`[router] ${method} ${request.path} failed: ${describeError(error)}`);
          return jsonResponse(500, { error: 'internal_error' });
        }
      }

      if (pathMatched) {
        return jsonResponse(405, { error: 'method_not_allowed' });
      }
      return jsonResponse(404, { error: 'not_found' });
    },
  };

  return router;
}
