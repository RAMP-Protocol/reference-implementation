// Drop-in stand-in for the removed `fetchMock` export of cloudflare:test
// (@cloudflare/vitest-pool-workers dropped it in the vitest-4 line; the
// documented replacement is stubbing globalThis.fetch). This helper keeps the
// undici-MockAgent call shape the suites already use — get(origin) →
// intercept({path, method, query?, body?}) → reply(...) [.persist()] — so a
// suite's mocking reads unchanged, and implements it over a fetch stub.
//
// Matching mirrors undici's rules for the subset the suites rely on:
//   * `path` (string) matches pathname+search exactly; a RegExp tests the same
//     string. When `query` is given, `path` matches the pathname alone and
//     each listed query param must equal the request's value (subset match).
//   * a non-persisted intercept is consumed by its first match (one-shot) —
//     the article-path suite's "no origin intercept registered → the deny
//     path cannot have fetched the origin" proof depends on this.
//   * with net-connect disabled, an unmatched fetch THROWS — inside the
//     worker that surfaces as the 502 origin-failure path, never as silently
//     served content.

interface InterceptOptions {
  path: string | RegExp;
  method: string;
  query?: Record<string, string>;
  body?: string;
}

interface ReplyCallbackResult {
  statusCode: number;
  data: string;
  responseOptions?: { headers?: Record<string, string> };
}

type ReplyCallback = (opts: { body: string }) => ReplyCallbackResult;

interface Route {
  origin: string;
  options: InterceptOptions;
  respond: (requestBody: string) => Response;
  persist: boolean;
  consumed: boolean;
}

const routes: Route[] = [];
let installed = false;
let netConnectDisabled = false;
let realFetch: typeof fetch | undefined;

function buildResponse(status: number, body: unknown, headers?: Record<string, string>): Response {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  return new Response(payload, { status, ...(headers !== undefined ? { headers } : {}) });
}

class Interceptor {
  private readonly route: Route;

  constructor(route: Route) {
    this.route = route;
  }

  reply(replyFn: ReplyCallback): Interceptor;
  reply(status: number, body: unknown, opts?: { headers?: Record<string, string> }): Interceptor;
  reply(
    statusOrFn: number | ReplyCallback,
    body?: unknown,
    opts?: { headers?: Record<string, string> },
  ): Interceptor {
    if (typeof statusOrFn === 'function') {
      this.route.respond = (requestBody) => {
        const result = statusOrFn({ body: requestBody });
        return buildResponse(result.statusCode, result.data, result.responseOptions?.headers);
      };
    } else {
      this.route.respond = () => buildResponse(statusOrFn, body, opts?.headers);
    }
    routes.push(this.route);
    return this;
  }

  persist(): Interceptor {
    this.route.persist = true;
    return this;
  }
}

class OriginScope {
  private readonly origin: string;

  constructor(origin: string) {
    this.origin = origin;
  }

  intercept(options: InterceptOptions): Interceptor {
    return new Interceptor({
      origin: this.origin,
      options,
      respond: () => buildResponse(200, ''),
      persist: false,
      consumed: false,
    });
  }
}

function matches(route: Route, url: URL, method: string): boolean {
  if (route.consumed && !route.persist) return false;
  if (route.origin !== url.origin) return false;
  if (route.options.method.toUpperCase() !== method.toUpperCase()) return false;
  const { path, query } = route.options;
  const target = query === undefined ? url.pathname + url.search : url.pathname;
  const pathOk = typeof path === 'string' ? path === target : path.test(target);
  if (!pathOk) return false;
  if (query !== undefined) {
    for (const [key, value] of Object.entries(query)) {
      if (url.searchParams.get(key) !== value) return false;
    }
  }
  return true;
}

async function dispatch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const request = input instanceof Request ? input : new Request(input, init);
  const url = new URL(request.url);
  for (const route of routes) {
    if (!matches(route, url, request.method)) continue;
    const wantsBody = route.options.body !== undefined || isCallbackRoute(route);
    const requestBody = wantsBody ? await request.clone().text() : '';
    if (route.options.body !== undefined && route.options.body !== requestBody) continue;
    route.consumed = true;
    return route.respond(requestBody);
  }
  if (netConnectDisabled || !realFetch) {
    throw new Error(
      `fetch to ${request.method} ${request.url} is not mocked (net connect disabled)`,
    );
  }
  return realFetch(request);
}

// A route needs the request body either to match on it or to hand it to a
// reply callback; respond's arity distinguishes the callback form.
function isCallbackRoute(route: Route): boolean {
  return route.respond.length > 0;
}

export const fetchMock = {
  // Installs the stub over globalThis.fetch (idempotent). The worker under
  // test runs in the same isolate as the suite, so its outbound `fetch`
  // resolves to this stub — the same property the removed undici-based
  // fetchMock relied on.
  activate(): void {
    if (installed) return;
    realFetch = globalThis.fetch;
    globalThis.fetch = dispatch as typeof fetch;
    installed = true;
  },
  disableNetConnect(): void {
    netConnectDisabled = true;
  },
  // Drops every registered route (the analogue of undici's per-test intercept
  // teardown); activation and the net-connect setting stay. Suites call this
  // first thing in beforeEach: without it routes accumulate across tests, and
  // a one-shot intercept that never fired — exactly the deny-path scenario —
  // would linger and satisfy a later test's fetch out of order.
  reset(): void {
    routes.length = 0;
  },
  get(origin: string): OriginScope {
    return new OriginScope(origin);
  },
};
