import net from "node:net";
import os from "node:os";
import fs from "node:fs";
import type { Duplex } from "node:stream";
import type { HandedOffConnection } from "../contract/handed-off-connection.ts";
import type { ExecHandler, ExecOutcome } from "../contract/exec-handler.ts";

/**
 * A convenience HTTP reverse-proxy handler for TS/Bun integrators.
 *
 * NOTE: This is not the flagship default. The flagship reverse-proxy handler is native Rust — it is
 * smaller, more auditable, and is what the low-memory profile (host-side membrane + handler in ~2–5 MB,
 * no JS runtime) requires. This TS handler exists so a TS/Bun integrator can stand the shell up in their
 * own runtime without shelling out to the Rust binary; it is a secondary convenience, kept deliberately
 * simple. Both bind the SAME language-agnostic wire contract (docs/wire-contract.md) — the fd handoff —
 * so they are drop-in interchangeable.
 *
 * What it does: point it at one upstream (an MCP server, an internal API, anything HTTP), give it a
 * credential to present, and every request a confined guest makes over the seam is forwarded there — with
 * the credential injected host-side, so the guest never holds it.
 *
 * HOW IT PARSES HTTP — it does NOT. It stands up the runtime's OWN production HTTP server on a private
 * unix socket, and each handed-off guest connection is pumped, byte-for-byte, into it. The runtime parses
 * (llhttp), enforces the body cap, and yields a `Request`; we forward that upstream with `fetch`. The pump
 * is deliberately HTTP-unaware — it relays bytes and knows nothing about the protocol. That keeps the one
 * thing a security shell must not get wrong (HTTP request parsing / smuggling) on the runtime's hardened
 * parser instead of a hand-rolled one, with no external dependency and no separate server process.
 *
 * The confined guest controls the METHOD, PATH, HEADERS, and BODY of its request; it does NOT control the
 * upstream HOST. Routing through a fixed reverse proxy (rather than letting the guest dial out) is the
 * point: the host is pinned in config, so the guest cannot reach an arbitrary target. Combined with
 * Firelock's confinement (no NIC, one vsock — see ../contract/topology-invariant), the ONLY way out of the
 * microVM is this proxy, and the only place this proxy reaches is the one upstream you configured.
 *
 * Security posture (fail-closed):
 *   • Fixed upstream origin — the guest's path is appended to `upstreamBaseUrl`; the host/scheme is never
 *     guest-controlled. (SSRF-closed by construction.)
 *   • Injected credential — set host-side; any guest-supplied `Authorization` (or the configured
 *     credential header) is dropped first, so the guest can neither read nor override it.
 *   • Redirects refused — a 3xx from the upstream is NOT followed (following it would re-send the injected
 *     credential to an unvetted host); the guest gets a 502.
 *   • Bounded body — the runtime rejects a request body over `maxBodyBytes` before it reaches us.
 *   • Hop-by-hop headers stripped both ways. Each response carries an ADVISORY `Connection: close`.
 *     ⚠️ NOTE: the runtime HTTP server (Bun) manages connection keep-alive itself and does NOT
 *     close on a response `Connection: close` header (verified Bun 1.3.13), so this convenience handler
 *     relays MULTIPLE sequential requests on one kept-alive connection — normal HTTP for a general reverse
 *     proxy. Every one of those requests is INDEPENDENTLY confined (fixed upstream, injected credential,
 *     method/body caps, redirects refused) — that is the actual security property, and it holds per-request
 *     regardless of connection reuse. The strict "exactly one exchange per handed-off connection" platform
 *     model is enforced by the FLAGSHIP Rust handler, not by this secondary TS convenience handler.
 *
 * Per-request status/refusals surface through `onOutcome` (fired where that detail is known). The
 * `ExecHandler` the loop drives returns a coarse TRANSPORT outcome — it never parses on the pump side.
 * A handler that needs a per-call adjudication result (the proprietary platform handler) reads the frame
 * itself rather than proxying; this default trades that for keeping the pump byte-pure.
 */

/** Hop-by-hop headers (RFC 7230 section 6.1) plus framing headers we let the runtime/fetch own. */
const HOP_BY_HOP = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
]);

export interface HttpReverseProxyConfig {
  /**
   * The one upstream origin every guest request is forwarded to (e.g. `https://mcp.internal.example`).
   * Only the guest's path+query is appended; the origin here is never guest-controlled. A path may be
   * included and is used as a prefix.
   */
  readonly upstreamBaseUrl: string;

  /**
   * The credential presented to the upstream, injected host-side. Defaults to reading
   * `FIRELOCK_UPSTREAM_CREDENTIAL` from the environment as a bearer token (`Authorization: Bearer …`).
   * Provide `{ header, value }` for a different scheme (e.g. `{ header: "x-api-key", value: "…" }`).
   * Omit (and unset the env var) for an unauthenticated upstream.
   */
  readonly credential?: { readonly header: string; readonly value: string };

  /** Methods the proxy will forward. Defaults to the common safe+write set; anything else gets a 405. */
  readonly allowedMethods?: readonly string[];

  /** Max request body the proxy will accept, in bytes. Default 1 MiB (matches the platform egress cap). */
  readonly maxBodyBytes?: number;

  /** Injectable fetch — test seam. Defaults to the global `fetch`. */
  readonly fetchImpl?: typeof fetch;

  /** Per-request telemetry hook, fired where the status/refusal is known (not the loop's return value). */
  readonly onOutcome?: (outcome: ExecOutcome) => void;

  /** Override the internal unix socket path. Default: a per-process path under the OS temp dir. */
  readonly socketPath?: string;
}

/** A running reverse proxy: an {@link ExecHandler} for the loop, plus its lifecycle. */
export interface HttpReverseProxy {
  /** The handler Firelock drives — pumps each guest connection into the runtime HTTP server. */
  readonly handle: ExecHandler;
  /** The private unix socket the internal HTTP server listens on. */
  readonly socketPath: string;
  /** Stop the internal server and remove its socket. Idempotent. */
  close(): Promise<void>;
}

const DEFAULT_ALLOWED_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] as const;
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024; // 1 MiB

let socketCounter = 0;

/** The resolved policy the pure request path runs against — built once from config. */
interface ProxyPolicy {
  readonly upstream: URL;
  readonly allowed: ReadonlySet<string>;
  readonly maxBodyBytes: number;
  readonly credential?: { readonly header: string; readonly value: string };
  readonly credentialHeaderLc?: string;
  readonly doFetch: typeof fetch;
}

/** The result of running the policy against one request: the response to write back, and the outcome. */
export interface ProxyDecision {
  readonly response: Response;
  readonly outcome: ExecOutcome;
}

/**
 * The pure request path — all of the reverse proxy's security decisions, with no sockets and no server.
 * Given a parsed {@link Request} (the runtime already parsed it), decide the response and the outcome.
 * Exported so the policy is unit-testable in isolation; the transport wiring (pump + internal server) is
 * tested separately. This is the shape the Rust flagship mirrors: a pure policy function over a parsed
 * request, with the transport concerns kept out of it.
 */
export async function proxyRequest(req: Request, policy: ProxyPolicy): Promise<ProxyDecision> {
  const method = req.method.toUpperCase();
  if (!policy.allowed.has(method)) {
    return {
      response: new Response("method not allowed\n", { status: 405 }),
      outcome: { egressed: false, failure: { kind: "malformed_request", detail: "method_not_allowed" } },
    };
  }

  // The guest's request-target is the path+query of `req.url` (its host is the guest's Host header, which
  // we ignore). Resolve it against the FIXED upstream origin — the guest cannot move the host.
  // Fail-closed on a guest-crafted request-target (HTTP/1.0, empty/odd Host) can make `req.url` unparseable —
  // `new URL` THROWS. Handle it as a fail-closed 400 here so the throw never escapes to the runtime's default
  // 500 (an unhandled throw would bypass `onOutcome` and, in a dev-mode runtime, echo host-side source to the guest).
  let guestUrl: URL;
  try {
    guestUrl = new URL(req.url);
  } catch {
    return {
      response: new Response("bad request\n", { status: 400 }),
      outcome: { egressed: false, failure: { kind: "malformed_request", detail: "unparseable_request_target" } },
    };
  }
  const basePath = policy.upstream.pathname.replace(/\/$/, "");
  const target = new URL(basePath + guestUrl.pathname + guestUrl.search, policy.upstream.origin);
  if (target.origin !== policy.upstream.origin) {
    return {
      response: new Response("bad request\n", { status: 400 }),
      outcome: { egressed: false, failure: { kind: "malformed_request", detail: "target_escaped_origin" } },
    };
  }

  const hasBody = method !== "GET" && method !== "HEAD";
  const body = hasBody ? new Uint8Array(await req.arrayBuffer()) : undefined;
  if (body && body.length > policy.maxBodyBytes) {
    return {
      response: new Response("payload too large\n", { status: 413 }),
      outcome: { egressed: false, failure: { kind: "bounds_exceeded", detail: `${body.length} > ${policy.maxBodyBytes}` } },
    };
  }

  const outHeaders = new Headers();
  req.headers.forEach((value, name) => {
    const lc = name.toLowerCase();
    if (HOP_BY_HOP.has(lc)) return;
    if (lc === "authorization") return; // never forward guest-supplied auth
    if (policy.credentialHeaderLc && lc === policy.credentialHeaderLc) return; // guest cannot pre-set our cred header
    outHeaders.append(name, value);
  });
  if (policy.credential) outHeaders.set(policy.credential.header, policy.credential.value);

  let res: Response;
  try {
    res = await policy.doFetch(target, {
      method,
      headers: outHeaders,
      ...(body && body.length > 0 ? { body: body as RequestInit["body"] } : {}),
      redirect: "manual", // never auto-follow — a redirect must not re-send the injected credential
    });
  } catch (e) {
    return {
      response: new Response("bad gateway\n", { status: 502 }),
      outcome: { egressed: false, failure: { kind: "upstream_error", detail: errMsg(e) } },
    };
  }

  if (res.status >= 300 && res.status < 400) {
    return {
      response: new Response("upstream redirect refused\n", { status: 502 }),
      outcome: { egressed: false, failure: { kind: "redirect_blocked", detail: `status ${res.status}` } },
    };
  }

  const respHeaders = new Headers();
  res.headers.forEach((value, name) => {
    if (!HOP_BY_HOP.has(name.toLowerCase())) respHeaders.set(name, value);
  });
  return {
    response: new Response(res.body, { status: res.status, statusText: res.statusText, headers: respHeaders }),
    outcome: { egressed: true, status: res.status, upstream: policy.upstream.origin },
  };
}

/**
 * Build a running {@link HttpReverseProxy}. Starts the internal HTTP server immediately (so the socket is
 * ready before the first handoff). Call {@link HttpReverseProxy.close} to tear it down.
 */
export function createHttpReverseProxy(config: HttpReverseProxyConfig): HttpReverseProxy {
  const upstream = new URL(config.upstreamBaseUrl); // throws on a bad config value — a startup error
  const allowed = new Set((config.allowedMethods ?? DEFAULT_ALLOWED_METHODS).map((m) => m.toUpperCase()));
  const maxBodyBytes = config.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const doFetch = config.fetchImpl ?? fetch;
  const onOutcome = config.onOutcome;

  const credential =
    config.credential ??
    (process.env.FIRELOCK_UPSTREAM_CREDENTIAL
      ? { header: "authorization", value: `Bearer ${process.env.FIRELOCK_UPSTREAM_CREDENTIAL}` }
      : undefined);
  const credentialHeaderLc = credential?.header.toLowerCase();

  const socketPath = config.socketPath ?? `${os.tmpdir()}/firelock-rp-${process.pid}-${socketCounter++}.sock`;
  try {
    fs.unlinkSync(socketPath); // clear a stale socket file from a crashed prior run
  } catch {
    /* not present — fine */
  }

  const report = (o: ExecOutcome): void => {
    if (onOutcome) {
      try {
        onOutcome(o);
      } catch {
        /* a telemetry hook must never break the exchange */
      }
    }
  };

  const policy: ProxyPolicy = {
    upstream,
    allowed,
    maxBodyBytes,
    doFetch,
    ...(credential ? { credential, credentialHeaderLc: credential.header.toLowerCase() } : {}),
  };

  // The internal HTTP server: the runtime parses; `proxyRequest` makes the routing/credential/redirect
  // decision; we only wire the two together and report the outcome.
  const server = Bun.serve({
    unix: socketPath,
    maxRequestBodySize: maxBodyBytes,
    // Never serve the runtime's verbose dev error page (host source path + stack) to a confined
    // guest on an unhandled throw. Force production error behavior regardless of the ambient NODE_ENV.
    development: false,
    async fetch(req): Promise<Response> {
      try {
        const { response, outcome } = await proxyRequest(req, policy);
        report(outcome);
        return closing(response);
      } catch (e) {
        // BELT: `proxyRequest` is fail-closed, but any unforeseen throw must NOT reach the runtime's
        // default 500 (opaque to the guest, and dev-mode would leak host source). Report host-side telemetry
        // and return a minimal, detail-free refusal — the error text stays in `onOutcome`, never on the wire.
        report({ egressed: false, failure: { kind: "malformed_request", detail: errMsg(e) } });
        return closing(new Response("bad request\n", { status: 400 }));
      }
    },
  });

  const handle: ExecHandler = async (conn: HandedOffConnection): Promise<ExecOutcome> => {
    let client: net.Socket;
    try {
      client = net.connect(socketPath);
      await new Promise<void>((resolve, reject) => {
        client.once("connect", () => resolve());
        client.once("error", reject);
      });
    } catch (e) {
      await conn.close();
      return { egressed: false, failure: { kind: "handler_error", detail: errMsg(e) } };
    }

    try {
      await pump(conn.socket, client);
      return { egressed: true };
    } catch (e) {
      return { egressed: false, failure: { kind: "handler_error", detail: errMsg(e) } };
    } finally {
      client.destroy();
      await conn.close();
    }
  };

  return {
    handle,
    socketPath,
    async close(): Promise<void> {
      server.stop(true);
      try {
        fs.unlinkSync(socketPath);
      } catch {
        /* already gone */
      }
    },
  };
}

/**
 * Set an ADVISORY `Connection: close` on the response. Bun's HTTP server manages keep-alive itself and does
 * not honor this header (verified Bun 1.3.13), so it does NOT force one-exchange-per-connection —
 * it is kept for HTTP correctness and for any compliant intermediary that does honor it. Per-request
 * confinement (the real security property) is independent of connection reuse.
 */
function closing(res: Response): Response {
  res.headers.set("connection", "close");
  return res;
}

/**
 * Relay bytes both ways between two streams until either closes. HTTP-UNAWARE by design — it moves bytes
 * and interprets none of them. Resolves when the exchange is done (either side ended or errored).
 */
function pump(a: Duplex, b: Duplex): Promise<void> {
  return new Promise<void>((resolve) => {
    let settled = false;
    const done = (): void => {
      if (!settled) {
        settled = true;
        resolve();
      }
    };
    a.on("error", done);
    b.on("error", done);
    a.on("close", done);
    b.on("close", done);
    a.pipe(b);
    b.pipe(a);
  });
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
