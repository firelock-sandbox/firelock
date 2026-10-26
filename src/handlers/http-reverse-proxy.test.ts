import { test, expect, afterEach } from "bun:test";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { createHttpReverseProxy, proxyRequest, type HttpReverseProxy } from "./http-reverse-proxy.ts";
import { assertFirelockTopology, FirelockTopologyViolation } from "../contract/topology-invariant.ts";
import type { HandedOffConnection } from "../contract/handed-off-connection.ts";
import type { ExecOutcome } from "../contract/exec-handler.ts";

// ── Policy unit tests: proxyRequest is a pure function over a parsed Request — no sockets, deterministic.

const UPSTREAM = new URL("https://mcp.internal.example");
const ALLOW_ALL = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]);

function policy(over: Partial<Parameters<typeof proxyRequest>[1]> = {}) {
  const base = {
    upstream: UPSTREAM,
    allowed: ALLOW_ALL,
    maxBodyBytes: 1024 * 1024,
    doFetch: (async () => new Response("ok", { status: 200 })) as unknown as typeof fetch,
  };
  return { ...base, ...over } as Parameters<typeof proxyRequest>[1];
}

test("forwards to the fixed upstream and injects the credential host-side", async () => {
  let seen: { url: string; auth: string | null } | null = null;
  const { outcome } = await proxyRequest(
    new Request("http://guest/v1/tools?x=1", { method: "POST", body: '{"q":"hi"}' }),
    policy({
      credential: { header: "authorization", value: "Bearer SECRET" },
      credentialHeaderLc: "authorization",
      doFetch: (async (url: URL, init: RequestInit) => {
        seen = { url: url.toString(), auth: new Headers(init.headers).get("authorization") };
        return new Response('{"ok":true}', { status: 200 });
      }) as unknown as typeof fetch,
    }),
  );
  expect(seen!.url).toBe("https://mcp.internal.example/v1/tools?x=1");
  expect(seen!.auth).toBe("Bearer SECRET");
  expect(outcome).toEqual({ egressed: true, status: 200, upstream: "https://mcp.internal.example" });
});

test("drops guest-supplied Authorization so it cannot override or read the injected credential", async () => {
  let sentAuth: string | null = "UNSET";
  await proxyRequest(
    new Request("http://guest/x", { method: "GET", headers: { authorization: "Bearer GUEST-FORGED" } }),
    policy({
      credential: { header: "authorization", value: "Bearer REAL" },
      credentialHeaderLc: "authorization",
      doFetch: (async (_u: URL, init: RequestInit) => {
        sentAuth = new Headers(init.headers).get("authorization");
        return new Response("ok", { status: 200 });
      }) as unknown as typeof fetch,
    }),
  );
  expect(sentAuth).toBe("Bearer REAL");
});

test("refuses an upstream redirect rather than following it (credential-resend guard)", async () => {
  const { response, outcome } = await proxyRequest(
    new Request("http://guest/x", { method: "GET" }),
    policy({
      doFetch: (async () =>
        new Response(null, { status: 302, headers: { location: "https://evil.example" } })) as unknown as typeof fetch,
    }),
  );
  expect(response.status).toBe(502);
  expect(outcome).toEqual({ egressed: false, failure: { kind: "redirect_blocked", detail: "status 302" } });
});

test("a method outside the allow-set is refused 405, upstream never called", async () => {
  let called = false;
  const { response, outcome } = await proxyRequest(
    new Request("http://guest/x", { method: "DELETE" }),
    policy({ allowed: new Set(["GET"]), doFetch: (async () => ((called = true), new Response("x"))) as unknown as typeof fetch }),
  );
  expect(response.status).toBe(405);
  expect(called).toBe(false);
  expect(outcome).toEqual({ egressed: false, failure: { kind: "malformed_request", detail: "method_not_allowed" } });
});

test("the guest cannot move the upstream host via a scheme-relative target — refused 400", async () => {
  let reachedHost: string | null = null;
  const { response, outcome } = await proxyRequest(
    // A Request with a scheme-relative path that, resolved naively, would escape the origin.
    new Request("http://guest//evil.example/x", { method: "GET" }),
    policy({ doFetch: (async (u: URL) => ((reachedHost = u.host), new Response("x"))) as unknown as typeof fetch }),
  );
  expect(reachedHost).toBeNull(); // upstream never reached
  expect(response.status).toBe(400);
  expect(outcome).toEqual({ egressed: false, failure: { kind: "malformed_request", detail: "target_escaped_origin" } });
});

test("a body over the cap is refused 413 before egress", async () => {
  let called = false;
  const big = "x".repeat(2048);
  const { response, outcome } = await proxyRequest(
    new Request("http://guest/x", { method: "POST", body: big }),
    policy({ maxBodyBytes: 1024, doFetch: (async () => ((called = true), new Response("x"))) as unknown as typeof fetch }),
  );
  expect(response.status).toBe(413);
  expect(called).toBe(false);
  expect(outcome.egressed).toBe(false);
});

// ── One integration test: the transport pump wires a real guest socket through the runtime parser.

let live: HttpReverseProxy | null = null;
afterEach(async () => {
  if (live) await live.close();
  live = null;
});

test("integration: a real guest connection is pumped through the runtime HTTP server and gets a response", async () => {
  live = createHttpReverseProxy({
    upstreamBaseUrl: "https://mcp.internal.example",
    credential: { header: "authorization", value: "Bearer SECRET" },
    fetchImpl: (async () => new Response('{"ok":true}', { status: 200, statusText: "OK" })) as unknown as typeof fetch,
  });

  // A loopback pair: `client` is the guest, `guestSide` is the fd Firelock would hand off.
  const listener = net.createServer();
  await new Promise<void>((r) => listener.listen(0, "127.0.0.1", () => r()));
  const port = (listener.address() as AddressInfo).port;
  const guestSideP = new Promise<net.Socket>((r) => listener.once("connection", (s) => r(s)));
  const client = net.connect(port, "127.0.0.1");
  await new Promise<void>((r) => client.once("connect", () => r()));
  const guestSide = await guestSideP;

  const conn: HandedOffConnection = { socket: guestSide, close: async () => {} };
  let resp = "";
  client.on("data", (d) => (resp += d.toString()));

  // Start the handler first (it establishes the pump), THEN the guest sends — the real order. A guest
  // that wrote before the fd was handed off would just buffer; here we mirror the live sequencing.
  const handlePromise = live.handle(conn);
  await new Promise((r) => setTimeout(r, 25)); // let handle() connect + wire the pump
  client.write("POST /v1/tools HTTP/1.1\r\nHost: guest\r\nConnection: close\r\nContent-Length: 10\r\n\r\n{\"q\":\"hi\"}");

  const outcome = await handlePromise;
  await new Promise((r) => setTimeout(r, 100)); // let the response drain to the guest

  expect(outcome.egressed).toBe(true);
  expect(resp).toContain("HTTP/1.1 200 OK");
  expect(resp).toContain('{"ok":true}');
  client.destroy();
  listener.close();
});

// ── The confinement invariant travels with the membrane.

test("topology invariant: 0 NIC + 1 vsock passes; a NIC or wrong vsock count is refused", () => {
  expect(() => assertFirelockTopology({ "network-interfaces": [], vsock: { guest_cid: 3 } })).not.toThrow();
  expect(() => assertFirelockTopology({ "network-interfaces": [{ iface_id: "eth0" }], vsock: {} })).toThrow(
    FirelockTopologyViolation,
  );
  expect(() => assertFirelockTopology({ vsock: {} })).not.toThrow(); // absent NIC → 0
  expect(() => assertFirelockTopology({ "network-interfaces": [] })).toThrow(FirelockTopologyViolation); // 0 vsock
  expect(() => assertFirelockTopology(null)).toThrow(FirelockTopologyViolation); // unreadable → refused
});

// ── A guest-crafted request-target that makes `req.url` unparseable must be a fail-closed 400
//    (surfaced via the outcome, so onOutcome fires) — NOT an unhandled throw that reaches the runtime's
//    default 500 (which bypasses onOutcome and, dev-mode, would echo host source to the confined guest).
test("unparseable request-target → fail-closed 400 malformed_request, never throws", async () => {
  for (const badUrl of ["", "/relative-no-host", "http://"]) {
    const req = {
      method: "GET",
      url: badUrl,
      headers: new Headers(),
      arrayBuffer: async () => new ArrayBuffer(0),
    } as unknown as Request;
    const { response, outcome } = await proxyRequest(req, policy());
    expect(response.status).toBe(400);
    expect(outcome).toEqual({
      egressed: false,
      failure: { kind: "malformed_request", detail: "unparseable_request_target" },
    });
    // and the response body carries no host-side detail
    expect(await response.text()).toBe("bad request\n");
  }
});
