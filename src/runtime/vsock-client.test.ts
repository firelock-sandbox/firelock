/**
 * vsock client unit tests (v2.3.4).
 *
 * Exercises:
 *   - HTTP/1.1 framing: encodeHttpRequest / decodeHttpResponse
 *   - MockVsockClient handler registration + per-(udsPath,guestPort)
 *     dispatch + error injection
 *
 * Real-vsock + Firecracker integration (CONNECT preamble, real HTTP
 * over UDS) is gated on the v2.3.5 ssh-test-runner harness.
 */

import { beforeEach, describe, expect, it } from "bun:test";
import {
  MockVsockClient,
  VsockClientError,
  decodeHttpResponse,
  encodeHttpRequest,
  type VsockHttpRequest,
} from "./vsock-client.ts";

let client: MockVsockClient;

beforeEach(() => {
  client = new MockVsockClient();
});

describe("encodeHttpRequest — HTTP/1.1 framing", () => {
  it("encodes a POST with JSON body, content-length, and default content-type", () => {
    const body = new TextEncoder().encode(`{"hello":"world"}`);
    const bytes = encodeHttpRequest({
      udsPath: "/x.sock",
      guestPort: 8080,
      method: "POST",
      path: "/invoke",
      body,
    });
    const text = new TextDecoder().decode(bytes);
    expect(text).toContain("POST /invoke HTTP/1.1\r\n");
    expect(text).toContain("Host: guest\r\n");
    expect(text).toContain("Connection: close\r\n");
    expect(text).toContain("Content-Type: application/json\r\n");
    expect(text).toContain("Content-Length: 17\r\n");
    expect(text).toContain(`\r\n\r\n{"hello":"world"}`);
  });

  it("encodes a GET with no body and Content-Length: 0", () => {
    const bytes = encodeHttpRequest({
      udsPath: "/x.sock",
      guestPort: 8080,
      method: "GET",
      path: "/healthz",
    });
    const text = new TextDecoder().decode(bytes);
    expect(text).toContain("GET /healthz HTTP/1.1\r\n");
    expect(text).toContain("Content-Length: 0\r\n");
    // No body content-type when body is empty.
    expect(text).not.toContain("Content-Type: application/json");
    expect(text.endsWith("\r\n\r\n")).toBe(true);
  });

  it("custom headers are forwarded", () => {
    const bytes = encodeHttpRequest({
      udsPath: "/x.sock",
      guestPort: 8080,
      method: "POST",
      path: "/invoke",
      headers: { "X-K9O-Trace-Id": "trc_abc123", "X-Custom": "1" },
      body: new TextEncoder().encode("ok"),
    });
    const text = new TextDecoder().decode(bytes);
    expect(text).toContain("X-K9O-Trace-Id: trc_abc123\r\n");
    expect(text).toContain("X-Custom: 1\r\n");
  });

  it("custom Content-Type overrides the default JSON header", () => {
    const bytes = encodeHttpRequest({
      udsPath: "/x.sock",
      guestPort: 8080,
      method: "POST",
      path: "/invoke",
      headers: { "Content-Type": "application/octet-stream" },
      body: new Uint8Array([0x42]),
    });
    const text = new TextDecoder().decode(bytes);
    expect(text).toContain("Content-Type: application/octet-stream\r\n");
    expect(text).not.toContain("Content-Type: application/json");
  });
});

describe("decodeHttpResponse — HTTP/1.1 parse", () => {
  it("parses a 200 response with JSON body + headers", () => {
    const raw = Buffer.from(
      "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"ok\":\"true\"}",
    );
    const resp = decodeHttpResponse(raw);
    expect(resp.status).toBe(200);
    expect(resp.headers["content-type"]).toBe("application/json");
    expect(resp.headers["content-length"]).toBe("13");
    expect(new TextDecoder().decode(resp.body)).toBe(`{"ok":"true"}`);
  });

  it("parses a 4xx response with empty body", () => {
    const raw = Buffer.from("HTTP/1.1 422 Unprocessable\r\nContent-Length: 0\r\n\r\n");
    const resp = decodeHttpResponse(raw);
    expect(resp.status).toBe(422);
    expect(resp.body.length).toBe(0);
  });

  it("preserves binary body bytes (non-UTF-8)", () => {
    const head = Buffer.from(
      "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 4\r\n\r\n",
    );
    const bin = Buffer.from([0xde, 0xad, 0xbe, 0xef]);
    const raw = Buffer.concat([head, bin]);
    const resp = decodeHttpResponse(raw);
    expect(resp.status).toBe(200);
    expect(resp.body.length).toBe(4);
    expect(resp.body[0]).toBe(0xde);
    expect(resp.body[3]).toBe(0xef);
  });

  it("malformed status line throws", () => {
    const raw = Buffer.from("not-an-http-response\r\n\r\n");
    expect(() => decodeHttpResponse(raw)).toThrow(/malformed status line/);
  });

  it("missing CRLF separator throws", () => {
    const raw = Buffer.from("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n");
    expect(() => decodeHttpResponse(raw)).toThrow(/no.*separator/);
  });
});

describe("MockVsockClient — request log + handler dispatch", () => {
  it("logs every request that comes through", async () => {
    client.defaultHandler = () => ({
      status: 204,
      headers: {},
      body: new Uint8Array(0),
    });
    const req: VsockHttpRequest = {
      udsPath: "/tmp/x.sock",
      guestPort: 8080,
      method: "GET",
      path: "/healthz",
    };
    await client.sendRequest(req);
    expect(client.requests).toHaveLength(1);
    expect(client.requests[0]).toEqual(req);
  });

  it("dispatches by (udsPath, guestPort) — handler receives the right request", async () => {
    let received: VsockHttpRequest | null = null;
    client.on("/tmp/a.sock", 8080, (req) => {
      received = req;
      return { status: 201, headers: {}, body: new Uint8Array(0) };
    });
    const req: VsockHttpRequest = {
      udsPath: "/tmp/a.sock",
      guestPort: 8080,
      method: "POST",
      path: "/invoke",
      body: new TextEncoder().encode(`{"x":1}`),
    };
    const resp = await client.sendRequest(req);
    expect(resp.status).toBe(201);
    expect(received).not.toBeNull();
    expect(received!.path).toBe("/invoke");
  });

  it("falls back to defaultHandler when no specific handler matches", async () => {
    client.defaultHandler = () => ({
      status: 200,
      headers: { "x-default": "1" },
      body: new TextEncoder().encode("default"),
    });
    const resp = await client.sendRequest({
      udsPath: "/x.sock",
      guestPort: 9999,
      method: "GET",
      path: "/",
    });
    expect(resp.headers["x-default"]).toBe("1");
    expect(new TextDecoder().decode(resp.body)).toBe("default");
  });

  it("throws when no handler is registered for the request", async () => {
    let caught: unknown = null;
    try {
      await client.sendRequest({
        udsPath: "/x.sock",
        guestPort: 8080,
        method: "GET",
        path: "/",
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VsockClientError);
    expect((caught as Error).message).toContain("no mock handler");
  });

  it("failNext surfaces a custom VsockClientError", async () => {
    client.failNext = {
      error: new VsockClientError("connect", "/x.sock", "ENOENT", "Firecracker not running"),
    };
    let caught: unknown = null;
    try {
      await client.sendRequest({
        udsPath: "/x.sock",
        guestPort: 8080,
        method: "GET",
        path: "/",
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VsockClientError);
    expect((caught as VsockClientError).stage).toBe("connect");
    expect((caught as VsockClientError).udsPath).toBe("/x.sock");
    expect((caught as Error).message).toContain("ENOENT");
    expect((caught as VsockClientError).detail).toContain("Firecracker not running");
  });

  it("failNext is one-shot — subsequent calls succeed via handler", async () => {
    client.defaultHandler = () => ({
      status: 200,
      headers: {},
      body: new Uint8Array(0),
    });
    client.failNext = {
      error: new VsockClientError("timeout", "/x.sock", "5s exceeded"),
    };
    await expect(
      client.sendRequest({ udsPath: "/x.sock", guestPort: 8080, method: "GET", path: "/" }),
    ).rejects.toThrow();
    const resp = await client.sendRequest({
      udsPath: "/x.sock",
      guestPort: 8080,
      method: "GET",
      path: "/",
    });
    expect(resp.status).toBe(200);
  });

  it("reset() clears requests + handlers", async () => {
    client.defaultHandler = () => ({ status: 200, headers: {}, body: new Uint8Array(0) });
    await client.sendRequest({ udsPath: "/x.sock", guestPort: 8080, method: "GET", path: "/" });
    expect(client.requests).toHaveLength(1);
    client.reset();
    expect(client.requests).toHaveLength(0);
    expect(client.defaultHandler).toBeNull();
  });
});

describe("MockVsockClient — invocation flow simulation", () => {
  it("simulates a Platform tier invocation: customer payload in, function result out", async () => {
    // The k9o-init agent on the guest side listens on guestPort=8080 and
    // routes POST /invoke to the customer agent. Mock that round-trip.
    client.on("/tmp/fc-customer.sock", 8080, (req) => {
      expect(req.method).toBe("POST");
      expect(req.path).toBe("/invoke");
      const payload = JSON.parse(new TextDecoder().decode(req.body!));
      expect(payload).toEqual({ name: "world" });
      const result = JSON.stringify({ greeting: `Hello, ${payload.name}!` });
      return {
        status: 200,
        headers: { "content-type": "application/json" },
        body: new TextEncoder().encode(result),
      };
    });
    const resp = await client.sendRequest({
      udsPath: "/tmp/fc-customer.sock",
      guestPort: 8080,
      method: "POST",
      path: "/invoke",
      body: new TextEncoder().encode(`{"name":"world"}`),
    });
    expect(resp.status).toBe(200);
    expect(JSON.parse(new TextDecoder().decode(resp.body))).toEqual({
      greeting: "Hello, world!",
    });
  });
});
