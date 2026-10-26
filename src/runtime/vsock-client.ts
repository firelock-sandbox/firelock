/**
 * vsock host-side client + HTTP-over-vsock layer.
 *
 * vsock is the host-to-guest IPC contract for the
 * sandbox tier. HTTP semantics ride on top so the existing Bun
 * HTTP client + KError shape mapping reuses cleanly.
 *
 * How vsock works in Firecracker:
 *
 *   - The Firecracker `/vsock` device is configured with a guest CID
 *     and a host UDS path (per FirecrackerClient.addVsock at v2.3.0).
 *   - Host-side: connect to the UDS as a normal Unix socket. The first
 *     bytes the host writes must be `CONNECT <guest-port>\n` — this
 *     instructs Firecracker to plumb the connection to the specified
 *     guest vsock port. Firecracker responds with `OK <host-port>\n`,
 *     after which the connection acts like a normal byte stream.
 *   - Subsequent traffic is opaque — the host and guest exchange any
 *     protocol they want. HTTP/1.1 is the k9o convention so existing
 *     host-side request/response shapes reuse.
 *
 * Reference: https://github.com/firecracker-microvm/firecracker/blob/main/docs/vsock.md
 *
 * Two implementations behind `VsockClient` (mirroring v2.3.0 / v2.3.2 /
 * v2.3.3 patterns):
 *
 *   - `RealVsockClient` — opens a Unix socket against the Firecracker-
 *     managed vsock UDS, sends the CONNECT preamble, exchanges HTTP
 *     bytes. Linux + Firecracker only.
 *
 *   - `MockVsockClient` — in-process state machine; tests register
 *     canned responses keyed by (udsPath, guestPort, request shape) and
 *     verify the host-side request shape.
 *
 * The HTTP layer is `VsockHttpClient.sendRequest({ udsPath, guestPort,
 * method, path, body }) → { status, body }`. Errors map to KError
 * shapes upstream (UPSTREAM_UNAVAILABLE on transport / connection
 * failures; FUNCTION_RUNTIME_ERROR on guest-side traps).
 */

import { Socket } from "node:net";

export type VsockHttpRequest = {
  /** UDS path created by Firecracker (matches the addVsock() udsPath). */
  udsPath: string;
  /** Guest vsock port to connect to. The k9o-init agent listens on a known port. */
  guestPort: number;
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  path: string;
  /** Optional headers; Content-Type defaults to application/json when body is non-empty. */
  headers?: Record<string, string>;
  body?: Uint8Array;
  /** Connection timeout in ms. Defaults to 5000. */
  timeoutMs?: number;
};

export type VsockHttpResponse = {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
};

export class VsockClientError extends Error {
  readonly stage: "connect" | "preamble" | "request" | "response" | "timeout";
  readonly udsPath: string;
  readonly detail?: string;
  constructor(stage: VsockClientError["stage"], udsPath: string, message: string, detail?: string) {
    super(`vsock ${stage} (${udsPath}): ${message}`);
    this.name = "VsockClientError";
    this.stage = stage;
    this.udsPath = udsPath;
    if (detail !== undefined) this.detail = detail;
  }
}

export interface VsockClient {
  /** Send an HTTP request through the vsock channel and return the response. */
  sendRequest(req: VsockHttpRequest): Promise<VsockHttpResponse>;
}

// ----------------------------------------------------------------------
// Real implementation
// ----------------------------------------------------------------------

const DEFAULT_TIMEOUT_MS = 5000;

export class RealVsockClient implements VsockClient {
  async sendRequest(req: VsockHttpRequest): Promise<VsockHttpResponse> {
    const timeoutMs = req.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const httpBytes = encodeHttpRequest(req);

    return new Promise((resolve, reject) => {
      const sock = new Socket();
      let timer: ReturnType<typeof setTimeout> | null = null;
      let stage: VsockClientError["stage"] = "connect";
      let preambleSeen = false;
      let settled = false;
      let buf = Buffer.alloc(0);

      const fail = (e: VsockClientError) => {
        if (timer !== null) {
          clearTimeout(timer);
          timer = null;
        }
        sock.destroy();
        reject(e);
      };

      timer = setTimeout(() => {
        fail(new VsockClientError("timeout", req.udsPath, `${timeoutMs}ms exceeded`));
      }, timeoutMs);

      sock.once("error", (e) => {
        fail(new VsockClientError(stage, req.udsPath, e.message));
      });

      sock.connect(req.udsPath, () => {
        stage = "preamble";
        // Send the Firecracker vsock CONNECT preamble. Format:
        //   CONNECT <guest-port>\n
        sock.write(`CONNECT ${req.guestPort}\n`);
      });

      sock.on("data", (chunk: Buffer) => {
        buf = Buffer.concat([buf, chunk]);
        if (!preambleSeen) {
          // Look for the "OK <port>\n" preamble response.
          const nl = buf.indexOf(0x0a);
          if (nl < 0) return;
          const line = buf.slice(0, nl).toString("ascii");
          buf = buf.slice(nl + 1);
          if (!line.startsWith("OK ")) {
            fail(
              new VsockClientError(
                "preamble",
                req.udsPath,
                `expected "OK <port>" preamble, got: ${line}`,
              ),
            );
            return;
          }
          preambleSeen = true;
          stage = "request";
          sock.write(httpBytes);
          stage = "response";
          // fall through; remaining buf may already contain response bytes
        }
        // Complete on the response's own framing, not on the socket ending. The guest's extension server (Bun) keeps
        // HTTP/1.1 connections alive and k9o-init splices until a side closes, so waiting for "end" held every answered
        // invoke until the 30 s timeout (observed: a 400 arrived in ms and was dropped at 30 s).
        if (preambleSeen && !settled) {
          let complete: VsockHttpResponse | null;
          try {
            complete = completeHttpResponse(buf);
          } catch (e) {
            settled = true;
            fail(new VsockClientError("response", req.udsPath, e instanceof Error ? e.message : String(e)));
            return;
          }
          if (complete !== null) {
            settled = true;
            if (timer !== null) {
              clearTimeout(timer);
              timer = null;
            }
            sock.destroy();
            resolve(complete);
          }
        }
      });

      sock.once("end", () => {
        if (settled) return;
        settled = true;
        if (timer !== null) {
          clearTimeout(timer);
          timer = null;
        }
        if (!preambleSeen) {
          reject(
            new VsockClientError(
              "preamble",
              req.udsPath,
              "connection ended before vsock CONNECT preamble was acknowledged",
            ),
          );
          return;
        }
        try {
          const response = decodeHttpResponse(buf);
          resolve(response);
        } catch (e) {
          reject(
            new VsockClientError(
              "response",
              req.udsPath,
              e instanceof Error ? e.message : String(e),
            ),
          );
        }
      });
    });
  }
}

// ----------------------------------------------------------------------
// Mock implementation
// ----------------------------------------------------------------------

/**
 * Canned-response registry. Tests set up expected request shapes +
 * canned responses; the mock verifies the request matches and returns
 * the canned response.
 */
export type MockVsockHandler = (req: VsockHttpRequest) => Promise<VsockHttpResponse> | VsockHttpResponse;

export class MockVsockClient implements VsockClient {
  readonly requests: VsockHttpRequest[] = [];
  /** Per-(udsPath,guestPort) handler. Falls back to defaultHandler if no specific handler is registered. */
  private readonly handlers = new Map<string, MockVsockHandler>();
  defaultHandler: MockVsockHandler | null = null;
  failNext: { error: VsockClientError } | null = null;

  /** Register a handler keyed on (udsPath, guestPort). */
  on(udsPath: string, guestPort: number, handler: MockVsockHandler): void {
    this.handlers.set(`${udsPath}:${guestPort}`, handler);
  }

  async sendRequest(req: VsockHttpRequest): Promise<VsockHttpResponse> {
    this.requests.push(req);
    if (this.failNext !== null) {
      const err = this.failNext.error;
      this.failNext = null;
      throw err;
    }
    const key = `${req.udsPath}:${req.guestPort}`;
    const handler = this.handlers.get(key) ?? this.defaultHandler;
    if (handler === null || handler === undefined) {
      throw new VsockClientError(
        "connect",
        req.udsPath,
        `no mock handler registered for ${key}`,
      );
    }
    return await handler(req);
  }

  reset(): void {
    this.requests.length = 0;
    this.handlers.clear();
    this.defaultHandler = null;
    this.failNext = null;
  }
}

// ----------------------------------------------------------------------
// DI singleton
// ----------------------------------------------------------------------

let _client: VsockClient | null = null;

export function getVsockClient(): VsockClient {
  if (_client !== null) return _client;
  _client = new RealVsockClient();
  return _client;
}

export function useTestVsockClient(client: VsockClient): void {
  _client = client;
}

export function resetVsockClient(): void {
  _client = null;
}

// ----------------------------------------------------------------------
// HTTP/1.1 framing helpers
// ----------------------------------------------------------------------

export function encodeHttpRequest(req: VsockHttpRequest): Uint8Array {
  const body = req.body ?? new Uint8Array(0);
  const headers: Record<string, string> = {
    Host: "guest",
    Connection: "close",
    ...(req.headers ?? {}),
    "Content-Length": `${body.length}`,
  };
  if (body.length > 0 && headers["Content-Type"] === undefined) {
    headers["Content-Type"] = "application/json";
  }
  const headerLines = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\r\n");
  const head = `${req.method} ${req.path} HTTP/1.1\r\n${headerLines}\r\n\r\n`;
  const headBytes = new TextEncoder().encode(head);
  const out = new Uint8Array(headBytes.length + body.length);
  out.set(headBytes, 0);
  out.set(body, headBytes.length);
  return out;
}

/**
 * The response, once its framing says it is whole: the headers plus `Content-Length` body bytes, or a chunked body up
 * to its last chunk (decoded). Null while more bytes are due, or when the response carries neither (then only the
 * socket ending completes it).
 */
export function completeHttpResponse(buf: Buffer): VsockHttpResponse | null {
  const sep = buf.indexOf(Buffer.from("\r\n\r\n"));
  if (sep < 0) return null;
  const head = decodeHttpResponse(buf.subarray(0, sep + 4));
  const bodyStart = sep + 4;
  const cl = head.headers["content-length"];
  if (cl !== undefined && /^\d{1,15}$/.test(cl)) {
    const len = Number(cl);
    if (buf.length - bodyStart < len) return null;
    return { status: head.status, headers: head.headers, body: new Uint8Array(buf.subarray(bodyStart, bodyStart + len)) };
  }
  if ((head.headers["transfer-encoding"] ?? "").toLowerCase().includes("chunked")) {
    const parts: Buffer[] = [];
    let at = bodyStart;
    for (;;) {
      const eol = buf.indexOf(Buffer.from("\r\n"), at);
      if (eol < 0) return null;
      const size = Number.parseInt(buf.subarray(at, eol).toString("ascii").split(";")[0]!.trim(), 16);
      if (!Number.isFinite(size) || size < 0) throw new Error("malformed chunk size");
      const dataStart = eol + 2;
      if (size === 0) {
        if (buf.indexOf(Buffer.from("\r\n"), dataStart) < 0) return null;
        return { status: head.status, headers: head.headers, body: new Uint8Array(Buffer.concat(parts)) };
      }
      if (buf.length < dataStart + size + 2) return null;
      parts.push(buf.subarray(dataStart, dataStart + size));
      at = dataStart + size + 2;
    }
  }
  return null;
}

export function decodeHttpResponse(buf: Buffer): VsockHttpResponse {
  const sep = buf.indexOf(Buffer.from("\r\n\r\n"));
  if (sep < 0) {
    throw new Error(`malformed HTTP response: no \\r\\n\\r\\n separator`);
  }
  const headPart = buf.slice(0, sep).toString("ascii");
  const bodyPart = buf.slice(sep + 4);
  const lines = headPart.split("\r\n");
  const statusLine = lines[0] ?? "";
  const m = /^HTTP\/1\.1 (\d{3})/.exec(statusLine);
  if (m === null) {
    throw new Error(`malformed status line: ${statusLine}`);
  }
  const status = Number.parseInt(m[1]!, 10);
  const headers: Record<string, string> = {};
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]!;
    const idx = line.indexOf(":");
    if (idx > 0) {
      const k = line.slice(0, idx).trim().toLowerCase();
      const v = line.slice(idx + 1).trim();
      headers[k] = v;
    }
  }
  return { status, headers, body: new Uint8Array(bodyPart) };
}
