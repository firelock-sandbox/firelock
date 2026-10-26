// The real vsock client against a socket that behaves like Firecracker in front of a keep-alive guest server: it
// answers the CONNECT preamble, writes a complete HTTP response, and never closes. In a prior incident every answered
// sandbox invoke was dropped at the 30 s timeout because the client waited for the socket to end.
import { afterEach, describe, expect, it } from "bun:test";
import { createServer, type Server, type Socket } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RealVsockClient, completeHttpResponse } from "./vsock-client.ts";

let server: Server | null = null;
let dir = "";
const held: Socket[] = [];
afterEach(() => {
  for (const s of held.splice(0)) s.destroy();
  server?.close();
  server = null;
  if (dir) rmSync(dir, { recursive: true, force: true });
});

/** A fake vsock UDS: OK preamble, then `reply` (written in `pieces` writes), then the socket is held open. */
async function fakeGuest(reply: string, pieces = 1, close = false): Promise<string> {
  dir = mkdtempSync(join(tmpdir(), "k9o-vsock-"));
  const path = join(dir, "fn.vsock");
  server = createServer((s) => {
    held.push(s);
    let gotPreamble = false;
    s.on("data", (d) => {
      if (!gotPreamble && d.toString().startsWith("CONNECT ")) {
        gotPreamble = true;
        s.write("OK 1073741824\n");
        return;
      }
      const step = Math.ceil(reply.length / pieces);
      let i = 0;
      const tick = () => {
        if (i >= reply.length) {
          if (close) s.end();
          return;
        }
        s.write(reply.slice(i, i + step));
        i += step;
        setTimeout(tick, 20);
      };
      tick();
    });
  });
  await new Promise<void>((r) => server!.listen(path, r));
  return path;
}

const send = (udsPath: string, timeoutMs = 3000) =>
  new RealVsockClient().sendRequest({ udsPath, guestPort: 8000, method: "POST", path: "/invoke", body: new TextEncoder().encode("{}"), timeoutMs });

describe("RealVsockClient completes on the response's framing, not on the socket ending", () => {
  it("a Content-Length response on a socket that stays open resolves at once", async () => {
    const body = '{"ok":true}';
    const path = await fakeGuest(`HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
    const t0 = Date.now();
    const r = await send(path);
    expect(Date.now() - t0).toBeLessThan(1000);
    expect(r.status).toBe(200);
    expect(new TextDecoder().decode(r.body)).toBe(body);
  });

  it("a response split across several writes resolves only when the last body byte arrives", async () => {
    const body = JSON.stringify({ items: Array.from({ length: 50 }, (_, i) => i) });
    const path = await fakeGuest(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n${body}`, 5);
    const r = await send(path);
    expect(new TextDecoder().decode(r.body)).toBe(body);
  });

  it("a chunked response resolves at its last chunk, decoded", async () => {
    const path = await fakeGuest("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
    const r = await send(path);
    expect(new TextDecoder().decode(r.body)).toBe("hello world");
  });

  it("with neither framing, it still waits for the socket to end (and times out if it never does)", async () => {
    const path = await fakeGuest("HTTP/1.1 200 OK\r\n\r\nraw", 1, true);
    const r = await send(path);
    expect(new TextDecoder().decode(r.body)).toBe("raw");
    const path2 = await (async () => {
      server?.close();
      return fakeGuest("HTTP/1.1 200 OK\r\n\r\nraw-never-closed");
    })();
    await expect(send(path2, 300)).rejects.toThrow("timeout");
  });
});

describe("completeHttpResponse", () => {
  const b = (s: string) => Buffer.from(s, "latin1");
  it("null until the headers end, and until Content-Length bytes are in", () => {
    expect(completeHttpResponse(b("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n"))).toBeNull();
    expect(completeHttpResponse(b("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab"))).toBeNull();
    expect(completeHttpResponse(b("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd"))?.status).toBe(200);
  });
  it("a malformed chunk size throws (the client fails the call, never hangs)", () => {
    expect(() => completeHttpResponse(b("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"))).toThrow("malformed chunk size");
  });
});
