/**
 * Firecracker client unit tests (v2.3.0).
 *
 * Exercises the FirecrackerClient interface through the
 * MockFirecrackerClient implementation — the goal is to verify that
 * the host-side lifecycle ordering, error-path handling, and
 * teardown idempotency are correct WITHOUT requiring Linux + KVM
 * locally. Real-Firecracker integration tests run on a Linux + KVM host via
 * a separate remote test-runner harness.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { unlink } from "node:fs/promises";
import {
  FirecrackerClientError,
  MockFirecrackerClient,
  RealFirecrackerClient,
  type FirecrackerClient,
  type FirecrackerHandle,
} from "./firecracker-client.ts";

let client: MockFirecrackerClient;

beforeEach(() => {
  client = new MockFirecrackerClient();
});

/**
 * Walks a fresh MicroVM through the cold-boot lifecycle. Mirrors the
 * sequence the pool implementation (v2.3.1) will execute:
 *
 *   spawn → configureMachine → configureBootSource → addDrive →
 *   addVsock → action(InstanceStart)
 *
 * Returns the handle for further assertions / teardown.
 */
async function coldBoot(c: FirecrackerClient, projectId: string): Promise<FirecrackerHandle> {
  const handle = await c.spawn();
  await c.configureMachine(handle, { vcpuCount: 1, memSizeMib: 128, smt: false });
  await c.configureBootSource(handle, {
    kernelImagePath: "/var/lib/k9o/kernels/vmlinux.bin",
    bootArgs: "console=ttyS0 reboot=k panic=1 pci=off",
  });
  await c.addDrive(handle, {
    driveId: "rootfs",
    pathOnHost: `/var/lib/k9o/rootfs/${projectId}.ext4`,
    isRootDevice: true,
    isReadOnly: true,
  });
  await c.addVsock(handle, {
    guestCid: 3,
    udsPath: `/tmp/k9o-firecracker/${handle.id}-vsock.sock`,
  });
  await c.action(handle, "InstanceStart");
  return handle;
}

describe("FirecrackerClient — lifecycle ordering (v2.3.0)", () => {
  it("spawn returns a fresh handle with state 'ready' and a unique id + socket path", async () => {
    const a = await client.spawn();
    const b = await client.spawn();
    expect(a.state).toBe("ready");
    expect(b.state).toBe("ready");
    expect(a.id).not.toBe(b.id);
    expect(a.apiSocketPath).not.toBe(b.apiSocketPath);
  });

  it("cold-boot lifecycle records the right ops in order", async () => {
    const handle = await coldBoot(client, "proj-test");
    expect(client.events.map((e) => e.op)).toEqual([
      "spawn",
      "configureMachine",
      "configureBootSource",
      "addDrive",
      "addVsock",
      "action",
    ]);
    expect(handle.state).toBe("running");
  });

  it("addDrive carries through the right per-project rootfs path", async () => {
    const handle = await client.spawn();
    await client.addDrive(handle, {
      driveId: "rootfs",
      pathOnHost: "/var/lib/k9o/rootfs/proj-abc.ext4",
      isRootDevice: true,
      isReadOnly: true,
    });
    const driveEvent = client.events.find((e) => e.op === "addDrive");
    expect(driveEvent?.args).toEqual({
      driveId: "rootfs",
      pathOnHost: "/var/lib/k9o/rootfs/proj-abc.ext4",
      isRootDevice: true,
      isReadOnly: true,
    });
  });

  it("addVsock carries the right CID + UDS path (vsock IPC contract)", async () => {
    const handle = await client.spawn();
    await client.addVsock(handle, { guestCid: 3, udsPath: "/tmp/k9o-fc/x-vsock.sock" });
    const vsockEvent = client.events.find((e) => e.op === "addVsock");
    expect(vsockEvent?.args).toEqual({ guestCid: 3, udsPath: "/tmp/k9o-fc/x-vsock.sock" });
  });
});

describe("FirecrackerClient — pause / resume / snapshot lifecycle", () => {
  it("pause flips handle state to 'paused'; resume flips back to 'running'", async () => {
    const handle = await coldBoot(client, "proj-test");
    expect(handle.state).toBe("running");
    await client.pause(handle);
    expect(handle.state).toBe("paused");
    await client.resume(handle);
    expect(handle.state).toBe("running");
  });

  it("createSnapshot writes the configured paths into the event log", async () => {
    const handle = await coldBoot(client, "proj-test");
    await client.pause(handle);
    await client.createSnapshot(handle, {
      snapshotPath: "/var/lib/k9o/snapshots/abc.bin",
      memoryFilePath: "/var/lib/k9o/snapshots/abc.mem",
    });
    const snapEvent = client.events.find((e) => e.op === "createSnapshot");
    expect(snapEvent?.args).toEqual({
      snapshotPath: "/var/lib/k9o/snapshots/abc.bin",
      memoryFilePath: "/var/lib/k9o/snapshots/abc.mem",
    });
  });

  it("loadSnapshot with resumeVm=false leaves the handle in 'paused' (warm-pool pre-load shape)", async () => {
    const handle = await client.spawn();
    await client.loadSnapshot(handle, {
      snapshotPath: "/snap.bin",
      memoryFilePath: "/snap.mem",
      resumeVm: false,
    });
    expect(handle.state).toBe("paused");
  });

  it("loadSnapshot with resumeVm=true leaves the handle in 'running' (cold-restore shape)", async () => {
    const handle = await client.spawn();
    await client.loadSnapshot(handle, {
      snapshotPath: "/snap.bin",
      memoryFilePath: "/snap.mem",
      resumeVm: true,
    });
    expect(handle.state).toBe("running");
  });
});

describe("FirecrackerClient — teardown + closed-handle guard", () => {
  it("shutdown flips state to 'closed' and is idempotent", async () => {
    const handle = await client.spawn();
    await client.shutdown(handle);
    expect(handle.state).toBe("closed");
    // Idempotency: second shutdown is a no-op.
    await client.shutdown(handle);
    expect(handle.state).toBe("closed");
  });

  it("operations on a closed handle throw FirecrackerClientError", async () => {
    const handle = await client.spawn();
    await client.shutdown(handle);
    await expect(
      client.configureMachine(handle, { vcpuCount: 1, memSizeMib: 128 }),
    ).rejects.toThrow(FirecrackerClientError);
    await expect(
      client.action(handle, "InstanceStart"),
    ).rejects.toThrow(FirecrackerClientError);
  });
});

describe("FirecrackerClient — error injection (mock-only)", () => {
  it("failNext on a specific op surfaces FirecrackerClientError carrying the diagnostic", async () => {
    client.failNext = { op: "configureMachine", message: "memory cap exceeds host" };
    const handle = await client.spawn();
    let caught: unknown = null;
    try {
      await client.configureMachine(handle, { vcpuCount: 1, memSizeMib: 999_999 });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(FirecrackerClientError);
    expect((caught as FirecrackerClientError).operation).toBe("configureMachine");
    expect((caught as Error).message).toContain("memory cap exceeds host");
  });

  // Regression guard from a prior warm-pool incident — `.message` used to drop status+detail entirely, so a
  // consumer logging the error generically (index.ts's warm-pool `.then(..., err => log(err.message))`)
  // saw only "Firecracker PUT /snapshot/load: non-2xx response" with no status and no body, even
  // though `put()` captures both on every non-2xx. `.status`/`.detail` stay structured for a caller
  // that branches on them (per the class doc); this pins that `.message` ALSO carries them, since
  // that is the one channel a plain error-log actually reads.
  it("FirecrackerClientError folds status+detail into .message, not only the structured fields", () => {
    const err = new FirecrackerClientError("PUT /snapshot/load", "non-2xx response", {
      status: 500,
      detail: "vmm error: no such file or directory (os error 2)",
    });
    expect(err.status).toBe(500); // structured access unchanged
    expect(err.detail).toBe("vmm error: no such file or directory (os error 2)");
    expect(err.message).toContain("500");
    expect(err.message).toContain("vmm error: no such file or directory (os error 2)");
  });

  it("FirecrackerClientError with no status: .message carries no diagnostic suffix (nothing to add)", () => {
    // The conditional must not misfire on the common no-status case (e.g. "handle is closed").
    const err = new FirecrackerClientError("configureMachine", "handle is closed");
    expect(err.status).toBeUndefined();
    expect(err.message).toBe("Firecracker configureMachine: handle is closed");
  });

  it("failNext is one-shot — subsequent calls of the same op succeed", async () => {
    client.failNext = { op: "spawn", message: "transient kvm error" };
    await expect(client.spawn()).rejects.toThrow(FirecrackerClientError);
    // Second spawn should succeed.
    const handle = await client.spawn();
    expect(handle.state).toBe("ready");
  });
});

describe("FirecrackerClient — concurrent handles (pool prerequisite)", () => {
  it("supports many concurrent handles with independent state", async () => {
    const handles = await Promise.all(Array.from({ length: 50 }, () => client.spawn()));
    expect(new Set(handles.map((h) => h.id)).size).toBe(50);
    expect(new Set(handles.map((h) => h.apiSocketPath)).size).toBe(50);
    // Each handle can transition independently.
    await Promise.all(handles.map((h) => client.action(h, "InstanceStart")));
    expect(handles.every((h) => h.state === "running")).toBe(true);
    await Promise.all(handles.map((h) => client.shutdown(h)));
    expect(handles.every((h) => h.state === "closed")).toBe(true);
  });

  it("reset() clears events + handles for the next test", async () => {
    await client.spawn();
    await client.spawn();
    expect(client.events.length).toBe(2);
    client.reset();
    expect(client.events.length).toBe(0);
    const fresh = await client.spawn();
    // ID counter resets; first id after reset is mock-microvm-1.
    expect(fresh.id).toBe("mock-microvm-1");
  });
});

/**
 * Real-client HTTP/1.1 response-framing tests.
 *
 * These exercise `RealFirecrackerClient.request()` — the ACTUAL socket
 * path — against a fake Unix-socket HTTP server, on macOS/Bun, without
 * spawning Firecracker. They are the regression guard for the
 * hang: config PUT/PATCH calls return `204 No Content` and Firecracker
 * keeps the API socket open (keep-alive), so a reader that waits on the
 * socket "end" event never resolves. The client MUST frame on
 * Content-Length / Transfer-Encoding / no-body status instead.
 *
 * The fake server deliberately keeps the socket OPEN after responding
 * (except the close-delimited case) so a passing test proves framing is
 * independent of connection close.
 */
describe("RealFirecrackerClient — HTTP response framing (204 keep-alive regression)", () => {
  const servers: Server[] = [];
  const paths: string[] = [];

  afterEach(async () => {
    await Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r()))));
    await Promise.all(paths.map((p) => unlink(p).catch(() => {})));
    servers.length = 0;
    paths.length = 0;
  });

  let sockSeq = 0;
  // Stand up a UDS server that replies with `raw` bytes once it has read
  // the request headers. `close: false` leaves the socket open — the
  // client must not depend on it closing to consider the reply complete.
  async function serve(reply: () => { raw: string; close: boolean }): Promise<string> {
    const path = `${tmpdir()}/k9o-fc-fram-${process.pid}-${sockSeq++}.sock`;
    await unlink(path).catch(() => {});
    const server = createServer((sock) => {
      let buf = Buffer.alloc(0);
      sock.on("data", (chunk) => {
        buf = Buffer.concat([buf, chunk as Buffer]);
        if (buf.indexOf("\r\n\r\n") < 0) return; // await full request headers
        const { raw, close } = reply();
        sock.write(raw);
        if (close) sock.end();
      });
    });
    await new Promise<void>((resolve) => server.listen(path, () => resolve()));
    servers.push(server);
    paths.push(path);
    return path;
  }

  function realClient(): RealFirecrackerClient {
    return new RealFirecrackerClient({ binaryPath: "firecracker", socketDir: tmpdir() });
  }

  const cfg = { vcpuCount: 1, memSizeMib: 128, smt: false };

  it("resolves on a 204 No Content WITHOUT the server closing the socket", async () => {
    // The exact hang case: no body, socket stays open. Before the fix
    // this never resolved. bun's per-test timeout fails the test if it
    // regresses, so a plain await is a sufficient assertion.
    const path = await serve(() => ({
      raw: "HTTP/1.1 204 No Content\r\nServer: Firecracker API\r\n\r\n",
      close: false,
    }));
    const handle: FirecrackerHandle = { id: "t204", apiSocketPath: path, state: "ready" };
    await realClient().configureMachine(handle, cfg);
  });

  it("resolves on a 200 framed by Content-Length without close", async () => {
    const body = '{"ok":true}';
    const path = await serve(() => ({
      raw: `HTTP/1.1 200 OK\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
      close: false,
    }));
    const handle: FirecrackerHandle = { id: "t200", apiSocketPath: path, state: "ready" };
    await realClient().configureMachine(handle, cfg);
  });

  it("rejects on a 4xx and surfaces the framed error body as detail", async () => {
    const body = '{"fault_message":"boot-source: kernel not found"}';
    const path = await serve(() => ({
      raw: `HTTP/1.1 400 Bad Request\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
      close: false,
    }));
    const handle: FirecrackerHandle = { id: "t400", apiSocketPath: path, state: "ready" };
    await expect(realClient().configureMachine(handle, cfg)).rejects.toMatchObject({
      status: 400,
      detail: expect.stringContaining("kernel not found"),
    } as Partial<FirecrackerClientError>);
  });

  it("decodes a chunked response body", async () => {
    // "hi" then "!" then terminal 0-chunk, socket left open.
    const path = await serve(() => ({
      raw:
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
        "2\r\nhi\r\n1\r\n!\r\n0\r\n\r\n",
      close: false,
    }));
    const handle: FirecrackerHandle = { id: "tchunk", apiSocketPath: path, state: "ready" };
    await realClient().configureMachine(handle, cfg);
  });

  it("still handles a legacy close-delimited response (no Content-Length)", async () => {
    // Backwards-compat: a server that DOES close, with no framing header.
    const path = await serve(() => ({
      raw: "HTTP/1.1 204 No Content\r\n\r\n",
      close: true,
    }));
    const handle: FirecrackerHandle = { id: "tclose", apiSocketPath: path, state: "ready" };
    await realClient().configureMachine(handle, cfg);
  });
});
