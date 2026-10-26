// The per-invocation function VM. No KVM, jailer or store: MockFirecrackerClient,
// MemoryStorageAdapter, a temp cache dir, a jail-staging stub.
import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync, chmodSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MockFirecrackerClient } from "./firecracker-client.ts";
import {
  _resetFunctionVmAdmissionForTest,
  FunctionVmRefused,
  admitFunctionVm,
  assertReadOnlyRootDrive,
  assertSignedImageDigest,
  bootFunctionVm,
  CONSOLE_DIAGNOSTIC_BYTES,
  consoleDiagnosticLines,
  functionVmUidsInUse,
  isInitNotReady,
  materializeVerifiedRootfs,
  ROOTFS_HASH_CHUNK_BYTES,
  sha256File,
  releaseFunctionVm,
  rootfsDigestFromKey,
} from "./function-vm.ts";

const PROJECT = "proj_abc123def456";
const EXT4 = new TextEncoder().encode("an ext4 image, for the purposes of this test");
const DIGEST = createHash("sha256").update(EXT4).digest("hex");
const KEY = `artifacts/proj/${PROJECT}/firecracker/${DIGEST}.ext4`;
const JAILER = { jailerBinaryPath: "/usr/local/bin/jailer", chrootRoot: "/mock/jails", uidFloor: 200_000, uidCeiling: 299_999 };
const noStage = async () => ({ root: "/mock", files: [], vsockDir: "/mock/tmp" });

let cacheDir: string;
beforeEach(() => {
  cacheDir = mkdtempSync(join(tmpdir(), "k9o-fnvm-cache-"));
  _resetFunctionVmAdmissionForTest();
});
afterEach(() => rmSync(cacheDir, { recursive: true, force: true }));

/** An in-memory artifact store holding one object. */
class MemoryStore {
  readonly objects = new Map<string, Uint8Array>();
  async fetchArtifact(key: string): Promise<Uint8Array> {
    const bytes = this.objects.get(key);
    if (bytes === undefined) throw new Error(`no such artifact: ${key}`);
    return bytes;
  }
}

async function storeWith(key: string, bytes: Uint8Array): Promise<MemoryStore> {
  const s = new MemoryStore();
  s.objects.set(key, bytes);
  return s;
}

describe("integrity before boot", () => {
  it("a key that is not content-addressed is refused", () => {
    expect(() => rootfsDigestFromKey("artifacts/proj/p/firecracker/abc.ext4")).toThrow(FunctionVmRefused);
    expect(() => rootfsDigestFromKey(`functions/${PROJECT}/${DIGEST}.tar`)).toThrow(FunctionVmRefused);
    expect(rootfsDigestFromKey(KEY)).toBe(DIGEST);
  });

  it("bytes from the store that do not match the key's digest are refused and never cached", async () => {
    const storage = await storeWith(KEY, new TextEncoder().encode("tampered in the store"));
    await expect(materializeVerifiedRootfs({ rootfsKey: KEY, cacheDir, storage })).rejects.toThrow("does not match its content-addressed key");
    expect(existsSync(join(cacheDir, `${DIGEST}.ext4`))).toBe(false);
  });

  it("a cache file tampered with after it was written is refused at the next boot and removed", async () => {
    const storage = await storeWith(KEY, EXT4);
    const first = await materializeVerifiedRootfs({ rootfsKey: KEY, cacheDir, storage });
    expect(first.hit).toBe(false);
    chmodSync(first.path, 0o644);
    writeFileSync(first.path, "rewritten on disk");
    await expect(materializeVerifiedRootfs({ rootfsKey: KEY, cacheDir, storage })).rejects.toThrow("failed its digest check");
    expect(existsSync(first.path)).toBe(false);
  });

  it("an intact cache file is re-hashed and reused (a hit)", async () => {
    const storage = await storeWith(KEY, EXT4);
    await materializeVerifiedRootfs({ rootfsKey: KEY, cacheDir, storage });
    const again = await materializeVerifiedRootfs({ rootfsKey: KEY, cacheDir, storage: null });
    expect(again).toMatchObject({ hit: true, bytes: EXT4.length });
  });

  it("an extension function without a signed image digest is refused", () => {
    expect(() => assertSignedImageDigest(null, "bff")).toThrow("no signed image digest");
    expect(() => assertSignedImageDigest("latest", "bff")).toThrow("no signed image digest");
    expect(() => assertSignedImageDigest(`sha256:${DIGEST}`, "bff")).not.toThrow();
  });
});

describe("the cache belongs to this process alone; no read store, no fetch", () => {
  it("a cached rootfs is mode 0444 and owned by this process's uid", async () => {
    const r = await materializeVerifiedRootfs({ rootfsKey: KEY, cacheDir, storage: await storeWith(KEY, EXT4) });
    const st = statSync(r.path);
    expect(st.mode & 0o777).toBe(0o444);
    expect(st.uid).toBe(process.getuid!());
    expect(new Uint8Array(readFileSync(r.path))).toEqual(EXT4);
  });

  it("without a read store a cache miss refuses rather than borrow another credential", async () => {
    await expect(materializeVerifiedRootfs({ rootfsKey: KEY, cacheDir, storage: null })).rejects.toThrow("read credential is not provisioned");
  });
});

describe("points 2, 4 and 5: boot under the jailer", () => {
  it("configures one read-only root drive, one vsock and no NIC, asserts the topology, THEN starts", async () => {
    const client = new MockFirecrackerClient();
    const vm = await bootFunctionVm({ client, vmId: "fn-inv-1", rootfsPath: "/cache/x.ext4", kernelPath: "/k/vmlinux", usedUids: new Set(), jailerConfig: JAILER, stage: noStage });
    const ops = client.events.filter((e) => e.id === vm.handle.id).map((e) => e.op);
    // (The mock does not log getVmConfig; the NIC test below proves the assert runs before the start.)
    expect(ops).toEqual(["spawn", "configureMachine", "configureBootSource", "addDrive", "addVsock", "action"]);
    const drive = client.events.find((e) => e.op === "addDrive")!.args as { isReadOnly: boolean; isRootDevice: boolean; pathOnHost: string };
    expect(drive).toMatchObject({ isReadOnly: true, isRootDevice: true, pathOnHost: "/cache/x.ext4" });
    expect(client.events.some((e) => e.op === "addNetworkInterface")).toBe(false);
    expect(vm.udsPath).toBe("/mock/jails/pool/firecracker/fn-inv-1/root/tmp/fn.vsock");
    await vm.dispose();
  });

  it("a NIC in the measured config refuses BEFORE InstanceStart, and the VM is torn down", async () => {
    const client = new MockFirecrackerClient();
    client.vmConfigOverride = { vsock: { guest_cid: 3, uds_path: "/tmp/fn.vsock" }, "network-interfaces": [{ iface_id: "eth0" }], drives: [{ is_root_device: true, is_read_only: true }] };
    await expect(bootFunctionVm({ client, vmId: "fn-inv-2", rootfsPath: "/c.ext4", kernelPath: "/k", usedUids: new Set(), jailerConfig: JAILER, stage: noStage })).rejects.toThrow();
    expect(client.events.some((e) => e.op === "action")).toBe(false);
    expect(client.events.some((e) => e.op === "shutdown")).toBe(true);
  });

  it("a writable or second drive in the measured config is refused", () => {
    expect(() => assertReadOnlyRootDrive({ drives: [{ is_root_device: true, is_read_only: false }] })).toThrow("read-only root drive");
    expect(() => assertReadOnlyRootDrive({ drives: [{ is_root_device: true, is_read_only: true }, { is_root_device: false, is_read_only: true }] })).toThrow();
    expect(() => assertReadOnlyRootDrive({ drives: [{ is_root_device: true, is_read_only: true }] })).not.toThrow();
  });

  it("a failure after spawn (staging) shuts down, and the uid is released", async () => {
    const client = new MockFirecrackerClient();
    const before = functionVmUidsInUse().size;
    const stage = async () => {
      throw new Error("staging refused");
    };
    await expect(bootFunctionVm({ client, vmId: "fn-inv-3", rootfsPath: "/c.ext4", kernelPath: "/k", usedUids: new Set(), jailerConfig: JAILER, stage })).rejects.toThrow("staging refused");
    expect(client.events.filter((e) => e.op === "shutdown")).toHaveLength(1);
    expect(functionVmUidsInUse().size).toBe(before);
  });

  it("dispose is idempotent and releases the uid; two VMs never share a uid", async () => {
    const client = new MockFirecrackerClient();
    const a = await bootFunctionVm({ client, vmId: "fn-inv-4", rootfsPath: "/c.ext4", kernelPath: "/k", usedUids: new Set(), jailerConfig: JAILER, stage: noStage });
    const b = await bootFunctionVm({ client, vmId: "fn-inv-5", rootfsPath: "/c.ext4", kernelPath: "/k", usedUids: new Set(), jailerConfig: JAILER, stage: noStage });
    expect(a.jailUid).not.toBe(b.jailUid);
    await a.dispose();
    await a.dispose();
    await b.dispose();
    expect(client.events.filter((e) => e.op === "shutdown")).toHaveLength(2);
    expect(functionVmUidsInUse().has(a.jailUid)).toBe(false);
  });
});

describe("readiness and the concurrency cap", () => {
  it("only k9o-init's own not-ready 503 counts as not ready (nothing was delivered)", () => {
    const enc = (s: string) => new TextEncoder().encode(s);
    expect(isInitNotReady({ status: 503, body: enc('{"code":"K9O_UPSTREAM_UNAVAILABLE","message":"extension invoke server is not reachable"}') })).toBe(true);
    expect(isInitNotReady({ status: 503, body: enc('{"error":"the extension itself is overloaded"}') })).toBe(false);
    expect(isInitNotReady({ status: 200, body: enc("extension invoke server is not reachable") })).toBe(false);
  });

  it("caps concurrent VMs per project and per host; a refusal names the cap; release frees a place", () => {
    process.env.K9O_EXEC_FN_VMS_PER_PROJECT = "2";
    process.env.K9O_EXEC_FN_VMS_PER_HOST = "3";
    try {
      expect(admitFunctionVm("p1")).toBeNull();
      expect(admitFunctionVm("p1")).toBeNull();
      expect(admitFunctionVm("p1")).toEqual({ scope: "project", limit: 2 });
      expect(admitFunctionVm("p2")).toBeNull();
      expect(admitFunctionVm("p3")).toEqual({ scope: "host", limit: 3 });
      releaseFunctionVm("p1");
      expect(admitFunctionVm("p3")).toBeNull();
    } finally {
      delete process.env.K9O_EXEC_FN_VMS_PER_PROJECT;
      delete process.env.K9O_EXEC_FN_VMS_PER_HOST;
    }
  });
});

describe("consoleDiagnosticLines: only k9o-init and kernel lines, bounded", () => {
  it("re-joins CR line ends, keeps k9o-init and panic lines, drops the function's own output", () => {
    const raw = "[ 0.9] Run /usr/bin/k9o-init as init process\r\nhello from the customer function: secret=abc\r\nk9o-init: could not create /run/k9o: No such file or directory\r\n";
    const out = consoleDiagnosticLines(raw);
    expect(out).toContain("k9o-init: could not create /run/k9o");
    expect(out).toContain("Run /usr/bin/k9o-init");
    expect(out).not.toContain("secret=abc");
  });
  it("never exceeds the cap, keeping the newest lines", () => {
    const raw = Array.from({ length: 500 }, (_, i) => `k9o-init: line ${i}`).join("\n");
    const out = consoleDiagnosticLines(raw);
    expect(out.length).toBeLessThanOrEqual(CONSOLE_DIAGNOSTIC_BYTES);
    expect(out).toContain("k9o-init: line 499");
  });
});

describe("the rootfs hash is streamed, and a first boot fetches once (out-of-memory regression)", () => {
  it("sha256File matches a whole-buffer hash across chunk boundaries, and reports the size", async () => {
    for (const n of [0, 1, ROOTFS_HASH_CHUNK_BYTES - 1, ROOTFS_HASH_CHUNK_BYTES, ROOTFS_HASH_CHUNK_BYTES * 2 + 17]) {
      const b = new Uint8Array(n).map((_, i) => (i * 31 + 7) & 0xff);
      const f = join(cacheDir, `f${n}`);
      writeFileSync(f, b);
      expect(await sha256File(f)).toEqual({ hex: createHash("sha256").update(b).digest("hex"), bytes: n });
    }
  });
  it("sha256File reads in bounded chunks, never the whole file", async () => {
    const big = new Uint8Array(ROOTFS_HASH_CHUNK_BYTES * 3 + 5).fill(9);
    const f = join(cacheDir, "big");
    writeFileSync(f, big);
    const sizes: number[] = [];
    const { open } = await import("node:fs/promises");
    const spyOpen = (async (...a: Parameters<typeof open>) => {
      const fh = await open(...a);
      const read = fh.read.bind(fh) as (b: Uint8Array, o: number, l: number, p: number | null) => Promise<{ bytesRead: number }>;
      (fh as unknown as { read: unknown }).read = async (buf: Uint8Array, off: number, len: number, pos: number | null) => (sizes.push(len), read(buf, off, len, pos));
      return fh;
    }) as typeof open;
    expect((await sha256File(f, spyOpen)).bytes).toBe(big.length);
    expect(sizes.length).toBeGreaterThan(3);
    expect(Math.max(...sizes)).toBeLessThanOrEqual(ROOTFS_HASH_CHUNK_BYTES);
  });
  it("a cache hit is hashed by the streamed hash", async () => {
    const storage = await storeWith(KEY, EXT4);
    await materializeVerifiedRootfs({ rootfsKey: KEY, cacheDir, storage });
    const seen: string[] = [];
    const r = await materializeVerifiedRootfs({ rootfsKey: KEY, cacheDir, storage: null, hashFile: async (p) => (seen.push(p), sha256File(p)) });
    expect(r.hit).toBe(true);
    expect(seen).toEqual([r.path]);
  });
  it("concurrent first boots of one function share one fetch from the store", async () => {
    const storage = await storeWith(KEY, EXT4);
    let fetches = 0;
    const orig = storage.fetchArtifact.bind(storage);
    storage.fetchArtifact = async (k: string) => (fetches++, await Bun.sleep(20), orig(k));
    const rs = await Promise.all([1, 2, 3].map(() => materializeVerifiedRootfs({ rootfsKey: KEY, cacheDir, storage })));
    expect(fetches).toBe(1);
    expect(rs.every((r) => r.bytes === EXT4.length)).toBe(true);
  });
});

