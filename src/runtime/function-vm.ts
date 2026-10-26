/**
 * Boot a sandbox function's OWN rootfs, one microVM per invocation.
 *
 * Before this, no code path ran a sandbox function: the deployment worker converted each signed image to an ext4
 * (`k9o-init` injected as PID 1) and stored it at `artifacts/proj/<project>/firecracker/<sha256>.ext4`, but dispatch
 * sent only that key to a generic warm VM booted from the base snapshot, whose `k9o-init` ignored it.
 *
 *   1. Integrity before boot. The key names the ext4's SHA-256, written at deploy with the signed `image_digest` on
 *      the same functions row. A row without `image_digest` is refused. The bytes are hashed on fetch AND on every
 *      boot from the cache; a mismatch refuses and deletes the file. A write to the store alone never runs.
 *   2. The cache belongs to this host process alone: content-addressed, mode 0444, owned by this process, hard-linked (never chowned)
 *      into each chroot, and attached as the ONE root drive with `isReadOnly: true`.
 *   3. The read-only artifact store is supplied by the caller (`useRootfsReadStorage()`); it should be read-only and
 *      scoped to the rootfs prefix. With a null store a fetch refuses; it never falls back to a deploy credential.
 *   4. One VM per invocation, never reused: fresh jail uid, torn down by the caller's `dispose()` on every path.
 *   5. The topology is unchanged: no call adds a NIC, `/vm/config` is asserted (one vsock, zero NICs) BEFORE
 *      `InstanceStart`, and an unreadable `/vm/config` refuses (jailed ⇒ mandatory).
 */

import { createHash } from "node:crypto";
import { chmod, mkdir, open, rename, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { DEFAULT_GUEST_BOOT_ARGS, type FirecrackerClient, type FirecrackerHandle } from "./firecracker-client.ts";
import { allocateSlotUid, loadJailerConfig, type JailerConfig } from "./jailer-wrapper.ts";
import { stageJailedSlot, type StageJailedSlotInput, type StageJailedSlotResult } from "./jailed-slot-staging.ts";
import { assertExecSeamTopology } from "./exec-seam.ts";
import { getCgroupPlacer } from "./vm-slot-cgroup-placer.ts";

/** `artifacts/proj/<projectId>/firecracker/<sha256>.ext4` — the deployment worker's content-addressed key. */
const ROOTFS_KEY = /^artifacts\/proj\/[A-Za-z0-9_]{1,64}\/firecracker\/([0-9a-f]{64})\.ext4$/;
const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/;

/** The guest-side path the function VM's vsock UDS binds at (inside the chroot). */
export const FUNCTION_VM_VSOCK_PATH = "/tmp/fn.vsock";
export const FUNCTION_VM_GUEST_CID = 3;

/** The read side of the artifact store the function rootfs is fetched from. The caller supplies the implementation. */
export interface ArtifactStore {
  fetchArtifact(key: string): Promise<Uint8Array>;
}

/**
 * Raised when a function VM is refused: a failed integrity check, a missing prerequisite, or a capacity cap.
 * `code` is a fixed, machine-readable string; `context` carries non-secret diagnostic fields.
 */
export class FunctionVmRefused extends Error {
  readonly code = "K9O_UPSTREAM_UNAVAILABLE";
  readonly context: Record<string, unknown> | undefined;
  constructor(message: string, context?: Record<string, unknown>) {
    super(message);
    this.name = "FunctionVmRefused";
    this.context = context;
  }
}

function refuse(message: string, context: Record<string, unknown>): FunctionVmRefused {
  return new FunctionVmRefused(message, context);
}

/** The SHA-256 a rootfs key names, or a refusal. */
export function rootfsDigestFromKey(rootfsKey: string): string {
  const m = ROOTFS_KEY.exec(rootfsKey);
  if (m === null) throw refuse("Sandbox rootfs key is not a content-addressed firecracker artifact", { rootfsKey });
  return m[1]!;
}

/** Point 1: a function with no signed image digest on its row never boots. */
export function assertSignedImageDigest(imageDigest: string | null | undefined, functionName: string): void {
  if (typeof imageDigest !== "string" || !IMAGE_DIGEST.test(imageDigest)) {
    throw refuse("Sandbox function has no signed image digest on its deploy record; it is not booted", { functionName });
  }
}

const sha256Hex = (b: Uint8Array): string => createHash("sha256").update(b).digest("hex");

export type RootfsCacheResult = { path: string; hit: boolean; bytes: number };

/** The read size for hashing a cached rootfs. One reused buffer, so a hash costs this much memory, not the file. */
export const ROOTFS_HASH_CHUNK_BYTES = 1024 * 1024;

/**
 * The file's sha256 and size, streamed through one reused buffer. A rootfs is ~240 MiB: reading it whole (and copying
 * it) on every boot cost ~470 MiB of heap per invocation, and three invocations together OOM-killed a
 * host with a 1536 MiB memory limit.
 */
export async function sha256File(path: string, openFile: typeof open = open): Promise<{ hex: string; bytes: number }> {
  const fh = await openFile(path, "r");
  try {
    const h = createHash("sha256");
    const buf = new Uint8Array(ROOTFS_HASH_CHUNK_BYTES);
    let bytes = 0;
    for (;;) {
      const { bytesRead } = await fh.read(buf, 0, buf.length, null);
      if (bytesRead === 0) break;
      h.update(buf.subarray(0, bytesRead));
      bytes += bytesRead;
    }
    return { hex: h.digest("hex"), bytes };
  } finally {
    await fh.close();
  }
}

/** Fetches in flight, by digest: concurrent first boots of one function share one fetch, so it is held in memory once. */
const inflightFetches = new Map<string, Promise<RootfsCacheResult>>();

/**
 * Points 1 and 2: the verified rootfs, from the cache or the store. A cache hit is re-hashed on EVERY call (every
 * boot); a mismatch deletes the file and refuses. A miss is fetched, hashed, written to a temp name and renamed in,
 * mode 0444, so a reader never sees a partial file.
 */
export async function materializeVerifiedRootfs(args: {
  rootfsKey: string;
  cacheDir: string;
  storage: ArtifactStore | null;
  /** Test seam: the cache-hit hash (default {@link sha256File}). */
  hashFile?: (path: string) => Promise<{ hex: string; bytes: number }>;
}): Promise<RootfsCacheResult> {
  const digest = rootfsDigestFromKey(args.rootfsKey);
  const path = join(args.cacheDir, `${digest}.ext4`);
  try {
    const cached = await (args.hashFile ?? sha256File)(path);
    if (cached.hex === digest) return { path, hit: true, bytes: cached.bytes };
    await rm(path, { force: true });
    throw refuse("Cached sandbox rootfs failed its digest check and was removed", { rootfsKey: args.rootfsKey });
  } catch (e) {
    if (e instanceof FunctionVmRefused) throw e;
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  }
  if (args.storage === null) {
    throw refuse("Sandbox rootfs read credential is not provisioned on this host", { rootfsKey: args.rootfsKey });
  }
  const running = inflightFetches.get(path);
  if (running !== undefined) return running;
  const p = fetchVerifyAndCache(args.rootfsKey, args.storage, args.cacheDir, path, digest);
  inflightFetches.set(path, p);
  try {
    return await p;
  } finally {
    inflightFetches.delete(path);
  }
}

/** A miss: fetch, hash, write to a temp name and rename in, mode 0444. The fetched buffer is never copied. */
async function fetchVerifyAndCache(rootfsKey: string, storage: ArtifactStore, cacheDir: string, path: string, digest: string): Promise<RootfsCacheResult> {
  const args = { rootfsKey };
  const bytes = await storage.fetchArtifact(rootfsKey);
  if (sha256Hex(bytes) !== digest) {
    throw refuse("Sandbox rootfs from the store does not match its content-addressed key", { rootfsKey: args.rootfsKey });
  }
  await mkdir(cacheDir, { recursive: true, mode: 0o755 });
  const tmp = `${path}.${process.pid}.${Date.now()}.part`;
  const fh = await open(tmp, "wx", 0o444);
  try {
    await fh.writeFile(bytes);
  } finally {
    await fh.close();
  }
  await chmod(tmp, 0o444);
  await rename(tmp, path);
  return { path, hit: false, bytes: bytes.length };
}

export type FunctionVm = {
  vmId: string;
  handle: FirecrackerHandle;
  /** Host path of the VM's vsock UDS (inside its chroot). */
  udsPath: string;
  jailUid: number;
  /** The guest's k9o-init and kernel-panic console lines, at most 2 KB (empty if none). For a failure's log line. */
  consoleDiagnostics(): string;
  /** Shut down, remove the chroot, drop the cgroup placement. Idempotent; never throws. */
  dispose(): Promise<void>;
};

export type BootFunctionVmArgs = {
  /** Defaults to the host's client ({@link useFunctionVmClient}). */
  client?: FirecrackerClient;
  vmId: string;
  rootfsPath: string;
  kernelPath: string;
  /** Uids already held by other jailed VMs (the warm pool's and other function VMs'). */
  usedUids: ReadonlySet<number>;
  memSizeMib?: number;
  jailerConfig?: JailerConfig;
  stage?: (input: StageJailedSlotInput) => Promise<StageJailedSlotResult>;
};

const liveFunctionVmUids = new Set<number>();
/** Uids held by live function VMs, for the warm pool's allocator and the next boot. */
export function functionVmUidsInUse(): ReadonlySet<number> {
  return liveFunctionVmUids;
}

/** Points 2, 4 and 5: spawn under the jailer, stage, configure, assert the topology, start. */
export async function bootFunctionVm(args: BootFunctionVmArgs): Promise<FunctionVm> {
  const client = args.client ?? getFunctionVmClient();
  const jc = args.jailerConfig ?? loadJailerConfig();
  const used = new Set<number>([...args.usedUids, ...liveFunctionVmUids]);
  const uid = allocateSlotUid(args.vmId, used, jc.uidFloor, jc.uidCeiling);
  liveFunctionVmUids.add(uid);
  let handle: FirecrackerHandle | null = null;
  let disposed = false;
  const dispose = async (): Promise<void> => {
    if (disposed) return;
    disposed = true;
    if (handle !== null) {
      await client.shutdown(handle).catch(() => {});
      if (handle.chrootDir !== undefined) await rm(handle.chrootDir, { recursive: true, force: true }).catch(() => {});
    }
    try {
      getCgroupPlacer().remove(args.vmId);
    } catch {
      /* placement is best-effort, as for warm slots */
    }
    liveFunctionVmUids.delete(uid);
  };
  try {
    handle = await client.spawn({ jail: { vmSlotId: args.vmId, uid, jailerConfig: jc } });
    if (handle.chrootDir === undefined) throw refuse("Function VM did not spawn under the jailer", { vmId: args.vmId });
    await (args.stage ?? stageJailedSlot)({
      chrootDir: handle.chrootDir,
      files: [args.kernelPath, args.rootfsPath],
      vsockUdsPath: FUNCTION_VM_VSOCK_PATH,
      uid,
      gid: uid,
      cacheDir: `${jc.chrootRoot}/pool/.staged`,
    });
    await client.configureMachine(handle, { vcpuCount: 1, memSizeMib: args.memSizeMib ?? 256, smt: false });
    await client.configureBootSource(handle, { kernelImagePath: args.kernelPath, bootArgs: DEFAULT_GUEST_BOOT_ARGS });
    await client.addDrive(handle, { driveId: "rootfs", pathOnHost: args.rootfsPath, isRootDevice: true, isReadOnly: true });
    await client.addVsock(handle, { guestCid: FUNCTION_VM_GUEST_CID, udsPath: FUNCTION_VM_VSOCK_PATH });
    let vmConfig: unknown;
    try {
      vmConfig = await client.getVmConfig(handle);
    } catch (err) {
      throw refuse("Function VM /vm/config could not be measured; a jailed VM is not started unmeasured", {
        vmId: args.vmId,
        reason: err instanceof Error ? err.message.slice(0, 200) : String(err),
      });
    }
    assertExecSeamTopology(vmConfig);
    assertReadOnlyRootDrive(vmConfig);
    getCgroupPlacer().place(args.vmId, handle.pid);
    await client.action(handle, "InstanceStart");
    const booted = handle;
    return {
      vmId: args.vmId,
      handle: booted,
      udsPath: `${booted.chrootDir}/root${FUNCTION_VM_VSOCK_PATH}`,
      jailUid: uid,
      consoleDiagnostics: () => consoleDiagnosticLines(client.guestConsoleTail?.(booted) ?? ""),
      dispose,
    };
  } catch (e) {
    await dispose();
    throw e;
  }
}

/** Point 2 at the measured config, not just at the call: exactly one drive, the root, read-only. */
export function assertReadOnlyRootDrive(vmConfig: unknown): void {
  const drives = (vmConfig as { drives?: unknown } | null)?.drives;
  const ok =
    Array.isArray(drives) &&
    drives.length === 1 &&
    (drives[0] as { is_root_device?: unknown }).is_root_device === true &&
    (drives[0] as { is_read_only?: unknown }).is_read_only === true;
  if (!ok) throw refuse("Function VM must have exactly one read-only root drive", { drives: Array.isArray(drives) ? drives.length : null });
}

/** The function VM's settings from env. Null ⇒ this host cannot boot function VMs (no kernel configured). */
export function functionVmEnv(env: NodeJS.ProcessEnv = process.env): { kernelPath: string; cacheDir: string } | null {
  const kernelPath = (env.K9O_EXEC_RUNTIME_KERNEL ?? "").trim();
  if (kernelPath === "") return null;
  const chrootRoot = (env.K9O_JAILER_CHROOT_ROOT ?? "/var/lib/k9o/jails").trim();
  const cacheDir = (env.K9O_EXEC_ROOTFS_CACHE_DIR ?? "").trim() || `${chrootRoot}/pool/.rootfs-cache`;
  return { kernelPath, cacheDir };
}

/** Exposed for tests: the file's mode and size, to assert 0444 on a cached rootfs. */
export async function cachedFileMode(path: string): Promise<number> {
  return (await stat(path)).mode & 0o777;
}

// ── Dispatch helpers ─────────────────────────────────────────────────────────────────────────────────────────────

/** How long a just-started VM may take before its k9o-init and the extension answer (5 s). */
export const FUNCTION_VM_BOOT_BUDGET_MS = 5_000;

/** k9o-init's own 503 when the extension's invoke server is not up yet (guest/k9o-init/src/proxy.rs). Nothing was
 *  delivered to the extension, so a retry cannot run it twice. */
export function isInitNotReady(response: { status: number; body: Uint8Array }): boolean {
  if (response.status !== 503) return false;
  return new TextDecoder().decode(response.body.slice(0, 512)).includes("extension invoke server is not reachable");
}

/** A jailer-safe VM id per invocation (alphanumerics and dashes, at most 64). */
export function functionVmIdFor(invocationId: string): string {
  const clean = invocationId.replace(/[^A-Za-z0-9-]/g, "-").slice(0, 48);
  return `fn-${clean}-${Math.random().toString(36).slice(2, 8)}`;
}

let _client: FirecrackerClient | null = null;
/** The Firecracker client function VMs boot through. Set at boot (index.ts); a test injects a mock. */
export function useFunctionVmClient(client: FirecrackerClient | null): void {
  _client = client;
}
export function getFunctionVmClient(): FirecrackerClient {
  if (_client === null) throw refuse("Function VM client is not initialised on this host", {});
  return _client;
}

let _readStorage: ArtifactStore | null = null;
/** Install the store function rootfs images are fetched from (null ⇒ not provisioned ⇒ a fetch refuses). */
export function useRootfsReadStorage(store: ArtifactStore | null): void {
  _readStorage = store;
}
/** The installed rootfs store, or null when none was provisioned. */
export function getRootfsReadStorage(): ArtifactStore | null {
  return _readStorage;
}
export function _setRootfsReadStorageForTest(s: ArtifactStore | null | undefined): void {
  _readStorage = s ?? null;
}

// Cap concurrent function VMs per project and per host, so one
// project's invokes cannot starve the host. A refusal is a 429, never a queue.
const runningByProject = new Map<string, number>();
let runningOnHost = 0;
function capFromEnv(name: string, fallback: number): number {
  const n = Number.parseInt((process.env[name] ?? "").trim(), 10);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}
/** Admit one function VM for `projectId`, or say which cap refused it. Pair every admit with {@link releaseFunctionVm}. */
export function admitFunctionVm(projectId: string): { scope: "project" | "host"; limit: number } | null {
  const perProject = capFromEnv("K9O_EXEC_FN_VMS_PER_PROJECT", 4);
  const perHost = capFromEnv("K9O_EXEC_FN_VMS_PER_HOST", 16);
  if (runningOnHost >= perHost) return { scope: "host", limit: perHost };
  const mine = runningByProject.get(projectId) ?? 0;
  if (mine >= perProject) return { scope: "project", limit: perProject };
  runningByProject.set(projectId, mine + 1);
  runningOnHost++;
  return null;
}
export function releaseFunctionVm(projectId: string): void {
  const mine = runningByProject.get(projectId) ?? 0;
  if (mine <= 1) runningByProject.delete(projectId);
  else runningByProject.set(projectId, mine - 1);
  if (runningOnHost > 0) runningOnHost--;
}
export function _resetFunctionVmAdmissionForTest(): void {
  runningByProject.clear();
  runningOnHost = 0;
}

// ── Test seam ────────────────────────────────────────────────────────────────────────────────────────────────────
// Dispatch tests run without KVM, a jailer or a store: they replace the host environment, the fetch-and-verify step
// and the boot. Production never sets it; `functionVmOps()` then returns the real steps.
export type FunctionVmOps = {
  env: () => { kernelPath: string; cacheDir: string } | null;
  materialize: typeof materializeVerifiedRootfs;
  boot: typeof bootFunctionVm;
};
let _opsOverride: Partial<FunctionVmOps> | null = null;
export function _setFunctionVmOpsForTest(ops: Partial<FunctionVmOps> | null): void {
  _opsOverride = ops;
}
export function functionVmOps(): FunctionVmOps {
  return {
    env: _opsOverride?.env ?? (() => functionVmEnv()),
    materialize: _opsOverride?.materialize ?? materializeVerifiedRootfs,
    boot: _opsOverride?.boot ?? bootFunctionVm,
  };
}

/**
 * The console lines worth a failure's log: k9o-init's own messages and kernel panics, at most 2 KB, newest kept.
 * Only these: the console also carries the function's own stdout, which is the customer's and stays out of our logs.
 * Firecracker's serial output arrives in fragments with CR line ends, so it is re-joined first.
 */
export const CONSOLE_DIAGNOSTIC_BYTES = 2048;
export function consoleDiagnosticLines(raw: string): string {
  const lines = raw.replace(/\r\n?/g, "\n").split("\n").map((l) => l.trim());
  const kept = lines.filter((l) => l.startsWith("k9o-init:") || /Kernel panic|Run \/usr\/bin\/k9o-init|devtmpfs: error/.test(l));
  const joined = kept.join("\n");
  return joined.length > CONSOLE_DIAGNOSTIC_BYTES ? joined.slice(-CONSOLE_DIAGNOSTIC_BYTES) : joined;
}
