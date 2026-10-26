/**
 * Host-side Firecracker HTTP API client.
 *
 * The Platform
 * tier dispatcher spawns Firecracker MicroVMs through the standard
 * Unix-socket HTTP API. This module wraps that surface — process
 * spawn, socket bind, machine-config / boot-source / drives / actions
 * / snapshot API calls, teardown — into a typed TypeScript surface
 * that the pool implementation (v2.3.1) consumes.
 *
 * Two implementations behind the `FirecrackerClient` interface:
 *
 *   - `RealFirecrackerClient` — spawns a real `firecracker` process,
 *     binds a Unix socket, sends HTTP API calls. Linux + KVM only.
 *     Exercised in integration tests on a Linux + KVM host (the
 *     macOS-dev-via-SSH workflow).
 *
 *   - `MockFirecrackerClient` — in-process state machine that mimics
 *     the API responses without spawning anything. Used for unit
 *     tests on macOS where Firecracker cannot run; lets the pool
 *     implementation be unit-testable end-to-end without Linux.
 *
 * The DI surface mirrors `storage/client.ts` and `db/pool.ts` —
 * `getFirecrackerClient()` returns the singleton; tests inject via
 * `useTestFirecrackerClient(...)`.
 */

import { Socket } from "node:net";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdir, rm, stat, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import {
  synthesiseSlotJail,
  loadJailerConfig,
  type JailerConfig,
} from "./jailer-wrapper.ts";

/**
 * Identifier for a running Firecracker MicroVM. Each instance has a
 * unique identifier used for logging, audit, and debug traceability;
 * this matches the `--id` CLI flag Firecracker accepts.
 */
export type MicroVmId = string;

export type MachineConfig = {
  /** Number of vCPUs to allocate. The sandbox tier defaults to 1. */
  vcpuCount: number;
  /** Guest memory in MiB. The sandbox tier caps at 128 by default; tier-tunable up to 1024 (premium). */
  memSizeMib: number;
  /** Symmetric multi-threading toggle (Firecracker rejects true on most kernels; default false). */
  smt?: boolean;
};

/**
 * The default sandbox tier kernel command-line. `init=/usr/bin/k9o-init`
 * is load-bearing: the OCI converter injects the k9o-init guest agent at that
 * path, and the kernel must run it as PID 1 (not the image's own entrypoint,
 * which k9o-init execs itself after setting up the vsock bridges). A base
 * snapshot / cold boot MUST use this line (or otherwise carry `init=`), or the
 * guest boots without the invocation server and every dispatch times out.
 */
export const DEFAULT_GUEST_BOOT_ARGS =
  "console=ttyS0 reboot=k panic=1 pci=off init=/usr/bin/k9o-init";

export type BootSource = {
  /** Absolute path on the host to the Linux kernel image. */
  kernelImagePath: string;
  /**
   * Kernel command-line. Use {@link DEFAULT_GUEST_BOOT_ARGS} for the Platform
   * tier — it carries `init=/usr/bin/k9o-init`, without which the guest agent
   * never runs.
   */
  bootArgs: string;
};

export type Drive = {
  /** Drive identifier — Firecracker requires a unique string per-drive. */
  driveId: string;
  /** Absolute path on the host to the rootfs / data drive image. */
  pathOnHost: string;
  /** True if this drive is the rootfs (mounted as /). */
  isRootDevice: boolean;
  /** True if read-only. The k9o-init rootfs is always read-only; ephemeral state lives in the /var tmpfs. */
  isReadOnly: boolean;
};

export type VsockDevice = {
  /** Guest CID — must be >= 3 (CID 0/1 reserved; 2 is the host). */
  guestCid: number;
  /** Host-side Unix socket path that vsock connections route to. */
  udsPath: string;
};

export type SnapshotConfig = {
  snapshotPath: string;
  memoryFilePath: string;
};

export type SnapshotLoadConfig = {
  snapshotPath: string;
  memoryFilePath: string;
  /** True to resume immediately on load; false to leave in Paused state (warm-pool pre-load). */
  resumeVm: boolean;
};

/**
 * Discriminant of the action sent through the /actions endpoint. The
 * sandbox tier uses InstanceStart for cold-spawn; SendCtrlAltDel
 * for graceful guest shutdown; FlushMetrics for observability sweeps.
 */
export type ActionType = "InstanceStart" | "SendCtrlAltDel" | "FlushMetrics";

/**
 * Lifecycle state of a Firecracker handle from the host's
 * perspective. Distinct from the guest's internal VM state.
 */
export type HandleState = "spawning" | "ready" | "running" | "paused" | "closed";

/**
 * Per-MicroVM handle. Carries the API socket path + child-process
 * reference + identifier for audit. Returned by `spawn()`; consumed by
 * subsequent API calls.
 */
export type FirecrackerHandle = {
  id: MicroVmId;
  apiSocketPath: string;
  state: HandleState;
  /**
   * OS pid of the firecracker child. The pool moves this into the slot's own
   * cgroup for per-VM resource attribution (vm-slot-cgroup-placer.ts).
   * Undefined if the process never reported a pid (spawn race) — the placer
   * treats that as "nothing to place" and attribution degrades to null.
   */
  pid?: number;
  /**
   * The jailer chroot directory this VM was spawned under, or undefined for a bare (non-jailed) spawn.
   * When set, every host-visible path for this VM (its API socket, its vsock UDS) lives UNDER
   * `<chrootDir>/root/…` because the jailer chroots Firecracker. The
   * pool records this on the slot so `vsockUdsPathForSlot` resolves the baked vsock path under the
   * per-slot chroot, which is what makes two slots' identical baked `uds_path` stop colliding.
   */
  chrootDir?: string;
};

/**
 * Parameters for a JAILED spawn. Absent ⇒ the legacy bare spawn,
 * byte-identical to prior behaviour. Present ⇒ Firecracker is exec'd by the jailer under a per-slot
 * chroot with a distinct uid + its own cgroup. `uid` is an INPUT (allocated by the pool via
 * `allocateSlotUid` against the live-slot set) — never derived here, so distinctness holds against
 * reality. `jailerConfig` defaults to `loadJailerConfig()`; injected in tests.
 */
export type JailSpawnSpec = {
  vmSlotId: string;
  uid: number;
  jailerConfig?: JailerConfig;
};

/**
 * Errors raised by the Firecracker client. Mapped to KError shapes by
 * the caller (invoke.ts) — different operations map to different KError
 * codes (timeout vs. bad-request vs. upstream-unavailable).
 */
export class FirecrackerClientError extends Error {
  readonly operation: string;
  readonly status?: number;
  readonly detail?: string;
  constructor(operation: string, message: string, opts: { status?: number; detail?: string } = {}) {
    // 🔴 status/detail were CAPTURED at the throw site and then DISCARDED before reaching any log
    // line that reads only `.message` — seen in a prior warm-pool incident. `put()` builds
    // `{ status, detail: respBody… }` on every non-2xx and hands it here; this constructor stored
    // both as properties for a structured caller (per the class doc, invoke.ts's KError mapping) but
    // never folded them into `.message`. index.ts's warm-pool `.then(..., err => console.error({
    // error: err.message }))` therefore logged exactly "Firecracker PUT /snapshot/load: non-2xx
    // response" — the one piece of information that would explain WHY (the actual Firecracker HTTP
    // status and response body) was silently dropped at the exact moment it mattered. Same shape as
    // the errno-discarding recvHandoff catch and the receiveFault-omitting decode catch fixed
    // earlier this week: information captured once, then thrown away before the log line a human
    // reads. Folding it into `.message` fixes every consumer that logs the error generically,
    // without touching `.status`/`.detail` for a caller that branches on them structurally.
    const diagnostic =
      opts.status !== undefined
        ? ` (status ${opts.status}${opts.detail !== undefined && opts.detail !== "" ? `, body: ${opts.detail}` : ""})`
        : "";
    super(`Firecracker ${operation}: ${message}${diagnostic}`);
    this.name = "FirecrackerClientError";
    this.operation = operation;
    if (opts.status !== undefined) this.status = opts.status;
    if (opts.detail !== undefined) this.detail = opts.detail;
  }
}

/**
 * The narrow HTTP-API surface the pool + executor consume. Implementations:
 *
 *   - `RealFirecrackerClient` (production; Linux + KVM)
 *   - `MockFirecrackerClient` (unit tests on macOS)
 *
 * Lifecycle ordering: `spawn` → `configureMachine` → `configureBootSource`
 * → `addDrive`* → optional `addVsock` → `start`. For warm-pool slots:
 * `spawn` → `loadSnapshot` (paused) → on-demand `resume`.
 */
export interface FirecrackerClient {
  /** The last bytes of this VM's guest console (serial), or "" when none were captured. Optional: diagnostics only. */
  guestConsoleTail?(handle: FirecrackerHandle): string;
  /**
   * Spawn a fresh Firecracker process bound to a unique Unix socket.
   * Returns once the API socket is reachable (i.e., Firecracker is
   * ready to accept configuration).
   *
   * @throws FirecrackerClientError if the process fails to spawn or
   *   the socket doesn't become reachable within the timeout.
   */
  spawn(opts?: { id?: MicroVmId; spawnTimeoutMs?: number; jail?: JailSpawnSpec }): Promise<FirecrackerHandle>;

  /** Configure machine resources. Must be called before `start`. */
  configureMachine(handle: FirecrackerHandle, cfg: MachineConfig): Promise<void>;

  /** Configure boot source (kernel + cmdline). Must be called before `start`. */
  configureBootSource(handle: FirecrackerHandle, src: BootSource): Promise<void>;

  /** Add a block device. At least one must be the root device (rootfs). */
  addDrive(handle: FirecrackerHandle, drive: Drive): Promise<void>;

  /** Add a vsock device (vsock IPC contract). */
  addVsock(handle: FirecrackerHandle, dev: VsockDevice): Promise<void>;

  /** Send an action to the running VM. */
  action(handle: FirecrackerHandle, action: ActionType): Promise<void>;

  /** Pause a running VM. */
  pause(handle: FirecrackerHandle): Promise<void>;

  /** Resume a paused VM. */
  resume(handle: FirecrackerHandle): Promise<void>;

  /** Take a full snapshot of a paused VM (state file + memory file). */
  createSnapshot(handle: FirecrackerHandle, cfg: SnapshotConfig): Promise<void>;

  /**
   * GET the full exported VM configuration Firecracker booted to. Used to
   * assert the exec-seam invariant against the actual artifact (no NIC, one
   * vsock) rather than only the source.
   */
  getVmConfig(handle: FirecrackerHandle): Promise<unknown>;

  /**
   * Load a snapshot into a fresh Firecracker instance. The handle must
   * have just been `spawn()`'d — no machine-config, no boot-source, no
   * drives. After load, the VM is in Paused state if `resumeVm: false`
   * (the warm-pool pre-load shape).
   */
  loadSnapshot(handle: FirecrackerHandle, cfg: SnapshotLoadConfig): Promise<void>;

  /**
   * Tear down the Firecracker process + clean up the API socket.
   * Idempotent. Errors during teardown are swallowed — the caller's
   * responsibility to ensure resources are released even if cleanup
   * is partial.
   */
  shutdown(handle: FirecrackerHandle): Promise<void>;
}

// ----------------------------------------------------------------------
// Real implementation (Linux + KVM)
// ----------------------------------------------------------------------

const DEFAULT_SPAWN_TIMEOUT_MS = 5000;
const DEFAULT_FIRECRACKER_BIN = "/usr/local/bin/firecracker";

function loadFirecrackerBinPath(): string {
  return process.env.K9O_FIRECRACKER_BIN ?? DEFAULT_FIRECRACKER_BIN;
}

function loadApiSocketDir(): string {
  return process.env.K9O_FIRECRACKER_SOCKET_DIR ?? "/tmp/k9o-firecracker";
}

const EMPTY_BUFFER = Buffer.alloc(0);

/**
 * Decode an HTTP/1.1 chunked-transfer body. Returns the assembled body
 * once the terminating zero-length chunk has been received, or `null`
 * if the buffer does not yet contain a complete chunked stream (caller
 * should await more bytes). Trailers, if any, are ignored.
 *
 * Firecracker's API server frames with Content-Length in practice; this
 * exists so the client is a correct HTTP/1.1 reader rather than one that
 * happens to work against today's server.
 */
function decodeChunked(buf: Buffer): Buffer | null {
  const parts: Buffer[] = [];
  let offset = 0;
  for (;;) {
    const lineEnd = buf.indexOf("\r\n", offset);
    if (lineEnd < 0) return null; // chunk-size line incomplete
    const sizeToken = buf.toString("latin1", offset, lineEnd).trim();
    const semi = sizeToken.indexOf(";"); // strip any chunk extensions
    const size = Number.parseInt(semi >= 0 ? sizeToken.slice(0, semi) : sizeToken, 16);
    if (Number.isNaN(size)) return null; // malformed — treat as incomplete
    if (size === 0) return Buffer.concat(parts); // terminal chunk
    const dataStart = lineEnd + 2;
    const dataEnd = dataStart + size;
    if (buf.length < dataEnd + 2) return null; // full chunk + CRLF not yet here
    parts.push(buf.subarray(dataStart, dataEnd));
    offset = dataEnd + 2; // skip the chunk's trailing CRLF
  }
}

/**
 * The absolute vsock UDS path baked INTO the base snapshot at creation time. A Firecracker snapshot
 * stores the vsock `uds_path` as an absolute string and re-binds it verbatim on restore, so the runtime
 * MUST resolve the live socket from this same value — inventing a different convention (as the pre-fix
 * `vsockUdsPathForSlot` did) produces a path nothing ever binds. Single-sourced here so snapshot creation
 * (`create-base-snapshot.ts`) and the runtime cannot drift.
 */
export const BAKED_SNAPSHOT_VSOCK_UDS_DEFAULT = "/tmp/k9o-base-snapshot.vsock";

export function bakedSnapshotVsockUdsPath(env: NodeJS.ProcessEnv = process.env): string {
  const v = env.K9O_EXEC_RUNTIME_SNAPSHOT_VSOCK_UDS;
  return v !== undefined && v !== "" ? v : BAKED_SNAPSHOT_VSOCK_UDS_DEFAULT;
}

/**
 * Combine the jailer argv with Firecracker's own argv. `jailer` consumes its flags up to `--`, then
 * exec's `--exec-file` passing everything AFTER `--` through to Firecracker. Pure so the composition is
 * unit-provable without a jailer install; the live spawn is validated on the cluster before the flag flips.
 */
export function buildJailedFirecrackerArgv(jailerArgs: readonly string[], firecrackerArgs: readonly string[]): string[] {
  return [...jailerArgs, "--", ...firecrackerArgs];
}

export class RealFirecrackerClient implements FirecrackerClient {
  private readonly binaryPath: string;
  private readonly socketDir: string;
  private readonly children = new Map<MicroVmId, ChildProcess>();
  private readonly consoles = new Map<MicroVmId, string>();

  guestConsoleTail(handle: FirecrackerHandle): string {
    return this.consoles.get(handle.id) ?? "";
  }

  constructor(opts: { binaryPath?: string; socketDir?: string } = {}) {
    this.binaryPath = opts.binaryPath ?? loadFirecrackerBinPath();
    this.socketDir = opts.socketDir ?? loadApiSocketDir();
  }

  async spawn(opts: { id?: MicroVmId; spawnTimeoutMs?: number; jail?: JailSpawnSpec } = {}): Promise<FirecrackerHandle> {
    const id = opts.id ?? mintMicroVmId();

    // ── Resolve WHAT to spawn and WHERE the host-visible API socket lands ──────────────────────────
    // Non-jailed (default): spawn firecracker directly, socket in `this.socketDir`. Jailed
    // Jailed: spawn the JAILER, which chroots firecracker under a per-slot
    // root, so firecracker's `--api-sock <p>` binds at `<chrootDir>/root<p>` on the host. The host process
    // then talks to that host path exactly as before — the rest of the lifecycle is path-agnostic.
    let binaryToSpawn: string;
    let argv: string[];
    let apiSocketPath: string;
    let chrootDir: string | undefined;
    if (opts.jail !== undefined) {
      const jailerConfig = opts.jail.jailerConfig ?? loadJailerConfig();
      const cmd = synthesiseSlotJail(
        { vmSlotId: opts.jail.vmSlotId, firecrackerBinaryPath: this.binaryPath },
        opts.jail.uid,
        jailerConfig,
      );
      await mkdir(dirname(cmd.chrootDir), { recursive: true });
      // Firecracker's API socket, as an in-chroot absolute path; host-visible under `<chrootDir>/root`
      // (validated landing point: `<chrootDir>/root/run/firecracker.sock`).
      const inChrootApiSocket = "/run/firecracker.sock";
      binaryToSpawn = jailerConfig.jailerBinaryPath;
      // 🔴 NO `--id` in the Firecracker args — the jailer INJECTS `--id <jail-id>` when it exec's
      // Firecracker, so an explicit one is a DuplicateArgument and Firecracker exits 153 (validated).
      // Seccomp is Firecracker's built-in filter (no flag) — see synthesiseSlotJail for why.
      argv = buildJailedFirecrackerArgv(cmd.args, ["--api-sock", inChrootApiSocket, "--level", "Warn"]);
      apiSocketPath = `${cmd.chrootDir}/root${inChrootApiSocket}`;
      chrootDir = cmd.chrootDir;
    } else {
      await mkdir(this.socketDir, { recursive: true });
      apiSocketPath = `${this.socketDir}/${id}.sock`;
      await rm(apiSocketPath, { force: true });
      binaryToSpawn = this.binaryPath;
      argv = ["--api-sock", apiSocketPath, "--id", id, "--level", "Warn"];
    }

    const child = spawn(binaryToSpawn, argv, { stdio: ["ignore", "pipe", "pipe"] });

    let stderr = "";
    child.stderr?.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    // Guest console capture. Firecracker forwards the guest serial (the kernel's
    // `console=ttyS0` + k9o-init's own stdout/stderr — e.g. "warm-pool-idle",
    // panic messages, a gate-probe's output) to ITS stdout; Firecracker's own
    // logs go to stderr (--level). We ignored stdout before, so post-boot guest
    // behaviour could only be inferred from the exit code. Keep a bounded tail
    // for diagnostics, and stream it (prefixed) when K9O_FIRECRACKER_GUEST_CONSOLE=1
    // so a base-snapshot probe run SHOWS k9o-init's log lines directly rather
    // than inferring them. Off by default so the warm pool (many VMs) stays quiet.
    const streamGuestConsole = process.env.K9O_FIRECRACKER_GUEST_CONSOLE === "1";
    let guestConsole = "";
    child.stdout?.on("data", (chunk) => {
      const text = chunk.toString();
      guestConsole = (guestConsole + text).slice(-16384);
      this.consoles.set(id, guestConsole);
      if (streamGuestConsole) {
        for (const line of text.split("\n")) {
          if (line.length > 0) process.stderr.write(`[fc-guest:${id}] ${line}\n`);
        }
      }
    });

    this.children.set(id, child);

    // Wait for the API socket to become reachable.
    const timeout = opts.spawnTimeoutMs ?? DEFAULT_SPAWN_TIMEOUT_MS;
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      if (child.exitCode !== null) {
        throw new FirecrackerClientError(
          "spawn",
          `firecracker exited with code ${child.exitCode} before binding socket`,
          { detail: `${stderr.slice(0, 500)}${guestConsole ? ` | guest-console: ${guestConsole.slice(-500)}` : ""}` },
        );
      }
      try {
        const stats = await stat(apiSocketPath);
        if (stats.isSocket()) break;
      } catch {
        // Socket not yet created; wait briefly and retry.
      }
      await new Promise((r) => setTimeout(r, 5));
    }
    if (Date.now() >= deadline) {
      child.kill("SIGKILL");
      this.children.delete(id);
      throw new FirecrackerClientError("spawn", `socket not reachable within ${timeout}ms`, {
        detail: stderr.slice(0, 500),
      });
    }

    return {
      id,
      apiSocketPath,
      state: "ready",
      ...(child.pid !== undefined ? { pid: child.pid } : {}),
      ...(chrootDir !== undefined ? { chrootDir } : {}),
    };
  }

  async configureMachine(handle: FirecrackerHandle, cfg: MachineConfig): Promise<void> {
    await this.put(handle, "/machine-config", {
      vcpu_count: cfg.vcpuCount,
      mem_size_mib: cfg.memSizeMib,
      smt: cfg.smt ?? false,
    });
  }

  async configureBootSource(handle: FirecrackerHandle, src: BootSource): Promise<void> {
    await this.put(handle, "/boot-source", {
      kernel_image_path: src.kernelImagePath,
      boot_args: src.bootArgs,
    });
  }

  async addDrive(handle: FirecrackerHandle, drive: Drive): Promise<void> {
    await this.put(handle, `/drives/${encodeURIComponent(drive.driveId)}`, {
      drive_id: drive.driveId,
      path_on_host: drive.pathOnHost,
      is_root_device: drive.isRootDevice,
      is_read_only: drive.isReadOnly,
    });
  }

  async addVsock(handle: FirecrackerHandle, dev: VsockDevice): Promise<void> {
    await this.put(handle, "/vsock", {
      guest_cid: dev.guestCid,
      uds_path: dev.udsPath,
    });
  }

  async action(handle: FirecrackerHandle, action: ActionType): Promise<void> {
    await this.put(handle, "/actions", { action_type: action });
    if (action === "InstanceStart") handle.state = "running";
  }

  async pause(handle: FirecrackerHandle): Promise<void> {
    await this.patch(handle, "/vm", { state: "Paused" });
    handle.state = "paused";
  }

  async resume(handle: FirecrackerHandle): Promise<void> {
    await this.patch(handle, "/vm", { state: "Resumed" });
    handle.state = "running";
  }

  async createSnapshot(handle: FirecrackerHandle, cfg: SnapshotConfig): Promise<void> {
    await mkdir(dirname(cfg.snapshotPath), { recursive: true });
    await this.put(handle, "/snapshot/create", {
      snapshot_type: "Full",
      snapshot_path: cfg.snapshotPath,
      mem_file_path: cfg.memoryFilePath,
    });
  }

  async loadSnapshot(handle: FirecrackerHandle, cfg: SnapshotLoadConfig): Promise<void> {
    await this.put(handle, "/snapshot/load", {
      snapshot_path: cfg.snapshotPath,
      mem_backend: { backend_type: "File", backend_path: cfg.memoryFilePath },
      resume_vm: cfg.resumeVm,
    });
    handle.state = cfg.resumeVm ? "running" : "paused";
  }

  async shutdown(handle: FirecrackerHandle): Promise<void> {
    if (handle.state === "closed") return;
    const child = this.children.get(handle.id);
    if (child !== undefined && child.exitCode === null) {
      child.kill("SIGKILL");
      try {
        await new Promise<void>((resolve) => child.once("exit", () => resolve()));
      } catch {
        // ignore
      }
    }
    this.children.delete(handle.id);
    this.consoles.delete(handle.id);
    await rm(handle.apiSocketPath, { force: true }).catch(() => {});
    handle.state = "closed";
  }

  // ------------------------------------------------------------------
  // HTTP-over-Unix-socket plumbing
  // ------------------------------------------------------------------

  private async put(handle: FirecrackerHandle, path: string, body: unknown): Promise<void> {
    await this.request(handle, "PUT", path, body);
  }

  private async patch(handle: FirecrackerHandle, path: string, body: unknown): Promise<void> {
    await this.request(handle, "PATCH", path, body);
  }

  private get(handle: FirecrackerHandle, path: string): Promise<Buffer> {
    return this.request(handle, "GET", path, undefined);
  }

  /**
   * GET /vm/config — the full exported VM configuration Firecracker booted to.
   * Used by create-base-snapshot to assert the no-NIC / one-vsock exec-seam
   * property against the actual artifact (not just the source).
   */
  async getVmConfig(handle: FirecrackerHandle): Promise<unknown> {
    const body = await this.get(handle, "/vm/config");
    const text = body.toString("utf8");
    try {
      return JSON.parse(text);
    } catch {
      throw new FirecrackerClientError("GET /vm/config", "response was not valid JSON", {
        detail: text.slice(0, 500),
      });
    }
  }

  private async request(handle: FirecrackerHandle, method: string, path: string, body: unknown): Promise<Buffer> {
    if (handle.state === "closed") {
      throw new FirecrackerClientError(`${method} ${path}`, "handle is closed");
    }
    const payload = body !== undefined ? JSON.stringify(body) : "";
    return new Promise<Buffer>((resolve, reject) => {
      const sock = new Socket();
      const chunks: Buffer[] = [];
      let settled = false;

      const fail = (message: string, extra?: { status?: number; detail?: string }) => {
        if (settled) return;
        settled = true;
        sock.destroy();
        reject(new FirecrackerClientError(`${method} ${path}`, message, extra));
      };

      // Resolve/reject from a fully-framed response body. On 2xx the framed
      // body is handed back (empty Buffer for 204/no-body) so GET callers can
      // read it; put/patch await and discard it.
      const complete = (status: number, respBody: Buffer) => {
        if (settled) return;
        if (status >= 200 && status < 300) {
          settled = true;
          sock.destroy();
          resolve(respBody);
          return;
        }
        fail("non-2xx response", { status, detail: respBody.toString("utf8").slice(0, 500) });
      };

      // Attempt to frame a complete HTTP/1.1 response out of the bytes
      // received so far, resolving as soon as the message is complete.
      //
      // We MUST frame on Content-Length / Transfer-Encoding / no-body
      // status rather than waiting on the socket "end" event: the
      // Firecracker API server keeps the Unix socket open (HTTP
      // keep-alive) even though we send `Connection: close`, so "end"
      // may never fire. Success responses to config PUT/PATCH calls are
      // `204 No Content` — no body, socket left open — which is exactly
      // the case the old `end`-based reader hung on forever.
      const tryParse = () => {
        if (settled) return;
        const buf = Buffer.concat(chunks);
        const headerEnd = buf.indexOf("\r\n\r\n");
        if (headerEnd < 0) return; // headers not fully received yet

        const lines = buf.toString("latin1", 0, headerEnd).split("\r\n");
        const statusLine = lines[0] ?? "";
        const m = /^HTTP\/1\.[01] (\d{3})/.exec(statusLine);
        if (m === null) {
          fail(`malformed response: ${statusLine}`);
          return;
        }
        const status = Number.parseInt(m[1]!, 10);
        const bodyStart = headerEnd + 4;

        const headers = new Map<string, string>();
        for (let i = 1; i < lines.length; i++) {
          const c = lines[i]!.indexOf(":");
          if (c > 0) {
            headers.set(lines[i]!.slice(0, c).trim().toLowerCase(), lines[i]!.slice(c + 1).trim());
          }
        }

        // Statuses defined to carry no body (RFC 9110 section 6.4.1).
        if (status === 204 || status === 304) {
          complete(status, EMPTY_BUFFER);
          return;
        }

        const te = headers.get("transfer-encoding");
        if (te !== undefined && te.toLowerCase().includes("chunked")) {
          const decoded = decodeChunked(buf.subarray(bodyStart));
          if (decoded === null) return; // terminal 0-chunk not yet received
          complete(status, decoded);
          return;
        }

        const clHeader = headers.get("content-length");
        if (clHeader !== undefined) {
          const len = Number.parseInt(clHeader, 10);
          if (Number.isNaN(len) || len < 0) {
            fail(`invalid Content-Length: ${clHeader}`);
            return;
          }
          if (buf.length - bodyStart < len) return; // await the full body
          complete(status, buf.subarray(bodyStart, bodyStart + len));
          return;
        }

        // No framing headers: body is delimited by connection close.
        // Defer to the "end" handler below.
      };

      sock.once("error", (e) => fail(e.message));
      sock.on("data", (chunk) => {
        chunks.push(chunk as Buffer);
        tryParse();
      });
      sock.on("end", () => {
        if (settled) return;
        // Reached here only for a close-delimited response (no
        // Content-Length / chunked framing): the peer closing IS the
        // end-of-body signal, so whatever we have now is complete.
        const buf = Buffer.concat(chunks);
        const headerEnd = buf.indexOf("\r\n\r\n");
        if (headerEnd < 0) {
          fail("connection closed before response headers");
          return;
        }
        const statusLine = buf.toString("latin1", 0, buf.indexOf("\r\n"));
        const m = /^HTTP\/1\.[01] (\d{3})/.exec(statusLine);
        if (m === null) {
          fail(`malformed response: ${statusLine}`);
          return;
        }
        complete(Number.parseInt(m[1]!, 10), buf.subarray(headerEnd + 4));
      });

      sock.connect(handle.apiSocketPath, () => {
        const req =
          `${method} ${path} HTTP/1.1\r\n` +
          `Host: localhost\r\n` +
          `Content-Type: application/json\r\n` +
          `Content-Length: ${Buffer.byteLength(payload)}\r\n` +
          `Connection: close\r\n` +
          `\r\n` +
          payload;
        sock.write(req);
      });
    });
  }
}

// ----------------------------------------------------------------------
// Mock implementation (unit tests on macOS — no Firecracker required)
// ----------------------------------------------------------------------

/**
 * In-process mock that records the API calls made against it without
 * spawning anything. Useful for unit tests where the host-side
 * logic (pool sizing, error handling, lifecycle ordering) needs
 * verification without Linux + KVM.
 *
 * The mock asserts API ordering — `configureMachine` before `start`,
 * etc. — so test failures surface on incorrect lifecycle invocation.
 */
export class MockFirecrackerClient implements FirecrackerClient {
  readonly events: Array<{ op: string; id: MicroVmId; args?: unknown }> = [];
  private readonly handles = new Map<MicroVmId, FirecrackerHandle>();
  private nextId = 1;

  /** Inject a deliberate failure on the next call to `op`. Tests use this to verify error-path mapping. */
  failNext: { op: string; message: string } | null = null;

  /**
   * When set, `getVmConfig` returns this verbatim instead of the synthesised config. Tests use it to
   * inject a NON-confined loaded topology (a NIC, or ≠1 vsock) so the warm-path topology re-assert can be
   * exercised — the synthesised default is always confined, so a violation can't arise organically.
   */
  vmConfigOverride: unknown | undefined = undefined;

  async spawn(opts: { id?: MicroVmId; jail?: JailSpawnSpec } = {}): Promise<FirecrackerHandle> {
    this.maybeFail("spawn");
    const seq = this.nextId++;
    const id = opts.id ?? `mock-microvm-${seq}`;
    // Echo a synthetic chroot dir + the allocated uid when jailed, so pool-wiring tests can assert the
    // jailed path (chrootDir recorded on the slot, cgroup placer NOT called) without a jailer install.
    // Mirror the REAL jailer layout `<base>/<exec-basename>/<id>` (validated) so pool tests are faithful.
    const chrootDir = opts.jail !== undefined ? `/mock/jails/pool/firecracker/${opts.jail.vmSlotId}` : undefined;
    const handle: FirecrackerHandle = {
      id,
      apiSocketPath: chrootDir !== undefined ? `${chrootDir}/root/run/firecracker.sock` : `/mock/${id}.sock`,
      state: "ready",
      // Synthetic but distinct pid so pool-wiring tests can assert cgroup placement.
      pid: 100000 + seq,
      ...(chrootDir !== undefined ? { chrootDir } : {}),
    };
    this.handles.set(id, handle);
    this.events.push({ op: "spawn", id, args: opts.jail !== undefined ? { jail: opts.jail } : undefined });
    return handle;
  }

  async configureMachine(handle: FirecrackerHandle, cfg: MachineConfig): Promise<void> {
    this.maybeFail("configureMachine");
    this.requireLive(handle, "configureMachine");
    this.events.push({ op: "configureMachine", id: handle.id, args: cfg });
  }

  async configureBootSource(handle: FirecrackerHandle, src: BootSource): Promise<void> {
    this.maybeFail("configureBootSource");
    this.requireLive(handle, "configureBootSource");
    this.events.push({ op: "configureBootSource", id: handle.id, args: src });
  }

  async addDrive(handle: FirecrackerHandle, drive: Drive): Promise<void> {
    this.maybeFail("addDrive");
    this.requireLive(handle, "addDrive");
    this.events.push({ op: "addDrive", id: handle.id, args: drive });
  }

  async addVsock(handle: FirecrackerHandle, dev: VsockDevice): Promise<void> {
    this.maybeFail("addVsock");
    this.requireLive(handle, "addVsock");
    this.events.push({ op: "addVsock", id: handle.id, args: dev });
  }

  async action(handle: FirecrackerHandle, action: ActionType): Promise<void> {
    this.maybeFail("action");
    this.requireLive(handle, "action");
    this.events.push({ op: "action", id: handle.id, args: action });
    if (action === "InstanceStart") handle.state = "running";
  }

  async pause(handle: FirecrackerHandle): Promise<void> {
    this.maybeFail("pause");
    this.requireLive(handle, "pause");
    this.events.push({ op: "pause", id: handle.id });
    handle.state = "paused";
  }

  async resume(handle: FirecrackerHandle): Promise<void> {
    this.maybeFail("resume");
    this.requireLive(handle, "resume");
    this.events.push({ op: "resume", id: handle.id });
    handle.state = "running";
  }

  async createSnapshot(handle: FirecrackerHandle, cfg: SnapshotConfig): Promise<void> {
    this.maybeFail("createSnapshot");
    this.requireLive(handle, "createSnapshot");
    this.events.push({ op: "createSnapshot", id: handle.id, args: cfg });
  }

  async loadSnapshot(handle: FirecrackerHandle, cfg: SnapshotLoadConfig): Promise<void> {
    this.maybeFail("loadSnapshot");
    this.requireLive(handle, "loadSnapshot");
    this.events.push({ op: "loadSnapshot", id: handle.id, args: cfg });
    handle.state = cfg.resumeVm ? "running" : "paused";
  }

  /**
   * Synthesise the exported VM config from recorded events. There is no
   * addNetworkInterface on this client, so `network-interfaces` is ALWAYS the
   * empty array — the exec-seam no-NIC invariant is structural in the mock too.
   *
   * Two paths reach a confined config faithfully:
   *   - the CREATE path calls `addVsock` explicitly → that vsock is exported;
   *   - the warm/LOAD path calls neither `addVsock` nor `configureMachine` — the topology comes from
   *     the restored snapshot, so a handle that has been `loadSnapshot`'d exports the snapshot's baked
   *     single vsock (real Firecracker reports the restored device on GET /vm/config). Without this,
   *     the mock would report `vsock: null` for every warm slot and the warm-path topology assert would spuriously
   *     refuse them — the mock must model restore, not just fresh configuration.
   *
   * `vmConfigOverride`, when set, wins over synthesis so tests can inject a non-confined topology.
   */
  async getVmConfig(handle: FirecrackerHandle): Promise<unknown> {
    this.maybeFail("getVmConfig");
    this.requireLive(handle, "getVmConfig");
    if (this.vmConfigOverride !== undefined) return this.vmConfigOverride;
    const vsocks = this.events
      .filter((e) => e.op === "addVsock" && e.id === handle.id)
      .map((e) => e.args as VsockDevice);
    const loadedSnapshot = this.events.some((e) => e.op === "loadSnapshot" && e.id === handle.id);
    // A restored snapshot carries exactly one baked vsock; model it when the caller didn't addVsock.
    const restoredVsock = loadedSnapshot ? { guest_cid: 3, uds_path: bakedSnapshotVsockUdsPath() } : null;
    return {
      "machine-config":
        (this.events.find((e) => e.op === "configureMachine" && e.id === handle.id)?.args ?? null),
      // Firecracker exports at most one vsock as an object (last-writer-wins);
      // mirror that shape so the assert sees exactly one.
      vsock: vsocks.length > 0 ? vsocks[vsocks.length - 1] : restoredVsock,
      "network-interfaces": [] as unknown[],
      // As Firecracker reports them: snake_case, one entry per configured drive.
      drives: this.events
        .filter((e) => e.op === "addDrive" && e.id === handle.id)
        .map((e) => e.args as Drive)
        .map((d) => ({ drive_id: d.driveId, path_on_host: d.pathOnHost, is_root_device: d.isRootDevice, is_read_only: d.isReadOnly })),
    };
  }

  async shutdown(handle: FirecrackerHandle): Promise<void> {
    if (handle.state === "closed") return;
    this.events.push({ op: "shutdown", id: handle.id });
    handle.state = "closed";
    this.handles.delete(handle.id);
  }

  /** Reset between test cases — clears events + handles. */
  reset(): void {
    this.events.length = 0;
    this.handles.clear();
    this.nextId = 1;
    this.failNext = null;
  }

  private requireLive(handle: FirecrackerHandle, op: string): void {
    if (handle.state === "closed") {
      throw new FirecrackerClientError(op, "handle is closed");
    }
  }

  private maybeFail(op: string): void {
    if (this.failNext !== null && this.failNext.op === op) {
      const msg = this.failNext.message;
      this.failNext = null;
      throw new FirecrackerClientError(op, msg);
    }
  }
}

// ----------------------------------------------------------------------
// DI singleton
// ----------------------------------------------------------------------

let _client: FirecrackerClient | null = null;

export function getFirecrackerClient(): FirecrackerClient {
  if (_client !== null) return _client;
  _client = new RealFirecrackerClient();
  return _client;
}

export function useTestFirecrackerClient(client: FirecrackerClient): void {
  _client = client;
}

export function resetFirecrackerClient(): void {
  _client = null;
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

function mintMicroVmId(): MicroVmId {
  // 12-char base36 ID prefixed with `fc-`. This id style is independent
  // of any other id scheme in the codebase and uses base36 for compactness in
  // shell-visible socket file paths.
  let id = "fc-";
  for (let i = 0; i < 12; i++) {
    const digit = Math.floor(Math.random() * 36);
    id += digit < 10 ? String.fromCharCode(48 + digit) : String.fromCharCode(87 + digit);
  }
  return id;
}

// ----------------------------------------------------------------------
// Optional helper: write a structured boot config to a file (for
// `firecracker --config-file` mode if used). Not currently consumed by
// the API-socket path; kept as a forward-compatible utility.
// ----------------------------------------------------------------------

export async function writeBootConfig(path: string, config: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(config, null, 2), "utf-8");
}
