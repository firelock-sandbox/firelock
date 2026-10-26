/**
 * k9o-managed `firecracker-jailer` wrapper.
 *
 * A TypeScript helper that synthesises the jailer
 * command line for each MicroVM invocation, resolving:
 *
 *   - **UID/GID** — derived deterministically from the project ID.
 *     Reused across invocations of the same customer for cgroup-name
 *     stability (matches the per-project credential isolation pattern).
 *   - **cgroup path** — `k9o.slice/customer-<projectId>.scope` for
 *     resource accounting + tracing.
 *   - **chroot** — `/var/lib/k9o/jails/<projectId>/<invocationId>`,
 *     tmpfs-backed; fully cleaned up at teardown.
 *   - **network namespace** — fresh per-invocation; tap interface
 *     created + torn down per call. The wrapper synthesises the
 *     `--netns` arg; setup of the namespace itself is a separate
 *     v2.3.x slice (closely related to vsock IPC at v2.3.4).
 *   - **seccomp filter** — Firecracker's BUILT-IN production filters.
 *     We pass no `--seccomp-filter` (which is a Firecracker flag, not a jailer flag) and never
 *     `--no-seccomp`; the built-in compiled filters apply and track the pinned binary version.
 *
 * Two implementations behind the `JailerWrapper` interface, mirroring
 * the v2.3.0 (Firecracker client) + v2.3.2 (OCI converter) pattern:
 *
 *   - `RealJailerWrapper` — shells out to `/usr/local/bin/jailer`
 *     with the synthesised CLI. Linux-only.
 *
 *   - `MockJailerWrapper` — in-process state machine that records the
 *     jailer invocations without spawning anything. Used for unit
 *     tests on macOS where the jailer toolchain is absent.
 *
 * Why wrap vs. call jailer directly: the wrapper centralises the per-
 * customer mapping logic (UID/GID derivation; cgroup naming; chroot
 * path layout), provides a single integration point for audit hooks,
 * and lets us add k9o-specific lifecycle (cleanup at jailer exit) on
 * top of the standard jailer behaviour.
 *
 * What we don't override: the seccomp filter,
 * jailer's chroot logic, cgroup enforcement. We set policy, jailer
 * enforces — same hardening lineage as upstream.
 */

import { spawn } from "node:child_process";
import { mkdir, rm } from "node:fs/promises";
import { dirname, basename } from "node:path";
import { createHash } from "node:crypto";
import { vmSlotCgroupName } from "./vm-slot-cgroup-placer.ts";

/**
 * A well-formed project id: `proj_<12-24 base62 chars>`, or the bare 12-24 base62 body. An ASCII
 * `[0-9A-Za-z]` allowlist, so path separators, `..`, NUL and bidi/zero-width codepoints never match.
 */
const PROJECT_ID = /^(?:proj_)?[0-9A-Za-z]{12,24}$/;

export type JailerInvocation = {
  /** k9o project the MicroVM is running on behalf of. */
  projectId: string;
  /** Stable invocation id, used for the per-invocation chroot path. */
  invocationId: string;
  /** Path to the firecracker binary jailer will exec into. */
  firecrackerBinaryPath: string;
  /** Path to the network namespace; if undefined, jailer runs in the host netns (NOT recommended for production). */
  netnsPath?: string;
};

export type JailerCmd = {
  /** Resolved UID for the jailed process (deterministic from projectId). */
  uid: number;
  /** Resolved GID for the jailed process (= UID by convention; matches per-project group). */
  gid: number;
  /** cgroup name jailer assigns. Format: `k9o.slice/customer-<projectId>.scope`. */
  cgroupName: string;
  /** Chroot directory jailer creates. Format: `/var/lib/k9o/jails/<projectId>/<invocationId>`. */
  chrootDir: string;
  /** Full jailer CLI arg list (excludes the binary path). */
  args: string[];
};

/**
 * The canonical cgroup-name convention for a project's MicroVMs:
 * `k9o.slice/customer-<projectId>.scope` (cgroup v2). This is the single source
 * of truth for the name — the jailer assigns it here, and the resource
 * sensor reads `${cgroupRoot}/${cgroupName}/` to attribute compute/memory back to
 * the project. Keep both sides on this helper so the sensor never drifts from the
 * name jailer actually creates.
 */
export function cgroupNameForProject(projectId: string): string {
  // CONFINEMENT — projectId becomes a cgroup PATH here (`k9o.slice/customer-<id>.scope`, read by the
  // resource sensor) and, via `synthesise`, a chroot path + jailer `--id` + a teardown `rm -rf` target.
  // A projectId that is not a well-formed id — a path separator, `..`, NUL, a bidi/zero-width codepoint,
  // an over-length value — is a directory-traversal / injection vector, so REFUSE it at this single
  // source (it protects both `synthesise` and `ActiveVmRegistry.recordProject`).
  // The check is the local PROJECT_ID allowlist regex (`^(?:proj_)?[0-9A-Za-z]{12,24}$`): only an ASCII
  // alphanumeric body of 12-24 characters, optionally prefixed `proj_`, is accepted. Being an allowlist
  // rather than a denylist, it rejects every dangerous codepoint by construction, while still accepting
  // the real mixed-case, underscore-prefixed shape of a project id (which a lowercase-hyphen URL-slug
  // validator would wrongly reject).
  if (!PROJECT_ID.test(projectId)) {
    throw new JailerWrapperError(
      "synthesis",
      `refusing a non-proj-id projectId ${JSON.stringify(projectId)}: it becomes a cgroup/chroot path and ` +
        `jailer --id, so a value that is not proj_<base62> is a traversal / injection vector`,
    );
  }
  return `k9o.slice/customer-${projectId}.scope`;
}

// NB: the per-SLOT cgroup name (warm-pool per-slot placement) is `vmSlotCgroupName` in `vm-slot-cgroup-placer.ts` — single-sourced with
// the placer that actually creates the cgroup. Not duplicated here.

export type JailerConfig = {
  /** Path to the jailer binary. Defaults to /usr/local/bin/jailer. */
  jailerBinaryPath: string;
  /** Root directory under which per-customer chroot dirs live. Defaults to /var/lib/k9o/jails. */
  chrootRoot: string;
  /** Numerical floor for the per-project UID derivation. Anything above 100000 is safe for unprivileged use. */
  uidFloor: number;
  /** Numerical ceiling. UID range = [uidFloor, uidCeiling). */
  uidCeiling: number;
};

/**
 * THE SINGLE SOURCE OF TRUTH for the pinned Firecracker version.
 *
 * This literal used to exist in several places that could drift independently — the installer
 * (`scripts/install-firecracker.sh`), this consumer, the test, and `README.md` — with the installer
 * *claiming* to be the single source in prose while nothing enforced it. Two copies make a pin
 * meaningless before you count the others.
 *
 * THE DEPENDENCY IS DELIBERATELY INVERTED: the TypeScript is the source and the SHELL derives from
 * it (parses this constant at install time). The other direction — the consumer reading a file at
 * runtime to learn its own version — adds a deploy dependency and a startup failure mode. **Source of
 * truth belongs where it costs nothing to read.** Changing this value is a one-line change; the
 * installer derives from it and `jailer-wrapper.test.ts` (AXIS 1/2/4) fails if they stop agreeing.
 *
 * NB: seccomp is no longer a consumer of this version. Firecracker's built-in production filters apply
 * — we pass no `--seccomp-filter`, so there is no version-derived filter
 * path to keep in lockstep. This pin now covers the firecracker/jailer BINARY version only.
 */
export const FIRECRACKER_VERSION = "1.15.1";

const DEFAULT_JAILER_CONFIG: JailerConfig = {
  jailerBinaryPath: "/usr/local/bin/jailer",
  chrootRoot: "/var/lib/k9o/jails",
  uidFloor: 200_000,
  uidCeiling: 300_000,
};

export function loadJailerConfig(): JailerConfig {
  return {
    jailerBinaryPath: process.env.K9O_JAILER_BIN ?? DEFAULT_JAILER_CONFIG.jailerBinaryPath,
    chrootRoot: process.env.K9O_JAILER_CHROOT_ROOT ?? DEFAULT_JAILER_CONFIG.chrootRoot,
    uidFloor: Number.parseInt(process.env.K9O_JAILER_UID_FLOOR ?? `${DEFAULT_JAILER_CONFIG.uidFloor}`, 10),
    uidCeiling: Number.parseInt(process.env.K9O_JAILER_UID_CEILING ?? `${DEFAULT_JAILER_CONFIG.uidCeiling}`, 10),
  };
}

/**
 * Errors raised by the jailer wrapper. Mapped to KError shapes
 * upstream — typically FUNCTION_RUNTIME_ERROR for jailer-runtime
 * failures, INTERNAL_ERROR for synthesis-time bugs.
 */
export class JailerWrapperError extends Error {
  readonly stage: "synthesis" | "spawn" | "exit" | "teardown";
  readonly detail?: string;
  constructor(stage: JailerWrapperError["stage"], message: string, detail?: string) {
    super(`Jailer ${stage}: ${message}`);
    this.name = "JailerWrapperError";
    this.stage = stage;
    if (detail !== undefined) this.detail = detail;
  }
}

export interface JailerWrapper {
  /**
   * Synthesise the jailer CLI for a given invocation. Pure function
   * (no side effects); the output is the deterministic k9o-managed
   * shape that `launch()` will exec.
   */
  synthesise(invocation: JailerInvocation): JailerCmd;

  /**
   * Launch firecracker through jailer. Returns once jailer has exec'd
   * into firecracker (which then binds its API socket — the
   * FirecrackerClient takes over from there). Throws on jailer
   * failures.
   *
   * The chroot directory is created if absent; jailer manages cgroup
   * + UID/GID drop on its own.
   */
  launch(invocation: JailerInvocation): Promise<JailerCmd>;

  /**
   * Tear down the per-invocation chroot directory. Best-effort;
   * idempotent.
   */
  teardown(cmd: JailerCmd): Promise<void>;
}

// ----------------------------------------------------------------------
// Real implementation (Linux + jailer binary)
// ----------------------------------------------------------------------

export class RealJailerWrapper implements JailerWrapper {
  private readonly config: JailerConfig;

  /**
   * The uids held by currently-live per-project jailer processes this wrapper launched — the
   * per-project uid collision guard. The live set is
   * OWNED here rather than threaded from a caller, because `launch` has no live invoke-path caller yet
   * (exec core not activated); the wrapper IS the host-side authority, and the set is HOST-SIDE ONLY —
   * a guest never sees or influences which uids are held. A uid is claimed at
   * `launch` and released at process exit / `teardown`, so `allocateJailUid` sees the true live set.
   */
  private readonly liveUids = new Set<number>();

  constructor(config?: JailerConfig) {
    this.config = config ?? loadJailerConfig();
  }

  /**
   * CLAIM a per-project uid DISTINCT BY CONSTRUCTION from every currently-live project's, and record it
   * as held — the fix for the birthday-bound collision that `projectIdToUid` alone allows (two customers
   * → shared uid → cross-tenant ptrace). The hash is the first probe; the free-list scans forward to a
   * free uid and FAILS CLOSED (named "no free uid" error) if the range is exhausted, never a colliding
   * uid. Allocate-and-record is ATOMIC (one synchronous step, no await between), so two claims cannot
   * race onto the same uid. Pair every claim with exactly one {@link releaseProjectUid}.
   */
  claimProjectUid(projectId: string): number {
    const { uidFloor, uidCeiling } = this.config;
    const uid = allocateJailUid(
      projectIdToUid(projectId, uidFloor, uidCeiling),
      this.liveUids,
      uidFloor,
      uidCeiling,
    );
    this.liveUids.add(uid);
    return uid;
  }

  /** Release a claimed uid back to the free set. Idempotent — safe to call from both the process-exit
   *  path and an explicit teardown for the same uid. */
  releaseProjectUid(uid: number): void {
    this.liveUids.delete(uid);
  }

  /** Uids currently held by live per-project jails — for tests + diagnostics. Host-side; never exposed
   *  to a guest. Returns a copy so callers cannot mutate the live set. */
  liveProjectUids(): ReadonlySet<number> {
    return new Set(this.liveUids);
  }

  /**
   * @param uid — the ALLOCATED uid (from {@link allocateProjectUid}). When omitted, falls back to the
   * raw `projectIdToUid` hash — used only by CLI-shape tests + the mock, which build argv without a
   * live process and so have no collision to avoid. The live path (`launch`) always passes the
   * free-listed uid, so a real jailed customer never gets a colliding uid.
   */
  synthesise(invocation: JailerInvocation, uid?: number): JailerCmd {
    // Confinement guard lives at `cgroupNameForProject` (called below) — the single source that refuses a
    // non-`proj_<base62>` projectId before any chroot path / cgroup name / jailer --id is built from it.
    const resolvedUid =
      uid ?? projectIdToUid(invocation.projectId, this.config.uidFloor, this.config.uidCeiling);
    const gid = resolvedUid;
    const cgroupName = cgroupNameForProject(invocation.projectId);
    // CHROOT PATH — the real jailer lays the chroot out as `<chroot-base-dir>/<exec-basename>/<id>/root`
    // (validated against the real jailer on the warm-slot path), where `<id>` is the jailer `--id`
    // (`<projectId>-<invocationId>`). The earlier `<chrootRoot>/<projectId>/<invocationId>` was doubly
    // wrong (missing the `firecracker/` component AND splitting the single hyphenated id on `/`).
    const jailId = `${invocation.projectId}-${invocation.invocationId}`;
    const chrootDir = `${this.config.chrootRoot}/${basename(invocation.firecrackerBinaryPath)}/${jailId}`;

    // SECCOMP + CGROUP — the real jailer REJECTS both flags this synthesis used to emit (validated
    // against the real jailer): `--seccomp-filter` is a FIRECRACKER flag not a jailer flag
    // (UnexpectedArgument) and OPTIONAL — Firecracker's built-in production filters apply when it is
    // absent, which is the intended posture (never `--no-seccomp`); `--cgroup name=<scope>` →
    // CgroupInvalidFile, so the jailer places NOTHING and the external cgroup placer stays.
    // Both retired. cgroupName is still returned (the placer's target, single-sourced via
    // cgroupNameForProject), just not handed to the jailer.
    const args: string[] = [
      "--id",
      jailId,
      "--exec-file",
      invocation.firecrackerBinaryPath,
      "--uid",
      `${resolvedUid}`,
      "--gid",
      `${gid}`,
      "--cgroup-version",
      "2",
      "--chroot-base-dir",
      this.config.chrootRoot,
    ];
    if (invocation.netnsPath !== undefined) {
      args.push("--netns", invocation.netnsPath);
    }

    return { uid: resolvedUid, gid, cgroupName, chrootDir, args };
  }

  async launch(invocation: JailerInvocation): Promise<JailerCmd> {
    // Per-project uid collision guard. Allocate a uid distinct from
    // every live project's, and CLAIM it synchronously — before the first `await` — so a concurrent
    // launch cannot allocate the same uid against a set that does not yet include this one. Fail-closed:
    // `allocateProjectUid` throws a NAMED "no free uid" error if the range is exhausted (a misconfig or
    // leak, not normal load — the range holds 100k live projects), never a colliding uid. Released on
    // process exit / error / `teardown` below.
    const uid = this.claimProjectUid(invocation.projectId);
    let cmd: JailerCmd;
    try {
      cmd = this.synthesise(invocation, uid);
      // NO seccomp precondition here anymore. The old `--seccomp-filter`
      // present/absent arms guarded a JAILER flag that does not exist — a control that can never fire as
      // intended is a false control. The intended posture is Firecracker's BUILT-IN production filters (no
      // flag), whose enforcement is proven out-of-band by reading `Seccomp: 2` from
      // `/proc/<firecracker-pid>/status` on the live host, not by an argv check the jailer would reject.
      await mkdir(dirname(cmd.chrootDir), { recursive: true }).catch((e) => {
        throw new JailerWrapperError("synthesis", `failed to create chroot parent dir: ${e.message}`);
      });
    } catch (e) {
      // Release the claimed uid on ANY pre-spawn failure (seccomp refusal, mkdir) so a refused launch
      // does not leak it — otherwise the range slowly fills with uids no live process holds.
      this.releaseProjectUid(uid);
      throw e;
    }

    return new Promise((resolve, reject) => {
      const child = spawn(this.config.jailerBinaryPath, cmd.args, { stdio: ["ignore", "pipe", "pipe"] });
      let stderr = "";
      let exited = false;
      child.stderr?.on("data", (chunk) => {
        stderr += chunk.toString();
      });
      child.once("error", (e) => {
        this.releaseProjectUid(uid);
        reject(new JailerWrapperError("spawn", e.message));
      });
      child.once("exit", (code) => {
        exited = true;
        // The jailed process is gone — its uid is free. Released here (and idempotently in teardown) so
        // the live set tracks reality: a uid is held for exactly as long as its process is alive.
        this.releaseProjectUid(uid);
        if (code !== 0 && code !== null) {
          reject(
            new JailerWrapperError(
              "exit",
              `jailer exited with code ${code}`,
              stderr.slice(0, 500),
            ),
          );
        }
      });

      // Jailer execs into firecracker after a small bootstrap window.
      // Resolve once we believe the bootstrap completed (~50ms is
      // generous; integration tests can tune via K9O_JAILER_BOOTSTRAP_MS).
      const bootstrapMs = Number.parseInt(process.env.K9O_JAILER_BOOTSTRAP_MS ?? "50", 10);
      setTimeout(() => {
        if (exited) return;
        resolve(cmd);
      }, bootstrapMs);
    });
  }

  async teardown(cmd: JailerCmd): Promise<void> {
    // Release the uid (idempotent with the exit handler) so an explicit teardown frees it even if the
    // process was killed without an exit event reaching us.
    this.releaseProjectUid(cmd.uid);
    await rm(cmd.chrootDir, { recursive: true, force: true }).catch(() => {
      // best-effort
    });
  }
}

// ----------------------------------------------------------------------
// Mock implementation (unit tests on macOS — no jailer required)
// ----------------------------------------------------------------------

/**
 * In-process mock that records jailer invocations + applies the same
 * synthesis logic as the real wrapper (so tests verify CLI shape +
 * UID/GID derivation against deterministic expectations).
 */
export class MockJailerWrapper implements JailerWrapper {
  readonly config: JailerConfig;
  readonly invocations: Array<{ inv: JailerInvocation; cmd: JailerCmd }> = [];
  failNextLaunch: { detail: string } | null = null;

  constructor(config?: Partial<JailerConfig>) {
    this.config = { ...DEFAULT_JAILER_CONFIG, ...config };
  }

  synthesise(invocation: JailerInvocation): JailerCmd {
    return new RealJailerWrapper(this.config).synthesise(invocation);
  }

  async launch(invocation: JailerInvocation): Promise<JailerCmd> {
    if (this.failNextLaunch !== null) {
      const detail = this.failNextLaunch.detail;
      this.failNextLaunch = null;
      throw new JailerWrapperError("spawn", "mock-injected failure", detail);
    }
    const cmd = this.synthesise(invocation);
    this.invocations.push({ inv: invocation, cmd });
    return cmd;
  }

  async teardown(_cmd: JailerCmd): Promise<void> {
    // no-op in mock
  }

  reset(): void {
    this.invocations.length = 0;
    this.failNextLaunch = null;
  }
}

// ----------------------------------------------------------------------
// DI singleton
// ----------------------------------------------------------------------

let _wrapper: JailerWrapper | null = null;

export function getJailerWrapper(): JailerWrapper {
  if (_wrapper !== null) return _wrapper;
  _wrapper = new RealJailerWrapper();
  return _wrapper;
}

export function useTestJailerWrapper(wrapper: JailerWrapper): void {
  _wrapper = wrapper;
}

export function resetJailerWrapper(): void {
  _wrapper = null;
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

/**
 * Deterministic UID derivation from project id. Maps any project id
 * into [uidFloor, uidCeiling) via SHA-256 hash modulo the range. The
 * range is configured to start at 200_000 by default — comfortably
 * above any system UID (typical max ~65535) and any LDAP / NIS UID
 * (typically <100_000), so collisions with non-k9o UIDs are
 * structurally impossible.
 *
 * THIS RETURNS A FIRST-PROBE CANDIDATE, NOT A FINAL UID.
 * The hash is a bare `sha256(projectId) % range`, so two DISTINCT customers collide at the birthday
 * bound. That is NOT acceptable at v2 launch (contra the note this replaces): a collision means two
 * customers share a uid, and `ptrace`/`kill`/signals key on uid, so a shared uid is cross-tenant reach
 * on the LIVE incumbent exec plane (`RealJailerWrapper.synthesise` at the `--uid`/`--gid` args). The fix
 * is to pass this candidate through {@link allocateJailUid} against the live per-project uid set, making
 * the uid distinct BY CONSTRUCTION.
 *
 * DETERMINISM IS NOT LOAD-BEARING. An earlier note asserted the uid must be stable across restarts/processes "otherwise cgroup-naming + audit-trail
 * joins break". It does not: `cgroupNameForProject` derives the cgroup name from `projectId` directly
 * (`customer-<projectId>.scope`), never from the uid, and the numeric uid is consumed ONLY as the jailer
 * `--uid`/`--gid` arg — nothing persists or joins on it. So the free-list (whose output depends on the
 * live set, not on projectId alone) sacrifices no real invariant. That note described a procedure with no
 * enforcing control.
 */
export function projectIdToUid(projectId: string, floor: number, ceiling: number): number {
  if (ceiling <= floor) {
    throw new JailerWrapperError("synthesis", `invalid UID range: floor=${floor}, ceiling=${ceiling}`);
  }
  const range = ceiling - floor;
  const hash = createHash("sha256").update(projectId).digest();
  // Take the first 4 bytes as an unsigned 32-bit integer.
  const v = hash.readUInt32BE(0);
  return floor + (v % range);
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// WARM-POOL SLOT JAILING — the PURE synthesis half.
//
// WHY THIS EXISTS. A Firecracker snapshot bakes the vsock `uds_path` in as an ABSOLUTE string and
// re-binds it verbatim on restore. `create-base-snapshot` bakes ONE path (`/tmp/k9o-base-snapshot.vsock`),
// so every warm slot restoring that snapshot tries to bind the SAME absolute path — slot 1 wins, slot 2+
// fail with `Address in use (os error 98)` (measured live). Chrooting each slot's
// Firecracker makes that same absolute path resolve UNDER a per-slot root, so the collision becomes
// structurally impossible rather than raced around.
//
// This module owns ONLY the pure argv synthesis (mirrors `synthesise` for the per-project path). The
// privileged `launch`/`teardown` wiring, the `FirecrackerPool` integration, and the two consequences
// below are deliberately NOT here; they need separate security review (guest seal and fault domain).
// Building the pure half first keeps the reviewed
// surface a pure function.
//
// CONSEQUENCE 1 — the vsock CONNECT path moves. `vsockUdsPathForSlot` (firecracker-pool.ts) returns
// `/run/k9o/firecracker/<vmSlotId>.vsock` and `invoke.ts` connects there — but under chroot the REAL
// socket lives at `<chrootDir>/root/<baked_uds_path>`. That helper's DOC already claims the snapshot is
// "configured against this convention", which is not true today (one baked path, no per-slot binding) —
// so it is a description that never matched. Under this fix it must be rewritten to the chroot path; the
// pin-bump alternative (vsock_override, absent at the pinned `FIRECRACKER_VERSION`) would instead make it
// true as-written. This partly re-weighs the choice between the two approaches.
//
// CONSEQUENCE 2 — the jailer was expected to REPLACE the cgroup placer for jailed slots (see the note in `synthesiseSlotJail`: the real jailer cannot place a named scope, so the placer stays). A warm slot already gets
// `k9o.slice/<vmSlotId>.scope` via `getCgroupPlacer().place()` AFTER a bare spawn. The jailer assigns its
// OWN cgroup via `--cgroup`. Routing through the jailer makes the placer a SECOND, racing placement of the
// same pid — so the wiring change must drop `getCgroupPlacer().place()` for jailed slots. This synthesis
// emits EXACTLY `vmSlotCgroupName(vmSlotId)` so the resource sensor keeps reading the right cgroup with no
// placer.
//
// CONSEQUENCE 3 — UID. A warm slot has no project, so `projectIdToUid` does not apply. Default here is
// a PER-SLOT UID (each slot a distinct uid, so two warm Firecrackers cannot ptrace/kill each other — same
// isolation the per-project uid gives between customers). The alternative — one shared warm-pool uid — is
// cheaper but lets warm slots interfere pre-claim. Per-slot is the safe default; a shared uid is only worth considering
// if the economy ever outweighs that isolation.
// ══════════════════════════════════════════════════════════════════════════════════════════════

/** A warm-pool slot to be jailed. Keyed on `vmSlotId` (`slot-<tier>-<seq>`), which is unique per host
 *  process — there is no project or invocation identity at warm time. */
export type JailerSlotInvocation = {
  /** Stable per-host-process slot id (`slot-<tier>-<seq>` from firecracker-pool.ts). Keys chroot/uid/cgroup. */
  vmSlotId: string;
  /** Path to the firecracker binary jailer will exec into. */
  firecrackerBinaryPath: string;
  /** Network namespace path; undefined ⇒ host netns (the warm pool's confinement is the guest's no-NIC
   *  seal + seccomp, not a per-slot netns, so this is normally left unset for pool slots). */
  netnsPath?: string;
};

/** A deterministic per-slot CANDIDATE uid from the slot id — the starting probe for
 *  {@link allocateSlotUid}, NOT the final uid. Keyed on `vmSlotId` for a stable, spread-out first
 *  guess; correctness (distinctness) is the allocator's job, because a hash into a range collides. */
export function vmSlotIdToUid(vmSlotId: string, floor: number, ceiling: number): number {
  if (ceiling <= floor) {
    throw new JailerWrapperError("synthesis", `invalid UID range: floor=${floor}, ceiling=${ceiling}`);
  }
  const range = ceiling - floor;
  const v = createHash("sha256").update(vmSlotId).digest().readUInt32BE(0);
  return floor + (v % range);
}

/**
 * Allocate a uid for a warm slot that is DISTINCT BY CONSTRUCTION from every live slot's uid.
 *
 * WHY NOT JUST THE HASH. `vmSlotIdToUid` is a hash into
 * `[floor, ceiling)`, so two distinct live slots collide at the birthday bound — ~1.2% at a
 * pool depth of 50, rising with depth. When they collide the isolation property INVERTS: `ptrace`/
 * `kill`/signals key on uid, so a shared uid means two warm Firecrackers CAN reach each other, and the
 * per-slot chroot does not help (process reach is a uid relation, not a filesystem one). A hash cannot
 * deliver "impossible"; a free-list can. This is the `RegionScoped`/`wl_`-prefix move — make the bad
 * state unrepresentable.
 *
 * The pool is BOUNDED (tier target depths), so the range dwarfs the live set and a free uid always
 * exists in practice. The hash is the first probe (keeps the common case spread out and cheap); on a
 * collision we scan forward deterministically to the first free uid. If the entire range is somehow
 * held — a misconfigured tiny range, or a leak — we FAIL CLOSED rather than hand back a colliding uid,
 * because a colliding uid is exactly the security boundary this exists to guarantee.
 *
 * `usedUids` is the set of uids held by currently-LIVE slots — the pool passes its own live-slot set,
 * so distinctness holds against reality, not against slot-id space.
 */
export function allocateSlotUid(
  vmSlotId: string,
  usedUids: ReadonlySet<number>,
  floor: number,
  ceiling: number,
): number {
  return allocateJailUid(vmSlotIdToUid(vmSlotId, floor, ceiling), usedUids, floor, ceiling);
}

/**
 * The free-list core shared by BOTH jailing paths (warm-slot and per-project). Given a first-probe
 * `candidate` uid (a hash — `vmSlotIdToUid` for slots, `projectIdToUid` for customers) and the set of
 * uids held by currently-LIVE jails, return a uid DISTINCT BY CONSTRUCTION from every live one.
 *
 * WHY THIS IS THE SHARED CORE, NOT EACH PATH'S OWN LOOP. `allocateSlotUid`
 * already free-lists the warm-slot path. The per-project
 * path (`projectIdToUid` at the live `synthesise`) is the SAME hash-into-range defect one level worse —
 * a collision there means two CUSTOMERS share a uid, and since `ptrace`/`kill`/signals key on uid, that
 * is cross-tenant reach on the LIVE incumbent exec plane. A hash cannot deliver "impossible"; a free-list
 * can. Extracting the loop makes the property one reviewed function instead of two copies that can drift.
 *
 * The uid space dwarfs any live set (bounded pool depth / customer count per host), so a free uid
 * exists in practice; the hash candidate keeps the common case spread out and cheap, and on a collision
 * we scan forward deterministically. If the whole range is somehow held we FAIL CLOSED — a colliding uid
 * is exactly the isolation boundary this exists to guarantee, so we never hand one back.
 *
 * `candidate` is clamped into `[floor, ceiling)` defensively; the two hash helpers already return in-range.
 */
export function allocateJailUid(
  candidate: number,
  usedUids: ReadonlySet<number>,
  floor: number,
  ceiling: number,
): number {
  if (ceiling <= floor) {
    throw new JailerWrapperError("synthesis", `invalid UID range: floor=${floor}, ceiling=${ceiling}`);
  }
  const range = ceiling - floor;
  const start = floor + ((((candidate - floor) % range) + range) % range);
  for (let i = 0; i < range; i++) {
    const probe = floor + ((start - floor + i) % range);
    if (!usedUids.has(probe)) return probe;
  }
  // Every uid in the range is held by a live jail. Fail closed — never return a colliding uid.
  throw new JailerWrapperError(
    "synthesis",
    `no free uid in [${floor}, ${ceiling}): all ${range} are held by live jails ` +
      `(live set exceeds the uid range — widen the range or lower the depth)`,
  );
}

/**
 * Pure synthesis of the jailer CLI for a warm-pool SLOT. No side effects — mirrors {@link
 * RealJailerWrapper.synthesise} for the per-project path, keyed on `vmSlotId` instead of
 * project+invocation. The chroot lives under a `pool/` prefix so warm-slot jails are segregated from
 * per-customer jails, and its LIFETIME is the slot's (created at warm, torn down at replenish) — NOT
 * per-invocation, which is the whole point: a slot is claimed many times inside one chroot.
 *
 * `uid` IS AN INPUT, not derived here. It must come from {@link allocateSlotUid} against the pool's
 * live-slot set, so the uid is DISTINCT BY CONSTRUCTION from every other live slot's — the isolation
 * boundary this exists to guarantee. Deriving it here from a hash would reintroduce the collision this
 * split exists to remove; allocation is the pool's job, synthesis is pure argv.
 */
export function synthesiseSlotJail(
  inv: JailerSlotInvocation,
  uid: number,
  config: JailerConfig = DEFAULT_JAILER_CONFIG,
): JailerCmd {
  const gid = uid;
  const cgroupName = vmSlotCgroupName(inv.vmSlotId);
  // CHROOT PATH — VALIDATED against the real jailer at FIRECRACKER_VERSION The jailer lays
  // the chroot out as `<chroot-base-dir>/<exec-file-basename>/<id>/root`, inserting the exec-file's
  // basename ("firecracker") as a path component. An earlier formula omitted it, so `vsockUdsPathForSlot`
  // would have resolved to a directory that never exists. This is the path the socket was OBSERVED at.
  const chrootDir = `${config.chrootRoot}/pool/${basename(inv.firecrackerBinaryPath)}/${inv.vmSlotId}`;

  // SECCOMP + CGROUP — VALIDATED that the real jailer REJECTS both flags this synthesis used to emit:
  //   • `--seccomp-filter` → `UnexpectedArgument("seccomp-filter")`. It is a *Firecracker* flag, not a
  //     jailer flag, and it is OPTIONAL — Firecracker applies its built-in production seccomp filters
  //     when it is absent. So we omit it and take the built-in posture (the recommended default). The
  //     bundled path was a YAML spec anyway, not a compiled BPF filter — never a valid `--seccomp-filter`.
  //   • `--cgroup name=<scope>` → `CgroupInvalidFile("name")`. `--cgroup` takes a controller FILE=value
  //     (e.g. `cpu.max=…`), it cannot create a named scope. So the jailer CANNOT place the VM into
  //     `k9o.slice/<slot>.scope`. The cgroup placement therefore stays with the existing cgroup placer
  //     (moves the firecracker pid post-spawn) — this REVERSES an earlier "drop the placer" reading,
  //     which assumed a jailer placement that the real binary does not perform.
  const args: string[] = [
    "--id",
    inv.vmSlotId,
    "--exec-file",
    inv.firecrackerBinaryPath,
    "--uid",
    `${uid}`,
    "--gid",
    `${gid}`,
    "--cgroup-version",
    "2",
    "--chroot-base-dir",
    `${config.chrootRoot}/pool`,
  ];
  if (inv.netnsPath !== undefined) {
    args.push("--netns", inv.netnsPath);
  }

  return { uid, gid, cgroupName, chrootDir, args };
}
