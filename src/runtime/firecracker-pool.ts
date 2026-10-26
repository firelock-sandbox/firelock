/**
 * Pre-warmed Firecracker MicroVM pool.
 *
 * Design:
 *   - A pre-warmed pool with snapshot-restore is the warm primitive.
 *   - Default pool depth is **15 top-tier-reserved + 5 second-tier-reserved
 *     + 30 generic = 50 slots per host process**.
 *
 * Architecture:
 *   - All slots share a **generic base snapshot** — kernel + rootfs +
 *     k9o-init agent in Paused state. Customer-specific code delivery
 *     happens via vsock at invocation time, not at warm-pool seed time.
 *     This keeps the pool tier-agnostic on the wire while the tier label
 *     governs claim eligibility.
 *   - Per-tier reservation: 15 slots reserved for the top tier
 *     ("Guaranteed Compute Throughput", sub-20ms); 5 for the second tier
 *     ("Priority Compute Pool", sub-50ms); 30 for generic (all other
 *     tiers and overflow). Total ~2 GB host RAM per host process.
 *   - **No slot reuse across invocations**, for isolation.
 *     Each invocation gets a fresh MicroVM; the pool just amortises
 *     spawn + snapshot-load cost (~50ms cold spawn → ~17ms warm resume).
 *   - **Cold-fallback** when the matching tier pool is empty: rather
 *     than queueing, the caller falls through to a fresh cold-spawn
 *     (~85ms). Graceful degradation, not failure.
 *   - **Replenishment** is eager on release + has an idle floor via the
 *     scheduler (`replenishPool` job). Slots that took >N minutes to
 *     replenish or that have aged past a freshness window are eligible
 *     for eviction.
 */

import { rm } from "node:fs/promises";
import {
  FirecrackerClientError,
  bakedSnapshotVsockUdsPath,
  type FirecrackerClient,
  type FirecrackerHandle,
  type SnapshotLoadConfig,
} from "./firecracker-client.ts";
import { getCgroupPlacer } from "./vm-slot-cgroup-placer.ts";
import { functionVmUidsInUse } from "./function-vm.ts";
import { allocateSlotUid, loadJailerConfig, type JailerConfig } from "./jailer-wrapper.ts";
import { stageJailedSlot, type StageJailedSlotInput, type StageJailedSlotResult } from "./jailed-slot-staging.ts";
import {
  assertExecSeamTopology,
  assertExecSeamMeasurementAvailable,
} from "./exec-seam.ts";

/**
 * Customer-tier discriminant. Eligibility for reserved pool slots is
 * tier-based:
 *
 *   summit          -> claim from top-tier-reserved (15) -> second-tier -> generic -> cold-fallback
 *   ridge           -> claim from second-tier-reserved (5) -> generic -> cold-fallback
 *   ascent / free   -> claim from generic (30)         -> cold-fallback
 *
 * Enterprise tiers with their own dedicated infrastructure do not
 * consume from this host-process pool.
 */
export type CustomerTier = "summit" | "ridge" | "ascent" | "free";

export type PoolDepth = {
  summitReserved: number;
  ridgeReserved: number;
  generic: number;
};

/** Default pool depths: 15 + 5 + 30 = 50 slots. */
export const DEFAULT_POOL_DEPTH: PoolDepth = {
  summitReserved: 15,
  ridgeReserved: 5,
  generic: 30,
};

export type VmSlotTier = "summit" | "ridge" | "generic";

export type VmSlotState = "warming" | "available" | "claimed" | "tearing-down";

export type PoolSlot = {
  /** Stable identifier independent of the FirecrackerHandle (which may rotate). */
  vmSlotId: string;
  /** The reserved pool this slot belongs to — governs which tiers can claim it. */
  tier: VmSlotTier;
  /** The Firecracker handle (spawned + snapshot-loaded; in Paused state when available). */
  handle: FirecrackerHandle | null;
  state: VmSlotState;
  /** When this slot became available (post-snapshot-load). Used for staleness eviction. */
  warmedAt: Date | null;
  /**
   * When this slot was CLAIMED, or `null` when it is not claimed.
   *
   * `warmedAt` drives staleness eviction, and that eviction only ever looks at
   * AVAILABLE slots — a claimed slot is deliberately exempt, because evicting a slot mid-invocation
   * would kill live work. The consequence was that NOTHING bounded a claimed slot: an invocation
   * that spins forever inside its machine-config CPU/memory limits is never reclaimed, so at depth
   * N, N runaway invocations wedge the entire exec runtime. That is the wall-clock gap, and it
   * needs its own timestamp — `warmedAt` cannot answer "how long has this been claimed" because it
   * is not reset on claim.
   */
  claimedAt: Date | null;
  /**
   * The jailer chroot dir this slot's Firecracker runs under, or null for a bare (non-jailed) slot.
   * Set from the spawn handle when the pool is in jail mode. `vsockUdsPathForSlot` resolves the baked
   * vsock path under this dir — the mechanism that makes two slots' identical baked `uds_path` stop
   * colliding (two slots' identical baked vsock path would otherwise collide).
   */
  chrootDir: string | null;
  /**
   * The distinct uid this slot's jailer was given, or null when not jailed. Allocated by
   * `allocateSlotUid` against the set of uids held by currently-live slots, so it is distinct BY
   * CONSTRUCTION — two live warm Firecrackers can never share a uid and therefore never ptrace/kill
   * each other. Recorded so the NEXT allocation can see it as live.
   */
  jailUid: number | null;
};

export type PoolStats = {
  summit: { reserved: number; available: number; claimed: number; warming: number };
  ridge: { reserved: number; available: number; claimed: number; warming: number };
  generic: { reserved: number; available: number; claimed: number; warming: number };
  totalSlots: number;
};

/** Configuration consumed by the pool. */
export type PoolConfig = {
  depth: PoolDepth;
  /** The base snapshot every warm slot loads. Customer code is delivered via vsock post-claim. */
  baseSnapshot: SnapshotLoadConfig;
  /** Warm attempts per slot before giving up (default 1: no retry), and the first backoff in ms, doubling (default 250).
   *  Production sets 5 (index.ts). */
  warmAttempts?: number;
  warmBackoffMs?: number;
  /** Maximum age of a warm slot before it's evicted + replaced. Default 10 min. */
  maxSlotAgeMs?: number;
  /**
   * When set, every warm slot is spawned JAILED (so identical baked vsock paths cannot collide): per-slot chroot,
   * a distinct uid allocated against the live-slot set, and the jailer's own cgroup. Absent/false ⇒
   * bare spawn, byte-identical to prior behaviour — the safe default, so environments without a jailer
   * (dev, CI, macOS, the Mock client) are untouched. Turned on only where the substrate is verified to
   * carry the jailer + a writable chroot mount + /dev/kvm (verified present on the target hosts).
   * `jailerConfig` defaults to `loadJailerConfig()`; injected in tests.
   *
   * `snapshotReferencedPaths` — the absolute host paths BAKED INTO the base snapshot beyond the
   * (state, memory) pair, i.e. the rootfs drive. Firecracker resolves them inside the chroot on restore,
   * so a jailed warm must STAGE them (`stageJailedSlot`) before `loadSnapshot` — measured live:
   * the flag alone fails every slot with "Failed to open snapshot file". `stage` is the
   * injectable seam (default = the real filesystem stager); tests record the call and its ordering.
   */
  jail?: {
    enabled: boolean;
    jailerConfig?: JailerConfig;
    snapshotReferencedPaths?: readonly string[];
    stage?: (input: StageJailedSlotInput) => Promise<StageJailedSlotResult>;
  };
};

/**
 * The warm-pool primitive. Single-instance per host process; the
 * `useTestFirecrackerPool` DI singleton mirrors the storage / pool
 * patterns elsewhere.
 *
 * Concurrency: the host process runs single-threaded inside Bun's event loop;
 * `claim` / `release` are synchronous-on-the-event-loop and cannot
 * interleave. Replenishment fires Promises that resolve later but do not
 * mutate the slot vector concurrently with claim/release.
 */
export class FirecrackerPool {
  private readonly client: FirecrackerClient;
  private readonly config: PoolConfig;
  private readonly slots: Map<string, PoolSlot> = new Map();
  private nextSlotIdSeq = 1;
  private readonly defaultMaxSlotAgeMs = 10 * 60 * 1000;

  constructor(client: FirecrackerClient, config: PoolConfig) {
    this.client = client;
    this.config = config;
  }

  /**
   * Bring the pool to target depth. Spawns + snapshot-loads slots for
   * each tier in parallel. Returns once every slot is in 'available'
   * state (or threw an error along the way).
   */
  async start(): Promise<void> {
    const promises: Promise<void>[] = [];
    for (let i = 0; i < this.config.depth.summitReserved; i++) {
      promises.push(this.warmSlotWithRetry("summit"));
    }
    for (let i = 0; i < this.config.depth.ridgeReserved; i++) {
      promises.push(this.warmSlotWithRetry("ridge"));
    }
    for (let i = 0; i < this.config.depth.generic; i++) {
      promises.push(this.warmSlotWithRetry("generic"));
    }
    await Promise.all(promises);
  }

  /**
   * Try to claim an available slot for a customer-tier invocation.
   * Returns the claimed slot or null if every eligible pool is empty
   * (caller falls through to cold-spawn).
   *
   * Tier eligibility waterfall:
   *   summit:   summit-reserved  -> ridge-reserved -> generic -> null
   *   ridge:    ridge-reserved   -> generic       -> null
   *   ascent:   generic          -> null
   *   free:     generic          -> null
   *
   * The top tier can borrow second-tier / generic slots (it is the highest
   * tier; borrowing down doesn't violate the SLA — second-tier slots also
   * support sub-20ms warm resume since the snapshot is identical). The
   * second tier cannot borrow top-tier slots (the top-tier reservation is
   * the load-bearing "Guaranteed Compute Throughput" claim — second-tier
   * claims consuming it under load would violate it).
   */
  claim(tier: CustomerTier): PoolSlot | null {
    const order = this.tierWaterfall(tier);
    for (const vmSlotTier of order) {
      const slot = this.findAvailable(vmSlotTier);
      if (slot !== null) {
        slot.state = "claimed";
        slot.claimedAt = new Date();
        return slot;
      }
    }
    return null;
  }

  /**
   * Resume a CLAIMED slot's VM. Warm slots are loaded Paused (`resumeVm: false`, so an idle slot burns no CPU),
   * and nothing resumed them on claim: every invoke then reached a frozen guest and timed out at 30 s with no
   * line logged (both warm slots reported `"state":"Paused"`). The caller releases the slot if this
   * throws.
   */
  async activate(slot: PoolSlot): Promise<void> {
    if (slot.state !== "claimed" || slot.handle === null) {
      throw new Error(`FirecrackerPool: cannot activate slot ${slot.vmSlotId} in state ${slot.state}`);
    }
    await this.client.resume(slot.handle);
  }

  /**
   * Release a claimed slot back to the pool. The slot is torn down (no
   * reuse, for isolation) and replenishment fires in the background
   * to bring the tier back to target depth.
   */
  release(slot: PoolSlot): void {
    if (slot.state !== "claimed") {
      throw new Error(`FirecrackerPool: cannot release slot ${slot.vmSlotId} in state ${slot.state}`);
    }
    slot.state = "tearing-down";
    slot.claimedAt = null;
    void this.teardownAndReplenish(slot);
  }

  /**
   * Every slot whose CLAIM has outlived `budgetMs`. A pure query: it decides nothing and
   * kills nothing, so the pool stays the owner of slot STATE while the termination decision stays
   * with the injected kill controller (see `slot-liveness-reaper.ts`); the controller never reaches
   * into the pool.
   *
   * `nowMs` is a parameter rather than a `Date.now()` call so the reaper's tests can advance time
   * without a timer — a sweep asserted through `setTimeout` is a test that silently never runs.
   */
  expiredClaims(budgetMs: number, nowMs: number): PoolSlot[] {
    const out: PoolSlot[] = [];
    for (const slot of this.slots.values()) {
      // `claimedAt !== null` is implied by `state === "claimed"`, but both are checked: the pair is
      // the invariant, and a slot that is claimed with no timestamp is a bug I would rather skip
      // than treat as infinitely old and kill.
      if (slot.state !== "claimed" || slot.claimedAt === null) continue;
      if (nowMs - slot.claimedAt.getTime() > budgetMs) out.push(slot);
    }
    return out;
  }

  /** Drain the pool — tear down every live slot. Used at host shutdown. */
  async drain(): Promise<void> {
    const promises: Promise<void>[] = [];
    for (const slot of this.slots.values()) {
      if (slot.handle !== null) {
        promises.push(
          this.client.shutdown(slot.handle).catch(() => {
            // best-effort; teardown errors during drain are not actionable
          }),
        );
      }
      // Remove each slot's cgroup at drain (best-effort).
      getCgroupPlacer().remove(slot.vmSlotId);
      // Jailed slots: tear down the chroot tree too (best-effort).
      promises.push(this.removeChroot(slot));
    }
    this.slots.clear();
    await Promise.all(promises);
  }

  /**
   * Snapshot of pool state — primarily for observability + tests.
   */
  stats(): PoolStats {
    const acc: PoolStats = {
      summit: { reserved: this.config.depth.summitReserved, available: 0, claimed: 0, warming: 0 },
      ridge: { reserved: this.config.depth.ridgeReserved, available: 0, claimed: 0, warming: 0 },
      generic: { reserved: this.config.depth.generic, available: 0, claimed: 0, warming: 0 },
      totalSlots: 0,
    };
    for (const slot of this.slots.values()) {
      acc.totalSlots++;
      const bucket = acc[slot.tier];
      switch (slot.state) {
        case "available":
          bucket.available++;
          break;
        case "claimed":
          bucket.claimed++;
          break;
        case "warming":
          bucket.warming++;
          break;
        // tearing-down slots aren't visible in the standard counters.
      }
    }
    return acc;
  }

  // ------------------------------------------------------------------
  // Internals
  // ------------------------------------------------------------------

  private tierWaterfall(tier: CustomerTier): VmSlotTier[] {
    switch (tier) {
      case "summit":
        return ["summit", "ridge", "generic"];
      case "ridge":
        return ["ridge", "generic"];
      case "ascent":
      case "free":
        return ["generic"];
    }
  }

  private findAvailable(vmSlotTier: VmSlotTier): PoolSlot | null {
    for (const slot of this.slots.values()) {
      if (slot.tier === vmSlotTier && slot.state === "available") {
        // Staleness eviction: skip + tear down slots past max age.
        const maxAge = this.config.maxSlotAgeMs ?? this.defaultMaxSlotAgeMs;
        if (slot.warmedAt !== null && Date.now() - slot.warmedAt.getTime() > maxAge) {
          slot.state = "tearing-down";
          void this.teardownAndReplenish(slot);
          continue;
        }
        return slot;
      }
    }
    return null;
  }

  /** The uids held by currently-live slots — fed to `allocateSlotUid` so each jailed slot's uid is
   *  distinct BY CONSTRUCTION from every other live slot's. The warming slot itself is already in the
   *  map with `jailUid === null`, so it is correctly excluded. */
  /** The uids live jailed slots hold (function VMs take theirs from outside this set). */
  jailUidsInUse(): ReadonlySet<number> {
    return this.liveJailUids();
  }

  private liveJailUids(): Set<number> {
    const used = new Set<number>(functionVmUidsInUse());
    for (const s of this.slots.values()) {
      if (s.jailUid !== null) used.add(s.jailUid);
    }
    return used;
  }

  /**
   * Warm one slot, retrying with backoff. One failed warm used to fail the whole start, and nothing retried:
   * after a host roll every call answered "pool is exhausted" until the process was restarted by hand (seen as
   * `PUT /snapshot/load: connect ENOENT …/firecracker.sock`, a load racing the jailed Firecracker's socket).
   */
  private async warmSlotWithRetry(tier: VmSlotTier): Promise<void> {
    const attempts = this.config.warmAttempts ?? 1;
    for (let i = 1; ; i++) {
      try {
        await this.warmNewSlot(tier);
        return;
      } catch (e) {
        if (i >= attempts) throw e;
        const delayMs = (this.config.warmBackoffMs ?? 250) * 2 ** (i - 1);
        console.warn(JSON.stringify({ level: "warn", msg: "firecracker-pool warm failed; retrying", tier, attempt: i, delayMs, error: (e as Error).message }));
        await new Promise((r) => setTimeout(r, delayMs));
      }
    }
  }

  private async warmNewSlot(tier: VmSlotTier): Promise<void> {
    const vmSlotId = `slot-${tier}-${this.nextSlotIdSeq++}`;
    const slot: PoolSlot = {
      vmSlotId,
      tier,
      handle: null,
      state: "warming",
      warmedAt: null,
      claimedAt: null,
      chrootDir: null,
      jailUid: null,
    };
    this.slots.set(vmSlotId, slot);
    let spawned: FirecrackerHandle | null = null;
    try {
      // Jailed: allocate a uid DISTINCT from every live slot's, then
      // spawn through the jailer. The uid is allocated here (not in the client) because distinctness is
      // a property of the live POOL, which only the pool sees.
      let spawnOpts: { jail?: { vmSlotId: string; uid: number; jailerConfig?: JailerConfig } } = {};
      let jc: JailerConfig | null = null;
      if (this.config.jail?.enabled === true) {
        jc = this.config.jail.jailerConfig ?? loadJailerConfig();
        const uid = allocateSlotUid(vmSlotId, this.liveJailUids(), jc.uidFloor, jc.uidCeiling);
        slot.jailUid = uid;
        spawnOpts = { jail: { vmSlotId, uid, jailerConfig: jc } };
      }
      const handle = await this.client.spawn(spawnOpts);
      spawned = handle;
      // Jailed: the jailer has now created `<chrootDir>/root`. Stage the snapshot's inputs into it
      // BEFORE the restore — Firecracker (chrooted, running as the slot uid) opens the state + memory
      // files AND the rootfs baked into the snapshot inside that root, and binds the baked vsock path
      // there. Same absolute strings go to `loadSnapshot` unchanged (host path == in-chroot path).
      // Throws fail-closed: a slot whose inputs cannot be staged is dropped, never half-restored.
      if (jc !== null && handle.chrootDir !== undefined && slot.jailUid !== null) {
        const stage = this.config.jail?.stage ?? stageJailedSlot;
        let staged: StageJailedSlotResult;
        try {
          staged = await stage({
            chrootDir: handle.chrootDir,
            files: [
              this.config.baseSnapshot.snapshotPath,
              this.config.baseSnapshot.memoryFilePath,
              ...(this.config.jail?.snapshotReferencedPaths ?? []),
            ],
            vsockUdsPath: bakedSnapshotVsockUdsPath(),
            uid: slot.jailUid,
            gid: slot.jailUid,
            cacheDir: `${jc.chrootRoot}/pool/.staged`,
          });
        } catch (e) {
          // A spawned-but-unrestored Firecracker would otherwise idle on its API socket forever (a
          // failed RESTORE makes Firecracker exit on its own; a failed STAGE leaves it waiting). Kill it
          // and drop the chroot before surfacing the staging error.
          await this.client.shutdown(handle).catch(() => {});
          await rm(handle.chrootDir, { recursive: true, force: true }).catch(() => {});
          throw e;
        }
        // eslint-disable-next-line no-console
        console.log(
          JSON.stringify({
            level: "info",
            msg: "firecracker-pool jailed slot staged",
            vmSlotId,
            uid: slot.jailUid,
            root: staged.root,
            files: staged.files.map((f) => ({ dest: f.dest, method: f.method })),
          }),
        );
      }
      await this.client.loadSnapshot(handle, this.config.baseSnapshot);

      // Re-assert the ACTUAL loaded /vm/config topology BEFORE this slot
      // is marked available/servable — the third confinement-assert call site (create-base-snapshot +
      // the gate probe already assert; this warm/load path would otherwise be the gap). No warm slot ever becomes
      // claimable without a measured no-NIC/one-vsock check. `loadSnapshot` re-binds the baked topology
      // verbatim (it PUTs only {snapshot_path, mem_file_path, resume_vm} — no NIC/vsock attach), so an
      // unchanged base snapshot loads the topology asserted at create; this defends the RESIDUAL that
      // create-time and probe-time asserts cannot see on the per-slot warm path — a tampered/swapped
      // snapshot, or a jailer/chroot STAGING DIVERGENCE (a confinement concern). Fail-closed: a slot whose
      // loaded topology cannot be measured (when the measurement is declared mandatory) or that
      // measures a NIC / ≠1 vsock is DROPPED, never marked available — same disposition as a staging
      // failure. Uses the SAME asserts as the other two sites (no parallel copy to drift).
      let loadedVmConfig: unknown = null;
      try {
        loadedVmConfig = await this.client.getVmConfig(handle);
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        // Jail ⇒ measurement mandatory, as a code invariant. `this.config.jail?.enabled` is the SAME signal that drives jailing: it is set
        // from `K9O_EXEC_RUNTIME_JAIL === "1"` at index.ts and is the exact bit the spawn above keys
        // on (`this.config.jail?.enabled === true`), so it cannot diverge from whether the slot is
        // really jailed. Therefore a JAILED slot whose loaded /vm/config cannot be measured is dropped
        // fail-closed REGARDLESS of env — the fail-closed guarantee the JAIL flip relies on can't be
        // undone by forgetting to also set K9O_REQUIRE_EXEC_SEAM_MEASUREMENT at deploy.
        if (this.config.jail?.enabled === true) {
          await this.teardownUnavailableSlot(handle);
          throw new Error(
            `Refusing jailed warm slot ${vmSlotId} — its loaded /vm/config could not be measured ` +
              `(${reason}); measurement is mandatory under K9O_EXEC_RUNTIME_JAIL, "could not check" is not "it is fine".`,
          );
        }
        // Non-jailed slot: env-gated dev-host tolerance. Throws when K9O_REQUIRE_EXEC_SEAM_MEASUREMENT
        // is set; returns (advisory) otherwise.
        try {
          assertExecSeamMeasurementAvailable(reason);
        } catch (assertErr) {
          await this.teardownUnavailableSlot(handle);
          throw assertErr;
        }
        // Advisory skip (non-jailed, measurement not mandated): the structural no-NIC guarantee still
        // holds (no addNetworkInterface code path exists), so the slot may proceed.
        // eslint-disable-next-line no-console
        console.log(
          JSON.stringify({
            level: "info",
            msg: "firecracker-pool warm slot topology capture unavailable — relying on structural no-NIC guarantee",
            vmSlotId,
            enforcement: "ADVISORY — set K9O_REQUIRE_EXEC_SEAM_MEASUREMENT=1 to make this refuse (jailed slots refuse regardless)",
            error: reason,
          }),
        );
      }
      if (loadedVmConfig !== null) {
        try {
          assertExecSeamTopology(loadedVmConfig);
        } catch (assertErr) {
          // A loaded topology that violates the invariant (a NIC, or ≠1 vsock) must never be marked
          // available — drop the slot fail-closed, exactly like a staging failure.
          await this.teardownUnavailableSlot(handle);
          throw assertErr;
        }
      }

      // Place the VM in its own cgroup so the resource sensor has a per-VM
      // cpu.stat/memory.current to attribute. Best-effort (fail-quiet inside the placer).
      // The placer runs for jailed slots too. An earlier version skipped it for jailed slots on the belief that
      // the jailer's `--cgroup` had already placed the process. The real jailer v1.15.1 REJECTS
      // `--cgroup name=<scope>` (`CgroupInvalidFile`) — it cannot create a named scope — so the jailer
      // performs NO placement into `k9o.slice/<vmSlotId>.scope`. The placer therefore stays for jailed
      // slots too: it moves the (host-visible) firecracker pid — the jailer exec's Firecracker without
      // daemonizing, so the pid is unchanged — into the scope the resource sensor reads. No race, because
      // nothing else places it. The jailer emits no `--cgroup` (synthesiseSlotJail).
      getCgroupPlacer().place(vmSlotId, handle.pid);
      slot.handle = handle;
      slot.chrootDir = handle.chrootDir ?? null;
      slot.state = "available";
      slot.warmedAt = new Date();
    } catch (e) {
      // Slot warming failed — drop the slot reference so replenishment
      // tries again later. The error is surfaced to the caller of
      // `start()` via Promise.all rejection; transient warming failures
      // mid-cycle (e.g., during idle replenishment) are logged and
      // retried at the next replenishment opportunity.
      this.slots.delete(vmSlotId);
      // A failure after spawn (e.g. the snapshot load) used to leave the Firecracker process and its chroot behind.
      if (spawned !== null && slot.handle === null) await this.teardownUnavailableSlot(spawned);
      if (e instanceof FirecrackerClientError) {
        throw e;
      }
      throw new Error(`FirecrackerPool: failed to warm slot for tier=${tier}: ${(e as Error).message}`);
    }
  }

  /** Fail-closed teardown of a warmed-but-rejected microVM: kill the Firecracker and drop its chroot
   *  tree, before the slot is ever marked available. Used by the loaded-topology confinement re-assert so a slot
   *  that fails the loaded-/vm/config check leaves nothing running. Best-effort on both legs — the
   *  slot is discarded regardless; a leaked chroot is disk hygiene, and the next warm of this vmSlotId
   *  overwrites the path. Mirrors the staging-failure disposition. */
  private async teardownUnavailableSlot(handle: FirecrackerHandle): Promise<void> {
    await this.client.shutdown(handle).catch(() => {});
    if (handle.chrootDir !== undefined) {
      await rm(handle.chrootDir, { recursive: true, force: true }).catch(() => {});
    }
  }

  /** Remove a jailed slot's chroot tree. The chroot's LIFETIME is the slot's — created at warm, torn
   *  down here at replenish, NOT per-invocation (a slot is claimed many times inside one chroot). No-op
   *  for a bare slot. Best-effort: a leaked chroot dir is a disk-hygiene issue, never a reason to fail
   *  teardown, and the next warm of THIS vmSlotId reuses the same path so a stale tree is overwritten. */
  private async removeChroot(slot: PoolSlot): Promise<void> {
    if (slot.chrootDir === null) return;
    await rm(slot.chrootDir, { recursive: true, force: true }).catch(() => {
      // best-effort; a leaked chroot is disk hygiene, not a correctness failure
    });
  }

  private async teardownAndReplenish(slot: PoolSlot): Promise<void> {
    if (slot.handle !== null) {
      await this.client.shutdown(slot.handle).catch(() => {
        // best-effort teardown
      });
    }
    // Remove the slot's cgroup after the VM is gone (best-effort). For a jailed slot this removes
    // the JAILER-created cgroup — same name via `vmSlotCgroupName`, so `remove` cleans it up even though
    // the placer never `place`d it.
    getCgroupPlacer().remove(slot.vmSlotId);
    await this.removeChroot(slot);
    this.slots.delete(slot.vmSlotId);
    // Replenish — try to bring this tier back to its target depth.
    // Errors during replenishment are logged + ignored (the next
    // replenishment opportunity tries again).
    await this.warmSlotWithRetry(slot.tier).catch((e) => {
      // eslint-disable-next-line no-console
      console.warn(
        JSON.stringify({
          level: "warn",
          msg: "firecracker-pool replenish failed",
          tier: slot.tier,
          error: (e as Error).message,
        }),
      );
    });
  }
}

// ----------------------------------------------------------------------
// Vsock UDS path convention
// ----------------------------------------------------------------------

/**
 * Host-side vsock UDS path for a given pool slot.
 *
 * A Firecracker snapshot bakes the vsock `uds_path`
 * as an ABSOLUTE string and re-binds it verbatim on restore, and `create-base-snapshot` bakes ONE path
 * (`bakedSnapshotVsockUdsPath()`, default `/tmp/k9o-base-snapshot.vsock`). So every warm slot restoring
 * that snapshot binds the SAME path — and the host socket is wherever that path resolves:
 *
 *   • JAILED slot  → firecracker is chrooted, so the baked path resolves UNDER the per-slot chroot:
 *                    `<chrootDir>/root<bakedPath>`. Two slots' identical baked path now land at DIFFERENT
 *                    host paths → the collision is structurally impossible rather than raced around.
 *   • bare slot    → legacy convention `/run/k9o/firecracker/<vmSlotId>.vsock`. NOTE this never matched
 *                    the baked path (an earlier doc claimed the snapshot was "configured against this
 *                    convention" — it was not; the snapshot bakes `/tmp/k9o-base-snapshot.vsock`). The
 *                    bare branch is kept only for the un-jailed dev/CI path where a single slot cannot
 *                    collide with itself; the jailed branch is the one that ships to a multi-slot pool.
 *
 * The invoke path (invoke.ts) calls this helper unchanged; only the RESOLVED path moves when jailed.
 * Both the guest-serve connect and the `${…}_9000` gate-dispatcher listen ride this single source.
 */
export function vsockUdsPathForSlot(slot: PoolSlot): string {
  if (slot.chrootDir !== null) {
    return `${slot.chrootDir}/root${bakedSnapshotVsockUdsPath()}`;
  }
  return `/run/k9o/firecracker/${slot.vmSlotId}.vsock`;
}

// ----------------------------------------------------------------------
// DI singleton
// ----------------------------------------------------------------------

let _pool: FirecrackerPool | null = null;

export function getFirecrackerPool(): FirecrackerPool {
  if (_pool === null) {
    throw new Error("FirecrackerPool not initialised; call useFirecrackerPool() first.");
  }
  return _pool;
}

export function useFirecrackerPool(pool: FirecrackerPool): void {
  _pool = pool;
}

export function resetFirecrackerPool(): void {
  _pool = null;
}
