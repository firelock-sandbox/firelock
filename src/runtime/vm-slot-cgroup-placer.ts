/**
 * vm-slot-cgroup-placer — places each warm-pool VM into its OWN cgroup at spawn, so the resource
 * sensor has a per-VM `cpu.stat`/`memory.current` to attribute.
 *
 * 🔴 Why this exists (finding): the warm pool spawns firecracker children
 * via raw `child_process` with NO jailer and NO cgroup placement, so the child sits in the host process's own
 * cgroup and there is no per-VM cgroup to read. The registry/sink/runner are correct but have nothing to
 * point at until a per-VM cgroup is created AT SPAWN. This is that placement.
 *
 * 🔴 Substrate decision (per-SLOT not per-project): a warm slot has no project until claim
 * and the jailer wraps *spawn* (not a snapshot-restored VM) — re-jailing per-project at claim would defeat
 * the warm-pool sub-20ms resume. Instead each slot gets its own stable cgroup `k9o.slice/<vmSlotId>.scope`
 * at `warmNewSlot`. Slots are never reused (release → teardown, for isolation), so a slot serves exactly
 * one invocation ⇒ per-slot cgroup + the claim-time principal tag == correct per-project attribution at
 * measurement time. The registry records `vmSlotCgroupName(vmSlotId)` (the REAL cgroup), never a guessed
 * `customer-<projectId>.scope`.
 *
 * 🔴 Placement is BEST-EFFORT / fail-quiet — attribution is observability, not correctness. A placement
 * failure (off-Linux dev box, permission, races) must NEVER break VM spawn: it degrades to "no cgroup",
 * which the cgroup-reader already handles by returning null and the sensor skips. Mirrors the jailer's
 * direct-cgroupfs model (`--cgroup-version 2`, `k9o.slice/...scope`): mkdir the unified-hierarchy dir +
 * write the child PID (TGID) to `cgroup.procs` — cgroup v2 moves the whole process incl. vCPU threads.
 */
import { mkdirSync, writeFileSync, rmdirSync } from "node:fs";

/** The per-slot cgroup name (single source; the registry hook + placement share it). */
export function vmSlotCgroupName(vmSlotId: string): string {
  return `k9o.slice/${vmSlotId}.scope`;
}

/** Creates/removes a per-slot cgroup and moves a VM process into it. Injected so the pool is testable. */
export interface CgroupPlacer {
  /** Create `k9o.slice/<vmSlotId>.scope` and move `pid` (the firecracker child) into it. No-op if pid is
   *  undefined (nothing to place) or on any failure (fail-quiet — attribution degrades, spawn survives). */
  place(vmSlotId: string, pid: number | undefined): void;
  /** Remove the slot's cgroup at teardown. Best-effort — a non-empty/absent cgroup is swallowed. */
  remove(vmSlotId: string): void;
}

export interface CgroupPlacerOptions {
  /** cgroup v2 unified mount (default `/sys/fs/cgroup`). */
  readonly cgroupRoot?: string;
  /** mkdir a cgroup dir. Injected for tests; the default is `fs.mkdirSync(dir, {recursive:true})`. */
  readonly mkdir?: (dir: string) => void;
  /** Write text to a file (the `cgroup.procs` move). Injected; default `fs.writeFileSync(path, text)`. */
  readonly writeText?: (path: string, text: string) => void;
  /** Remove a cgroup dir. Injected; default `fs.rmdirSync(dir)` (rmdir, not recursive — must be empty). */
  readonly rmdir?: (dir: string) => void;
}

/**
 * The real placer: direct cgroup-v2 manipulation, mirroring the jailer's model. Every syscall is wrapped
 * fail-quiet — off a cgroup-v2 Linux host (e.g. macOS dev, where `/sys/fs/cgroup` has no unified writable
 * hierarchy) every op throws ENOENT and is swallowed, so the pool warms normally and the sensor simply
 * reads null for those VMs.
 */
export function createCgroupPlacer(opts: CgroupPlacerOptions = {}): CgroupPlacer {
  const root = opts.cgroupRoot ?? "/sys/fs/cgroup";
  const mkdir = opts.mkdir ?? ((dir: string) => mkdirSync(dir, { recursive: true }));
  const writeText = opts.writeText ?? ((path: string, text: string) => writeFileSync(path, text));
  const rmdir = opts.rmdir ?? ((dir: string) => rmdirSync(dir));

  const dirFor = (vmSlotId: string): string => `${root}/${vmSlotCgroupName(vmSlotId)}`;

  return {
    place(vmSlotId: string, pid: number | undefined): void {
      if (pid === undefined) return; // no process to move — nothing to place
      const dir = dirFor(vmSlotId);
      try {
        mkdir(dir);
        // cgroup v2: writing the TGID to cgroup.procs migrates the whole process (all threads).
        writeText(`${dir}/cgroup.procs`, String(pid));
      } catch {
        // Fail-quiet: attribution degrades to "no cgroup for this VM"; the VM spawn is unaffected.
      }
    },
    remove(vmSlotId: string): void {
      try {
        rmdir(dirFor(vmSlotId));
      } catch {
        // Best-effort: the VM's already gone; a missing/non-empty cgroup dir is not actionable here.
      }
    },
  };
}

/** A placer that records calls without touching the fs — for pool wiring tests. */
export class RecordingCgroupPlacer implements CgroupPlacer {
  readonly placed: Array<{ vmSlotId: string; pid: number | undefined }> = [];
  readonly removed: string[] = [];
  place(vmSlotId: string, pid: number | undefined): void {
    this.placed.push({ vmSlotId, pid });
  }
  remove(vmSlotId: string): void {
    this.removed.push(vmSlotId);
  }
}

// ----------------------------------------------------------------------
// DI singleton — mirrors getFirecrackerPool() / getActiveVmRegistry().
// ----------------------------------------------------------------------

let _placer: CgroupPlacer | null = null;

export function getCgroupPlacer(): CgroupPlacer {
  if (_placer !== null) return _placer;
  _placer = createCgroupPlacer();
  return _placer;
}

export function useTestCgroupPlacer(placer: CgroupPlacer): void {
  _placer = placer;
}

export function resetCgroupPlacer(): void {
  _placer = null;
}
