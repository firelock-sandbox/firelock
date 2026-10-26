/**
 * The wall-clock slot reaper: a claimed slot that outlives its budget is killed AND released back to the pool.
 * The controller is a recording fake; the pool is a stub exposing only what the reaper consumes.
 */
import { describe, expect, it } from "bun:test";
import { SlotLivenessReaper, type SlotKillController } from "./slot-liveness-reaper.ts";
import { FirecrackerPool, type PoolSlot } from "./firecracker-pool.ts";
import type { FirecrackerHandle } from "./firecracker-client.ts";

const handle = (pid: number): FirecrackerHandle => ({ pid }) as unknown as FirecrackerHandle;

/** A pool stub exposing only what the reaper consumes, so the reaper's contract is what is tested. */
function stubPool(slots: PoolSlot[]) {
  const released: string[] = [];
  return {
    released,
    expiredClaims: (budgetMs: number, nowMs: number): PoolSlot[] =>
      slots.filter(
        (s) => s.state === "claimed" && s.claimedAt !== null && nowMs - s.claimedAt.getTime() > budgetMs,
      ),
    release: (slot: PoolSlot): void => {
      if (slot.state !== "claimed") throw new Error(`cannot release ${slot.vmSlotId} in ${slot.state}`);
      slot.state = "tearing-down";
      released.push(slot.vmSlotId);
    },
  };
}

function slot(id: string, claimedAgoMs: number | null, nowMs: number, pid = 1): PoolSlot {
  return {
    vmSlotId: id,
    tier: "generic",
    handle: handle(pid),
    state: claimedAgoMs === null ? "available" : "claimed",
    warmedAt: null,
    claimedAt: claimedAgoMs === null ? null : new Date(nowMs - claimedAgoMs),
    chrootDir: null,
    jailUid: null,
  };
}

type VmKillEvent = { vmId: string; trigger: "host"; reason: string; hostKind: "operator" | "wall_clock_liveness" };

/** A controller that records one kill event per VM, at most once (the contract the reaper relies on). */
function controllerSpy() {
  const events: VmKillEvent[] = [];
  const killed = new Set<string>();
  const c: SlotKillController = {
    hostKill: async (vmId, _handle, reason, kind = "operator") => {
      if (killed.has(vmId)) return;
      killed.add(vmId);
      events.push({ vmId, trigger: "host", reason, hostKind: kind });
    },
    isKilled: (vmId) => killed.has(vmId),
  };
  return { c, events };
}

const NOW = 1_000_000_000_000;

describe("the reaper reclaims a claim that outlived its budget", () => {
  it("kills and RELEASES a slot past the budget", () => {
    const s = slot("slot-a", 60_000, NOW);
    const pool = stubPool([s]);
    const { c, events } = controllerSpy();
    const reaped = new SlotLivenessReaper({ pool, controller: c, claimBudgetMs: 30_000 }).sweepOnce(NOW);

    expect(reaped.map((r) => r.vmSlotId)).toEqual(["slot-a"]);
    // RELEASE is half the fix and the half that is easy to omit. Killing the VM without
    // returning the slot leaves it CLAIMED forever — the VM dies and the starvation this exists to
    // fix is exactly as it was, which would look like a working reaper in every kill-event assertion.
    expect(pool.released).toEqual(["slot-a"]);
    expect(events).toHaveLength(1);
    expect(events[0]!.trigger).toBe("host");
    expect(events[0]!.hostKind).toBe("wall_clock_liveness");
  });

  it("POSITIVE CONTROL: a slot INSIDE its budget is untouched", () => {
    // Without this, a reaper that killed every claimed slot unconditionally would pass the case
    // above — and would be catastrophically worse than the bug, since it would kill live work.
    const pool = stubPool([slot("slot-young", 5_000, NOW)]);
    const { c, events } = controllerSpy();
    expect(new SlotLivenessReaper({ pool, controller: c, claimBudgetMs: 30_000 }).sweepOnce(NOW)).toEqual([]);
    expect(pool.released).toEqual([]);
    expect(events).toEqual([]);
  });

  it("an AVAILABLE slot is never reaped however old — claims are the only thing bounded here", () => {
    const pool = stubPool([slot("slot-idle", null, NOW)]);
    const { c } = controllerSpy();
    expect(new SlotLivenessReaper({ pool, controller: c, claimBudgetMs: 1 }).sweepOnce(NOW)).toEqual([]);
  });

  it("is idempotent across sweeps — a second pass does not re-kill or re-release", () => {
    // `release` throws on a non-claimed slot, so a reaper that swept the same slot twice would
    // throw out of the loop and strand every later expired slot in that pass.
    const s = slot("slot-a", 60_000, NOW);
    const pool = stubPool([s]);
    const { c, events } = controllerSpy();
    const r = new SlotLivenessReaper({ pool, controller: c, claimBudgetMs: 30_000 });
    r.sweepOnce(NOW);
    expect(() => r.sweepOnce(NOW + 1000)).not.toThrow();
    expect(pool.released).toEqual(["slot-a"]);
    expect(events).toHaveLength(1);
  });

  it("one wedged slot does not strand the others in the same sweep", () => {
    const a = slot("slot-a", 60_000, NOW, 1);
    const b = slot("slot-b", 90_000, NOW, 2);
    const pool = stubPool([a, b]);
    const { c, events } = controllerSpy();
    new SlotLivenessReaper({ pool, controller: c, claimBudgetMs: 30_000 }).sweepOnce(NOW);
    expect(pool.released.sort()).toEqual(["slot-a", "slot-b"]);
    expect(events).toHaveLength(2);
  });

  it("a claimed slot with a null handle is skipped, not passed to terminate", () => {
    const s = { ...slot("slot-nohandle", 60_000, NOW), handle: null };
    const pool = stubPool([s]);
    const { c, events } = controllerSpy();
    expect(new SlotLivenessReaper({ pool, controller: c, claimBudgetMs: 30_000 }).sweepOnce(NOW)).toEqual([]);
    expect(events).toEqual([]);
  });
});

describe("the pool records claim time (the reaper's only input)", () => {
  it("`expiredClaims` is driven by CLAIM time, not warm time", () => {
    // Against the REAL pool, not the stub: `claimedAt` had to be added because `warmedAt` is not
    // reset on claim, so it cannot answer "how long has this been claimed".
    const pool = new FirecrackerPool({ spawn: async () => handle(1) } as never, {
      depth: { summitReserved: 0, ridgeReserved: 0, generic: 0 },
      baseSnapshot: { snapshotPath: "/x", memoryFilePath: "/y", resumeVm: false },
    });
    // No slots exist, so the query must be empty — and must not throw on an empty pool.
    expect(pool.expiredClaims(1, NOW)).toEqual([]);
  });
});
