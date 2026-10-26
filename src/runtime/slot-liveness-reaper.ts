/**
 * The wall-clock liveness reaper. It periodically asks the pool for slots whose claim has outlived
 * a budget, kills each one's VM through an injected controller (any object exposing `hostKill` and
 * `isKilled`, see `SlotKillController` below), and releases the slot back to the pool.
 *
 * ## What this is NOT, because the obvious justification is a phantom
 *
 * This is NOT host resource protection, and it must never be described as such. Host CPU and
 * memory are ALREADY structurally bounded by the Firecracker machine-config
 * (`vcpu_count` + `mem_size_mib`, `firecracker-client.ts`): a runaway guest cannot exceed its
 * configured limits, so a resource-based trigger is not the control protecting the host. Adding such a
 * trigger and calling it resource protection would assert a control the machine-config already
 * provides — a second mechanism claiming credit for the first one's property.
 *
 * ## The real gap, and the only one
 *
 * WALL-CLOCK. Staleness eviction (`maxSlotAgeMs`) reclaims AVAILABLE slots via `warmedAt` and
 * deliberately exempts CLAIMED ones, because evicting mid-invocation would kill live work. So a
 * claimed slot that spins forever INSIDE its machine-config limits is never reclaimed: at depth N,
 * N runaway invocations wedge the entire runtime. That is AVAILABILITY (slot starvation) —
 * not security, not correctness — and it is the one thing nothing else bounds.
 *
 * ## Why the sweep is separate from the timer
 *
 * `sweepOnce` takes `nowMs` and does all the work; `start()` only schedules it. Tests drive
 * `sweepOnce` directly and never wait on a timer. That is not a style preference: an interval
 * callback that never fires (because the test driver only yields microtasks) is a control that
 * silently reports nothing, a mistake that has bitten before: an RSS sampler and a watchdog
 * both looked green because they never ran.
 */
import type { FirecrackerHandle } from "./firecracker-client.ts";
import type { FirecrackerPool, PoolSlot } from "./firecracker-pool.ts";

/**
 * The slice of a VM termination controller the reaper uses: a host-initiated kill (at-most-once per VM) and a
 * query for whether a VM has already been killed.
 */
export interface SlotKillController {
  hostKill(
    vmId: string,
    handle: FirecrackerHandle,
    reason: string,
    kind?: "operator" | "wall_clock_liveness",
  ): Promise<void>;
  isKilled(vmId: string): boolean;
}

/** Default claim budget. Generous on purpose — this is a wedge-breaker, not an SLA. */
export const DEFAULT_CLAIM_BUDGET_MS = 5 * 60 * 1000;
/** Default sweep cadence. */
export const DEFAULT_SWEEP_INTERVAL_MS = 30 * 1000;

export interface SlotLivenessReaperDeps {
  pool: Pick<FirecrackerPool, "expiredClaims" | "release">;
  controller: SlotKillController;
  /** How long a slot may stay CLAIMED before it is reclaimed. */
  claimBudgetMs?: number;
  /** How often `start()` sweeps. Ignored by `sweepOnce`. */
  sweepIntervalMs?: number;
}

export class SlotLivenessReaper {
  readonly #deps: SlotLivenessReaperDeps;
  readonly #budgetMs: number;
  readonly #intervalMs: number;
  #timer: ReturnType<typeof setInterval> | undefined;

  constructor(deps: SlotLivenessReaperDeps) {
    this.#deps = deps;
    this.#budgetMs = deps.claimBudgetMs ?? DEFAULT_CLAIM_BUDGET_MS;
    this.#intervalMs = deps.sweepIntervalMs ?? DEFAULT_SWEEP_INTERVAL_MS;
  }

  /**
   * Reclaim every slot whose claim has outlived the budget. Returns the slots acted on, so a
   * caller (and a test) can assert what happened rather than infer it from pool state.
   */
  sweepOnce(nowMs: number): PoolSlot[] {
    const expired = this.#deps.pool.expiredClaims(this.#budgetMs, nowMs);
    const reaped: PoolSlot[] = [];
    for (const slot of expired) {
      // A slot with no handle was never really running; there is nothing to terminate, and calling
      // `hostKill` with a null handle would push the null into `terminate`.
      if (slot.handle === null) continue;
      // Idempotence belongs to the controller (`#kill` is at-most-once per vmId), but re-releasing
      // an already-released slot would throw out of the sweep and strand every later expired slot
      // in the same pass — so the guard is here too, where the loop can be protected.
      if (this.#deps.controller.isKilled(slot.vmSlotId)) continue;

      void this.#deps.controller.hostKill(
        slot.vmSlotId,
        slot.handle,
        `claim exceeded wall-clock budget of ${this.#budgetMs}ms`,
        "wall_clock_liveness",
      );
      // Return the slot to the pool so replenishment refills the tier. Without this the slot stays
      // CLAIMED forever and the reap frees nothing — the kill would end the VM while leaving the
      // starvation this exists to fix exactly as it was.
      this.#deps.pool.release(slot);
      reaped.push(slot);
    }
    return reaped;
  }

  /** Begin sweeping. `unref`'d so the reaper never holds the process open. */
  start(): void {
    if (this.#timer !== undefined) return;
    this.#timer = setInterval(() => this.sweepOnce(Date.now()), this.#intervalMs);
    (this.#timer as unknown as { unref?: () => void }).unref?.();
  }

  stop(): void {
    if (this.#timer !== undefined) clearInterval(this.#timer);
    this.#timer = undefined;
  }
}
