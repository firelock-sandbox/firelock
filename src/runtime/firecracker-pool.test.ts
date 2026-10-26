/**
 * FirecrackerPool unit tests (v2.3.1).
 *
 * Exercises the pool against the MockFirecrackerClient — verifies
 * warming + claim + release lifecycle, per-tier reservation waterfall,
 * cold-fallback shape (claim returns null), eviction, and replenishment.
 *
 * Default depth is 15 summit-reserved + 5 ridge-reserved + 30 generic = 50
 * slots — that's the production
 * shape; tests run with smaller depths to keep wall time low.
 */

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { MockFirecrackerClient } from "./firecracker-client.ts";
import {
  DEFAULT_POOL_DEPTH,
  FirecrackerPool,
  type PoolConfig,
} from "./firecracker-pool.ts";

let client: MockFirecrackerClient;
let pool: FirecrackerPool;

const SNAPSHOT = {
  snapshotPath: "/var/lib/k9o/snapshots/base.bin",
  memoryFilePath: "/var/lib/k9o/snapshots/base.mem",
  resumeVm: false,
};

function buildPool(opts: Partial<PoolConfig> = {}, c: MockFirecrackerClient = client): FirecrackerPool {
  const cfg: PoolConfig = {
    depth: opts.depth ?? { summitReserved: 3, ridgeReserved: 2, generic: 5 },
    baseSnapshot: opts.baseSnapshot ?? SNAPSHOT,
    ...(opts.maxSlotAgeMs !== undefined ? { maxSlotAgeMs: opts.maxSlotAgeMs } : {}),
  };
  return new FirecrackerPool(c, cfg);
}

beforeEach(() => {
  client = new MockFirecrackerClient();
});

afterEach(async () => {
  if (pool !== undefined) {
    await pool.drain();
  }
});

describe("FirecrackerPool — warm + stats (v2.3.1)", () => {
  it("warms to target depth across all three tiers", async () => {
    pool = buildPool();
    await pool.start();
    const stats = pool.stats();
    expect(stats.summit.available).toBe(3);
    expect(stats.ridge.available).toBe(2);
    expect(stats.generic.available).toBe(5);
    expect(stats.totalSlots).toBe(10);
  });

  it("each warm slot calls spawn + loadSnapshot, with spawn preceding loadSnapshot per microvm id", async () => {
    pool = buildPool({ depth: { summitReserved: 1, ridgeReserved: 1, generic: 1 } });
    await pool.start();
    const ops = client.events.map((e) => e.op);
    expect(ops.filter((o) => o === "spawn").length).toBe(3);
    expect(ops.filter((o) => o === "loadSnapshot").length).toBe(3);
    // Per-microvm ordering: for each id, the spawn event index must
    // precede the loadSnapshot event index.
    const ids = new Set(client.events.map((e) => e.id));
    for (const id of ids) {
      const spawnIdx = client.events.findIndex((e) => e.id === id && e.op === "spawn");
      const loadIdx = client.events.findIndex((e) => e.id === id && e.op === "loadSnapshot");
      expect(spawnIdx).toBeGreaterThanOrEqual(0);
      expect(loadIdx).toBeGreaterThan(spawnIdx);
    }
  });

  it("default depth constant is 15 + 5 + 30", () => {
    expect(DEFAULT_POOL_DEPTH).toEqual({ summitReserved: 15, ridgeReserved: 5, generic: 30 });
  });

  it("reflects depth correctly under the production split", async () => {
    pool = buildPool({ depth: DEFAULT_POOL_DEPTH });
    await pool.start();
    const stats = pool.stats();
    expect(stats.totalSlots).toBe(50);
    expect(stats.summit.reserved).toBe(15);
    expect(stats.ridge.reserved).toBe(5);
    expect(stats.generic.reserved).toBe(30);
  });
});

describe("FirecrackerPool — tier eligibility waterfall", () => {
  it("summit tier consumes summit-reserved slots first", async () => {
    pool = buildPool({ depth: { summitReserved: 2, ridgeReserved: 2, generic: 2 } });
    await pool.start();
    const slot = pool.claim("summit");
    expect(slot).not.toBeNull();
    expect(slot!.tier).toBe("summit");
    expect(slot!.state).toBe("claimed");
  });

  it("summit borrows from ridge when summit-reserved is exhausted", async () => {
    pool = buildPool({ depth: { summitReserved: 1, ridgeReserved: 1, generic: 1 } });
    await pool.start();
    const a = pool.claim("summit"); // takes summit-reserved
    const b = pool.claim("summit"); // borrows from ridge
    expect(a!.tier).toBe("summit");
    expect(b!.tier).toBe("ridge");
  });

  it("summit borrows from generic when summit + ridge are exhausted", async () => {
    pool = buildPool({ depth: { summitReserved: 1, ridgeReserved: 1, generic: 1 } });
    await pool.start();
    pool.claim("summit"); // summit-reserved
    pool.claim("summit"); // ridge
    const c = pool.claim("summit"); // generic
    expect(c!.tier).toBe("generic");
  });

  it("summit returns null when every pool is empty (cold-fallback signal)", async () => {
    pool = buildPool({ depth: { summitReserved: 1, ridgeReserved: 1, generic: 1 } });
    await pool.start();
    pool.claim("summit");
    pool.claim("summit");
    pool.claim("summit");
    const fallback = pool.claim("summit");
    expect(fallback).toBeNull();
  });

  it("ridge cannot borrow from summit-reserved (load-bearing isolation)", async () => {
    pool = buildPool({ depth: { summitReserved: 5, ridgeReserved: 0, generic: 0 } });
    await pool.start();
    // Pool has 5 summit slots, 0 ridge, 0 generic.
    const ridgeClaim = pool.claim("ridge");
    expect(ridgeClaim).toBeNull(); // ridge can't take summit slots.
    // But summit can claim its own.
    const summitClaim = pool.claim("summit");
    expect(summitClaim).not.toBeNull();
    expect(summitClaim!.tier).toBe("summit");
  });

  it("ridge consumes ridge-reserved first, then borrows generic", async () => {
    pool = buildPool({ depth: { summitReserved: 0, ridgeReserved: 1, generic: 1 } });
    await pool.start();
    const a = pool.claim("ridge");
    const b = pool.claim("ridge");
    expect(a!.tier).toBe("ridge");
    expect(b!.tier).toBe("generic");
  });

  it("Free + Ascent only consume generic slots", async () => {
    pool = buildPool({ depth: { summitReserved: 5, ridgeReserved: 5, generic: 0 } });
    await pool.start();
    expect(pool.claim("free")).toBeNull();
    expect(pool.claim("ascent")).toBeNull();
  });
});

describe("FirecrackerPool — claim + release + replenishment", () => {
  it("release tears down the slot and triggers replenishment to maintain target depth", async () => {
    pool = buildPool({ depth: { summitReserved: 2, ridgeReserved: 0, generic: 0 } });
    await pool.start();
    expect(pool.stats().summit.available).toBe(2);

    const slot = pool.claim("summit")!;
    expect(pool.stats().summit.available).toBe(1);
    expect(pool.stats().summit.claimed).toBe(1);

    pool.release(slot);

    // Wait for replenishment to land (background Promise).
    await new Promise((r) => setTimeout(r, 50));
    expect(pool.stats().summit.available).toBe(2);
    expect(pool.stats().summit.claimed).toBe(0);

    // Verify shutdown was called for the released slot.
    expect(client.events.filter((e) => e.op === "shutdown").length).toBe(1);
  });

  it("release on a non-claimed slot throws", async () => {
    pool = buildPool({ depth: { summitReserved: 1, ridgeReserved: 0, generic: 0 } });
    await pool.start();
    const slot = pool.claim("summit")!;
    pool.release(slot);
    await new Promise((r) => setTimeout(r, 50));
    // Slot is now in tearing-down/torn-down state; second release throws.
    expect(() => pool.release(slot)).toThrow();
  });

  it("burst claim/release cycle ends back at target depth", async () => {
    pool = buildPool({ depth: { summitReserved: 3, ridgeReserved: 0, generic: 0 } });
    await pool.start();

    const slots = [pool.claim("summit")!, pool.claim("summit")!, pool.claim("summit")!];
    expect(pool.claim("summit")).toBeNull(); // pool empty
    for (const s of slots) pool.release(s);

    // Wait for all replenishments.
    await new Promise((r) => setTimeout(r, 100));
    expect(pool.stats().summit.available).toBe(3);
  });
});

describe("FirecrackerPool — staleness eviction", () => {
  it("slots past max age are evicted on claim attempt and replaced", async () => {
    // Set an aggressive max age so the test can exercise the path.
    pool = buildPool({
      depth: { summitReserved: 1, ridgeReserved: 0, generic: 0 },
      maxSlotAgeMs: 1, // 1 ms -> any slot is stale almost immediately
    });
    await pool.start();

    // Wait > 1 ms so the warm slot is now stale.
    await new Promise((r) => setTimeout(r, 10));

    const claimResult = pool.claim("summit");
    // The stale slot was evicted → claim returns null this round.
    expect(claimResult).toBeNull();

    // Wait for replenishment. The replacement slot will also be stale
    // immediately, but the next claim attempt evicts + replaces again.
    // For a stable test, just verify shutdown fired on the stale slot.
    await new Promise((r) => setTimeout(r, 50));
    expect(client.events.filter((e) => e.op === "shutdown").length).toBeGreaterThan(0);
  });
});

describe("FirecrackerPool — drain", () => {
  it("drain shuts down every live slot and empties the pool", async () => {
    pool = buildPool();
    await pool.start();
    expect(pool.stats().totalSlots).toBe(10);

    await pool.drain();

    expect(pool.stats().totalSlots).toBe(0);
    // Every spawned slot should have a corresponding shutdown.
    const spawnCount = client.events.filter((e) => e.op === "spawn").length;
    const shutdownCount = client.events.filter((e) => e.op === "shutdown").length;
    expect(shutdownCount).toBe(spawnCount);
  });
});

describe("FirecrackerPool — error path during warming", () => {
  it("start() rejects if a warmNewSlot call fails", async () => {
    pool = buildPool({ depth: { summitReserved: 1, ridgeReserved: 0, generic: 0 } });
    client.failNext = { op: "spawn", message: "kvm not available" };
    await expect(pool.start()).rejects.toThrow();
  });
});

describe("FirecrackerPool — loaded /vm/config re-assert", () => {
  const ONE_GENERIC = { summitReserved: 0, ridgeReserved: 0, generic: 1 } as const;

  it("marks a slot available when the loaded topology is confined (no NIC, one vsock)", async () => {
    // The mock synthesises the restored snapshot's single baked vsock + no NIC on the warm path,
    // so the re-assert passes and the slot reaches available — the normal, expected outcome.
    pool = buildPool({ depth: ONE_GENERIC });
    await pool.start();
    expect(pool.stats().generic.available).toBe(1);
  });

  it("REFUSES a warm slot whose loaded /vm/config has a network interface (fail-closed)", async () => {
    // Mutation control: this is the whole point of the re-assert. If the assertExecSeamTopology
    // call is removed from the LOAD path, this slot becomes available and start() resolves — the test
    // then fails. The mutation must reach the load path (create/probe asserts don't run here).
    pool = buildPool({ depth: ONE_GENERIC });
    client.vmConfigOverride = {
      "network-interfaces": [{ iface_id: "eth0" }],
      vsock: { guest_cid: 3 },
    };
    await expect(pool.start()).rejects.toThrow(/network interface/);
    // The refused slot is dropped, not left available.
    expect(pool.stats().generic.available).toBe(0);
  });

  it("REFUSES a warm slot whose loaded /vm/config has no vsock (≠ exactly one)", async () => {
    pool = buildPool({ depth: ONE_GENERIC });
    client.vmConfigOverride = { "network-interfaces": [], vsock: null };
    await expect(pool.start()).rejects.toThrow(/vsock/);
    expect(pool.stats().generic.available).toBe(0);
  });

  it("tears the microVM down when it refuses a slot — no orphaned Firecracker", async () => {
    pool = buildPool({ depth: ONE_GENERIC });
    client.vmConfigOverride = {
      "network-interfaces": [{ iface_id: "eth0" }],
      vsock: { guest_cid: 3 },
    };
    await expect(pool.start()).rejects.toThrow();
    const spawns = client.events.filter((e) => e.op === "spawn").length;
    const shutdowns = client.events.filter((e) => e.op === "shutdown").length;
    expect(spawns).toBeGreaterThanOrEqual(1);
    expect(shutdowns).toBe(spawns); // every spawned-then-refused microVM was shut down
  });

  describe("unreadable /vm/config — declare-then-verify (K9O_REQUIRE_EXEC_SEAM_MEASUREMENT)", () => {
    const ENV = "K9O_REQUIRE_EXEC_SEAM_MEASUREMENT";
    let prior: string | undefined;
    beforeEach(() => {
      prior = process.env[ENV];
    });
    afterEach(() => {
      if (prior === undefined) delete process.env[ENV];
      else process.env[ENV] = prior;
    });

    it("REFUSES the slot when the measurement is mandatory and /vm/config cannot be read", async () => {
      process.env[ENV] = "1";
      pool = buildPool({ depth: ONE_GENERIC });
      client.failNext = { op: "getVmConfig", message: "api socket gone" };
      await expect(pool.start()).rejects.toThrow(/UNVERIFIABLE|could not read/i);
      expect(pool.stats().generic.available).toBe(0);
    });

    it("proceeds (advisory) when the measurement is NOT mandatory and /vm/config cannot be read", async () => {
      delete process.env[ENV];
      pool = buildPool({ depth: ONE_GENERIC });
      client.failNext = { op: "getVmConfig", message: "api socket gone" };
      await pool.start();
      // Structural no-NIC guarantee stands; the slot is available despite the unreadable measurement.
      expect(pool.stats().generic.available).toBe(1);
    });

    // (b) CODE-COUPLE: jail ⇒ measurement mandatory as a CODE invariant, env-independent.
    const JC = {
      jailerBinaryPath: "/usr/local/bin/jailer",
      chrootRoot: "/var/lib/k9o/jails",
      uidFloor: 200_000,
      uidCeiling: 200_006,
    };
    function buildJailedPool(): FirecrackerPool {
      return new FirecrackerPool(client, {
        depth: ONE_GENERIC,
        baseSnapshot: SNAPSHOT,
        jail: {
          enabled: true,
          jailerConfig: JC,
          snapshotReferencedPaths: [],
          stage: async (input) => ({ root: `${input.chrootDir}/root`, files: [], vsockDir: `${input.chrootDir}/root/tmp` }),
        },
      });
    }

    it("REFUSES a JAILED slot with an unreadable /vm/config even when REQUIRE is UNSET (jail ⇒ mandatory)", async () => {
      // `jail.enabled` is the same bit that drives jailing (from K9O_EXEC_RUNTIME_JAIL),
      // so a jailed slot must fail closed on an unreadable measurement regardless of env. Mutation
      // control: remove the jail⇒mandatory branch and this slot advisory-proceeds → available → fails.
      delete process.env[ENV];
      pool = buildJailedPool();
      client.failNext = { op: "getVmConfig", message: "api socket gone" };
      await expect(pool.start()).rejects.toThrow(/mandatory under K9O_EXEC_RUNTIME_JAIL|could not be measured/i);
      expect(pool.stats().generic.available).toBe(0);
    });

    it("a JAILED slot with a confined loaded config still warms (the mandatory arm only bites on failure)", async () => {
      delete process.env[ENV];
      pool = buildJailedPool();
      await pool.start();
      expect(pool.stats().generic.available).toBe(1);
    });
  });
});

describe("FirecrackerPool — resume on claim, warm retry, no leaked VM", () => {
  const ONE = { summitReserved: 0, ridgeReserved: 0, generic: 1 } as const;

  it("activate() resumes the claimed slot's VM (warm slots stay Paused until then)", async () => {
    pool = buildPool({ depth: ONE });
    await pool.start();
    const slot = pool.claim("free")!;
    expect(client.events.some((e) => e.op === "resume")).toBe(false);
    await pool.activate(slot);
    expect(client.events.filter((e) => e.op === "resume").map((e) => e.id)).toEqual([slot.handle!.id]);
  });

  it("activate() refuses a slot that is not claimed", async () => {
    pool = buildPool({ depth: ONE });
    await pool.start();
    const slot = pool.claim("free")!;
    pool.release(slot);
    await expect(pool.activate(slot)).rejects.toThrow("cannot activate");
  });

  it("a warm that fails once is retried and the pool reaches depth (the 01:41 snapshot-load race)", async () => {
    pool = new FirecrackerPool(client, { depth: ONE, baseSnapshot: SNAPSHOT, warmAttempts: 3, warmBackoffMs: 1 });
    client.failNext = { op: "loadSnapshot", message: "connect ENOENT …/firecracker.sock" };
    await pool.start();
    expect(pool.stats().generic.available).toBe(1);
  });

  it("a warm that fails after spawn shuts that VM down instead of leaving it running", async () => {
    pool = buildPool({ depth: ONE });
    client.failNext = { op: "loadSnapshot", message: "connect ENOENT …/firecracker.sock" };
    await expect(pool.start()).rejects.toThrow();
    const spawned = client.events.filter((e) => e.op === "spawn").map((e) => e.id);
    const shut = client.events.filter((e) => e.op === "shutdown").map((e) => e.id);
    expect(spawned).toHaveLength(1);
    expect(shut).toEqual(spawned);
  });
});
