/**
 * Jailer wrapper unit tests (v2.3.3).
 *
 * Exercises the JailerWrapper interface through the MockJailerWrapper
 * implementation (which delegates synthesis to RealJailerWrapper.synthesise
 * for fidelity — only the spawn step differs). Verifies UID/GID
 * determinism, cgroup naming convention, chroot path layout, CLI
 * argument shape, and error injection.
 */

import { beforeEach, describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  JailerWrapperError,
  MockJailerWrapper,
  RealJailerWrapper,
  projectIdToUid,
  cgroupNameForProject,
  type JailerInvocation,
  FIRECRACKER_VERSION,
  synthesiseSlotJail,
  vmSlotIdToUid,
  allocateSlotUid,
  allocateJailUid,
} from "./jailer-wrapper.ts";
import { vmSlotCgroupName } from "./vm-slot-cgroup-placer.ts";

let wrapper: MockJailerWrapper;

// Real projectIds are `proj_<12-24 base62>` ids (distinct from a URL slug),
// and cgroupNameForProject refuses anything else. Fixtures use valid ids so they exercise the real
// shape rather than the readable-but-invalid `proj-<name>` forms an unguarded implementation would accept.
const PID = "proj_testtesttest";
const PID2 = "proj_abcabcabcabc";
const PID3 = "proj_xxxxxxxxxxxx";

const sampleInvocation = (proj: string = PID, inv: string = "inv-abcd"): JailerInvocation => ({
  projectId: proj,
  invocationId: inv,
  firecrackerBinaryPath: "/usr/local/bin/firecracker",
});

beforeEach(() => {
  wrapper = new MockJailerWrapper();
});

describe("projectIdToUid — deterministic project-to-UID derivation", () => {
  it("same project id maps to the same UID across calls", () => {
    const a = projectIdToUid("proj-abc", 200_000, 300_000);
    const b = projectIdToUid("proj-abc", 200_000, 300_000);
    expect(a).toBe(b);
  });

  it("UID falls within the configured range [floor, ceiling)", () => {
    for (const projId of ["proj-1", "proj-2", "proj-foo-bar", "proj-with-uuid-shape-aabbccddeeff00112233"]) {
      const uid = projectIdToUid(projId, 200_000, 300_000);
      expect(uid).toBeGreaterThanOrEqual(200_000);
      expect(uid).toBeLessThan(300_000);
    }
  });

  it("different project ids generally map to different UIDs (collision is birthday-paradox)", () => {
    const seen = new Set<number>();
    for (let i = 0; i < 100; i++) {
      seen.add(projectIdToUid(`proj-${i}`, 200_000, 300_000));
    }
    // 100 ids in 100k slots — expected collisions ~0.05; the test tolerates up to a few but should be near-100.
    expect(seen.size).toBeGreaterThan(95);
  });

  it("invalid range throws JailerWrapperError", () => {
    expect(() => projectIdToUid("proj", 100, 100)).toThrow(JailerWrapperError);
    expect(() => projectIdToUid("proj", 100, 50)).toThrow(JailerWrapperError);
  });
});

describe("JailerWrapper.synthesise — CLI shape", () => {
  it("synthesises a CLI matching the expected jailer CLI shape", () => {
    const cmd = wrapper.synthesise(sampleInvocation());
    // UID/GID must be in the configured range.
    expect(cmd.uid).toBeGreaterThanOrEqual(200_000);
    expect(cmd.uid).toBeLessThan(300_000);
    expect(cmd.gid).toBe(cmd.uid);
    // cgroup name follows k9o.slice/customer-<projectId>.scope convention.
    expect(cmd.cgroupName).toBe(`k9o.slice/customer-${PID}.scope`);
    // chroot dir follows /var/lib/k9o/jails/<projectId>/<invocationId>.
    expect(cmd.chrootDir).toBe(`/var/lib/k9o/jails/firecracker/${PID}-inv-abcd`);
  });

  it("CLI args carry the right --id, --exec-file, --uid, --gid, --chroot-base-dir; and NO --seccomp-filter / --cgroup (the real jailer rejects both)", () => {
    const cmd = wrapper.synthesise(sampleInvocation());
    expect(cmd.args).toContain("--id");
    expect(cmd.args).toContain(`${PID}-inv-abcd`);
    expect(cmd.args).toContain("--exec-file");
    expect(cmd.args).toContain("/usr/local/bin/firecracker");
    expect(cmd.args).toContain("--uid");
    expect(cmd.args).toContain(`${cmd.uid}`);
    expect(cmd.args).toContain("--gid");
    expect(cmd.args).toContain(`${cmd.gid}`);
    expect(cmd.args).toContain("--cgroup-version");
    expect(cmd.args).toContain("2");
    expect(cmd.args).toContain("--chroot-base-dir");
    expect(cmd.args).toContain("/var/lib/k9o/jails");
    // seccomp = built-in (omit --seccomp-filter); cgroup = placer stays
    // (jailer rejects --cgroup name=). The cgroupName is still RETURNED (the placer's target) but not
    // handed to the jailer.
    expect(cmd.args).not.toContain("--seccomp-filter");
    expect(cmd.args).not.toContain("--cgroup");
    expect(cmd.cgroupName).toBe(cgroupNameForProject(PID));
  });

  it("--netns is added when netnsPath is provided; omitted otherwise", () => {
    const without = wrapper.synthesise(sampleInvocation());
    expect(without.args.includes("--netns")).toBe(false);

    const withNetns = wrapper.synthesise({
      ...sampleInvocation(),
      netnsPath: "/var/run/netns/k9o-customer-proj-test",
    });
    const idx = withNetns.args.indexOf("--netns");
    expect(idx).toBeGreaterThanOrEqual(0);
    expect(withNetns.args[idx + 1]).toBe("/var/run/netns/k9o-customer-proj-test");
  });

  it("same project id + different invocation id share the same UID + cgroup but different chroot dirs", () => {
    const a = wrapper.synthesise(sampleInvocation(PID2, "inv-1"));
    const b = wrapper.synthesise(sampleInvocation(PID2, "inv-2"));
    expect(a.uid).toBe(b.uid);
    expect(a.cgroupName).toBe(b.cgroupName);
    expect(a.chrootDir).not.toBe(b.chrootDir);
    expect(a.chrootDir).toMatch(/inv-1$/);
    expect(b.chrootDir).toMatch(/inv-2$/);
  });

  it("different project ids get different UIDs + cgroup names + chroot dirs", () => {
    const a = wrapper.synthesise(sampleInvocation(PID2, "inv-1"));
    const b = wrapper.synthesise(sampleInvocation(PID3, "inv-1"));
    expect(a.cgroupName).not.toBe(b.cgroupName);
    expect(a.chrootDir).not.toBe(b.chrootDir);
    // UIDs are deterministic but different (probabilistically — collision possible but unlikely).
    // For these specific ids: assert they're different. If the test ever collides, change ids.
    expect(a.uid).not.toBe(b.uid);
  });
});

describe("JailerWrapper.launch — invocation log + error injection", () => {
  it("launch records the invocation in the events log", async () => {
    const cmd = await wrapper.launch(sampleInvocation(PID, "inv-001"));
    expect(wrapper.invocations).toHaveLength(1);
    expect(wrapper.invocations[0]?.inv.projectId).toBe(PID);
    expect(wrapper.invocations[0]?.cmd).toEqual(cmd);
  });

  it("launch returns the same JailerCmd that synthesise would produce", async () => {
    const inv = sampleInvocation(PID, "inv-eq");
    const synthesised = wrapper.synthesise(inv);
    const launched = await wrapper.launch(inv);
    expect(launched).toEqual(synthesised);
  });

  it("failNextLaunch surfaces JailerWrapperError with stage='spawn'", async () => {
    wrapper.failNextLaunch = { detail: "no /dev/kvm — kernel missing kvm module" };
    let caught: unknown = null;
    try {
      await wrapper.launch(sampleInvocation());
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(JailerWrapperError);
    expect((caught as JailerWrapperError).stage).toBe("spawn");
    expect((caught as JailerWrapperError).detail).toContain("no /dev/kvm");
  });

  it("failNextLaunch is one-shot — subsequent launches succeed", async () => {
    wrapper.failNextLaunch = { detail: "transient" };
    await expect(wrapper.launch(sampleInvocation())).rejects.toThrow();
    const cmd = await wrapper.launch(sampleInvocation(PID2, "inv-2"));
    expect(cmd.chrootDir).toBe(`/var/lib/k9o/jails/firecracker/${PID2}-inv-2`);
  });
});

describe("JailerWrapper — config overrides", () => {
  it("custom UID range narrows the derivation domain", () => {
    const w = new MockJailerWrapper({ uidFloor: 1000, uidCeiling: 2000 });
    // Valid proj_<base62> ids — the confinement guard rejects any other id shape; this test is about
    // the uid range, so use distinct real ids.
    for (const projId of ["proj_aaaaaaaaaaaa", "proj_bbbbbbbbbbbb", "proj_cccccccccccc", "proj_dddddddddddd", "proj_eeeeeeeeeeee"]) {
      const cmd = w.synthesise(sampleInvocation(projId));
      expect(cmd.uid).toBeGreaterThanOrEqual(1000);
      expect(cmd.uid).toBeLessThan(2000);
    }
  });

  it("custom chroot root is reflected in the chroot dir", () => {
    const w = new MockJailerWrapper({ chrootRoot: "/srv/jails" });
    const cmd = w.synthesise(sampleInvocation(PID, "inv-cr"));
    expect(cmd.chrootDir).toBe(`/srv/jails/firecracker/${PID}-inv-cr`);
    expect(cmd.args).toContain("/srv/jails");
  });
});

describe("RealJailerWrapper.synthesise — parity with mock", () => {
  it("real synthesise produces an identical CLI shape to mock (mock delegates to real)", () => {
    const real = new RealJailerWrapper();
    const realCmd = real.synthesise(sampleInvocation(PID, "inv-parity"));
    const mockCmd = wrapper.synthesise(sampleInvocation(PID, "inv-parity"));
    expect(realCmd).toEqual(mockCmd);
  });
});




/**
 * The Firecracker version pin is single-sourced: `FIRECRACKER_VERSION` in `jailer-wrapper.ts` is the one copy
 * (an install script derives the binary version from it), so prose in that file must never restate the literal.
 */
describe("Firecracker version pin — single-sourced", () => {
  it("the defining file holds EXACTLY ONE version literal — the constant itself", () => {
    const wrapper = readFileSync(resolve(import.meta.dir, "./jailer-wrapper.ts"), "utf8");
    const occurrences = wrapper.split(FIRECRACKER_VERSION).length - 1;
    expect(occurrences).toBe(1);
    // ...and the one occurrence is the declaration, not some other line that happens to be alone.
    const declaration = new RegExp(
      `^export const FIRECRACKER_VERSION = "${FIRECRACKER_VERSION.replace(/\./g, "\\.")}";$`,
      "m",
    );
    expect(declaration.test(wrapper)).toBe(true);
  });
});

// ── warm-pool slot jailing — the pure slot-jail synthesis ─────────────────────────────────
describe("synthesiseSlotJail — warm-pool per-slot jailing", () => {
  const inv = { vmSlotId: "slot-generic-7", firecrackerBinaryPath: "/usr/local/bin/firecracker" };
  const UID = 250_000; // a resolved uid, as allocateSlotUid would produce

  it("chroot path matches the REAL jailer layout <base>/<exec-basename>/<id> (validated against the real jailer)", () => {
    const cmd = synthesiseSlotJail(inv, UID);
    // The chroot is the WHOLE fix: a per-slot root makes the snapshot's one baked absolute uds_path
    // resolve to a different real socket per slot. The jailer inserts the exec-file basename
    // ("firecracker") as a path component — omitting it (the earlier formula) pointed the vsock helper
    // at a directory that never exists. Observed socket landed under exactly this dir on the real binary.
    expect(cmd.chrootDir).toBe("/var/lib/k9o/jails/pool/firecracker/slot-generic-7");
    const i = cmd.args.indexOf("--chroot-base-dir");
    expect(cmd.args[i + 1]).toBe("/var/lib/k9o/jails/pool");
    expect(cmd.args[cmd.args.indexOf("--id") + 1]).toBe("slot-generic-7");
  });

  it("emits NO --seccomp-filter and NO --cgroup — the real jailer v1.15.1 REJECTS both", () => {
    const cmd = synthesiseSlotJail(inv, UID);
    // Validated against the real jailer: `--seccomp-filter` → UnexpectedArgument (it is a Firecracker flag, and
    // Firecracker's built-in filters are the default posture); `--cgroup name=<scope>` →
    // CgroupInvalidFile. So the jailer gets neither, and cgroup placement stays with the cgroup placer.
    expect(cmd.args).not.toContain("--seccomp-filter");
    expect(cmd.args).not.toContain("--cgroup");
    // cgroupName is still returned (the placer's target, single-sourced), just not handed to the jailer.
    expect(cmd.cgroupName).toBe(vmSlotCgroupName("slot-generic-7"));
  });

  it("the ALLOCATED uid is what lands in argv, gid == uid — synthesis does not re-derive it", () => {
    const cmd = synthesiseSlotJail(inv, UID);
    expect(cmd.uid).toBe(UID);
    expect(cmd.gid).toBe(UID);
    expect(cmd.args[cmd.args.indexOf("--uid") + 1]).toBe(`${UID}`);
    expect(cmd.args[cmd.args.indexOf("--gid") + 1]).toBe(`${UID}`);
  });
});

// ── allocateSlotUid — distinct-by-construction, the uid-collision requirement ─────────────────────
describe("allocateSlotUid — cross-slot uid isolation is CONSTRUCTED, not hashed", () => {
  const F = 200_000, C = 300_000; // the default range [floor, ceiling)

  it("a KNOWN colliding pair gets DISTINCT uids — the whole point of the allocator", () => {
    // slot-generic-473 and slot-generic-916 hash to the SAME uid (248095, brute-forced). Under the
    // old hash-only derivation both live slots would share a uid ⇒ mutual ptrace. The allocator, fed
    // the first slot's uid as live, MUST hand the second a different one.
    const first = allocateSlotUid("slot-generic-473", new Set(), F, C);
    const second = allocateSlotUid("slot-generic-916", new Set([first]), F, C);
    expect(vmSlotIdToUid("slot-generic-473", F, C)).toBe(vmSlotIdToUid("slot-generic-916", F, C)); // they DO collide
    expect(second).not.toBe(first); // ...but the allocator refuses to reuse the live uid
  });

  it("never returns a uid already held by a live slot, across a filled range window", () => {
    const used = new Set<number>();
    for (let i = 0; i < 60; i++) { // above a pool depth of 50
      const u = allocateSlotUid(`slot-generic-${i}`, used, F, C);
      expect(used.has(u)).toBe(false); // distinct from every prior live slot, by construction
      expect(u).toBeGreaterThanOrEqual(F);
      expect(u).toBeLessThan(C);
      used.add(u);
    }
    expect(used.size).toBe(60);
  });

  it("FAILS CLOSED when the range is exhausted — never hands back a colliding uid", () => {
    // A tiny range fully held by live slots. The allocator must THROW, not return a duplicate — a
    // colliding uid is exactly the isolation boundary it exists to guarantee.
    const tiny = new Set([200_000, 200_001, 200_002]);
    expect(() => allocateSlotUid("slot-x", tiny, 200_000, 200_003)).toThrow(/no free uid/);
  });
});

// ── allocateJailUid — the shared free-list core, exercised on the PER-PROJECT collision ────────────
// Per-project uid collision: `projectIdToUid` is a
// bare hash-into-range, so two CUSTOMERS collide at the birthday bound → shared uid → cross-tenant
// ptrace on the LIVE plane. `allocateJailUid` is the same free-list that fixed the warm-slot path,
// generalised to take a raw candidate so both paths share ONE reviewed loop.
describe("allocateJailUid — per-project uid distinct-by-construction (the live-plane hazard)", () => {
  const F = 200_000, C = 300_000; // the production default range

  it("two REAL colliding customers get DISTINCT uids in the production range", () => {
    // proj-273 and proj-368 both hash to 212505 under projectIdToUid in [200000,300000) — brute-forced
    // against the shipped derivation, not a contrived tiny range. Under the raw hash both live
    // customers would share a uid ⇒ mutual ptrace/kill. The free-list, fed the first customer's uid as
    // live, MUST refuse to reuse it.
    const a = projectIdToUid("proj-273", F, C);
    const b = projectIdToUid("proj-368", F, C);
    expect(a).toBe(b); // they DO collide on the raw hash — the whole reason the free-list is needed
    const uidA = allocateJailUid(a, new Set(), F, C);
    const uidB = allocateJailUid(b, new Set([uidA]), F, C);
    expect(uidA).toBe(a); // first customer keeps the hash candidate (cheap common case)
    expect(uidB).not.toBe(uidA); // second is deflected off the collision — the property under test
    expect(uidB).toBeGreaterThanOrEqual(F);
    expect(uidB).toBeLessThan(C);
  });

  it("clamps an out-of-range candidate into [floor, ceiling) rather than trusting it", () => {
    // The two hash helpers already return in-range, but allocateJailUid takes a raw number now, so a
    // candidate below floor / at-or-above ceiling must still yield a valid uid, not an out-of-range one.
    const below = allocateJailUid(F - 5, new Set(), F, C);
    const above = allocateJailUid(C + 7, new Set(), F, C);
    for (const u of [below, above]) {
      expect(u).toBeGreaterThanOrEqual(F);
      expect(u).toBeLessThan(C);
    }
  });

  it("allocateSlotUid still routes through the shared core (no behavioural drift)", () => {
    // The refactor made allocateSlotUid a thin wrapper over allocateJailUid(vmSlotIdToUid(...)). Prove
    // the wrapper equals the composed call for the same inputs — the warm-slot property is unchanged.
    const used = new Set<number>([250_123]);
    expect(allocateSlotUid("slot-generic-9", used, F, C)).toBe(
      allocateJailUid(vmSlotIdToUid("slot-generic-9", F, C), used, F, C),
    );
  });

  it("FAILS CLOSED when every uid in the range is held — never a duplicate", () => {
    const tiny = new Set([200_000, 200_001, 200_002]);
    expect(() => allocateJailUid(200_000, tiny, 200_000, 200_003)).toThrow(/no free uid/);
  });
});

// ── per-project uid collision guard — the per-project free-list claim/release lifecycle ─────
// Requirements: (1) track the live per-project uid set host-side/guest-blind,
// (2) fail-closed refuse-don't-collide, exhaustion error names its cause. The wrapper OWNS the live set
// (launch has no live invoke-path caller yet), so the claim/release lifecycle is directly testable
// without spawning a jailer.
describe("RealJailerWrapper — per-project uid claim/release (the reach)", () => {
  const config = {
    jailerBinaryPath: "/usr/local/bin/jailer",
    chrootRoot: "/var/lib/k9o/jails",
    defaultSeccompPath: "/mock/seccomp.yaml",
    uidFloor: 200_000,
    uidCeiling: 300_000, // production range — proj-273 and proj-368 both hash to 212505 in it
  };

  it("two REAL colliding customers claim DISTINCT uids — the whole point of the reach", () => {
    const w = new RealJailerWrapper(config);
    // proj-273 and proj-368 both hash to 212505 (brute-forced against the shipped derivation). Without
    // the free-list both live customers would share a uid ⇒ cross-tenant ptrace. The claim against the
    // live set MUST hand the second a different uid.
    expect(projectIdToUid("proj-273", 200_000, 300_000)).toBe(projectIdToUid("proj-368", 200_000, 300_000));
    const a = w.claimProjectUid("proj-273");
    const b = w.claimProjectUid("proj-368");
    expect(a).not.toBe(b);
    expect(w.liveProjectUids().size).toBe(2);
  });

  it("release frees the uid — a later claim can reuse it (live set tracks reality)", () => {
    const w = new RealJailerWrapper(config);
    const a = w.claimProjectUid("proj-273");
    expect(w.liveProjectUids().has(a)).toBe(true);
    w.releaseProjectUid(a);
    expect(w.liveProjectUids().has(a)).toBe(false);
    expect(w.liveProjectUids().size).toBe(0);
    // With the collider gone, proj-368 gets the hash candidate back (no live holder to deflect off).
    expect(w.claimProjectUid("proj-368")).toBe(projectIdToUid("proj-368", 200_000, 300_000));
  });

  it("release is idempotent — double release (exit handler + teardown) is safe", () => {
    const w = new RealJailerWrapper(config);
    const a = w.claimProjectUid("proj-x");
    w.releaseProjectUid(a);
    w.releaseProjectUid(a); // no throw, no underflow
    expect(w.liveProjectUids().size).toBe(0);
  });

  it("FAILS CLOSED with a NAMED error when the uid range is exhausted — never a colliding uid", () => {
    // A range of exactly 2 uids. Two claims fill it; the third must THROW, naming the cause, not collide.
    const tiny = new RealJailerWrapper({ ...config, uidFloor: 200_000, uidCeiling: 200_002 });
    tiny.claimProjectUid("proj-a");
    tiny.claimProjectUid("proj-b");
    expect(tiny.liveProjectUids().size).toBe(2);
    let err: unknown;
    try {
      tiny.claimProjectUid("proj-c");
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(JailerWrapperError);
    expect((err as Error).message).toMatch(/no free uid/); // names the cause: range exhausted
    expect(tiny.liveProjectUids().size).toBe(2); // the failed claim added nothing
  });

  it("synthesise threads the claimed uid; the bare form falls back to the raw hash (CLI-shape compat)", () => {
    const w = new RealJailerWrapper(config);
    // A valid proj_<base62> id (synthesise's cgroupNameForProject guard refuses any other id shape).
    const pid = "proj_synthreadaa1";
    const claimed = 212_505; // an arbitrary already-allocated uid, distinct from projectIdToUid(pid)
    const withUid = w.synthesise({ projectId: pid, invocationId: "i1", firecrackerBinaryPath: "/fc" }, claimed);
    // synthesise uses THE INPUT uid, not a re-derivation from projectId.
    expect(withUid.uid).toBe(claimed);
    expect(withUid.args[withUid.args.indexOf("--uid") + 1]).toBe(`${claimed}`);
    // Bare form (no uid) — the pure arg-builder path used by CLI-shape tests + the mock — uses the hash.
    const bare = w.synthesise({ projectId: pid, invocationId: "i1", firecrackerBinaryPath: "/fc" });
    expect(bare.uid).toBe(projectIdToUid(pid, 200_000, 300_000));
  });
});
