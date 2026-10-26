/**
 * stageJailedSlot — the filesystem half of jailing a warm slot.
 *
 * Real fs in a tmpdir (macOS/Linux, unprivileged): the chown target is the test's OWN uid/gid, which is
 * always permitted. The EXDEV branch cannot be produced on one tmpfs, so it is driven through the
 * injectable `link` seam — it is the branch the rootfs ALWAYS takes live (image overlay → emptyDir), so it
 * is the load-bearing one to pin, together with the once-per-process cache it relies on.
 */
import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { chmod, chown, link, copyFile, mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import {
  JailedSlotStagingError,
  stageJailedSlot,
  stagingCacheNameFor,
  type StagingFsOps,
} from "./jailed-slot-staging.ts";

let base: string;
let chrootDir: string;
let cacheDir: string;
let stateSrc: string;
let memSrc: string;
let rootfsSrc: string;
const UID = process.getuid?.() ?? 0;
const GID = process.getgid?.() ?? 0;
// The vsock path lives in the test's OWN base tree, in a subtree DISJOINT from the snapshot source
// files (`base/src/...`). It must NOT sit under a directory that is an ancestor of the snapshot sources:
// the guard refuses a snapshot-referenced file that lies under the vsock dir (the slot uid will own it and
// could unlink/replace the staged inode). The prior hardcoded `/tmp/k9o-base-snapshot.vsock` collided on
// Linux CI — there `tmpdir()` IS `/tmp`, so the mkdtemp'd `base` (and its snapshot sources) sat UNDER the
// vsock parent `/tmp` and every stage was correctly refused (green on macOS only, whose tmpdir is
// `/var/folders/...`). Anchoring the vsock under `base/run` keeps it disjoint from `base/src` on every
// platform. (Production is disjoint by construction: sources under /var/lib/k9o, vsock under /tmp.)
let VSOCK: string;

beforeEach(async () => {
  base = await mkdtemp(join(tmpdir(), "k9o-jailstage-"));
  VSOCK = join(base, "run/k9o-base-snapshot.vsock");
  chrootDir = join(base, "jails/pool/firecracker/slot-generic-1");
  cacheDir = join(base, "jails/pool/.staged");
  const src = join(base, "src/var/lib/k9o/exec");
  await mkdir(src, { recursive: true });
  await mkdir(join(base, "src/usr/local/share/k9o"), { recursive: true });
  stateSrc = join(src, "base.state");
  memSrc = join(src, "base.mem");
  rootfsSrc = join(base, "src/usr/local/share/k9o/base.ext4");
  // The base snapshot's inputs are READ-ONLY on the host (root-owned 0644 in prod, slot uid ≠ owner).
  // Here the slot uid IS the test user, so the fixtures are 0444 — the same "the slot cannot write
  // it" property CONDITION 1 asserts on the staged inode.
  await writeFile(stateSrc, "STATE", { mode: 0o444 });
  await writeFile(memSrc, "MEM", { mode: 0o444 });
  await writeFile(rootfsSrc, "ROOTFS", { mode: 0o444 });
  // Mirror the jailer: it creates `<chrootDir>/root` before we stage.
  await mkdir(join(chrootDir, "root"), { recursive: true });
});

afterEach(async () => {
  await rm(base, { recursive: true, force: true });
});

const exdevLinkOps: StagingFsOps = {
  link: async (src, dest) => {
    // Sources outside the chroot base are "another device"; links inside it (cache → slot) succeed.
    if (!src.startsWith(join(base, "jails"))) {
      const e = new Error("cross-device link") as NodeJS.ErrnoException;
      e.code = "EXDEV";
      throw e;
    }
    await link(src, dest);
  },
  copyFile: (s, d) => copyFile(s, d),
  chown: (p, u, g) => chown(p, u, g),
};

describe("stageJailedSlot", () => {
  it("places every file at <chrootDir>/root<absolute host path> — host path == in-chroot path", async () => {
    const r = await stageJailedSlot({ chrootDir, files: [stateSrc, memSrc, rootfsSrc], vsockUdsPath: VSOCK, uid: UID, gid: GID, cacheDir });
    expect(r.root).toBe(join(chrootDir, "root"));
    for (const src of [stateSrc, memSrc, rootfsSrc]) {
      const dest = `${r.root}${src}`;
      expect((await stat(dest)).isFile()).toBe(true);
      expect(await readFile(dest, "utf8")).toBe(await readFile(src, "utf8"));
    }
    // Same mount ⇒ hard links: the dest shares the source's inode (zero bytes per slot).
    expect((await stat(`${r.root}${stateSrc}`)).ino).toBe((await stat(stateSrc)).ino);
    expect(r.files.map((f) => f.method)).toEqual(["link", "link", "link"]);
  });

  it("prepares the baked vsock path: parent dir exists in the chroot, owned by the slot uid, no stale socket file", async () => {
    // A leftover file at the baked path = EADDRINUSE at bind — plant one and prove it is cleared.
    const stale = join(chrootDir, "root", VSOCK);
    await mkdir(join(chrootDir, "root", dirname(VSOCK)), { recursive: true });
    await writeFile(stale, "stale");
    const r = await stageJailedSlot({ chrootDir, files: [stateSrc], vsockUdsPath: VSOCK, uid: UID, gid: GID, cacheDir });
    expect(r.vsockDir).toBe(`${join(chrootDir, "root")}${dirname(VSOCK)}`);
    const d = await stat(r.vsockDir);
    expect(d.isDirectory()).toBe(true);
    expect(d.uid).toBe(UID);
    await expect(stat(stale)).rejects.toThrow();
  });

  it("EXDEV source: copied ONCE into the cache, then hard-linked per slot (second slot copies nothing)", async () => {
    let copies = 0;
    const ops: StagingFsOps = { ...exdevLinkOps, copyFile: async (s, d) => { copies++; await copyFile(s, d); } };
    const slot2 = join(base, "jails/pool/firecracker/slot-generic-2");
    await mkdir(join(slot2, "root"), { recursive: true });
    const r1 = await stageJailedSlot({ chrootDir, files: [rootfsSrc], vsockUdsPath: VSOCK, uid: UID, gid: GID, cacheDir, ops });
    const r2 = await stageJailedSlot({ chrootDir: slot2, files: [rootfsSrc], vsockUdsPath: VSOCK, uid: UID, gid: GID, cacheDir, ops });
    expect(copies).toBe(1);
    expect(r1.files[0]!.method).toBe("copy");
    expect(r2.files[0]!.method).toBe("copy");
    const cached = join(cacheDir, stagingCacheNameFor(rootfsSrc));
    const cachedIno = (await stat(cached)).ino;
    expect((await stat(`${r1.root}${rootfsSrc}`)).ino).toBe(cachedIno);
    expect((await stat(`${r2.root}${rootfsSrc}`)).ino).toBe(cachedIno);
    expect(await readFile(`${r2.root}${rootfsSrc}`, "utf8")).toBe("ROOTFS");
    // No temp file left behind in the cache dir.
    const { readdir } = await import("node:fs/promises");
    expect((await readdir(cacheDir)).filter((n) => n.endsWith(".tmp"))).toEqual([]);
  });

  it("concurrent slots that miss the cache together each copy to their OWN temp (per-call-unique) — the depth≥2 jailed-warm ENOENT regression", async () => {
    // Observed live: enabling the jail failed every jailed warm at depth 2 with
    // `ENOENT ... chmod '<...>.tmp'`. Cause: the cache temp was `${pid}.${Date.now()}` — pid is 1 in
    // the container and Date.now() collides at ms resolution when pool.start() fans warms out, so two
    // slots computed the SAME temp and one slot's `finally rm(tmp)` deleted the temp another was
    // mid-copy/chmod/link on. A barrier holds every concurrent miss in-flight together (the exact race),
    // then we assert every temp was DISTINCT and every stage succeeded. Reverting to pid+Date.now()
    // collides the temps under this concurrency ⇒ this goes red.
    const N = 4;
    const tmpsSeen: string[] = [];
    let entered = 0;
    let release!: () => void;
    const allEntered = new Promise<void>((r) => (release = r));
    const ops: StagingFsOps = {
      ...exdevLinkOps,
      copyFile: async (s, d) => {
        if (d.endsWith(".tmp")) {
          tmpsSeen.push(d);
          if (++entered === N) release();
          await allEntered; // every concurrent miss is now in-flight — temps must not collide
        }
        await copyFile(s, d);
      },
    };
    const results = await Promise.all(
      Array.from({ length: N }, (_, i) =>
        stageJailedSlot({
          chrootDir: join(base, `jails/pool/firecracker/slot-generic-${i + 1}`),
          files: [memSrc], // same EXDEV source → all miss the shared cache together
          vsockUdsPath: VSOCK,
          uid: UID,
          gid: GID,
          cacheDir,
          ops,
        }),
      ),
    );
    expect(results.length).toBe(N); // all resolved — no ENOENT from a clobbered temp
    expect(tmpsSeen.length).toBe(N); // all N genuinely missed together and each entered the copy branch
    expect(new Set(tmpsSeen).size).toBe(N); // every temp path DISTINCT (the fix) — pid+Date.now() would collide
    // Cache converges to exactly one entry; no temp left behind.
    const { readdir } = await import("node:fs/promises");
    const entries = await readdir(cacheDir);
    expect(entries.filter((n) => n.endsWith(".tmp"))).toEqual([]);
    expect(entries).toEqual([stagingCacheNameFor(memSrc)]);
  });

  it("re-staging the same slot over a stale tree overwrites cleanly", async () => {
    await stageJailedSlot({ chrootDir, files: [stateSrc, memSrc], vsockUdsPath: VSOCK, uid: UID, gid: GID, cacheDir });
    // A NEW base snapshot on the host (rebuilt read-only) — the producer's write, not the slot's.
    await chmod(stateSrc, 0o644);
    await writeFile(stateSrc, "STATE-v2");
    await chmod(stateSrc, 0o444);
    const r = await stageJailedSlot({ chrootDir, files: [stateSrc, memSrc], vsockUdsPath: VSOCK, uid: UID, gid: GID, cacheDir });
    expect(await readFile(`${r.root}${stateSrc}`, "utf8")).toBe("STATE-v2");
  });

  it("fail-closed: a missing source throws naming the path, and NOTHING is placed", async () => {
    const missing = join(base, "src/usr/local/share/k9o/absent.ext4");
    const p = stageJailedSlot({ chrootDir, files: [stateSrc, missing], vsockUdsPath: VSOCK, uid: UID, gid: GID, cacheDir });
    await expect(p).rejects.toBeInstanceOf(JailedSlotStagingError);
    await expect(p).rejects.toThrow(missing);
    // state was listed FIRST but must not have been placed — sources are checked before any placement.
    await expect(stat(join(chrootDir, "root", stateSrc))).rejects.toThrow();
  });

  it("fail-closed: a relative snapshot-referenced path is refused", async () => {
    await expect(
      stageJailedSlot({ chrootDir, files: ["relative/base.ext4"], vsockUdsPath: VSOCK, uid: UID, gid: GID, cacheDir }),
    ).rejects.toThrow("must be absolute");
  });

  // ── defense-in-depth conditions on shared staged inodes and the vsock directory ───────────────────
  it("COND-1: refuses a staged inode the slot uid could WRITE (owner-write bit) — shared writable inode = cross-slot tamper channel; the placement is undone", async () => {
    // The slot uid IS the test user, and this fixture is writable by its owner ⇒ the slot could write it.
    const writable = join(base, "src/usr/local/share/k9o/scratch.ext4");
    await writeFile(writable, "SCRATCH", { mode: 0o644 });
    const p = stageJailedSlot({ chrootDir, files: [stateSrc, writable], vsockUdsPath: VSOCK, uid: UID, gid: GID, cacheDir });
    await expect(p).rejects.toBeInstanceOf(JailedSlotStagingError);
    await expect(p).rejects.toThrow("WRITABLE by the slot uid");
    await expect(p).rejects.toThrow(writable);
    // The offending placement is removed; the read-only sibling placed before it is not left as a partial.
    await expect(stat(join(chrootDir, "root", writable))).rejects.toThrow();
  });

  it("COND-1: cache copies (the EXDEV path every rootfs takes) are published 0444 — a writable SOURCE never becomes the shared inode", async () => {
    // Source is owner-writable, but it is cross-device: the slot links the CACHE inode, which is 0444.
    const src = join(base, "src/usr/local/share/k9o/writable-src.ext4");
    await writeFile(src, "W", { mode: 0o644 });
    const r = await stageJailedSlot({ chrootDir, files: [src], vsockUdsPath: VSOCK, uid: UID, gid: GID, cacheDir, ops: exdevLinkOps });
    const cached = join(cacheDir, stagingCacheNameFor(src));
    expect((await stat(cached)).mode & 0o777).toBe(0o444);
    expect((await stat(`${r.root}${src}`)).ino).toBe((await stat(cached)).ino);
    expect((await stat(`${r.root}${src}`)).mode & 0o777).toBe(0o444);
  });

  it("COND-2: refuses a baked vsock path whose parent is the chroot ROOT (chown would hand the slot the whole root); nothing placed", async () => {
    const p = stageJailedSlot({ chrootDir, files: [stateSrc], vsockUdsPath: "/k9o.vsock", uid: UID, gid: GID, cacheDir });
    await expect(p).rejects.toThrow("parent is the chroot root");
    await expect(stat(join(chrootDir, "root", stateSrc))).rejects.toThrow();
    // ...and the chroot root's ownership was not touched (still the test user's dir, but more to the
    // point: no chown ran because we refused pre-flight — the root still exists and is ours to rm).
    expect((await stat(join(chrootDir, "root"))).isDirectory()).toBe(true);
  });

  it("COND-2: refuses a staged file at or under the dir the slot uid will OWN (it could unlink + replace the inode); nothing placed", async () => {
    const vsockBesideState = `${join(base, "src/var/lib/k9o/exec")}/k9o.vsock`; // dirname == dirname(stateSrc)
    // Both listed files sit in that dir; the guard names the FIRST offender (memSrc) and places nothing.
    const p = stageJailedSlot({ chrootDir, files: [memSrc, stateSrc], vsockUdsPath: vsockBesideState, uid: UID, gid: GID, cacheDir });
    await expect(p).rejects.toThrow("under the vsock dir the slot uid will own");
    await expect(p).rejects.toThrow(memSrc);
    await expect(stat(join(chrootDir, "root", memSrc))).rejects.toThrow(); // pre-flight: nothing placed
    await expect(stat(join(chrootDir, "root", stateSrc))).rejects.toThrow();
  });

  // ── hardening: chroot scoping by construction ─────────────────────────────────────────────────────
  it("DOTDOT: refuses a snapshot-referenced path with a `..` segment even when it resolves to a real file; nothing placed", async () => {
    const viaDotDot = `${join(base, "src/var/lib/k9o")}/../k9o/exec/base.state`; // exists on the host
    expect((await stat(viaDotDot)).isFile()).toBe(true);
    const p = stageJailedSlot({ chrootDir, files: [memSrc, viaDotDot], vsockUdsPath: VSOCK, uid: UID, gid: GID, cacheDir });
    await expect(p).rejects.toThrow("not canonical");
    await expect(p).rejects.toThrow(viaDotDot);
    await expect(stat(join(chrootDir, "root", memSrc))).rejects.toThrow(); // pre-flight: nothing placed
  });

  it("DOTDOT: refuses a baked vsock path with a `..` segment (the stale-socket rm would reach outside the chroot)", async () => {
    await expect(
      stageJailedSlot({ chrootDir, files: [stateSrc], vsockUdsPath: "/tmp/../k9o-base-snapshot.vsock", uid: UID, gid: GID, cacheDir }),
    ).rejects.toThrow("not canonical");
    await expect(stat(join(chrootDir, "root", stateSrc))).rejects.toThrow();
  });

  it("cache names are unique per absolute source path (no basename aliasing)", () => {
    expect(stagingCacheNameFor("/a/base.state")).not.toBe(stagingCacheNameFor("/b/base.state"));
    expect(stagingCacheNameFor("/a/base.state")).not.toContain("/");
  });
});
