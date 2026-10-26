/**
 * Stage the base snapshot's inputs INTO a jailed warm slot's chroot (the half that enabling
 * the jail flag alone was missing).
 *
 * WHY THIS EXISTS — measured live on a deployed host. The jailer
 * chroots Firecracker under `<chrootDir>/root`, and Firecracker resolves EVERY path it is handed — the
 * `PUT /snapshot/load` `snapshot_path` + `mem_backend.backend_path`, AND the paths BAKED INTO the
 * snapshot (the rootfs drive's `path_on_host`, the vsock `uds_path`) — inside that chroot. Nothing
 * staged them there, so `K9O_EXEC_RUNTIME_JAIL=1` on its own fails EVERY warm slot:
 *
 *   PUT /snapshot/load → 400 {"fault_message":"Load snapshot error: Failed to restore from snapshot:
 *     Failed to get snapshot state from file: Failed to open snapshot file: No such file or directory"}
 *
 * With the same three files placed at `<chrootDir>/root<absolute-host-path>` (and the vsock socket's
 * parent dir present + owned by the slot uid), the SAME jailed Firecracker restored (204), resumed
 * (`state: Running`), bound its vsock at `<chrootDir>/root/tmp/k9o-base-snapshot.vsock` alongside the
 * un-jailed pool slot's `/tmp/k9o-base-snapshot.vsock` (no collision), and the guest answered
 * `CONNECT 8000` → `OK 1073741824`. That is the vsock/jailer proof; this module is that hand sequence
 * as code.
 *
 * Path rule: the host path and the in-chroot path are THE SAME STRING. The pool keeps handing
 * Firecracker the absolute host paths (unchanged `SnapshotLoadConfig`); staging makes those strings
 * resolve inside the chroot. No path rewriting, so the un-jailed branch stays byte-identical.
 *
 * Hard-link first, copy on EXDEV. The chroot base (`jailer-root` emptyDir) and the snapshot pair
 * (`exec-artifacts` emptyDir) are DIFFERENT mounts in a pod even though `stat` reports one device —
 * `link(2)` returns EXDEV across them (measured). The rootfs lives on the image overlay — always EXDEV.
 * So a cross-device source is copied ONCE into `<cacheDir>` (same mount as the chroots) and every slot
 * hard-links from the cache: ~195 MB copied once per process, zero bytes per slot after that. Removing
 * a slot's chroot (`removeChroot`) drops only its links; the cache survives for the next warm.
 *
 * Fail-closed: a missing source, an unreadable file, or a failed chown throws — the slot does NOT warm.
 * A half-staged chroot restores nothing useful; better one loud line naming the file than the
 * hypervisor's "No such file" several layers down (the shape of a prior warm-pool incident).
 */

import { chmod, chown, copyFile, link, mkdir, rm, stat } from "node:fs/promises";
import type { Stats } from "node:fs";
import { dirname, normalize } from "node:path";
import { randomUUID } from "node:crypto";

/**
 * Two defense-in-depth conditions:
 *
 * CONDITION 1 — sharing one cache inode across slots is safe ONLY because no guest can write it (the
 * rootfs drive is `is_read_only`, the mem File-backend is copy-on-write). That was safe-by-happenstance.
 * `slotCanWriteByMode` makes it safe-by-construction: after placement the staged inode is refused if
 * the slot (uid, gid) could write it by mode — owner-write when the slot owns it, group-write when its
 * group matches, or other-write. Cache copies are published 0444 so a source's mode never reaches the
 * slot. A future WRITABLE drive baked into the snapshot therefore cannot silently become a shared inode:
 * Firecracker (as the slot uid) could not open it for write, and this guard refuses it first, by name.
 *
 * CONDITION 2 — `chown(dirname(vsockUdsPath))` hands the slot uid a directory. That is safe only while
 * the directory holds nothing but the vsock: if the baked path's parent were the chroot root, or an
 * ancestor of a staged file, the slot could unlink and replace a staged read-only inode (directory
 * write permission is what `unlink` needs, not file permission). Refused before any placement.
 */
export function slotCanWriteByMode(st: Pick<Stats, "mode" | "uid" | "gid">, uid: number, gid: number): boolean {
  const mode = st.mode & 0o777;
  if (st.uid === uid && (mode & 0o200) !== 0) return true;
  if (st.gid === gid && (mode & 0o020) !== 0) return true;
  return (mode & 0o002) !== 0;
}

const CACHE_ENTRY_MODE = 0o444;

/** Injectable fs seam — production uses node:fs/promises; tests inject an EXDEV-throwing `link` to
 *  prove the copy-fallback + cache-reuse branch, which is the branch the rootfs ALWAYS takes live. */
export type StagingFsOps = {
  link: (src: string, dest: string) => Promise<void>;
  copyFile: (src: string, dest: string) => Promise<void>;
  chown: (path: string, uid: number, gid: number) => Promise<void>;
};

const REAL_FS_OPS: StagingFsOps = {
  link: (src, dest) => link(src, dest),
  copyFile: (src, dest) => copyFile(src, dest),
  chown: (path, uid, gid) => chown(path, uid, gid),
};

export type StageJailedSlotInput = {
  /** The jailer's per-slot chroot dir (`<chrootRoot>/pool/firecracker/<vmSlotId>`); Firecracker's root is `<chrootDir>/root`. */
  chrootDir: string;
  /** Absolute host paths Firecracker will open on restore: the snapshot state + memory file, and every
   *  path baked into the snapshot (the rootfs drive). Each MUST exist on the host. */
  files: readonly string[];
  /** The vsock `uds_path` baked into the snapshot — its parent dir must exist in the chroot and be
   *  writable by the slot uid, or the restore fails at the vsock bind. */
  vsockUdsPath: string;
  /** The slot's jail uid/gid (Firecracker runs as this inside the chroot). */
  uid: number;
  gid: number;
  /** Where cross-device sources are copied once for hard-linking. Must be on the chroots' mount. */
  cacheDir: string;
  ops?: StagingFsOps;
};

export type StagedFile = { src: string; dest: string; method: "link" | "copy" };

export type StageJailedSlotResult = {
  root: string;
  files: readonly StagedFile[];
  vsockDir: string;
};

export class JailedSlotStagingError extends Error {
  readonly path: string;
  constructor(message: string, path: string) {
    super(`jailed-slot staging: ${message} (${path})`);
    this.name = "JailedSlotStagingError";
    this.path = path;
  }
}

function errnoOf(e: unknown): string | undefined {
  return typeof e === "object" && e !== null && "code" in e ? String((e as { code: unknown }).code) : undefined;
}

/** The cache filename for a host source: unique per absolute path (two `base.state`s in different dirs
 *  cannot alias), filesystem-safe. */
export function stagingCacheNameFor(src: string): string {
  return encodeURIComponent(src);
}

/**
 * Link-or-copy `src` to `dest` (dest's parent already exists). Same-mount ⇒ hard link (zero bytes).
 * EXDEV ⇒ copy `src` once into `cacheDir` (skipped if the cache entry already exists) and hard-link
 * from there; if even that is EXDEV (cache on yet another mount — misconfiguration, still workable)
 * fall back to a plain copy. A stale `dest` from a previous warm of the same vmSlotId is removed first.
 */
async function placeFile(
  src: string,
  dest: string,
  cacheDir: string,
  ops: StagingFsOps,
): Promise<StagedFile> {
  await rm(dest, { force: true });
  try {
    await ops.link(src, dest);
    return { src, dest, method: "link" };
  } catch (e) {
    if (errnoOf(e) !== "EXDEV") throw new JailedSlotStagingError(`link failed: ${(e as Error).message}`, src);
  }
  await mkdir(cacheDir, { recursive: true });
  const cached = `${cacheDir}/${stagingCacheNameFor(src)}`;
  let cacheHit = true;
  try {
    await stat(cached);
  } catch {
    cacheHit = false;
  }
  if (!cacheHit) {
    // Copy to a PER-CALL-UNIQUE temp then rename-by-link so a concurrent slot never links a
    // half-written cache entry: two slots warming in parallel (pool.start() fans out) both miss, both
    // copy their OWN temp, and `link(temp, cached)` succeeds for exactly one — the other gets EEXIST
    // and uses the published entry.
    // The temp name MUST be unique PER CALL. `${process.pid}.${Date.now()}` is NOT: the host process is
    // pid 1 in its container and `Date.now()` collides at ms resolution when the pool fans warms out,
    // so two slots computed the SAME temp and one slot's `finally rm(tmp)` below deleted the temp the
    // other was mid-copy/chmod/link on → `ENOENT ... chmod '<tmp>'`, failing every jailed warm at
    // depth ≥ 2 (measured live). randomUUID makes each call's temp its own.
    const tmp = `${cached}.${process.pid}.${randomUUID()}.tmp`;
    await ops.copyFile(src, tmp);
    // CONDITION 1: the cache inode is what every slot links — publish it read-only regardless of the
    // source's mode, so nothing writable ever becomes the shared inode.
    await chmod(tmp, CACHE_ENTRY_MODE);
    try {
      await ops.link(tmp, cached);
    } catch (e) {
      if (errnoOf(e) !== "EEXIST") throw new JailedSlotStagingError(`cache publish failed: ${(e as Error).message}`, src);
    } finally {
      await rm(tmp, { force: true });
    }
  }
  try {
    await ops.link(cached, dest);
    return { src, dest, method: "copy" };
  } catch (e) {
    if (errnoOf(e) !== "EXDEV") throw new JailedSlotStagingError(`link from cache failed: ${(e as Error).message}`, src);
  }
  await ops.copyFile(cached, dest);
  return { src, dest, method: "copy" };
}

/**
 * Make every path in `files` resolve inside `<chrootDir>/root`, and prepare the vsock socket's parent
 * dir. Idempotent per slot (re-staging over a stale tree overwrites). Throws — fail-closed — on any
 * missing source or failed step; the caller must NOT proceed to `loadSnapshot`.
 */
export async function stageJailedSlot(input: StageJailedSlotInput): Promise<StageJailedSlotResult> {
  const ops = input.ops ?? REAL_FS_OPS;
  const root = `${input.chrootDir}/root`;

  // Every source must exist BEFORE any file is placed: one missing rootfs should not leave a chroot
  // with a staged state+mem that a later retry could mistake for complete.
  for (const src of input.files) {
    if (!src.startsWith("/")) throw new JailedSlotStagingError("snapshot-referenced path must be absolute", src);
    try {
      const s = await stat(src);
      if (!s.isFile()) throw new JailedSlotStagingError("snapshot-referenced path is not a regular file", src);
    } catch (e) {
      if (e instanceof JailedSlotStagingError) throw e;
      throw new JailedSlotStagingError(`snapshot-referenced file missing on host: ${(e as Error).message}`, src);
    }
  }
  if (!input.vsockUdsPath.startsWith("/")) {
    throw new JailedSlotStagingError("baked vsock uds path must be absolute", input.vsockUdsPath);
  }
  // CHROOT-SCOPING BY CONSTRUCTION (substrate review hardening): every host path below is
  // built as `${root}${p}` by concatenation, so a `..` segment (or a non-canonical path) would resolve
  // OUTSIDE the chroot root — a link placed on the host, or the stale-socket `rm` reaching a host path.
  // Today every input is a substrate-authored constant, but this module is exported; refuse any path that
  // is not already canonical so the in-chroot scoping does not depend on the caller being trusted.
  for (const p of [...input.files, input.vsockUdsPath]) {
    if (normalize(p) !== p || p.split("/").includes("..") || p.split("/").includes(".")) {
      throw new JailedSlotStagingError(
        "path is not canonical (`..`/`.` segment or redundant separators) — it would resolve outside the chroot root",
        p,
      );
    }
  }
  // CONDITION 2 (pre-flight, before anything is placed): the directory the slot uid will OWN must hold
  // nothing but the vsock. Its parent at the chroot root would chown the whole root to the slot; a
  // staged file at or under it would be unlink-and-replaceable by the slot (directory write is all
  // `unlink` needs). Both are operator-config mistakes, refused by name rather than staged.
  const vsockParent = dirname(input.vsockUdsPath);
  if (vsockParent === "/") {
    throw new JailedSlotStagingError(
      "baked vsock uds path's parent is the chroot root — chown would hand the slot uid the whole chroot root",
      input.vsockUdsPath,
    );
  }
  for (const src of input.files) {
    if (src === vsockParent || src.startsWith(`${vsockParent}/`)) {
      throw new JailedSlotStagingError(
        `snapshot-referenced file lies under the vsock dir the slot uid will own (${vsockParent}) — the slot could unlink and replace the staged inode`,
        src,
      );
    }
  }

  const staged: StagedFile[] = [];
  for (const src of input.files) {
    const dest = `${root}${src}`;
    await mkdir(dirname(dest), { recursive: true });
    const placed = await placeFile(src, dest, input.cacheDir, ops);
    // CONDITION 1 (post-placement, on the inode Firecracker will actually open): refuse anything the slot
    // (uid, gid) could write — a writable inode shared across slots is a cross-slot tamper channel.
    const st = await stat(dest);
    if (slotCanWriteByMode(st, input.uid, input.gid)) {
      await rm(dest, { force: true });
      throw new JailedSlotStagingError(
        `staged inode is WRITABLE by the slot uid ${input.uid} (mode ${(st.mode & 0o777).toString(8)}, owner ${st.uid}:${st.gid}) — a writable inode shared across slots is a cross-slot tamper channel; the base snapshot's inputs must be read-only`,
        src,
      );
    }
    staged.push(placed);
  }

  // The vsock bind: Firecracker (as the slot uid) creates `<root><udsPath>` on restore. The parent must
  // exist and be writable by that uid, and NO stale socket file may sit at the path — a leftover file is
  // EADDRINUSE at bind, the exact symptom this whole seam exists to remove.
  const vsockDir = `${root}${dirname(input.vsockUdsPath)}`;
  await mkdir(vsockDir, { recursive: true });
  await rm(`${root}${input.vsockUdsPath}`, { force: true });
  try {
    await ops.chown(vsockDir, input.uid, input.gid);
  } catch (e) {
    throw new JailedSlotStagingError(`chown of vsock dir to slot uid ${input.uid} failed: ${(e as Error).message}`, vsockDir);
  }

  return { root, files: staged, vsockDir };
}
