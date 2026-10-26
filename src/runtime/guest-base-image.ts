/**
 * The sanctioned BASE IMAGE the warm-pool generic rootfs is built from — the
 * second of the exec-runtime warm pool's three inputs (kernel → base rootfs →
 * base snapshot). Same arrangement as {@link file://./guest-kernel.ts}: this
 * module is the single source and `scripts/build-base-rootfs.sh` DERIVES the pin
 * from it, so the image the build fetches and the image the estate sanctioned
 * cannot drift apart.
 *
 * 🟢 THE CHAIN IS PROVEN, NOT ASSUMED. Run by hand in a pod
 * before any of this was written down:
 *
 *   skopeo copy docker://busybox@sha256:3c6ae80…  ->  /tmp/base.tar   875,520 B
 *   build-base-rootfs.ts                          ->  /tmp/base.ext4  69,206,016 B
 *   create-base-snapshot.ts                       ->  base.state 13,985 B
 *                                                     base.mem  134,217,728 B
 *
 * and `create-base-snapshot` reported `networkInterfaces=0, vsock=1` read back
 * from Firecracker's own `/vm/config`. So the base below is not a guess about
 * what k9o-init needs — it is the one that booted.
 *
 * WHY BUSYBOX, and why this is the RIGHT minimal base: k9o-init is a static-musl
 * PID 1 that sets up its own mounts and vsock bridges, so the base image supplies
 * userspace and nothing else — no init, no libc requirement. `build-base-rootfs.ts`
 * documents busybox or a distroless-static base as the intended shapes; busybox
 * over distroless-static because it retains a shell, which is the difference
 * between diagnosing a wedged guest and staring at a silent one. `-musl` to match
 * the static-musl k9o-init the converter injects.
 *
 * 📌 PINNED BY DIGEST, NOT BY TAG. `stable-musl` moves; this digest does not. It
 * is the multi-arch INDEX digest — `skopeo copy` is given `--override-os linux
 * --override-arch amd64` to select the amd64 manifest out of it, matching the
 * x86_64-only posture of `install-firecracker.sh` and `install-kernel.sh`.
 *
 * ⚠️ NO OUTPUT DIGEST IS PINNED, deliberately. `mkfs.ext4` embeds a filesystem
 * UUID and timestamps, so the built ext4 is NOT byte-reproducible and asserting a
 * digest on it would fail every build for a reason that is not a supply-chain
 * event. The integrity boundary is the INPUT (this digest) plus the k9o-init
 * binary the converter injects, both of which are pinned.
 */

/** Repository of the warm-pool generic base image. */
export const GUEST_BASE_IMAGE_REPO = "docker.io/library/busybox";

/**
 * Multi-arch index digest of `busybox:stable-musl`, resolved from the registry
 * (`docker-content-digest` on the manifest HEAD). The ONLY place this is written
 * down; `build-base-rootfs.sh` parses it out of this file.
 */
export const GUEST_BASE_IMAGE_DIGEST =
  "sha256:3c6ae8008e2c2eedd141725c30b20d9c36b026eb796688f88205845ef17aa213";

/**
 * Where the built generic base rootfs lands in the image. `/usr/local/share/k9o`
 * alongside the kernel — both are exec-runtime data the operator points env vars
 * at, not executables the runtime shells out to.
 */
export const GUEST_BASE_ROOTFS_PATH = "/usr/local/share/k9o/base.ext4";
