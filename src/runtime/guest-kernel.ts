/**
 * The sanctioned guest kernel for the sandbox tier exec-runtime (the
 * enforced-boundary sandbox). This module is the SINGLE SOURCE for which kernel
 * this project boots microVMs on, and `scripts/install-kernel.sh` DERIVES the pin
 * from here — the same one-way coupling `install-firecracker.sh` has with
 * `jailer-wrapper.ts`, and for the same reason: a literal duplicated into the
 * install script drifts silently in the one direction no test catches.
 *
 * 🔴 WHY THIS EXISTS AT ALL. Originally NOTHING in the deployment supplied a
 * kernel. The host carried `K9O_EXEC_RUNTIME_KERNEL=/tmp/vmlinux`
 * pointing at a path that has never had a file at it (`/tmp` is an emptyDir and
 * no build step, init container or job ever wrote there — measured in-pod on
 * an early beta: firecracker, jailer, k9o-init, umoci,
 * skopeo and mkfs.ext4 are ALL present, and there is no `vmlinux*` and no
 * `*.ext4` anywhere on the filesystem). That is the first of the warm pool's
 * three missing inputs — kernel, then base rootfs, then the base snapshot pair
 * `create-base-snapshot.ts` writes from them. This module closes the first.
 *
 * ⚠️ IT IS DELIBERATELY NOT A DEFAULT. `K9O_EXEC_RUNTIME_KERNEL` stays REQUIRED
 * and the deploy overlay points it at {@link GUEST_KERNEL_PATH} explicitly. A
 * silent fallback to the installed path would be the same class of defect as the
 * `K9O_REGION ?? "us-east-1"` default removed earlier — it makes a
 * kernel-less pod look configured, which is precisely the state that produced
 * "warm pool failed to reach target depth" on every boot for weeks.
 *
 * PROVENANCE: the Firecracker project's own CI guest kernels, the artifacts
 * Firecracker itself is tested against —
 *   s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-6.1.155
 * The `v1.15` prefix tracks `FIRECRACKER_VERSION` (jailer-wrapper.ts), so the
 * VMM and the kernel it boots come from one release line rather than two
 * independently-chosen versions. 6.1 over the co-published 5.10: it is the
 * current LTS, and it is the line Firecracker builds its ACPI-enabled x86_64
 * artifacts on (the bucket carries an explicit `-no-acpi` 5.10 variant for the
 * pre-ACPI path we are not on). x86_64 only — the KVM hosts are AMD
 * and `install-firecracker.sh` is already x86_64-only for the same reason.
 */

/** Guest kernel version — the ONLY place this is written down. */
export const GUEST_KERNEL_VERSION = "6.1.155";

/**
 * SHA-256 of the `vmlinux-${GUEST_KERNEL_VERSION}` artifact, measured on the
 * downloaded bytes (44,279,576 bytes; ELF 64-bit LSB executable, x86-64,
 * statically linked). `install-kernel.sh` verifies the download against this and
 * REFUSES to install on a mismatch — the image must not be able to acquire a
 * kernel nobody chose. Bumping {@link GUEST_KERNEL_VERSION} without re-measuring
 * this fails the build, which is the intended forcing function.
 */
export const GUEST_KERNEL_SHA256 =
  "e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2";

/**
 * Where `install-kernel.sh` places the kernel in the image. DERIVED from the
 * version rather than written out, so the two cannot disagree; the install
 * script builds the identical path from the identical constant. `/usr/local/share`
 * (not `/usr/local/bin`) because it is data, not an executable the runtime shells
 * out to — the same shelf `install-firecracker.sh` uses for its seccomp filter.
 */
export const GUEST_KERNEL_PATH = `/usr/local/share/k9o/vmlinux-${GUEST_KERNEL_VERSION}`;
