/**
 * Guest-kernel pin tests. `guest-kernel.ts` is the single source for which kernel the runtime boots; an
 * install script derives the same path and checksum from it, so the shape of both constants is load-bearing.
 */

import { describe, expect, it } from "bun:test";
import {
  GUEST_KERNEL_VERSION,
  GUEST_KERNEL_SHA256,
  GUEST_KERNEL_PATH,
} from "./guest-kernel.ts";

describe("guest kernel pin", () => {
  it("GUEST_KERNEL_PATH is derived from GUEST_KERNEL_VERSION", () => {
    // The install script builds the destination path from the same constant. If
    // these two constructions ever diverge, the image installs the kernel under
    // one name and the overlay points K9O_EXEC_RUNTIME_KERNEL at another — the
    // exact drift install-firecracker.sh's seccomp-filter path once had.
    expect(GUEST_KERNEL_PATH).toContain(GUEST_KERNEL_VERSION);
    expect(GUEST_KERNEL_PATH).toBe(`/usr/local/share/k9o/vmlinux-${GUEST_KERNEL_VERSION}`);
  });

  it("GUEST_KERNEL_SHA256 is a lowercase 64-hex digest", () => {
    // Not cosmetic: `sha256sum -c` matches case-sensitively against the checksum
    // line the script builds, so an uppercase digest fails the verification of a
    // kernel that is in fact correct — and the failure reads as a supply-chain
    // alarm rather than a formatting slip.
    expect(GUEST_KERNEL_SHA256).toMatch(/^[0-9a-f]{64}$/);
  });
});
