/**
 * Warm-pool base-image pin tests: the base image is pinned by digest, never by a tag that moves.
 */

import { describe, expect, it } from "bun:test";
import {
  GUEST_BASE_IMAGE_REPO,
  GUEST_BASE_IMAGE_DIGEST,
} from "./guest-base-image.ts";

describe("warm-pool base image pin", () => {
  it("is pinned by digest, not by a tag that moves", () => {
    expect(GUEST_BASE_IMAGE_DIGEST).toMatch(/^sha256:[0-9a-f]{64}$/);
    // A repo string carrying a tag would mean the digest is decorative.
    expect(GUEST_BASE_IMAGE_REPO).not.toContain(":");
    expect(GUEST_BASE_IMAGE_REPO).not.toContain("@");
  });
});
