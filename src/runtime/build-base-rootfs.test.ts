/**
 * Base-rootfs build tool. Tests the parts exercisable without a Linux host:
 * plan validation (pure) + the convert→write orchestration against
 * MockOciConverter with injected in-memory I/O. The real skopeo→umoci→mkfs.ext4
 * conversion runs on the exec node.
 */

import { describe, it, expect } from "bun:test";
import { createHash } from "node:crypto";
import { buildBaseRootfsPlan, buildBaseRootfs, type BaseRootfsIO, type OciConverter } from "./build-base-rootfs.ts";

type ConvertReq = Parameters<OciConverter["convert"]>[0];

/** An identity converter: records each request, returns the input bytes as the "ext4", and can be told to fail once. */
class MockOciConverter implements OciConverter {
  readonly conversions: Array<{ req: ConvertReq }> = [];
  failNext: { stage: string; detail: string } | null = null;

  async convert(req: ConvertReq) {
    if (this.failNext !== null) {
      const { stage, detail } = this.failNext;
      this.failNext = null;
      throw new Error(`OCI conversion failed at ${stage}: ${detail}`);
    }
    const sha = createHash("sha256").update(req.ociImageBytes).digest("hex");
    this.conversions.push({ req });
    return {
      rootfsKey: `artifacts/proj/${req.projectId}/firecracker/${sha}.ext4`,
      rootfsSha256: sha,
      rootfsBytes: req.ociImageBytes.length,
      ext4Data: req.ociImageBytes,
    };
  }
}

const FULL_ENV = {
  K9O_EXEC_RUNTIME_BASE_OCI_ARCHIVE: "/tmp/base.tar",
  K9O_EXEC_RUNTIME_BASE_ROOTFS: "/out/base.ext4",
} as NodeJS.ProcessEnv;

/** In-memory I/O: a fixed archive in, a captured ext4 out. */
function memIO(archive: Uint8Array): { io: BaseRootfsIO; written: { path?: string; bytes?: Uint8Array } } {
  const written: { path?: string; bytes?: Uint8Array } = {};
  return {
    written,
    io: {
      readArchive: async () => archive,
      writeExt4: async (path, bytes) => {
        written.path = path;
        written.bytes = bytes;
      },
    },
  };
}

describe("buildBaseRootfsPlan", () => {
  it("assembles from the two required vars + default tag", () => {
    const plan = buildBaseRootfsPlan({ ...FULL_ENV });
    expect(plan).toEqual({ ociArchivePath: "/tmp/base.tar", outputPath: "/out/base.ext4", tag: "latest", generic: true });
  });

  it("honours an explicit oci tag", () => {
    const plan = buildBaseRootfsPlan({ ...FULL_ENV, K9O_EXEC_RUNTIME_BASE_OCI_TAG: "v1" });
    expect(plan.tag).toBe("v1");
  });

  it("lists EVERY missing required var in one error", () => {
    let err: Error | null = null;
    try {
      buildBaseRootfsPlan({} as NodeJS.ProcessEnv);
    } catch (e) {
      err = e as Error;
    }
    expect(err).not.toBeNull();
    expect(err!.message).toContain("K9O_EXEC_RUNTIME_BASE_OCI_ARCHIVE");
    expect(err!.message).toContain("K9O_EXEC_RUNTIME_BASE_ROOTFS");
  });
});

describe("buildBaseRootfs — convert → write orchestration", () => {
  it("converts the base image (project `_base`) and writes ext4 to the output path", async () => {
    const archive = new TextEncoder().encode("oci-archive-bytes");
    const { io, written } = memIO(archive);
    const mock = new MockOciConverter();
    const plan = buildBaseRootfsPlan({ ...FULL_ENV });

    const { sha256, bytes } = await buildBaseRootfs(mock, plan, io, () => {});

    // The converter saw the base image under the sentinel `_base` project.
    expect(mock.conversions).toHaveLength(1);
    expect(mock.conversions[0]!.req.projectId).toBe("_base");
    expect(mock.conversions[0]!.req.ociImageBytes).toEqual(archive);
    expect(mock.conversions[0]!.req.tag).toBe("latest");
    // generic: true → the converter skips /etc/k9o/entry.json so k9o-init boots
    // warm-pool-idle instead of exec'ing the base image entrypoint (→ exit 127 panic).
    expect(mock.conversions[0]!.req.generic).toBe(true);
    // The ext4 bytes were written to the pool-read path, and the sha is surfaced.
    expect(written.path).toBe("/out/base.ext4");
    expect(written.bytes).toEqual(archive); // mock converter is identity
    expect(sha256).toHaveLength(64);
    expect(bytes).toBe(archive.length);
  });

  it("throws (no ext4 written) when the converter retains no ext4Data — never a silent empty rootfs", async () => {
    const archive = new TextEncoder().encode("x");
    const { io, written } = memIO(archive);
    // A converter whose convert() returns no ext4Data (upload-only shape).
    const uploadOnly = {
      async convert() {
        return { rootfsKey: "k", rootfsSha256: "0".repeat(64), rootfsBytes: 1 /* ext4Data omitted */ };
      },
    };
    const plan = buildBaseRootfsPlan({ ...FULL_ENV });
    await expect(buildBaseRootfs(uploadOnly, plan, io, () => {})).rejects.toThrow(/no ext4Data/);
    expect(written.bytes).toBeUndefined(); // nothing written on the error path
  });

  it("propagates a converter failure (no ext4 written)", async () => {
    const archive = new TextEncoder().encode("x");
    const { io, written } = memIO(archive);
    const mock = new MockOciConverter();
    mock.failNext = { stage: "mkfs-ext4", detail: "no space left on device" };
    const plan = buildBaseRootfsPlan({ ...FULL_ENV });
    await expect(buildBaseRootfs(mock, plan, io, () => {})).rejects.toThrow(/no space left/);
    expect(written.bytes).toBeUndefined();
  });
});

// The sandbox-tier `generic` flag: generic=true (default) is Bun-tier
// warm-pool-idle (no entry.json); generic=false is sandbox-tier (entry.json written
// so k9o-init launches the baked-in sandbox-tier runner at boot).
describe("buildBaseRootfsPlan — generic flag (sandbox tier)", () => {
  it("defaults to generic=true (Bun-tier warm-pool-idle preserved)", () => {
    expect(buildBaseRootfsPlan({ ...FULL_ENV }).generic).toBe(true);
  });

  it("K9O_EXEC_RUNTIME_BASE_GENERIC=false flips it (sandbox tier)", () => {
    expect(buildBaseRootfsPlan({ ...FULL_ENV, K9O_EXEC_RUNTIME_BASE_GENERIC: "false" }).generic).toBe(false);
  });

  it("is case-insensitive; ONLY 'false' flips it (any other value stays safe-default true)", () => {
    expect(buildBaseRootfsPlan({ ...FULL_ENV, K9O_EXEC_RUNTIME_BASE_GENERIC: "FALSE" }).generic).toBe(false);
    expect(buildBaseRootfsPlan({ ...FULL_ENV, K9O_EXEC_RUNTIME_BASE_GENERIC: "true" }).generic).toBe(true);
    expect(buildBaseRootfsPlan({ ...FULL_ENV, K9O_EXEC_RUNTIME_BASE_GENERIC: "0" }).generic).toBe(true);
  });
});

describe("buildBaseRootfs — generic passes through to the converter", () => {
  it("generic=false reaches converter.convert (entry.json written → runner launches at boot)", async () => {
    const mock = new MockOciConverter();
    const { io } = memIO(new Uint8Array([1, 2, 3]));
    await buildBaseRootfs(mock, { ociArchivePath: "/x", outputPath: "/y", tag: "latest", generic: false }, io, () => {});
    expect(mock.conversions[0]!.req.generic).toBe(false);
  });

  it("generic=true reaches converter.convert (warm-pool-idle, no entry.json)", async () => {
    const mock = new MockOciConverter();
    const { io } = memIO(new Uint8Array([1, 2, 3]));
    await buildBaseRootfs(mock, { ociArchivePath: "/x", outputPath: "/y", tag: "latest", generic: true }, io, () => {});
    expect(mock.conversions[0]!.req.generic).toBe(true);
  });
});
