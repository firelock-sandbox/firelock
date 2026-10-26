/**
 * Base-rootfs build tool for the exec-runtime warm pool (sandbox tier).
 * The warm-pool base snapshot (`create-base-snapshot.ts`) boots a GENERIC base
 * microVM — kernel + a base rootfs with k9o-init as PID 1 (no customer code;
 * customer code arrives via vsock post-claim). This tool MATERIALIZES that base
 * rootfs: it runs the base OCI image through an injected
 * `OciConverter` (the caller supplies the implementation: skopeo → umoci →
 * mkfs.ext4, injecting k9o-init at
 * `K9O_INIT_BINARY_PATH`) and writes the resulting ext4 to the path the snapshot
 * tool reads (`K9O_EXEC_RUNTIME_BASE_ROOTFS`).
 *
 * It reuses the converter rather than a bespoke mkfs script so the base rootfs is
 * built by the SAME pipeline that converts per-function images (same k9o-init
 * injection, same ext4 sizing) — one code path, not two.
 *
 * PREREQUISITE — fetch the minimal base image to an oci-archive tar first (the
 * converter consumes tar bytes, it does not pull from a registry):
 *   skopeo copy docker://<minimal-base-image> oci-archive:/tmp/base.tar
 * A minimal base is right (busybox / a distroless-static base) — k9o-init is a
 * static-musl PID-1 that sets up its own mounts + vsock bridges, so the base image
 * only needs a minimal userspace, no init of its own.
 *
 * The caller needs a Linux host with skopeo/umoci/mkfs.ext4 and the k9o-init
 * binary present, and passes the environment variables
 * `K9O_EXEC_RUNTIME_BASE_OCI_ARCHIVE`, `K9O_EXEC_RUNTIME_BASE_ROOTFS` and
 * `K9O_INIT_BINARY_PATH` (see `buildBaseRootfsPlan`).
 */

/** What the base-rootfs build asks of an OCI-to-ext4 converter. The caller supplies the implementation. */
export interface OciConverter {
  convert(req: {
    projectId: string;
    ociImageBytes: Uint8Array;
    tag: string;
    /** Skip writing `/etc/k9o/entry.json` so k9o-init boots warm-pool-idle. */
    generic: boolean;
  }): Promise<{
    rootfsKey: string;
    rootfsSha256: string;
    rootfsBytes: number;
    /** The ext4 image bytes; the base-rootfs build needs them locally. */
    ext4Data?: Uint8Array;
  }>;
}

/** A validated plan for one base-rootfs build. */
export type BaseRootfsPlan = {
  /** Path to the base image's oci-archive tar (the converter's input). */
  ociArchivePath: string;
  /** Where to write the built ext4 (the pool + snapshot tool read this path). */
  outputPath: string;
  /** oci-archive tag to unpack (defaults to "latest"). */
  tag: string;
  /**
   * Warm-pool GENERIC base: skip `/etc/k9o/entry.json` so k9o-init boots
   * warm-pool-idle (the Bun tier — customer code arrives post-claim via vsock).
   * Defaults to `true` (the original, Bun-tier behavior).
   *
   * Set `false` for the **sandbox-tier** base, whose baked-in payload IS the
   * ENTRYPOINT (the sandbox-tier runner): with `generic: false` the converter
   * writes entry.json from the image's ENTRYPOINT, so k9o-init exec's the runner
   * at boot and the warm-pool VM is already listening on the invoke port.
   */
  generic: boolean;
};

const REQUIRED: ReadonlyArray<{ env: string; what: string }> = [
  { env: "K9O_EXEC_RUNTIME_BASE_OCI_ARCHIVE", what: "the base image's oci-archive tar path (skopeo copy … oci-archive:<tar>)" },
  { env: "K9O_EXEC_RUNTIME_BASE_ROOTFS", what: "the OUTPUT ext4 path (the warm pool + snapshot tool read this)" },
];

function nonEmpty(env: NodeJS.ProcessEnv, key: string): string {
  return (env[key] ?? "").trim();
}

/**
 * Assemble + validate the plan from the environment. Pure (no I/O). Throws a
 * single error listing EVERY missing required var. NB: the k9o-init binary path is
 * read + existence-checked by the converter itself (`K9O_INIT_BINARY_PATH`),
 * so it is not re-validated here.
 */
export function buildBaseRootfsPlan(env: NodeJS.ProcessEnv = process.env): BaseRootfsPlan {
  const missing = REQUIRED.filter((r) => nonEmpty(env, r.env) === "");
  if (missing.length > 0) {
    throw new Error(
      "build-base-rootfs: missing required env vars:\n" +
        missing.map((m) => `  - ${m.env}: ${m.what}`).join("\n"),
    );
  }
  return {
    ociArchivePath: nonEmpty(env, "K9O_EXEC_RUNTIME_BASE_OCI_ARCHIVE"),
    outputPath: nonEmpty(env, "K9O_EXEC_RUNTIME_BASE_ROOTFS"),
    tag: nonEmpty(env, "K9O_EXEC_RUNTIME_BASE_OCI_TAG") || "latest",
    // Default true (Bun-tier generic base). Only an explicit "false" flips it —
    // the sandbox-tier base sets K9O_EXEC_RUNTIME_BASE_GENERIC=false so k9o-init
    // launches the baked-in runner via entry.json.
    generic: nonEmpty(env, "K9O_EXEC_RUNTIME_BASE_GENERIC").toLowerCase() !== "false",
  };
}

type StepLogger = (step: string, detail?: Record<string, unknown>) => void;
const jsonLog: StepLogger = (step, detail) =>
  console.log(JSON.stringify({ level: "info", msg: `build-base-rootfs: ${step}`, ...detail }));

/** Injectable I/O so the orchestration is testable without touching the real FS. */
export type BaseRootfsIO = {
  readArchive: (path: string) => Promise<Uint8Array>;
  writeExt4: (path: string, bytes: Uint8Array) => Promise<void>;
};

const realIO: BaseRootfsIO = {
  readArchive: (path) => Bun.file(path).bytes(),
  writeExt4: async (path, bytes) => {
    await Bun.write(path, bytes);
  },
};

/**
 * Build the base rootfs: read the base oci-archive, convert it (k9o-init injected
 * by the converter), and write the ext4 to `plan.outputPath`. The converter is a
 * project-scoped API — the base rootfs uses the sentinel project `_base` (the
 * derived storage key is unused; we consume `ext4Data` directly). Throws if the
 * converter returns no `ext4Data` (a converter configured to only upload to object storage
 * would — the base-rootfs build needs the bytes locally, so that is a hard error,
 * not a silent no-op).
 */
export async function buildBaseRootfs(
  converter: OciConverter,
  plan: BaseRootfsPlan,
  io: BaseRootfsIO = realIO,
  log: StepLogger = jsonLog,
): Promise<{ sha256: string; bytes: number }> {
  const ociImageBytes = await io.readArchive(plan.ociArchivePath);
  log("base image read", { ociArchivePath: plan.ociArchivePath, bytes: ociImageBytes.length });

  // generic base (Bun tier, plan.generic=true) → skip /etc/k9o/entry.json so
  // k9o-init boots warm-pool-idle; there is no real function to exec (a contract
  // would point at the base image's own entrypoint → execvp-fail → PID-1 exit 127
  // → guest panic). The sandbox tier (plan.generic=false) DOES want the entrypoint:
  // the baked-in runner is the ENTRYPOINT, so k9o-init exec's it at boot.
  const result = await converter.convert({ projectId: "_base", ociImageBytes, tag: plan.tag, generic: plan.generic });
  if (result.ext4Data === undefined) {
    throw new Error(
      "build-base-rootfs: converter returned no ext4Data — it must retain the bytes " +
        "for a local base-rootfs build (not upload-only to object storage)",
    );
  }
  await io.writeExt4(plan.outputPath, result.ext4Data);
  log("base rootfs written", { outputPath: plan.outputPath, sha256: result.rootfsSha256, bytes: result.rootfsBytes });
  return { sha256: result.rootfsSha256, bytes: result.rootfsBytes };
}
