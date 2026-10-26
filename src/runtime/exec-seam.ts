/**
 * The two exec-seam assertions the runtime applies to a booted microVM's exported `/vm/config`.
 *
 * - {@link assertExecSeamTopology}: the booted VM carries NO network interface and exactly ONE vsock device.
 *   This is the Firelock topology invariant (`../contract/topology-invariant.ts`), the single source of that check.
 * - {@link assertExecSeamMeasurementAvailable}: decides what an UNREADABLE `/vm/config` means. A deployment can
 *   declare the measurement mandatory, and then "could not check" refuses instead of passing silently.
 */
import { assertFirelockTopology } from "../contract/topology-invariant.ts";

/** Refuse (throw) unless the VM config has zero network interfaces and exactly one vsock device. */
export const assertExecSeamTopology: (vmConfig: unknown) => void = assertFirelockTopology;

/**
 * Env that turns the MEASURED half of the exec-seam assertion from advisory into required.
 *
 * Reading `/vm/config` can fail (wrong API socket, a VM that died during configuration, an old Firecracker
 * without the export endpoint). If a failed read were treated as "nothing to check", the measured leg would
 * silently reduce to the structural guarantee alone (no code path adds a network interface). Declaring this env
 * makes the measurement mandatory:
 *
 *   required + readable + no NIC / one vsock  -> proceed (measured)
 *   required + readable + violation           -> REFUSE (a topology that could egress off-vsock)
 *   required + UNREADABLE                     -> REFUSE ("could not check" is never "it is fine")
 *   not required (local dev)                  -> skip, loudly, naming the env that would enforce it
 */
export const REQUIRE_EXEC_SEAM_MEASUREMENT_ENV = "K9O_REQUIRE_EXEC_SEAM_MEASUREMENT";

/** Whether the deployment has declared the measured leg mandatory. */
export function execSeamMeasurementRequired(env: NodeJS.ProcessEnv = process.env): boolean {
  const v = env[REQUIRE_EXEC_SEAM_MEASUREMENT_ENV];
  return v !== undefined && v !== "" && v !== "0" && v.toLowerCase() !== "false";
}

/**
 * Decide what an UNREADABLE `/vm/config` means: throws when the measurement is required, returns otherwise.
 * A pure function so the fail-closed arm is testable without a Firecracker host.
 */
export function assertExecSeamMeasurementAvailable(
  reason: string,
  env: NodeJS.ProcessEnv = process.env,
): void {
  if (!execSeamMeasurementRequired(env)) return;
  throw new Error(
    `exec-seam invariant UNVERIFIABLE: could not read the booted VM's /vm/config (${reason}).\n` +
      `${REQUIRE_EXEC_SEAM_MEASUREMENT_ENV} is set, so the MEASURED no-NIC/one-vsock check is\n` +
      `mandatory and "could not check" is not "it is fine". Refusing to proceed with a VM whose\n` +
      `topology was never measured.\n\n` +
      `Firecracker >= 1.15 serves GET /vm/config, so this usually means the API socket is wrong,\n` +
      `the VM died during configuration, or the Firecracker binary was downgraded.\n` +
      `To proceed WITHOUT the measured leg (local dev only), unset ${REQUIRE_EXEC_SEAM_MEASUREMENT_ENV}.`,
  );
}
