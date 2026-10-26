/**
 * Firelock — THE VM TOPOLOGY INVARIANT (the membrane's IP-less-by-construction, fail-closed assert).
 *
 * This is the load-bearing confinement guarantee. A Firelock-confined microVM has:
 *   • ZERO network interfaces — it is IP-less BY CONSTRUCTION. Firelock has no code path that adds a
 *     network interface and always seeds the guest with `network-interfaces: []`, so the guest cannot
 *     reach the network at all; the ONLY egress is the single guest-initiated vsock channel the handler
 *     owns (the handler is the sole egress).
 *   • EXACTLY ONE vsock device — that one gate channel, and nothing else.
 *
 * This module is the SINGLE SOURCE of that assertion. Whoever materialises, loads, or accepts a Firelock
 * VM config asserts the SAME topology through THIS function, so no code path can drift into a different
 * idea of what "confined" means. The structural no-NIC guarantee (no add-interface code path) is the
 * belt; this measured assert is the braces.
 *
 * 🔴 FAIL-CLOSED, AND "COULD NOT CHECK" IS NEVER "IT IS FINE". A config that is unreadable or whose
 * topology cannot be positively confirmed as {0 NIC, 1 vsock} is REFUSED, never waved through — a VM
 * that grew a NIC via drift or a future tap path must be rejected before it is captured or trusted. The
 * IP-less property is not something we configure and hope holds — it is asserted here.
 *
 * Provenance: factored out of the Kilimanjaro monorepo's `assertExecSeamTopology` so the OSS Firelock
 * membrane and the platform's own snapshot/probe paths carry one identical check.
 */

/** Machine-readable reason a VM topology was refused — typed so the membrane can act/audit, never a bare string. */
export type FirelockTopologyRejectCode =
  | "network_interface_present" // ≥1 NIC — the guest could egress off-vsock; the whole confinement is void
  | "wrong_vsock_count"; //         ≠1 vsock — not exactly the single handler gate channel

/** Thrown when a VM config violates the Firelock topology invariant. Fail-closed; carries no guest data. */
export class FirelockTopologyViolation extends Error {
  readonly code: FirelockTopologyRejectCode;
  /** The observed count that failed the check (NIC count or vsock count), for the audit line. */
  readonly observed: number;
  constructor(code: FirelockTopologyRejectCode, message: string, observed: number) {
    super(message);
    this.name = "FirelockTopologyViolation";
    this.code = code;
    this.observed = observed;
  }
}

/** Count Firecracker `network-interfaces` defensively: an array → its length; absent/null → 0; any other
 *  shape → 1 (present-and-not-empty is a NIC — err toward "has a NIC", the fail-closed direction). */
function nicCount(vmConfig: Record<string, unknown>): number {
  const nics = vmConfig["network-interfaces"];
  if (Array.isArray(nics)) return nics.length;
  return nics == null ? 0 : 1;
}

/** Count `vsock` devices: an array → its length; a single device object → 1; absent/null → 0. */
function vsockCount(vmConfig: Record<string, unknown>): number {
  const vsock = vmConfig["vsock"];
  if (Array.isArray(vsock)) return vsock.length;
  return vsock == null ? 0 : 1;
}

/**
 * 🔴 THE ASSERT — refuse any VM config that is not {0 network interfaces, exactly 1 vsock}. The one place
 * the Firelock membrane and any host-side snapshot/probe path all decide "is this VM confined?".
 * Throws {@link FirelockTopologyViolation} on any violation; returns void when the topology is exactly the
 * confined shape. A non-object config is treated as `{}` → 0 NIC but 0 vsock → refused on the vsock leg
 * (an unreadable/empty config is not a confirmed-confined config).
 */
export function assertFirelockTopology(vmConfig: unknown): void {
  const cfg = (vmConfig ?? {}) as Record<string, unknown>;

  const nics = nicCount(cfg);
  if (nics !== 0) {
    throw new FirelockTopologyViolation(
      "network_interface_present",
      `Firelock topology violated: VM has ${nics} network interface(s); a confined microVM MUST have none ` +
        `(IP-less by construction — the single vsock channel is sole egress). Refusing.`,
      nics,
    );
  }

  const vsocks = vsockCount(cfg);
  if (vsocks !== 1) {
    throw new FirelockTopologyViolation(
      "wrong_vsock_count",
      `Firelock topology violated: VM has ${vsocks} vsock device(s); expected exactly one (the handler gate ` +
        `channel). Refusing.`,
      vsocks,
    );
  }
}
