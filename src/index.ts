/**
 * Firelock — public surface.
 *
 * A Firecracker-microVM execution shell: confine an untrusted guest to a single guest-initiated vsock
 * egress and relay its connection to a handler. What crosses the membrane is one thing — a
 * {@link HandedOffConnection}. What the handler does with it is entirely the handler's.
 *
 * This is the P1 (internal-extraction) surface: the confinement/relay contract and the OSS default
 * handler. The native fd-relay substrate (the vsock listener, the SCM_RIGHTS fd-handoff crate,
 * the Firecracker/jailer lifecycle) is carved in as the next increment; see docs/wire-contract.md and
 * README.md for status.
 */

// The confinement guarantee — the load-bearing, fail-closed topology assert.
export {
  assertFirelockTopology,
  FirelockTopologyViolation,
  type FirelockTopologyRejectCode,
} from "./contract/topology-invariant.ts";

// The membrane → handler boundary.
export type { HandedOffConnection } from "./contract/handed-off-connection.ts";
export type { ExecHandler, ExecOutcome, ExecFailure } from "./contract/exec-handler.ts";

// A convenience HTTP reverse-proxy handler for TS/Bun integrators (the flagship default is native Rust).
export {
  createHttpReverseProxy,
  proxyRequest,
  type HttpReverseProxyConfig,
  type HttpReverseProxy,
  type ProxyDecision,
} from "./handlers/http-reverse-proxy.ts";
