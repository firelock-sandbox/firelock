/**
 * Firelock — public surface.
 *
 * A Firecracker-microVM execution shell: confine an untrusted guest to a single guest-initiated vsock
 * egress and relay its connection to a handler. What crosses the membrane is one thing — a
 * {@link HandedOffConnection}. What the handler does with it is entirely the handler's.
 *
 * This package includes the confinement/relay contract, the OSS default handler, and the TypeScript
 * runtime: the Firecracker API client and warm pool, the jailer wrapper, the vsock client, the fd-handoff
 * FFI bindings, and the per-invocation function VM. The native crates (native/: the SCM_RIGHTS fd-handoff
 * library and the handler-confine library) and the guest init (guest/k9o-init) ship in the same repository;
 * see docs/wire-contract.md.
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

// ── runtime ────────────────────────────────────────────────────────────────────────────────────────────
// The TypeScript sandbox runtime. Each module is also importable on its own via "firelock/runtime/<name>".
export * from "./runtime/build-base-rootfs.ts";
export * from "./runtime/exec-seam.ts";
export * from "./runtime/fd-handoff-ffi.ts";
export * from "./runtime/firecracker-client.ts";
export * from "./runtime/firecracker-pool.ts";
export * from "./runtime/function-vm.ts";
export * from "./runtime/guest-base-image.ts";
export * from "./runtime/guest-kernel.ts";
export * from "./runtime/handoff-envelope.ts";
export * from "./runtime/jailed-slot-staging.ts";
export * from "./runtime/jailer-wrapper.ts";
export * from "./runtime/slot-liveness-reaper.ts";
export * from "./runtime/vm-slot-cgroup-placer.ts";
export * from "./runtime/vsock-client.ts";
