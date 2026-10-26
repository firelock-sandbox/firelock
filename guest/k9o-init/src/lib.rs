//! k9o-init — the Firecracker guest agent (PID 1).
//!
//! Every converted guest rootfs has this binary as its init process.
//! It exists because a Bun/Node extension cannot itself speak the two vsock
//! directions Firecracker needs:
//!
//!   * **host → guest invocation** — the host dials the guest on vsock port
//!     [`INVOKE_VSOCK_PORT`] and sends `POST /invoke` (HTTP/1.1 over vsock, see
//!     the host-side vsock client). Bun cannot `accept()` on
//!     `AF_VSOCK`, so k9o-init is the listener and reverse-proxies each request
//!     to the extension's own loopback server ([`INVOKE_LOOPBACK_DEFAULT`]).
//!
//!   * **guest → host gate** — the SDK's gate call reaches the host's gate
//!     dispatcher at `cid=2:9000` directly via `bun:ffi` on Linux (its primary
//!     path); k9o-init provides the documented UDS *fallback* at
//!     [`GATE_UDS_PATH`], splicing it to the same host vsock endpoint.
//!
//! Plus the ordinary PID-1 duties: mount the essential pseudo-filesystems,
//! `exec`/supervise the extension entrypoint (from the [`ENTRY_CONTRACT_PATH`]
//! the image converter writes), and reap zombies.
//!
//! The pure protocol logic ([`http`], [`splice`], [`entry`], [`proxy`]) is
//! platform-agnostic and unit-tested on any host. The syscall layers
//! ([`vsock`], [`sysinit`], [`supervise`]) are Linux-only and `cfg`-gated.

pub mod callback;
pub mod entry;
pub mod http;
pub mod proxy;
pub mod splice;

#[cfg(target_os = "linux")]
pub mod runtime;
#[cfg(target_os = "linux")]
pub mod supervise;
#[cfg(target_os = "linux")]
pub mod sysinit;
#[cfg(target_os = "linux")]
pub mod vsock;

/// Guest vsock port the host dials for `POST /invoke` (host-initiated).
/// MUST match the host's `K9O_INIT_VSOCK_PORT` (the invoke route).
pub const INVOKE_VSOCK_PORT: u32 = 8000;

/// The host's well-known vsock context id (`VMADDR_CID_HOST`). The guest→host
/// gate dials this.
pub const GATE_HOST_CID: u32 = 2;

/// Host vsock port the host's gate dispatcher listens on. MUST match the host's
/// `GATE_PORT` and the SDK's gate client.
pub const GATE_HOST_PORT: u32 = 9000;

/// The UDS the SDK's gate-call UDS fallback connects to
/// (the default of `K9O_GATE_SOCKET` in the SDK). k9o-init listens here and bridges
/// to the host vsock gate.
pub const GATE_UDS_PATH: &str = "/run/k9o/gate.sock";

/// Loopback address k9o-init serves the extension's plugin-API calls and egress on.
/// Each request becomes ONE gate frame on [`GATE_HOST_PORT`]: this listener's only dial is the gate, so the guest
/// still has exactly one guest→host port (vsock 9000).
pub const CALLBACK_LISTEN: &str = "127.0.0.1:8082";

/// Loopback address the extension serves its invoke handler on. k9o-init
/// reverse-proxies host `POST /invoke` requests here. Exported to the extension
/// as `K9O_INVOKE_LISTEN` so the SDK knows where to bind.
pub const INVOKE_LOOPBACK_DEFAULT: &str = "127.0.0.1:8081";

/// Where the image converter writes the resolved image entrypoint (argv/env/cwd)
/// for k9o-init to exec.
pub const ENTRY_CONTRACT_PATH: &str = "/etc/k9o/entry.json";
