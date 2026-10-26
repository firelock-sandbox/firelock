//! C-ABI surface for the executor runtime (bun:ffi), mirroring `firelock-fd-handoff`. Load it
//! ONLY in the runtime context where the shared library is built; the crate is Linux-only.
//!
//! This exports the SEAL (Phase B) — the call the handler makes before its first guest byte.
//! The Phase-A spawn (`clone3`/netns/cgroup + exec of the handler runtime) is NOT exported:
//! it execs the confined handler runtime and passes it the oracle fd, so it belongs with the
//! runtime's own FFI seam. The spawn PRIMITIVE is built and real-kernel proven in `launch.rs`
//! (tests/launch_kernel.rs).

use crate::policy::WxPosture;
use crate::seccomp::seal;

/// Posture selector for the C ABI: 0 = StrictNoExec (interpreter handler — strict W^X),
/// 1 = JitRelaxed (native/JIT handler — PROT_EXEC permitted).
const POSTURE_STRICT_NO_EXEC: i32 = 0;
const POSTURE_JIT_RELAXED: i32 = 1;

/// Install the steady-state seccomp seal for `posture`. Call from the confined handler AFTER setup,
/// BEFORE reading the first guest byte. Returns 0 on success; a positive errno on a seccomp
/// failure; -1 for an invalid posture. Fail-closed contract: a non-zero return means NOT sealed
/// — the caller MUST NOT read a guest byte (abort the invocation).
///
/// # Safety
/// C-ABI export; no pointer args. After a `0` return the calling thread group runs under the
/// filter (installed with TSYNC) and every non-allowlisted syscall is an uncatchable kill.
#[no_mangle]
pub extern "C" fn firelock_handler_seal(posture: i32) -> i32 {
    let posture = match posture {
        POSTURE_STRICT_NO_EXEC => WxPosture::StrictNoExec,
        POSTURE_JIT_RELAXED => WxPosture::JitRelaxed,
        _ => return -1,
    };
    match seal(posture) {
        Ok(()) => 0,
        Err(e) => e.errno.max(1), // ensure non-zero even if errno came back 0
    }
}
