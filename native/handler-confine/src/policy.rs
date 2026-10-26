//! The steady-state seccomp policy for the confined handler — the load-bearing review
//! artifact. Discipline: enumerate the complete class of denied syscalls before coding;
//! this module is that enumeration.
//!
//! Mechanism = **allowlist-only, default `SECCOMP_RET_KILL_PROCESS`**. Every syscall not
//! in [`STEADY_ALLOWLIST`] is an uncatchable kill — so "complete-class" is STRUCTURAL
//! (default-deny), not a spot list. [`AUDIT_DENY_CLASSES`] is the audit ENUMERATION of the
//! load-bearing deny classes (for review assertions and the real-kernel assert-die
//! tests); it is documentation, NOT the mechanism — a syscall absent from both lists is
//! still killed by default.
//!
//! seccomp-bpf can only inspect SCALAR register args (it cannot deref a pointer). So arg-filters exist only where the discriminant is a scalar: `mmap`
//! prot/flags (args 2,3), `mprotect` prot (arg 2), `fcntl` cmd (arg 1). `clone3`'s flags
//! are behind a pointer → un-filterable → denied WHOLE (threads are pre-created pre-seal).

use libc::c_long;

/// W^X posture of the filter — contingent on the handler's runtime:
///   • `StrictNoExec` — the handler runs an interpreter (for example Wasmtime's Pulley
///     interpreter): NO executable pages. `mmap`/`mprotect` deny `PROT_EXEC`, `memfd_create`
///     is denied. The strong form; the real-kernel proof is "a handler runs to completion
///     UNDER this filter" (JIT-off verification).
///   • `JitRelaxed` — the handler runs a JIT runtime (a native JIT broker, for example):
///     executable pages are REQUIRED, so `PROT_EXEC` must be permitted or the runtime
///     SIGSYS-kills itself at first codegen. A documented weaker posture (the RWX class
///     stays reachable) for use only when an interpreter handler is not available.
///
/// The concrete posture for a deployment is chosen by the caller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WxPosture {
    /// Interpreter handler — strict W^X, `PROT_EXEC` denied everywhere.
    StrictNoExec,
    /// JIT handler — `PROT_EXEC` permitted; weaker, documented, interim.
    JitRelaxed,
}

/// A scalar arg-filter on one syscall argument (the only thing seccomp-bpf can inspect).
#[derive(Clone, Copy, Debug)]
pub enum ArgFilter {
    /// `mmap`: require `MAP_ANONYMOUS` in flags (deny file-backed maps); under
    /// [`WxPosture::StrictNoExec`] additionally require `PROT_EXEC` clear in prot (W^X at
    /// map time — an anon `mmap(PROT_WRITE|PROT_EXEC)` creates a W+X page without touching
    /// `mprotect`, so the mprotect guard alone is insufficient).
    Mmap,
    /// `mprotect`: under [`WxPosture::StrictNoExec`], deny adding `PROT_EXEC` (no RW→RX flip).
    Mprotect,
    /// `fcntl`: allow only `{F_GETFL, F_SETFL, F_GETFD, F_SETFD}` (the runtime sets
    /// `O_NONBLOCK`/`FD_CLOEXEC` on the oracle_fd); deny `F_SETLK`/`F_SETOWN`/
    /// `F_SETPIPE_SZ`/etc. which widen surface.
    FcntlCmd,
}

/// One allowlisted syscall + an optional scalar arg-filter. Absent filter ⇒ unconditionally
/// allowed (the fd is already open / the op carries no dangerous scalar discriminant).
#[derive(Clone, Copy, Debug)]
pub struct SyscallRule {
    pub nr: c_long,
    pub filter: Option<ArgFilter>,
}

impl SyscallRule {
    /// The syscall number as the BPF `k` field type (u32). x86_64 syscall numbers are small
    /// positive values, so the narrowing is lossless.
    pub const fn k_nr(&self) -> u32 {
        self.nr as u32
    }
}

const fn allow(nr: c_long) -> SyscallRule {
    SyscallRule { nr, filter: None }
}
const fn allow_filtered(nr: c_long, filter: ArgFilter) -> SyscallRule {
    SyscallRule {
        nr,
        filter: Some(filter),
    }
}

/// The steady-state ALLOWLIST — the closed set; everything else is `KILL_PROCESS`.
///
/// STARTING set: to be REFINED by an strace of the REAL handler runtime on a real Linux
/// kernel before the filter is treated as final — hand-enumeration will otherwise miss a syscall the
/// runtime needs (fail-safe: killed, but the runtime breaks). Every addition is re-checked
/// for surface. NO `open*`/`socket*`/`clone*`/`execve*` here BY CONSTRUCTION — all fds are
/// set up pre-seal (only the oracle_fd; no new fds in steady state).
pub const STEADY_ALLOWLIST: &[SyscallRule] = &[
    // ── I/O on already-open fds (the oracle_fd + stdio; no open/socket) ────────────────
    allow(libc::SYS_read),
    allow(libc::SYS_write),
    allow(libc::SYS_readv),
    allow(libc::SYS_writev),
    // positioned I/O the runtime's async layer commonly uses (likely-needed set)
    allow(libc::SYS_pread64),
    allow(libc::SYS_pwrite64),
    allow(libc::SYS_preadv2),
    allow(libc::SYS_pwritev2),
    allow(libc::SYS_close),
    allow(libc::SYS_fstat),
    allow(libc::SYS_lseek),
    allow_filtered(libc::SYS_fcntl, ArgFilter::FcntlCmd),
    // ── Event loop on PRE-CREATED fds (created Phase A; no *_create here steady-state) ──
    allow(libc::SYS_ppoll),
    allow(libc::SYS_epoll_wait),
    allow(libc::SYS_epoll_pwait),
    allow(libc::SYS_epoll_ctl),
    // ── Memory (no exec pages under StrictNoExec; anon-only always) ────────────────────
    allow_filtered(libc::SYS_mmap, ArgFilter::Mmap),
    allow_filtered(libc::SYS_mprotect, ArgFilter::Mprotect),
    allow(libc::SYS_munmap),
    allow(libc::SYS_brk),
    allow(libc::SYS_madvise),
    // ── Scheduling / time / signals the runtime needs ─────────────────────────────────
    allow(libc::SYS_futex),
    allow(libc::SYS_nanosleep),
    allow(libc::SYS_clock_gettime),
    allow(libc::SYS_clock_nanosleep),
    allow(libc::SYS_rt_sigaction),
    allow(libc::SYS_rt_sigprocmask),
    allow(libc::SYS_rt_sigreturn),
    allow(libc::SYS_rt_sigtimedwait),
    allow(libc::SYS_sigaltstack),
    allow(libc::SYS_sched_yield),
    allow(libc::SYS_sched_getaffinity),
    allow(libc::SYS_getrandom),
    allow(libc::SYS_getpid),
    allow(libc::SYS_gettid),
    allow(libc::SYS_set_robust_list),
    allow(libc::SYS_get_robust_list),
    allow(libc::SYS_restart_syscall),
    // ── Clean exit ────────────────────────────────────────────────────────────────────
    allow(libc::SYS_exit),
    allow(libc::SYS_exit_group),
];

/// The audit ENUMERATION of the load-bearing deny classes (documentation + the
/// assert-die targets). NOT the mechanism — default-`KILL_PROCESS` already kills these; this
/// list makes the review assertion COMPLETE (each entry = a structural attack made
/// type-impossible). Names (not `SYS_*` constants) so the enumeration never fails to compile
/// on a libc missing a newer number; the real-kernel tests resolve names → numbers on the test kernel.
pub const AUDIT_DENY_CLASSES: &[(&str, &[&str])] = &[
    (
        "process-creation / code-injection (handler is a separate process + no execve)",
        &[
            "execve",
            "execveat",
            "fork",
            "vfork",
            "clone",
            "clone3",
            "ptrace",
            "process_vm_readv",
            "process_vm_writev",
            "kcmp",
        ],
    ),
    (
        "socket — ALL address families incl AF_UNIX (complete-class; the AF_UNIX host-UDS hole)",
        &[
            "socket",
            "socketpair",
            "connect",
            "bind",
            "listen",
            "accept",
            "accept4",
            "sendto",
            "recvfrom",
            "sendmsg",
            "recvmsg",
            "setsockopt",
            "getsockopt",
        ],
    ),
    (
        "io_uring — the seccomp BYPASS (I/O on kernel worker threads off the syscall path)",
        &["io_uring_setup", "io_uring_enter", "io_uring_register"],
    ),
    (
        "filesystem-open / new fds (all fds set up pre-seal)",
        &[
            "open",
            "openat",
            "openat2",
            "creat",
            "memfd_create",
            "open_by_handle_at",
            "eventfd2",
            "timerfd_create",
            "pipe2",
            "epoll_create1",
            "close_range",
        ],
    ),
    (
        "fd-stealing from the core via a pidfd",
        &["pidfd_open", "pidfd_getfd", "pidfd_send_signal"],
    ),
    (
        "privilege / namespace / mount / kernel surface",
        &[
            "setuid",
            "setgid",
            "setresuid",
            "setresgid",
            "unshare",
            "setns",
            "mount",
            "umount2",
            "pivot_root",
            "chroot",
            "fsopen",
            "fsconfig",
            "fsmount",
            "move_mount",
            "open_tree",
            "bpf",
            "perf_event_open",
            "keyctl",
            "add_key",
            "request_key",
            "init_module",
            "finit_module",
            "userfaultfd",
            "ioctl",
            "prctl",
        ],
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_excludes_the_load_bearing_deny_classes_by_construction() {
        // No allowlisted rule may name a syscall that appears in an audit deny class — a
        // cheap structural guard against a copy-paste that both allows AND "denies" one.
        for (class, names) in AUDIT_DENY_CLASSES {
            for name in *names {
                if let Some(nr) = crate::syscall_nr_by_name(name) {
                    assert!(
                        !STEADY_ALLOWLIST.iter().any(|r| r.nr == nr),
                        "syscall '{name}' (class '{class}') is BOTH allowlisted and audit-denied",
                    );
                }
            }
        }
    }

    #[test]
    fn arg_filters_only_on_scalar_discriminant_syscalls() {
        // mmap/mprotect/fcntl are the only filtered syscalls — their discriminant is a
        // scalar register arg (deref-free), the only thing seccomp-bpf can inspect.
        for rule in STEADY_ALLOWLIST {
            if rule.filter.is_some() {
                assert!(
                    rule.nr == libc::SYS_mmap
                        || rule.nr == libc::SYS_mprotect
                        || rule.nr == libc::SYS_fcntl,
                    "arg-filter on a non-scalar-discriminant syscall nr={}",
                    rule.nr,
                );
            }
        }
    }
}
