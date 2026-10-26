//! Handler confinement for the Firelock sandbox (netns + seccomp-bpf + cgroup v2).
//!
//! Confines the credential-less HANDLER: a HOST-SIDE process the executor core spawns,
//! distinct from and additional to the Firecracker microVM (which confines the GUEST). Two
//! boundaries, two trust domains. The handler is a separate process from the
//! credential-holding core (so it cannot read the core's credential memory), and it is fully
//! sealed BEFORE it reads its first guest byte.
//!
//! Two-phase confinement:
//!   * Phase A - LAUNCH (core-side, at spawn): `clone3(NEWNET|NEWNS|NEWPID|CLONE_INTO_CGROUP)`
//!     gives a fresh netns with NO route, born into a cgroup-v2 leaf with mem/cpu/pids caps;
//!     the runtime's full thread set and event-loop fds are pre-created; capabilities are
//!     dropped and `no_new_privs` + `PR_SET_DUMPABLE=0` are set. The handler is handed ONLY
//!     the oracle fd: the guest connection `C` NEVER crosses, `rawFrame` arrives as a plain
//!     `read`, and the core writes the response on `C`. So there is no SCM_RIGHTS receive
//!     into the handler and `recvmsg` is denied unconditionally in steady state.
//!   * Phase B - SEAL (handler-side, after setup, BEFORE the first guest byte): install the
//!     [`policy`] steady-state seccomp filter with `SECCOMP_FILTER_FLAG_TSYNC` so all
//!     pre-created threads are covered atomically. The seal is gated on a CLEAN, complete
//!     `rawFrame` receive: a short or malformed receive makes the handler exit with no seal
//!     and no guest byte read.
//!
//! The crate provides the reviewable [`policy`] enumeration, the seccomp filter builder and
//! installer, the `clone3`/netns/cgroup launch primitive, the `handler_seal` C ABI, and the
//! name-to-number resolver the real-kernel proofs use (`socket(AF_UNIX)`/`socket(AF_INET)`/
//! `execve`/`ptrace`/`io_uring_setup`/`mmap(PROT_EXEC)`/non-sealing-thread all die with
//! SIGSYS). The real-kernel proofs live under `tests/` and need Linux.

// Linux-only — seccomp-bpf / CLONE_NEWNET / cgroup v2 are Linux syscalls. Fail LOUD off
// Linux (e.g. a macOS development build) rather than silently produce a no-op confinement.
#[cfg(not(target_os = "linux"))]
compile_error!(
    "firelock-handler-confine is Linux-only (seccomp-bpf / netns / cgroup v2). Build it on a Linux \
     target."
);

pub mod ffi;
pub mod launch;
pub mod policy;
pub mod seccomp;

use libc::c_long;

/// Resolve a syscall NAME → its `x86_64` number, or `None` if this libc has no constant for
/// it (a newer syscall on an older libc). Used by the structural test here and by the
/// real-kernel proofs to target a syscall for an assert-die check. `None` ⇒ the caller skips
/// that name (the audit deny-class is documentation; default-`KILL_PROCESS` covers it
/// regardless of whether this build can name it).
pub fn syscall_nr_by_name(name: &str) -> Option<c_long> {
    // Only names referenced by the policy (allowlist + audit deny classes). Kept explicit
    // (not a proc-macro over the whole table) so an absent `libc::SYS_*` is a compile error
    // HERE — surfaced on the Linux build — rather than a silent gap in the enumeration.
    let nr = match name {
        // allowlist
        "read" => libc::SYS_read,
        "write" => libc::SYS_write,
        "readv" => libc::SYS_readv,
        "writev" => libc::SYS_writev,
        "pread64" => libc::SYS_pread64,
        "pwrite64" => libc::SYS_pwrite64,
        "preadv2" => libc::SYS_preadv2,
        "pwritev2" => libc::SYS_pwritev2,
        "close" => libc::SYS_close,
        "fstat" => libc::SYS_fstat,
        "lseek" => libc::SYS_lseek,
        "fcntl" => libc::SYS_fcntl,
        "ppoll" => libc::SYS_ppoll,
        "epoll_wait" => libc::SYS_epoll_wait,
        "epoll_pwait" => libc::SYS_epoll_pwait,
        "epoll_ctl" => libc::SYS_epoll_ctl,
        "mmap" => libc::SYS_mmap,
        "mprotect" => libc::SYS_mprotect,
        "munmap" => libc::SYS_munmap,
        "brk" => libc::SYS_brk,
        "madvise" => libc::SYS_madvise,
        "futex" => libc::SYS_futex,
        "nanosleep" => libc::SYS_nanosleep,
        "clock_gettime" => libc::SYS_clock_gettime,
        "clock_nanosleep" => libc::SYS_clock_nanosleep,
        "rt_sigaction" => libc::SYS_rt_sigaction,
        "rt_sigprocmask" => libc::SYS_rt_sigprocmask,
        "rt_sigreturn" => libc::SYS_rt_sigreturn,
        "rt_sigtimedwait" => libc::SYS_rt_sigtimedwait,
        "sigaltstack" => libc::SYS_sigaltstack,
        "sched_yield" => libc::SYS_sched_yield,
        "sched_getaffinity" => libc::SYS_sched_getaffinity,
        "getrandom" => libc::SYS_getrandom,
        "getpid" => libc::SYS_getpid,
        "gettid" => libc::SYS_gettid,
        "set_robust_list" => libc::SYS_set_robust_list,
        "get_robust_list" => libc::SYS_get_robust_list,
        "restart_syscall" => libc::SYS_restart_syscall,
        "exit" => libc::SYS_exit,
        "exit_group" => libc::SYS_exit_group,
        // audit deny classes — the assert-die targets
        "execve" => libc::SYS_execve,
        "execveat" => libc::SYS_execveat,
        "fork" => libc::SYS_fork,
        "vfork" => libc::SYS_vfork,
        "clone" => libc::SYS_clone,
        "clone3" => libc::SYS_clone3,
        "ptrace" => libc::SYS_ptrace,
        "process_vm_readv" => libc::SYS_process_vm_readv,
        "process_vm_writev" => libc::SYS_process_vm_writev,
        "kcmp" => libc::SYS_kcmp,
        "socket" => libc::SYS_socket,
        "socketpair" => libc::SYS_socketpair,
        "connect" => libc::SYS_connect,
        "bind" => libc::SYS_bind,
        "listen" => libc::SYS_listen,
        "accept" => libc::SYS_accept,
        "accept4" => libc::SYS_accept4,
        "sendto" => libc::SYS_sendto,
        "recvfrom" => libc::SYS_recvfrom,
        "sendmsg" => libc::SYS_sendmsg,
        "recvmsg" => libc::SYS_recvmsg,
        "setsockopt" => libc::SYS_setsockopt,
        "getsockopt" => libc::SYS_getsockopt,
        "io_uring_setup" => libc::SYS_io_uring_setup,
        "io_uring_enter" => libc::SYS_io_uring_enter,
        "io_uring_register" => libc::SYS_io_uring_register,
        "open" => libc::SYS_open,
        "openat" => libc::SYS_openat,
        "openat2" => libc::SYS_openat2,
        "creat" => libc::SYS_creat,
        "memfd_create" => libc::SYS_memfd_create,
        "open_by_handle_at" => libc::SYS_open_by_handle_at,
        "eventfd2" => libc::SYS_eventfd2,
        "timerfd_create" => libc::SYS_timerfd_create,
        "pipe2" => libc::SYS_pipe2,
        "epoll_create1" => libc::SYS_epoll_create1,
        "close_range" => libc::SYS_close_range,
        "pidfd_open" => libc::SYS_pidfd_open,
        "pidfd_getfd" => libc::SYS_pidfd_getfd,
        "pidfd_send_signal" => libc::SYS_pidfd_send_signal,
        "setuid" => libc::SYS_setuid,
        "setgid" => libc::SYS_setgid,
        "setresuid" => libc::SYS_setresuid,
        "setresgid" => libc::SYS_setresgid,
        "unshare" => libc::SYS_unshare,
        "setns" => libc::SYS_setns,
        "mount" => libc::SYS_mount,
        "umount2" => libc::SYS_umount2,
        "pivot_root" => libc::SYS_pivot_root,
        "chroot" => libc::SYS_chroot,
        "fsopen" => libc::SYS_fsopen,
        "fsconfig" => libc::SYS_fsconfig,
        "fsmount" => libc::SYS_fsmount,
        "move_mount" => libc::SYS_move_mount,
        "open_tree" => libc::SYS_open_tree,
        "bpf" => libc::SYS_bpf,
        "perf_event_open" => libc::SYS_perf_event_open,
        "keyctl" => libc::SYS_keyctl,
        "add_key" => libc::SYS_add_key,
        "request_key" => libc::SYS_request_key,
        "init_module" => libc::SYS_init_module,
        "finit_module" => libc::SYS_finit_module,
        "userfaultfd" => libc::SYS_userfaultfd,
        "ioctl" => libc::SYS_ioctl,
        "prctl" => libc::SYS_prctl,
        _ => return None,
    };
    Some(nr)
}
