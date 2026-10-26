//! Phase-A LAUNCH (network namespace + cgroup v2) — the privileged
//! launcher that spawns the handler into its confinement BEFORE any handler code runs. Pairs with
//! the Phase-B [`crate::seccomp::seal`] the handler calls before its first guest byte.
//!
//! The handler is born (via `clone3`) into:
//!   • a fresh NETWORK namespace with NO interfaces/route (a `socket(AF_INET)` has
//!     nowhere to go; the only egress is the core, over the oracle_fd);
//!   • a fresh PID namespace (the handler is pid 1 — can't see/signal host pids);
//!   • a fresh MOUNT namespace (mount changes don't leak to the host);
//!   • a cgroup-v2 leaf with mem/cpu/pids caps, entered ATOMICALLY at clone via
//!     `CLONE_INTO_CGROUP` (no fork→attach race window).
//! In the child, before handler entry: `no_new_privs` + `PR_SET_DUMPABLE=0` (the core
//! can't `/proc/<handler>/mem`-read it either; symmetric with the seal's ptrace deny).
//!
//! Privilege: creating netns/pidns/mountns + a cgroup leaf needs `CAP_SYS_ADMIN` — the
//! executor runs this via a privileged launcher (runc/jailer model), or under a userns. Tests
//! run under `sudo` on a Linux host (gated by FIRELOCK_CONFINE_PRIV_TESTS so an unprivileged
//! `cargo test` honestly SKIPS them rather than silently passing).

use libc::{c_int, c_void};
use std::ffi::CString;
use std::os::unix::io::RawFd;

// clone3 CLONE_INTO_CGROUP is bit 33 — not always in libc; defined here (stable ABI).
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// The canonical fd the oracle channel lands at in the confined handler after fd-table
/// sanitization. This is the handler's ONLY channel — `rawFrame` in, oracle requests +
/// the response out — read/written as plain bytes (no `recvmsg`). The handler runtime knows the
/// oracle is here.
pub const SLOT_ORACLE_FD: RawFd = 3;

/// Per-exec resource envelope `None` ⇒ leave that controller at "max".
#[derive(Clone, Copy, Debug)]
pub struct HandlerCaps {
    pub memory_max_bytes: Option<u64>,
    /// (quota_us, period_us) — e.g. (50_000, 100_000) = 50% of one CPU. `None` ⇒ "max".
    pub cpu_max: Option<(u64, u64)>,
    pub pids_max: Option<u64>,
}

impl Default for HandlerCaps {
    fn default() -> Self {
        // Conservative per-handler defaults; the executor tunes per workload.
        HandlerCaps {
            memory_max_bytes: Some(128 * 1024 * 1024),
            cpu_max: Some((50_000, 100_000)),
            pids_max: Some(64),
        }
    }
}

#[derive(Debug)]
pub struct LaunchError {
    pub op: &'static str,
    pub errno: c_int,
}
fn err(op: &'static str) -> LaunchError {
    LaunchError {
        op,
        errno: unsafe { *libc::__errno_location() },
    }
}

/// A created cgroup-v2 leaf; holds the O_DIRECTORY fd for `CLONE_INTO_CGROUP` and its path so
/// the caller can remove it on handler teardown (the leaf must not outlive the invocation).
pub struct CgroupLeaf {
    pub dir_fd: RawFd,
    pub path: String,
}

impl CgroupLeaf {
    /// Remove the leaf (after the handler has exited). Best-effort; a non-empty leaf (handler still
    /// alive) returns EBUSY — the caller reaps the handler first.
    pub fn remove(&self) -> Result<(), LaunchError> {
        unsafe { libc::close(self.dir_fd) };
        let c = CString::new(self.path.clone()).unwrap();
        if unsafe { libc::rmdir(c.as_ptr()) } != 0 {
            return Err(err("rmdir(cgroup leaf)"));
        }
        Ok(())
    }
}

fn write_file(path: &str, contents: &str) -> Result<(), LaunchError> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|_| err("open(cgroup attr)"))?;
    f.write_all(contents.as_bytes())
        .map_err(|_| err("write(cgroup attr)"))?;
    Ok(())
}

/// Create a cgroup-v2 leaf at `<cgroup_root>/<name>` and apply `caps`. The parent
/// (`cgroup_root`) must have `memory cpu pids` enabled in its `cgroup.subtree_control` (the
/// root cgroup does on most systemd hosts). Returns the leaf with its O_DIRECTORY fd for `CLONE_INTO_CGROUP`.
pub fn create_cgroup_leaf(
    cgroup_root: &str,
    name: &str,
    caps: &HandlerCaps,
) -> Result<CgroupLeaf, LaunchError> {
    let path = format!("{cgroup_root}/{name}");
    let cpath = CString::new(path.clone()).unwrap();
    if unsafe { libc::mkdir(cpath.as_ptr(), 0o755) } != 0 {
        return Err(err("mkdir(cgroup leaf)"));
    }
    if let Some(m) = caps.memory_max_bytes {
        write_file(&format!("{path}/memory.max"), &m.to_string())?;
    }
    if let Some((q, p)) = caps.cpu_max {
        write_file(&format!("{path}/cpu.max"), &format!("{q} {p}"))?;
    }
    if let Some(pm) = caps.pids_max {
        write_file(&format!("{path}/pids.max"), &pm.to_string())?;
    }
    let dir_fd = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if dir_fd < 0 {
        return Err(err("open(cgroup leaf dir)"));
    }
    Ok(CgroupLeaf { dir_fd, path })
}

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

/// The child's `_exit` code when fd-table sanitization could not be established — the child
/// aborts rather than run the handler with a possibly-un-sanitized (bypass-able) fd table.
pub const SLOT_SANITIZE_FAILED_EXIT: i32 = 90;

/// Fallback close (used when `close_range` is unavailable/errors): close every fd from `floor`
/// (exclusive) up to the process fd-limit. `close` on an unopened fd is a harmless EBADF — the
/// point is that no fd above `floor` survives. SAFETY: raw syscalls; no allocation.
unsafe fn close_fds_above(floor: RawFd) {
    let mut rl: libc::rlimit = core::mem::zeroed();
    let max_fd: libc::c_int = if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0
        && rl.rlim_cur != libc::RLIM_INFINITY
        && rl.rlim_cur < i32::MAX as libc::rlim_t
    {
        rl.rlim_cur as libc::c_int
    } else {
        // Limit unbounded/unreadable → a conservative cap that covers any realistic fd table.
        65536
    };
    let mut fd = floor + 1;
    while fd < max_fd {
        libc::close(fd);
        fd += 1;
    }
}

/// fd-table sanitization (LOAD-BEARING).
/// `clone3` has no `CLONE_FILES` → the child inherited a COPY of the core's ENTIRE fd table, and
/// `O_CLOEXEC` fires only on `exec`, not `clone`. An inherited core fd (a connected DB socket, a
/// cred-store fd) is `read`/`write`-able — and `read`/`write` are allowlisted (the oracle_fd needs
/// them) — so it would BYPASS both the netns (the socket was connected before the netns existed)
/// and the seccomp socket-deny (no new `socket()` needed). So the child must POSITIVELY close
/// every inherited fd except stdio + the oracle. Move the oracle to the canonical low fd, then
/// `close_range` everything above it — which drops the original oracle fd (if it was higher) AND
/// every inherited fd, in one syscall. `close_range` is in the steady-state DENY class, so
/// this MUST run PRE-SEAL (sanitize-then-seal ordering is load-bearing).
///
/// FAIL-CLOSED: returns `false` on a `dup2`
/// failure (the oracle didn't land at the canonical fd) → the caller aborts the child, never
/// running the handler with an unproven table. `close_range` needs kernel ≥5.9; on ANY
/// `close_range` error (ENOSYS on <5.9, or an outer-seccomp interposition) it FALLS BACK to
/// [`close_fds_above`] — so an inherited core fd can never silently survive. This is the
/// fail-closed EXCEPTION window, not just the happy path.
///
/// SAFETY: raw syscalls in the just-cloned child; no allocation.
unsafe fn sanitize_fd_table(oracle_fd: RawFd) -> bool {
    if oracle_fd != SLOT_ORACLE_FD {
        // The oracle MUST land EXACTLY at SLOT_ORACLE_FD; a dup2 failure (EBADF/EINTR) could
        // leave the wrong fd there, which close_range(oracle+1,..) would then preserve → fail closed.
        if libc::dup2(oracle_fd, SLOT_ORACLE_FD) != SLOT_ORACLE_FD {
            return false;
        }
    }
    // Fast path: close_range(first=SLOT_ORACLE_FD+1, last=~0, flags=0) — every fd above the oracle.
    if libc::syscall(
        libc::SYS_close_range,
        (SLOT_ORACLE_FD as libc::c_uint) + 1,
        libc::c_uint::MAX,
        0,
    ) == 0
    {
        return true;
    }
    // close_range unavailable/errored → the portable fallback still fully sanitizes (fail-closed,
    // not fail-open): no inherited fd survives, even on <5.9.
    close_fds_above(SLOT_ORACLE_FD);
    true
}

/// Spawn the handler into a fresh net/pid/mount ns + `cgroup_fd`'s leaf (atomic via
/// `CLONE_INTO_CGROUP`), handing it ONLY the oracle channel (no guest `C`, no cred/
/// broker fd). `clone3` with `stack=0` is fork-like: the child gets a COW copy of the address
/// space and continues from the syscall — so `child` runs with its own memory. Pre-`child`
/// (Phase A, pre-seal): fd-table sanitization (only stdio + oracle@`SLOT_ORACLE_FD` survive) +
/// `no_new_privs` + `PR_SET_DUMPABLE=0`. If sanitization can't be established the child ABORTS
/// (`_exit(SLOT_SANITIZE_FAILED_EXIT)`) before running the handler. In production `child` execs
/// the handler runtime (which reads `rawFrame` off the oracle fd, then calls [`crate::seccomp::seal`]
/// before its first guest byte). Returns the child pid to the parent.
///
/// `oracle_fd` MUST be `>= SLOT_ORACLE_FD` (rejected otherwise) — an oracle at a stdio handler would
/// alias after `dup2` and survive the range-close. Core-side hygiene assumption: the
/// core presents CLEAN stdio {0,1,2} to the spawn — the sanitizer keeps stdio, so a sensitive fd
/// must never be placed in the stdio range core-side.
///
/// SAFETY: post-clone the child runs `child` then `_exit`; `child` must be fork-safe (no lock it
/// could deadlock on). The test children do only direct syscalls + `_exit`.
pub fn spawn_confined<F: FnOnce()>(
    cgroup_fd: RawFd,
    oracle_fd: RawFd,
    child: F,
) -> Result<libc::pid_t, LaunchError> {
    // Guard: oracle_fd below the canonical handler means dup2 would leave a duplicate
    // oracle at a stdio handler that close_range(oracle+1,..) can't reach. Reject up front.
    if oracle_fd < SLOT_ORACLE_FD {
        return Err(LaunchError {
            op: "oracle_fd must be >= SLOT_ORACLE_FD (stdio-reserved)",
            errno: libc::EINVAL,
        });
    }
    let mut args = CloneArgs {
        flags: (libc::CLONE_NEWNET as u64)
            | (libc::CLONE_NEWNS as u64)
            | (libc::CLONE_NEWPID as u64)
            | CLONE_INTO_CGROUP,
        exit_signal: libc::SIGCHLD as u64,
        cgroup: cgroup_fd as u64,
        ..Default::default()
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &mut args as *mut CloneArgs,
            core::mem::size_of::<CloneArgs>(),
        )
    };
    if rc < 0 {
        return Err(err("clone3"));
    }
    if rc == 0 {
        // CHILD — Phase A confinement prep, all PRE-SEAL, that must precede handler entry.
        unsafe {
            // Load-bearing: drop every inherited core fd before anything runs. FAIL-CLOSED —
            // if sanitization can't be established, abort; NEVER run the handler with an
            // un-sanitized (bypass-able) fd table.
            if !sanitize_fd_table(oracle_fd) {
                libc::_exit(SLOT_SANITIZE_FAILED_EXIT);
            }
            // no_new_privs: a suid exec can't regain privilege; also required before a later seal.
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            // Not core-dumpable → the core (or anything) can't /proc/<handler>/mem read it.
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
        child();
        unsafe { libc::_exit(0) };
    }
    Ok(rc as libc::pid_t)
}

/// Bind-mount-free helper for the tests: is a fresh netns route-less? Returns true iff a UDP
/// `connect` to a routable address fails with ENETUNREACH (no route/iface in this netns).
pub fn netns_has_no_route() -> bool {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return false; // can't even make the socket — treat as inconclusive
        }
        let mut addr: libc::sockaddr_in = core::mem::zeroed();
        addr.sin_family = libc::AF_INET as u16;
        addr.sin_port = 53u16.to_be();
        addr.sin_addr.s_addr = u32::from_be_bytes([1, 1, 1, 1]).to_be();
        let rc = libc::connect(
            fd,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            core::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        let e = *libc::__errno_location();
        libc::close(fd);
        rc != 0 && e == libc::ENETUNREACH
    }
}

// Re-export a couple of libc bits the tests need without importing libc there.
#[doc(hidden)]
pub fn wait_status(pid: libc::pid_t) -> c_int {
    let mut status: c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    status
}
#[doc(hidden)]
pub fn _void() -> *mut c_void {
    core::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Guard: an oracle at a stdio handler is rejected up front — the check runs before
    // any clone3, so this needs no privilege. cgroup_fd is unused on the reject path.
    #[test]
    fn spawn_rejects_oracle_fd_below_canonical() {
        let r = spawn_confined(-1, 1, || {});
        assert!(r.is_err(), "oracle_fd < SLOT_ORACLE_FD must be rejected");
        assert_eq!(r.err().unwrap().errno, libc::EINVAL);
    }

    // The fail-closed fallback (close_range unavailable on <5.9) must still close an inherited fd
    // above the oracle. Forked so closing the whole table only affects the child, not the harness.
    #[test]
    fn fallback_close_fds_above_closes_inherited_fd() {
        unsafe {
            let marker = 10; // force a marker well above SLOT_ORACLE_FD
            assert_eq!(
                libc::dup2(0, marker),
                marker,
                "set up the inherited marker fd"
            );
            let pid = libc::fork();
            assert!(pid >= 0, "fork");
            if pid == 0 {
                close_fds_above(SLOT_ORACLE_FD);
                let still_open = libc::fcntl(marker, libc::F_GETFD) >= 0;
                libc::_exit(if still_open { 1 } else { 0 });
            }
            let mut st: c_int = 0;
            libc::waitpid(pid, &mut st, 0);
            libc::close(marker);
            assert!(
                libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
                "the fallback must close an inherited fd above the oracle",
            );
        }
    }
}
