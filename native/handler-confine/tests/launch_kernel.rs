//! REAL-KERNEL proofs of the Phase-A launch (network namespace + cgroup v2).
//! Creating net/pid/mount namespaces + a cgroup leaf needs CAP_SYS_ADMIN → these run only when
//! FIRELOCK_CONFINE_PRIV_TESTS=1 AND euid==0 (`sudo -E ... cargo test`). Otherwise
//! they SKIP LOUDLY (printed) — an honest skip, never a silent pass. Run:
//!   sudo FIRELOCK_CONFINE_PRIV_TESTS=1 ~/.cargo/bin/cargo test --release --test launch_kernel

use firelock_handler_confine::launch::{
    create_cgroup_leaf, netns_has_no_route, spawn_confined, wait_status, HandlerCaps,
    SLOT_ORACLE_FD,
};
use std::sync::atomic::{AtomicU32, Ordering};

/// A stand-in oracle fd for the tests that don't exercise the channel — a dup of stdin (a valid
/// fd the sanitizer moves to SLOT_ORACLE_FD).
fn oracle_stub() -> libc::c_int {
    unsafe { libc::dup(0) }
}

static SEQ: AtomicU32 = AtomicU32::new(0);
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Three-state gate (never a silent skip-pass in CI):
///   • env NOT set (plain `cargo test`) → SKIP (printed) — the launch proofs need privilege.
///   • env set but euid != 0 → HARD FAIL — a CI job that requested the priv tests but landed on
///     a runner without CAP_SYS_ADMIN must go RED, not falsely green.
///   • env set AND euid 0 → RUN.
fn require_priv_or_skip() -> bool {
    let requested = std::env::var("FIRELOCK_CONFINE_PRIV_TESTS").as_deref() == Ok("1");
    if !requested {
        eprintln!(
            "SKIP: set FIRELOCK_CONFINE_PRIV_TESTS=1 + run as root (CAP_SYS_ADMIN) to exercise the launch proofs",
        );
        return false;
    }
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "FIRELOCK_CONFINE_PRIV_TESTS=1 but euid!=0 — the launch proofs need CAP_SYS_ADMIN \
         (a privileged runner); refusing to silently skip",
    );
    true
}

/// Unique leaf name without Date/rand — pid + a monotonic counter.
fn leaf_name(tag: &str) -> String {
    format!(
        "firelock-handler-test-{}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed),
        tag
    )
}

macro_rules! skip_if_unpriv {
    () => {
        if !require_priv_or_skip() {
            return;
        }
    };
}

#[test]
fn confined_child_has_no_network_route() {
    skip_if_unpriv!();
    let leaf = create_cgroup_leaf(CGROUP_ROOT, &leaf_name("netns"), &HandlerCaps::default())
        .expect("leaf");
    let pid = spawn_confined(leaf.dir_fd, oracle_stub(), || {
        // In the fresh netns: no iface, no route → a connect must fail ENETUNREACH.
        let ok = netns_has_no_route();
        unsafe { libc::_exit(if ok { 0 } else { 1 }) };
    })
    .expect("clone3");
    let status = wait_status(pid);
    leaf.remove().ok();
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "the confined handler's netns must have NO route",
    );
}

#[test]
fn confined_child_is_pid_1_in_its_own_pidns() {
    skip_if_unpriv!();
    let leaf = create_cgroup_leaf(CGROUP_ROOT, &leaf_name("pidns"), &HandlerCaps::default())
        .expect("leaf");
    let pid = spawn_confined(leaf.dir_fd, oracle_stub(), || {
        // Fresh PID namespace → the handler sees itself as pid 1; it cannot see/signal host pids.
        let me = unsafe { libc::getpid() };
        unsafe { libc::_exit(if me == 1 { 0 } else { 2 }) };
    })
    .expect("clone3");
    let status = wait_status(pid);
    leaf.remove().ok();
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "the confined handler must be pid 1 in a fresh PID namespace",
    );
}

#[test]
fn confined_child_is_in_the_cgroup_leaf() {
    skip_if_unpriv!();
    let name = leaf_name("member");
    let leaf = create_cgroup_leaf(CGROUP_ROOT, &name, &HandlerCaps::default()).expect("leaf");
    // Pass the expected basename to the child via env (read pre-clone, in the parent).
    let pid = spawn_confined(leaf.dir_fd, oracle_stub(), {
        let name = name.clone();
        move || {
            // /proc/self/cgroup (v2) = "0::<path>"; CLONE_INTO_CGROUP put us in the leaf.
            let membership = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
            let ok = membership.contains(&name);
            unsafe { libc::_exit(if ok { 0 } else { 3 }) };
        }
    })
    .expect("clone3");
    let status = wait_status(pid);
    leaf.remove().ok();
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "the confined handler must be born into its cgroup leaf (CLONE_INTO_CGROUP)",
    );
}

#[test]
fn cgroup_leaf_has_caps_applied() {
    skip_if_unpriv!();
    let caps = HandlerCaps {
        memory_max_bytes: Some(64 * 1024 * 1024),
        cpu_max: Some((25_000, 100_000)),
        pids_max: Some(32),
    };
    let leaf = create_cgroup_leaf(CGROUP_ROOT, &leaf_name("caps"), &caps).expect("leaf");
    let mem = std::fs::read_to_string(format!("{}/memory.max", leaf.path)).unwrap_or_default();
    let pids = std::fs::read_to_string(format!("{}/pids.max", leaf.path)).unwrap_or_default();
    let cpu = std::fs::read_to_string(format!("{}/cpu.max", leaf.path)).unwrap_or_default();
    leaf.remove().ok();
    assert_eq!(
        mem.trim(),
        (64 * 1024 * 1024).to_string(),
        "memory.max applied"
    );
    assert_eq!(pids.trim(), "32", "pids.max applied");
    assert_eq!(cpu.trim(), "25000 100000", "cpu.max applied");
}

// ── Load-bearing: the fd table is sanitized to
//    stdio + the oracle_fd ONLY. An inherited core fd (connected socket / cred-store fd) would
//    be read/write-able and bypass BOTH netns and the seccomp socket-deny — so the confinement
//    is a credential/egress bypass unless the spawn positively closes every inherited fd. ─────
#[test]
fn fd_table_sanitized_to_oracle_and_stdio_only() {
    skip_if_unpriv!();
    // Simulate the core's inherited fds: several extra open fds the child MUST NOT retain.
    let inherited_sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    let inherited_dn = unsafe {
        libc::open(
            b"/dev/null\0".as_ptr() as *const libc::c_char,
            libc::O_RDONLY,
        )
    };
    assert!(inherited_sock >= 0 && inherited_dn >= 0, "setup fds");
    // The oracle channel — one end of a socketpair, handed to the handler.
    let mut sv = [0i32; 2];
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) },
        0
    );
    let oracle = sv[0];

    let leaf = create_cgroup_leaf(CGROUP_ROOT, &leaf_name("fdsan"), &HandlerCaps::default())
        .expect("leaf");
    let pid = spawn_confined(leaf.dir_fd, oracle, || {
        // Raw fcntl only (no fd-opening → no /proc dirfd artifact). After sanitization the ONLY
        // open fds must be stdio {0,1,2} + the oracle at SLOT_ORACLE_FD. Every other fd — the
        // inherited core fds at whatever numbers — must be EBADF.
        unsafe {
            if libc::fcntl(SLOT_ORACLE_FD, libc::F_GETFD) < 0 {
                libc::_exit(10); // oracle not present at the canonical fd
            }
            for fd in 0..3 {
                if libc::fcntl(fd, libc::F_GETFD) < 0 {
                    libc::_exit(11); // stdio must survive
                }
            }
            // Scan a generous range: any open fd above the oracle = an un-closed inherited fd.
            for fd in (SLOT_ORACLE_FD + 1)..4096 {
                if libc::fcntl(fd, libc::F_GETFD) >= 0 {
                    libc::_exit(20); // a leaked inherited fd — the inherited-fd bypass
                }
            }
            libc::_exit(0);
        }
    })
    .expect("clone3");
    let status = wait_status(pid);
    leaf.remove().ok();
    unsafe {
        libc::close(inherited_sock);
        libc::close(inherited_dn);
        libc::close(sv[0]);
        libc::close(sv[1]);
    }
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "the handler's fd table must be sanitized to stdio + oracle only (no inherited core fd); exit={}",
        libc::WEXITSTATUS(status),
    );
}

#[test]
fn cgroup_leaf_removed_after_handler_exit_single_use() {
    skip_if_unpriv!();
    let leaf = create_cgroup_leaf(CGROUP_ROOT, &leaf_name("teardown"), &HandlerCaps::default())
        .expect("leaf");
    let path = leaf.path.clone();
    let pid =
        spawn_confined(leaf.dir_fd, oracle_stub(), || unsafe { libc::_exit(0) }).expect("clone3");
    let _ = wait_status(pid); // reap the handler first (a non-empty leaf can't be removed — EBUSY)
    leaf.remove()
        .expect("leaf must be removable after the handler exits (single-use)");
    assert!(
        !std::path::Path::new(&path).exists(),
        "the cgroup leaf must be gone after teardown"
    );
}
