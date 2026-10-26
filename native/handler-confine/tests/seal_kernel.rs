//! REAL-KERNEL proofs of the seal. Each case forks a child
//! that installs the steady filter then attempts a syscall; the parent asserts the child was
//! KILLED with SIGSYS (denied) or EXITED cleanly (allowed). Needs a real kernel with seccomp
//! — run on a Linux host, never on macOS. Run: `cargo test --release --test seal_kernel`.
//!
//! The child does only fork-safe work (a couple of direct syscalls); the filter Vec is built
//! inside `seal()` — glibc resets the malloc arena lock across fork, so the single-threaded
//! child allocates safely.

use firelock_handler_confine::policy::WxPosture;
use firelock_handler_confine::seccomp::seal;

#[derive(Debug, PartialEq)]
enum Outcome {
    Survived,
    KilledSigsys,
    Other(i32),
}

/// Fork; run `offend` in the child (which should either return — survived — or trigger a
/// SIGSYS kill mid-syscall). Classify from the child's wait status.
fn run_child<F: FnOnce()>(offend: F) -> Outcome {
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            offend();
            libc::_exit(0); // reached only if no denied syscall killed us
        }
        let mut status: libc::c_int = 0;
        libc::waitpid(pid, &mut status, 0);
        if libc::WIFSIGNALED(status) {
            if libc::WTERMSIG(status) == libc::SIGSYS {
                Outcome::KilledSigsys
            } else {
                Outcome::Other(libc::WTERMSIG(status))
            }
        } else if libc::WIFEXITED(status) {
            match libc::WEXITSTATUS(status) {
                0 => Outcome::Survived,
                n => Outcome::Other(-n),
            }
        } else {
            Outcome::Other(-999)
        }
    }
}

/// Seal for `posture`; on seal failure `_exit(42)` so the parent sees `Other(-42)` (a broken
/// seal, distinct from a SIGSYS). Returns only if the seal succeeded.
fn seal_or_bail(posture: WxPosture) {
    if seal(posture).is_err() {
        unsafe { libc::_exit(42) };
    }
}

// ── Positive control: an allowlisted syscall survives the seal (proves the filter isn't just
//    killing everything) ────────────────────────────────────────────────────────────────
#[test]
fn allowlisted_getpid_survives_the_seal() {
    let o = run_child(|| {
        seal_or_bail(WxPosture::StrictNoExec);
        unsafe {
            libc::syscall(libc::SYS_getpid);
        }
    });
    assert_eq!(
        o,
        Outcome::Survived,
        "allowlisted getpid should survive the seal"
    );
}

// ── Complete-class socket deny — BOTH AF_UNIX and AF_INET die (a family-scoped filter
//    would let AF_UNIX through; this is the load-bearing check) ─────────────────────────
#[test]
fn socket_af_unix_dies_sigsys() {
    let o = run_child(|| {
        seal_or_bail(WxPosture::StrictNoExec);
        unsafe {
            libc::syscall(libc::SYS_socket, libc::AF_UNIX, libc::SOCK_STREAM, 0);
        }
    });
    assert_eq!(o, Outcome::KilledSigsys, "socket(AF_UNIX) must be denied");
}

#[test]
fn socket_af_inet_dies_sigsys() {
    let o = run_child(|| {
        seal_or_bail(WxPosture::StrictNoExec);
        unsafe {
            libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0);
        }
    });
    assert_eq!(o, Outcome::KilledSigsys, "socket(AF_INET) must be denied");
}

// ── Process-creation / injection ────────────────────────────────────────────────────────
#[test]
fn execve_dies_sigsys() {
    let o = run_child(|| {
        seal_or_bail(WxPosture::StrictNoExec);
        let path = b"/bin/true\0";
        unsafe {
            libc::syscall(
                libc::SYS_execve,
                path.as_ptr(),
                core::ptr::null::<*const libc::c_char>(),
                core::ptr::null::<*const libc::c_char>(),
            );
        }
    });
    assert_eq!(o, Outcome::KilledSigsys, "execve must be denied");
}

#[test]
fn ptrace_dies_sigsys() {
    let o = run_child(|| {
        seal_or_bail(WxPosture::StrictNoExec);
        unsafe {
            libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0);
        }
    });
    assert_eq!(o, Outcome::KilledSigsys, "ptrace must be denied");
}

// ── io_uring — the seccomp bypass ───────────────────────────────────────────────
#[test]
fn io_uring_setup_dies_sigsys() {
    let o = run_child(|| {
        seal_or_bail(WxPosture::StrictNoExec);
        // io_uring_setup(entries, params*) — params NULL is enough; the syscall never returns
        // (denied), so the null deref never happens.
        unsafe {
            libc::syscall(libc::SYS_io_uring_setup, 1u32, core::ptr::null::<u8>());
        }
    });
    assert_eq!(
        o,
        Outcome::KilledSigsys,
        "io_uring_setup must be denied (seccomp bypass)"
    );
}

// ── W^X (StrictNoExec): mmap(PROT_EXEC) dies; mmap without exec survives ─────────────────
#[test]
fn strict_mmap_prot_exec_dies_sigsys() {
    let o = run_child(|| {
        seal_or_bail(WxPosture::StrictNoExec);
        unsafe {
            libc::syscall(
                libc::SYS_mmap,
                core::ptr::null_mut::<libc::c_void>(),
                4096usize,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1i32,
                0i64,
            );
        }
    });
    assert_eq!(
        o,
        Outcome::KilledSigsys,
        "strict W^X: mmap(PROT_EXEC) must be denied"
    );
}

#[test]
fn strict_mmap_anon_rw_survives() {
    let o = run_child(|| {
        seal_or_bail(WxPosture::StrictNoExec);
        unsafe {
            libc::syscall(
                libc::SYS_mmap,
                core::ptr::null_mut::<libc::c_void>(),
                4096usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1i32,
                0i64,
            );
        }
    });
    assert_eq!(
        o,
        Outcome::Survived,
        "an anon RW mmap must be allowed under strict W^X"
    );
}

// ── JitRelaxed: mmap(PROT_EXEC) SURVIVES (a JIT handler needs exec pages) — the contingent leg ─
#[test]
fn relaxed_mmap_prot_exec_survives() {
    let o = run_child(|| {
        seal_or_bail(WxPosture::JitRelaxed);
        unsafe {
            libc::syscall(
                libc::SYS_mmap,
                core::ptr::null_mut::<libc::c_void>(),
                4096usize,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1i32,
                0i64,
            );
        }
    });
    assert_eq!(
        o,
        Outcome::Survived,
        "JitRelaxed: mmap(PROT_EXEC) must be permitted"
    );
}

// ── fcntl arg-filter: an allowed cmd survives, a denied cmd dies ─────────────────────────
#[test]
fn fcntl_getfl_survives_setlk_dies() {
    let getfl = run_child(|| {
        seal_or_bail(WxPosture::StrictNoExec);
        unsafe {
            // fd 0 (stdin) is open in the child; F_GETFL is on the allowed cmd set.
            libc::syscall(libc::SYS_fcntl, 0, libc::F_GETFL);
        }
    });
    assert_eq!(getfl, Outcome::Survived, "fcntl(F_GETFL) must be allowed");

    let setlk = run_child(|| {
        seal_or_bail(WxPosture::StrictNoExec);
        let mut fl: libc::flock = unsafe { core::mem::zeroed() };
        fl.l_type = libc::F_RDLCK as i16;
        unsafe {
            libc::syscall(libc::SYS_fcntl, 0, libc::F_SETLK, &fl as *const libc::flock);
        }
    });
    assert_eq!(
        setlk,
        Outcome::KilledSigsys,
        "fcntl(F_SETLK) must be denied"
    );
}

// ── TSYNC covers a thread created BEFORE the seal — else a sibling stays unconfined ─
#[test]
fn tsync_covers_a_pre_created_sibling_thread() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let o = run_child(|| {
        let go = Arc::new(AtomicBool::new(false));
        let go2 = go.clone();
        // The sibling is spawned BEFORE the seal. Without TSYNC it would NOT inherit the
        // filter (seccomp filters are per-thread), so its socket() would succeed and the
        // process would exit 0. With TSYNC the seal covers it → socket() → SIGSYS → the
        // whole thread group dies.
        let h = std::thread::spawn(move || {
            while !go2.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
            unsafe {
                libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0);
            }
        });
        seal_or_bail(WxPosture::StrictNoExec); // installs with SECCOMP_FILTER_FLAG_TSYNC
        go.store(true, Ordering::Release);
        let _ = h.join(); // reached only if TSYNC failed (sibling survived its socket())
    });
    assert_eq!(
        o,
        Outcome::KilledSigsys,
        "TSYNC must apply the filter to the pre-created sibling thread",
    );
}
