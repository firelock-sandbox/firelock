//! Spawn + supervise the extension process.
//!
//! [`spawn_extension`] MUST be called while k9o-init is still single-threaded
//! (before the gate/invoke server threads start): `fork(2)` in a single-threaded
//! process gives a child that can safely allocate before `execvp`, avoiding the
//! multithreaded-fork async-signal-safety hazard. As PID 1, k9o-init then reaps
//! every child ([`reap_until`]) so no zombie accumulates, and exits with the
//! extension's status when it terminates.
//!
//! # Safety
//! `unsafe` blocks are single libc calls (`fork`/`chdir`/`setenv`/`execvp`/
//! `_exit`/`waitpid`) with `CString` arguments and checked returns.

use crate::entry::EntryContract;
use std::ffi::CString;
use std::io;

fn cstring(s: &str) -> CString {
    CString::new(s).unwrap_or_else(|_| CString::new("").unwrap())
}

fn setenv(key: &str, val: &str) {
    let k = cstring(key);
    let v = cstring(val);
    // SAFETY: both are valid NUL-terminated CStrings; overwrite = 1.
    unsafe {
        libc::setenv(k.as_ptr(), v.as_ptr(), 1);
    }
}

/// Fork + exec the extension entrypoint from `contract`, injecting the two
/// k9o-init-provided env vars. Returns the child pid to the parent; the child
/// path never returns (it execs or `_exit`s).
pub fn spawn_extension(
    contract: &EntryContract,
    gate_socket: &str,
    invoke_listen: &str,
) -> io::Result<libc::pid_t> {
    let argv: Vec<CString> = contract.argv.iter().map(|a| cstring(a)).collect();

    // SAFETY: fork(2). Caller guarantees we are single-threaded here.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid > 0 {
        // Parent: hand the pid back for supervision.
        return Ok(pid);
    }

    // ---- Child ----------------------------------------------------------
    if let Some(cwd) = contract.cwd.as_deref() {
        let c = cstring(cwd);
        // SAFETY: valid CString; failure is non-fatal (exec below reports).
        unsafe {
            libc::chdir(c.as_ptr());
        }
    }
    for (k, v) in &contract.env {
        setenv(k, v);
    }
    // k9o-init tells the extension where the gate UDS and its own invoke server
    // must be. These win over any image-provided values (they're runtime facts).
    setenv("K9O_GATE_SOCKET", gate_socket);
    setenv("K9O_INVOKE_LISTEN", invoke_listen);

    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: argv is NUL-terminated; ptrs[0] is a valid program name. execvp
    // resolves PATH from the environment we just set.
    unsafe {
        libc::execvp(ptrs[0], ptrs.as_ptr());
    }
    // Only reached if exec failed.
    eprintln!("k9o-init: failed to exec extension entrypoint: {}", io::Error::last_os_error());
    // SAFETY: _exit(2) — terminate the failed child without running atexit hooks.
    unsafe {
        libc::_exit(127);
    }
}

/// Reap children until `target` (the extension) exits, returning its exit code
/// (128 + signal for a signalled exit). Every other reaped child is a zombie we
/// silently clear — the core PID-1 duty.
pub fn reap_until(target: libc::pid_t) -> i32 {
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: waitpid(2) with a valid out-param.
        let pid = unsafe { libc::waitpid(-1, &mut status as *mut libc::c_int, 0) };
        if pid < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                // No children left — nothing more to supervise.
                Some(libc::ECHILD) => return 0,
                _ => return 1,
            }
        }
        if pid == target {
            return exit_code(status);
        }
        // Some other child (a grandchild reparented to PID 1) — reaped, continue.
    }
}

/// Idle PID-1 duty for a warm-pool VM with no entry contract yet: there is no
/// extension to wait on, so park forever, reaping any orphan reparented to PID 1
/// so no zombie accumulates. Never returns — the VM lives (gate bridge serving)
/// until the host pauses/snapshots or tears it down. On `ECHILD` (the common
/// idle case: no children at all) or any other `waitpid` error it sleeps briefly
/// rather than spin.
pub fn reap_forever() -> ! {
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: waitpid(2) with a valid out-param.
        let pid = unsafe { libc::waitpid(-1, &mut status as *mut libc::c_int, 0) };
        if pid < 0 {
            match io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => continue,
                _ => std::thread::sleep(std::time::Duration::from_millis(500)),
            }
        }
        // Reaped an orphan (or slept on ECHILD) — keep parking.
    }
}

fn exit_code(status: libc::c_int) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}
