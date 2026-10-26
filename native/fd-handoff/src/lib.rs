//! The `SCM_RIGHTS` guest-connection-fd handoff.
//!
//! On `allow`, the gate dispatcher must give the executor the
//! guest connection fd `C` (so the executor writes the tool result directly onto
//! the connection the guest is blocked reading) together with the decision
//! receipt — over a **host-internal AF_UNIX control socket** established at
//! startup, never guest-reachable. Then the dispatcher **closes its own copy of
//! `C`**, leaving the executor the *sole* fd owner.
//!
//! That sole-owner property is the load-bearing invariant:
//!   * the receipt travels host-internal only — **it never crosses the guest
//!     boundary** (the precondition structural single-use rests on);
//!   * `C` has exactly one owner after handoff, so it cannot be re-presented —
//!     single-use is *structural*, needing no nonce store.
//!
//! The API encodes the discipline in the type system: [`send_conn_fd`] takes the
//! connection fd **by value** (`OwnedFd`) and drops it after the send, so the
//! sender's copy is closed automatically — you cannot forget to close it.
//!
//! ## Trust-anchor boundary (what this crate does NOT do)
//! This is the *transport* of the handoff. It deliberately does NOT verify the
//! receipt or authorize the call — that is the executor's job, and it
//! must authorize on the receipt verified against the **bytes read off `C`**, not
//! on anything this transport carries in the payload (the payload's resolved
//! metadata is a hint only). Keeping verification out of the transport is what
//! keeps the guest-facing dispatcher out of the authorization trust base.
//!
//! Portable across Linux (production, x86_64) and macOS (development) — `SCM_RIGHTS` is BSD
//! sockets on both; the real-fd tests run on both.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::raw::c_int;

/// Max receipt+metadata payload accepted on a single handoff message. The
/// receipt is a compact JWS + resolved-call metadata; 64 KiB is generous and
/// bounds a hostile/buggy sender.
pub const MAX_PAYLOAD: usize = 64 * 1024;

/// A cmsghdr-aligned scratch buffer holding exactly one `SCM_RIGHTS` control
/// message (one fd). The `union` with a `cmsghdr` field guarantees the alignment
/// the `CMSG_*` macros require; 64 bytes comfortably exceeds
/// `CMSG_SPACE(size_of::<c_int>())` on every supported platform (~16–24 bytes).
#[repr(C)]
union CmsgBuf {
    _align: libc::cmsghdr,
    bytes: [u8; 64],
}

impl CmsgBuf {
    fn zeroed() -> Self {
        CmsgBuf { bytes: [0u8; 64] }
    }
}

/// One received handoff: the passed connection fd (now solely owned by this
/// process) plus the payload bytes that rode with it (the decision receipt +
/// resolved-call metadata).
#[derive(Debug)]
pub struct Handoff {
    /// The guest connection fd `C`. Dropping this closes the connection.
    pub conn: OwnedFd,
    /// The receipt + metadata payload. Authorization must NOT trust this over the
    /// bytes read from `conn` (trust-anchor rule).
    pub payload: Vec<u8>,
}

/// Send the guest connection fd `conn` plus `payload` (the decision receipt +
/// resolved metadata) to the executor over the host-internal control socket.
///
/// Takes `conn` **by value** and drops it on return — this is the "dispatcher
/// closes its copy of `C`" discipline made structural. `payload` must be
/// non-empty (SCM_RIGHTS requires at least one data byte to transfer the fd) and
/// at most [`MAX_PAYLOAD`].
pub fn send_conn_fd(control: BorrowedFd<'_>, conn: OwnedFd, payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "handoff payload must be non-empty (SCM_RIGHTS needs a data byte)",
        ));
    }
    if payload.len() > MAX_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "handoff payload exceeds MAX_PAYLOAD",
        ));
    }

    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut cmsg = CmsgBuf::zeroed();
    let raw = conn.as_raw_fd();

    // SAFETY: msghdr is zero-initialised then fully populated; the control buffer
    // is cmsghdr-aligned and sized >= one-fd space; we write exactly one fd into
    // the space CMSG_LEN(size_of::<c_int>()) reserves.
    let sent = unsafe {
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.bytes.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = libc::CMSG_SPACE(mem::size_of::<c_int>() as u32) as _;

        let hdr = libc::CMSG_FIRSTHDR(&msg);
        debug_assert!(!hdr.is_null());
        (*hdr).cmsg_level = libc::SOL_SOCKET;
        (*hdr).cmsg_type = libc::SCM_RIGHTS;
        (*hdr).cmsg_len = libc::CMSG_LEN(mem::size_of::<c_int>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &raw as *const RawFd as *const u8,
            libc::CMSG_DATA(hdr),
            mem::size_of::<c_int>(),
        );

        libc::sendmsg(control.as_raw_fd(), &msg, 0)
    };

    // CAPTURE THE SEND ERRNO BEFORE ANY OTHER SYSCALL. `drop(conn)` below calls `close(2)`, which SETS
    // errno — so reading `last_os_error()` AFTER the drop returns close's errno, not sendmsg's, mislabelling
    // every failed handoff Snapshot it here, at the sendmsg, first.
    let send_err = if sent < 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };

    // `conn` drops here regardless of outcome → the sender's copy of `C` is closed. On the happy path the
    // executor now holds the only reference; on a failed send C is not transmitted and is released here too
    // (there is no retry — the clear_nonblock at seam setup is what keeps a blocking `sendmsg` from EAGAIN).
    drop(conn);

    if let Some(e) = send_err {
        return Err(e);
    }
    Ok(())
}

/// Receive one handoff on the control socket: the passed fd (now owned here) plus
/// its payload. Fails closed if no fd was actually attached — a message without
/// an `SCM_RIGHTS` fd is never treated as a valid handoff.
/// Shared `recvmsg` + `SCM_RIGHTS`-gather (extracted verbatim from `recv_conn_fd` so the fd-passing
/// guards — MSG_CMSG_CLOEXEC, MSG_CTRUNC detection, gathering EVERY attached fd — are IDENTICAL on both
/// the handoff path (`recv_conn_fd`, exactly one fd) and the control-frame path (`recv_control_frame`,
/// zero-or-one). One code path makes "mirror exactly" structural, not a duplicated block that
/// could drift. The CALLER applies the fd-count policy + CLOEXEC-set; this only reads + gathers.
fn recvmsg_gather_fds(control: BorrowedFd<'_>) -> io::Result<(Vec<u8>, usize, Vec<RawFd>, bool)> {
    let mut buf = vec![0u8; MAX_PAYLOAD];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut cmsg = CmsgBuf::zeroed();

    // SAFETY: msghdr zero-init then populated; control buffer is aligned and
    // sized for one fd; we parse every returned cmsg header and bound the fd count.
    let (n, received_fds, ctrunc) = unsafe {
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.bytes.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = 64 as _;

        // MSG_CMSG_CLOEXEC (Linux) marks the received fd close-on-exec atomically,
        // so a concurrent exec can't leak `C`. macOS lacks the flag; we set
        // FD_CLOEXEC explicitly below on both for uniformity.
        #[cfg(target_os = "linux")]
        let flags = libc::MSG_CMSG_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = 0;

        let n = libc::recvmsg(control.as_raw_fd(), &mut msg, flags);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        // The kernel installs EVERY fd a sender attached, across every SCM_RIGHTS
        // cmsg, into our fd table before we run. A compromised dispatcher (an actor
        // excluded from the executor's trust base)
        // could attach `C` PLUS extra fds — an fd-exhaustion DoS, a non-CLOEXEC
        // leak across a later exec(), and a confused-deputy vector. So we must
        // gather ALL of them and fail closed unless there is exactly one.
        let mut fds: Vec<RawFd> = Vec::new();
        let ctrunc = msg.msg_flags & libc::MSG_CTRUNC != 0;

        let mut hdr = libc::CMSG_FIRSTHDR(&msg);
        while !hdr.is_null() {
            if (*hdr).cmsg_level == libc::SOL_SOCKET && (*hdr).cmsg_type == libc::SCM_RIGHTS {
                // A single SCM_RIGHTS cmsg can carry an ARRAY of fds. Count them
                // from the cmsg's own length (data spans CMSG_DATA..hdr+cmsg_len).
                let data = libc::CMSG_DATA(hdr);
                let cmsg_end = (hdr as *const u8).add((*hdr).cmsg_len as usize);
                let bytes = cmsg_end as usize - data as usize;
                let count = bytes / mem::size_of::<c_int>();
                for i in 0..count {
                    let mut raw: RawFd = -1;
                    std::ptr::copy_nonoverlapping(
                        data.add(i * mem::size_of::<c_int>()),
                        &mut raw as *mut RawFd as *mut u8,
                        mem::size_of::<c_int>(),
                    );
                    fds.push(raw);
                }
            }
            hdr = libc::CMSG_NXTHDR(&msg, hdr);
        }
        (n as usize, fds, ctrunc)
    };
    Ok((buf, n, received_fds, ctrunc))
}

pub fn recv_conn_fd(control: BorrowedFd<'_>) -> io::Result<Handoff> {
    let (mut buf, n, received_fds, ctrunc) = recvmsg_gather_fds(control)?;
    // Fail closed on truncation or on anything other than exactly one fd, and
    // CLOSE every fd we received first so no smuggled/extra fd is leaked into the
    // executor. This is the guard that matters: the transport itself bounds
    // the fd count so a hostile dispatcher can't inject open fds past the seam.
    if ctrunc || received_fds.len() != 1 {
        for fd in &received_fds {
            // SAFETY: each is a freshly-installed fd we own and are discarding.
            unsafe { libc::close(*fd) };
        }
        let why = if ctrunc {
            "handoff control message was truncated (MSG_CTRUNC)"
        } else if received_fds.is_empty() {
            "handoff message carried no SCM_RIGHTS fd"
        } else {
            "handoff carried more than one fd"
        };
        return Err(io::Error::new(io::ErrorKind::InvalidData, why));
    }

    // SAFETY: the sole received fd was just transferred to us and is not owned
    // elsewhere in this process; wrap it so it is closed on drop.
    let conn = unsafe { OwnedFd::from_raw_fd(received_fds[0]) };
    set_cloexec(&conn)?;

    buf.truncate(n);
    Ok(Handoff { conn, payload: buf })
}

/// A demuxed control-channel frame: `Some(fd)` = a handoff (byte-clean payload + the guest conn fd),
/// `None` = a data frame (no fd). Same recvmsg + fd guards as `recv_conn_fd` (shared helper); the
/// ONLY difference is that ZERO fds is VALID here (a data frame). This is the demux primitive: the
/// executor's accept loop discriminates handoff vs data frame by fd-presence — fd-presence, because the handoff
/// payload must stay byte-exact (no type byte) for the executor's `input_sha256` check.
#[derive(Debug)]
pub struct ControlFrame {
    pub conn: Option<OwnedFd>,
    pub payload: Vec<u8>,
}

pub fn recv_control_frame(control: BorrowedFd<'_>) -> io::Result<ControlFrame> {
    let (mut buf, n, received_fds, ctrunc) = recvmsg_gather_fds(control)?;
    // Fail closed on truncation or fd-EXHAUSTION (> 1). Zero fds is a valid data frame. Close every
    // received fd on the reject path so no smuggled fd leaks into the executor (same guard as recv_conn_fd).
    if ctrunc || received_fds.len() > 1 {
        for fd in &received_fds {
            unsafe { libc::close(*fd) };
        }
        let why = if ctrunc {
            "control message was truncated (MSG_CTRUNC)"
        } else {
            "control frame carried more than one fd (fd-exhaustion guard)"
        };
        return Err(io::Error::new(io::ErrorKind::InvalidData, why));
    }
    let conn = if received_fds.len() == 1 {
        // SAFETY: the sole received fd was just transferred to us and is owned nowhere else.
        let c = unsafe { OwnedFd::from_raw_fd(received_fds[0]) };
        set_cloexec(&c)?; // CLOEXEC belt-and-braces (macOS) / redundant with MSG_CMSG_CLOEXEC (Linux)
        Some(c)
    } else {
        None // a data frame — no fd
    };
    buf.truncate(n);
    Ok(ControlFrame { conn, payload: buf })
}

/// Set FD_CLOEXEC on the received fd (belt-and-braces on macOS, redundant with
/// MSG_CMSG_CLOEXEC on Linux) so `C` cannot leak across an executor exec().
fn set_cloexec(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: fd is a valid open descriptor owned by `fd`.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Bound `recv_conn_fd`'s block on `control` to at most `timeout`.
///
/// WHY THIS MUST LIVE HERE AND CANNOT LIVE IN TS. `recvmsg` is a SYNCHRONOUS BLOCKING syscall:
/// an executor wedged inside it never reaches the loop-exit path, so readiness keeps reporting healthy
/// while nothing is served. A
/// racing JS `setTimeout` cannot rescue this — the call blocks the OS thread, so the timer that
/// would fire it never runs. `SO_RCVTIMEO` is a kernel-level socket option: it bounds EVERY future
/// `recvmsg` on this fd, regardless of which language issues the call, which is why setting it once
/// here — rather than threading a deadline through the FFI boundary per-call — is both correct and
/// the cheaper build.
///
/// Applies to the socket, not to one call: call ONCE after the control fd is established (accept or
/// socketpair), before the accept loop starts. Uses the `libc` crate's per-platform `timeval`
/// layout rather than hand-rolling the struct over FFI from TS — `timeval` is NOT byte-identical
/// between Linux and macOS (padding differs), and getting that wrong from raw `bun:ffi` bytes would
/// silently corrupt the timeout rather than fail loudly.
///
/// A `recvmsg` that times out returns `-1` with `errno = EAGAIN` (`EWOULDBLOCK` on macOS, a distinct
/// value there) — `recv_conn_fd` already propagates that via `io::Error::last_os_error()`, so no
/// change to the receive path itself is needed. The CALLER (the accept loop, TS-side) is what must
/// treat that specific errno as an IDLE TICK rather than a receive fault; this function only makes
/// the tick possible.
/// Clear `O_NONBLOCK` on `control` — the load-bearing flag fix a `dup`'d control fd needs on BOTH ends.
///
/// The prod control fd is `dup()`'d from a libuv/Bun socket (duplicated on the TS side), and `dup` SHARES the open
/// file description, so it inherits libuv's `O_NONBLOCK`. On a non-blocking fd a BLOCKING syscall returns
/// EAGAIN IMMEDIATELY:
///   - RECV side: `recvmsg` + `SO_RCVTIMEO` becomes a HOT SPIN (measured at ~4,700
///     EAGAIN/sec instead of one tick per timeout).
///   - SEND side: `sendmsg` EAGAINs under any send-buffer back-pressure, and `send_conn_fd` neither retries
///     nor keeps the guest connection — so a handoff is dropped and C lost.
///
/// The recv side cleared this via [`set_recv_timeout`]; the send side did not — this helper is now the
/// single source both call, so the two ends cannot drift.
///
/// Idempotent: an already-blocking fd is left unchanged. Why here and not TS: `bun:ffi` cannot call the
/// VARIADIC `fcntl(F_SETFL, ...)` — the flags arg lands in a register the variadic callee never reads, so
/// it silently no-ops (measured). Rust's `libc::fcntl` is variadic-correct,
/// and `libc::O_NONBLOCK` is the per-platform value (0o4000 Linux / 0x4 macOS).
fn clear_nonblock(control: BorrowedFd<'_>) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(control.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_NONBLOCK != 0 {
        let rc = unsafe {
            libc::fcntl(
                control.as_raw_fd(),
                libc::F_SETFL,
                flags & !libc::O_NONBLOCK,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn set_recv_timeout(control: BorrowedFd<'_>, timeout: std::time::Duration) -> io::Result<()> {
    // CLEAR O_NONBLOCK FIRST — the load-bearing half of the EAGAIN-flood fix (see `clear_nonblock`). A
    // timed BLOCKING recv is only blocking if the fd is blocking, so clearing the flag is part of "set the
    // receive timeout", not a separate concern.
    clear_nonblock(control)?;
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as _,
    };
    // SAFETY: `tv` is a valid, fully-initialised `timeval`; `control` is a valid fd for the
    // lifetime of this call. `setsockopt` copies the option value, so no aliasing survives the call.
    let rc = unsafe {
        libc::setsockopt(
            control.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// C ABI for the Bun/TS gate dispatcher (loaded via `bun:ffi`). The dispatcher is
// the SEND side; the recv side is the executor, which links the rlib directly. Kept minimal + fail-closed.
// ---------------------------------------------------------------------------

/// Set the receive timeout on `control_fd` — see [`set_recv_timeout`]. Returns 0 on success, a
/// negative errno-style code on failure. `timeout_ms == 0` is REJECTED (`-EINVAL`), not treated as
/// "no timeout": a silent zero would restore the original unbounded-block hazard invisibly, and a
/// caller that means "no timeout" should not call this function at all rather than pass a sentinel.
///
/// A NEW SYMBOL, NOT A NEW PARAMETER ON AN EXISTING ONE — deliberate, matching the usual ABI discipline: both `firelock_fd_handoff_send` and
/// `firelock_fd_handoff_recv` are `dlopen`'d at MODULE LOAD by two independent processes (dispatcher,
/// executor), so changing either signature is a version-skew hazard between them. Adding a symbol
/// neither loads is zero-risk to both.
///
/// # Safety
/// `control_fd` must be a valid open descriptor.
#[no_mangle]
pub unsafe extern "C" fn firelock_fd_set_recv_timeout(control_fd: c_int, timeout_ms: u32) -> c_int {
    if timeout_ms == 0 {
        return -(libc::EINVAL);
    }
    let control = BorrowedFd::borrow_raw(control_fd);
    match set_recv_timeout(control, std::time::Duration::from_millis(timeout_ms as u64)) {
        Ok(()) => 0,
        Err(e) => -(e.raw_os_error().unwrap_or(libc::EIO)),
    }
}

/// Clear `O_NONBLOCK` on `control_fd` — the SEND-side analog of the recv-side clear inside
/// [`set_recv_timeout`]. The DISPATCHER send fd is `dup`'d from a libuv/Bun socket and inherits
/// `O_NONBLOCK`, but nothing cleared it — so `send_conn_fd`'s single non-retrying `sendmsg` EAGAINs under
/// back-pressure and the handoff (and guest connection) is lost. The
/// dispatcher calls this ONCE at seam setup so its `sendmsg` BLOCKS like the recv side, restoring symmetry.
/// Returns 0 on success, a negative errno-style code on failure. Idempotent (an already-blocking fd is a
/// success no-op). A NEW symbol, not a signature change — same ABI-skew discipline as `set_recv_timeout`.
///
/// # Safety
/// `control_fd` must be a valid open descriptor.
#[no_mangle]
pub unsafe extern "C" fn firelock_fd_clear_nonblock(control_fd: c_int) -> c_int {
    let control = BorrowedFd::borrow_raw(control_fd);
    match clear_nonblock(control) {
        Ok(()) => 0,
        Err(e) => -(e.raw_os_error().unwrap_or(libc::EIO)),
    }
}

/// Send handoff over `control_fd`, passing `conn_fd`, with `payload_len` bytes at
/// `payload_ptr`. Returns 0 on success, or a negative errno-style code. The
/// caller (dispatcher) MUST NOT continue to use `conn_fd` afterward — ownership
/// transferred; this function closes the sender's copy on **every** path,
/// including the early input-validation errors (so the bun:ffi dispatcher never
/// leaks `conn_fd`).
///
/// # Safety
/// `payload_ptr` must point to `payload_len` readable bytes; `conn_fd` and
/// `control_fd` must be valid open descriptors.
#[no_mangle]
pub unsafe extern "C" fn firelock_fd_handoff_send(
    control_fd: c_int,
    conn_fd: c_int,
    payload_ptr: *const u8,
    payload_len: usize,
) -> c_int {
    // Take ownership up front so `conn_fd` is closed on EVERY return path — the
    // "always closes the sender's copy" contract holds even for a null payload.
    let conn = OwnedFd::from_raw_fd(conn_fd);
    if payload_ptr.is_null() {
        drop(conn);
        return -(libc::EINVAL);
    }
    let control = BorrowedFd::borrow_raw(control_fd);
    let payload = std::slice::from_raw_parts(payload_ptr, payload_len);
    match send_conn_fd(control, conn, payload) {
        Ok(()) => 0,
        Err(e) => -(e.raw_os_error().unwrap_or(libc::EIO)),
    }
}

/// Receive a handoff on `control_fd` (the executor side). Copies up to
/// `payload_cap` payload bytes into `payload_out`, writes the actual length to
/// `*payload_len_out`, and RETURNS the received connection fd `C` (>= 0) — the C
/// caller now owns it and must close it. Returns a negative errno-style code on
/// failure (including the exactly-one-fd / MSG_CTRUNC fail-closed guards). If the
/// payload would not fit in `payload_cap` the received fd is closed and `-ENOSPC`
/// returned (callers pass a MAX_PAYLOAD-sized buffer, so this never fires in
/// practice — but never silently truncate the digest preimage's sibling bytes).
///
/// # Safety
/// `payload_out` must point to `payload_cap` writable bytes; `payload_len_out`
/// must point to a writable `usize`; `control_fd` must be a valid open descriptor.
#[no_mangle]
pub unsafe extern "C" fn firelock_fd_handoff_recv(
    control_fd: c_int,
    payload_out: *mut u8,
    payload_cap: usize,
    payload_len_out: *mut usize,
) -> c_int {
    use std::os::fd::IntoRawFd;
    if payload_out.is_null() || payload_len_out.is_null() {
        return -(libc::EINVAL);
    }
    let control = BorrowedFd::borrow_raw(control_fd);
    match recv_conn_fd(control) {
        Ok(handoff) => {
            if handoff.payload.len() > payload_cap {
                // handoff.conn (OwnedFd) drops here → closed. No truncation.
                return -(libc::ENOSPC);
            }
            std::ptr::copy_nonoverlapping(
                handoff.payload.as_ptr(),
                payload_out,
                handoff.payload.len(),
            );
            *payload_len_out = handoff.payload.len();
            handoff.conn.into_raw_fd() // ownership transferred to the C caller
        }
        Err(e) => -(e.raw_os_error().unwrap_or(libc::EIO)),
    }
}

/// Demuxing recv for the trusted control channel — a NEW symbol (ABI-skew discipline: no signature change
/// to `firelock_fd_handoff_recv`). Returns **1** = a handoff (the guest conn fd is written to `*fd_out`, payload
/// filled), **0** = a data frame (no fd, `*fd_out = -1`, payload filled), or a **negative errno** on
/// error. The executor's accept loop calls this instead of `firelock_fd_handoff_recv` to demux handoff vs data frame by
/// fd-presence — the boundary being that a data-frame entry is reachable ONLY over this trusted control connection, and the
/// fd-passing guards (CLOEXEC / MSG_CTRUNC-reject / fd-exhaustion-bound) are enforced in `recv_control_frame`.
///
/// # Safety
/// `control_fd` must be valid; `payload_out`/`payload_len_out`/`fd_out` must be valid writable pointers.
#[no_mangle]
pub unsafe extern "C" fn firelock_control_recv(
    control_fd: c_int,
    payload_out: *mut u8,
    payload_cap: usize,
    payload_len_out: *mut usize,
    fd_out: *mut c_int,
) -> c_int {
    use std::os::fd::IntoRawFd;
    if payload_out.is_null() || payload_len_out.is_null() || fd_out.is_null() {
        return -(libc::EINVAL);
    }
    let control = BorrowedFd::borrow_raw(control_fd);
    match recv_control_frame(control) {
        Ok(frame) => {
            if frame.payload.len() > payload_cap {
                // frame.conn (if Some) drops here → closed. No truncation.
                return -(libc::ENOSPC);
            }
            std::ptr::copy_nonoverlapping(frame.payload.as_ptr(), payload_out, frame.payload.len());
            *payload_len_out = frame.payload.len();
            match frame.conn {
                Some(conn) => {
                    *fd_out = conn.into_raw_fd(); // ownership transferred to the C caller
                    1 // handoff
                }
                None => {
                    *fd_out = -1;
                    0 // data frame
                }
            }
        }
        Err(e) => -(e.raw_os_error().unwrap_or(libc::EIO)),
    }
}

/// Write ALL `len` bytes of `buf` to `fd` (the executor's `writeResult`/`writeRefusal`
/// on the handed-off connection `C`). Loops on partial writes / `EINTR`. Returns the
/// byte count written (== `len` on success) or a negative errno-style code.
///
/// **RAW write — NO framing, NO re-encode.** The executor frames the response; this
/// moves exactly those bytes to `C` verbatim. That is what keeps the byte path
/// non-interposed: the transport never buffers,
/// re-frames, or proxies — it symmetrically writes the fd it recv'd, keeping the whole
/// fd lifecycle (recv → write → close) in one lane.
///
/// # Safety
/// `buf` must point to `len` readable bytes; `fd` must be a valid open descriptor.
#[no_mangle]
pub unsafe extern "C" fn firelock_fd_write(fd: c_int, buf: *const u8, len: usize) -> isize {
    if buf.is_null() {
        return -(libc::EINVAL as isize);
    }
    let mut written: usize = 0;
    while written < len {
        let n = libc::write(fd, buf.add(written) as *const libc::c_void, len - written);
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue; // interrupted before any byte moved — retry
            }
            return -(e.raw_os_error().unwrap_or(libc::EIO) as isize);
        }
        if n == 0 {
            break; // peer closed / no progress — return the short count
        }
        written += n as usize;
    }
    written as isize
}

/// Close a handed-off fd `C` (the executor's `close`, after writing the result).
/// Returns 0 on success or a negative errno-style code. The executor owns `C` after
/// `firelock_fd_handoff_recv` (sole owner — structural single-use), so this is the one
/// close of that fd.
///
/// # Safety
/// `fd` must be a valid open descriptor the caller owns.
#[no_mangle]
pub unsafe extern "C" fn firelock_fd_close(fd: c_int) -> c_int {
    if libc::close(fd) < 0 {
        return -(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO));
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    /// Build a host-internal control-socket pair standing in for the
    /// dispatcher⇄executor channel.
    fn control_pair() -> (UnixStream, UnixStream) {
        UnixStream::pair().unwrap()
    }

    #[test]
    fn passes_an_fd_and_the_receiver_can_use_it() {
        let (disp, exec) = control_pair();
        // `C` stand-in: a UnixStream pair. We hand one end across; the other end
        // is our "guest".
        let (guest_side, conn_side) = control_pair();

        // Dispatcher sends conn_side's fd + a receipt payload, then its copy closes.
        let receipt = b"receipt-bytes";
        send_conn_fd(disp.as_fd(), OwnedFd::from(conn_side), receipt).unwrap();

        // Executor receives the fd + payload.
        let handoff = recv_conn_fd(exec.as_fd()).unwrap();
        assert_eq!(handoff.payload, receipt);

        // The received fd is a live connection to the guest side: writing on it is
        // read by the guest end. Proves the executor owns a working `C`.
        let mut received = UnixStream::from(handoff.conn);
        received.write_all(b"result").unwrap();
        drop(received);

        let mut got = Vec::new();
        let mut guest = guest_side;
        guest.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"result");
    }

    #[test]
    fn sender_close_does_not_kill_the_connection_receiver_is_sole_owner() {
        let (disp, exec) = control_pair();
        let (guest_side, conn_side) = control_pair();

        // After send, the sender's copy of `C` is dropped (closed). If that were
        // the ONLY owner, the guest side would see EOF. It must NOT — the executor
        // now holds the sole live reference.
        send_conn_fd(disp.as_fd(), OwnedFd::from(conn_side), b"r").unwrap();

        let handoff = recv_conn_fd(exec.as_fd()).unwrap();

        // Guest writes; the executor's received fd reads it — the connection is
        // alive solely through the handed-off fd.
        let mut guest = guest_side;
        guest.write_all(b"ping").unwrap();
        drop(guest);

        let mut received = UnixStream::from(handoff.conn);
        let mut got = Vec::new();
        received.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"ping");
    }

    #[test]
    fn received_fd_is_cloexec() {
        let (disp, exec) = control_pair();
        let (_guest, conn_side) = control_pair();
        send_conn_fd(disp.as_fd(), OwnedFd::from(conn_side), b"r").unwrap();
        let handoff = recv_conn_fd(exec.as_fd()).unwrap();
        let flags = unsafe { libc::fcntl(handoff.conn.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
    }

    #[test]
    fn empty_payload_is_rejected() {
        let (disp, _exec) = control_pair();
        let (_g, conn_side) = control_pair();
        let err = send_conn_fd(disp.as_fd(), OwnedFd::from(conn_side), b"").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// TEST-ONLY: send `fds` (one or more) as a single SCM_RIGHTS cmsg — models a
    /// compromised dispatcher smuggling extra fds. Uses the crate's aligned
    /// `CmsgBuf` (64 B holds up to ~12 fds).
    unsafe fn send_raw_fds(control: RawFd, payload: &[u8], fds: &[RawFd]) {
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };
        let mut cmsg = CmsgBuf::zeroed();
        let n = fds.len() * mem::size_of::<c_int>();
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.bytes.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = libc::CMSG_SPACE(n as u32) as _;
        let hdr = libc::CMSG_FIRSTHDR(&msg);
        (*hdr).cmsg_level = libc::SOL_SOCKET;
        (*hdr).cmsg_type = libc::SCM_RIGHTS;
        (*hdr).cmsg_len = libc::CMSG_LEN(n as u32) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr() as *const u8, libc::CMSG_DATA(hdr), n);
        let r = libc::sendmsg(control, &msg, 0);
        assert!(r >= 0, "sendmsg failed: {}", io::Error::last_os_error());
    }

    #[test]
    fn more_than_one_fd_is_rejected_and_extras_closed() {
        // A hostile dispatcher attaches THREE fds in one SCM_RIGHTS cmsg. recv must
        // refuse (exactly-one guard) and close every smuggled fd — none may survive
        // in the executor's fd table.
        let (disp, exec) = control_pair();
        let (_a1, a) = control_pair();
        let (_b1, b) = control_pair();
        let (_c1, c) = control_pair();
        unsafe {
            send_raw_fds(
                disp.as_raw_fd(),
                b"smuggle",
                &[a.as_raw_fd(), b.as_raw_fd(), c.as_raw_fd()],
            );
        }
        let err = recv_conn_fd(exec.as_fd()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("more than one fd"));
        // a/b/c are still owned by this test process; the duped copies the kernel
        // installed into the receiver were closed by the guard (no leak).
    }

    #[test]
    fn control_frame_data_frame_yields_no_fd() {
        // A data frame: plain bytes, NO SCM_RIGHTS fd. recv_control_frame must classify it as a
        // data frame (conn == None) and return the payload verbatim — this is the fd-presence demux.
        let (disp, exec) = control_pair();
        let mut d = disp;
        d.write_all(b"data-frame-body").unwrap();
        let frame = recv_control_frame(exec.as_fd()).unwrap();
        assert!(
            frame.conn.is_none(),
            "a no-fd frame must be a DATA frame (None)"
        );
        assert_eq!(frame.payload, b"data-frame-body");
    }

    #[test]
    fn control_frame_handoff_yields_fd_with_cloexec() {
        // A handoff: one SCM_RIGHTS fd. recv_control_frame must classify it as a handoff (conn == Some),
        // return the payload, and the received fd must be CLOEXEC (no leak across exec()).
        let (disp, exec) = control_pair();
        let (_guest, conn_side) = control_pair();
        send_conn_fd(disp.as_fd(), OwnedFd::from(conn_side), b"receipt").unwrap();
        let frame = recv_control_frame(exec.as_fd()).unwrap();
        let conn = frame.conn.expect("a one-fd frame must be a handoff (Some)");
        assert_eq!(frame.payload, b"receipt");
        let flags = unsafe { libc::fcntl(conn.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            flags & libc::FD_CLOEXEC,
            libc::FD_CLOEXEC,
            "received fd must be CLOEXEC"
        );
    }

    #[test]
    fn control_frame_rejects_multiple_fds_fd_exhaustion() {
        // fd-exhaustion guard: a hostile dispatcher attaches TWO fds on the trusted channel.
        // recv_control_frame must refuse (>1 fd) and close every smuggled fd — same bound as recv_conn_fd.
        let (disp, exec) = control_pair();
        let (_a1, a) = control_pair();
        let (_b1, b) = control_pair();
        unsafe {
            send_raw_fds(
                disp.as_raw_fd(),
                b"smuggle",
                &[a.as_raw_fd(), b.as_raw_fd()],
            );
        }
        let err = recv_control_frame(exec.as_fd()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("more than one fd"));
    }

    /// TEST-ONLY: send `fds` in one SCM_RIGHTS cmsg using a HEAP control buffer sized for ANY count —
    /// unlike `send_raw_fds` (fixed 64 B `CmsgBuf`, ~12 fds max), this lets a test attach MORE fds than
    /// the RECEIVER's fixed 64 B control buffer (`recvmsg_gather_fds`, line ~161) can hold, so the kernel
    /// TRUNCATES the ancillary data and sets `MSG_CTRUNC`. The backing is `Vec<u64>` for 8-byte alignment
    /// (cmsghdr alignment on 64-bit).
    unsafe fn send_raw_fds_oversized(control: RawFd, payload: &[u8], fds: &[RawFd]) {
        let n = fds.len() * mem::size_of::<c_int>();
        let space = libc::CMSG_SPACE(n as u32) as usize;
        let mut backing = vec![0u64; space.div_ceil(8)];
        let mut iov = libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        };
        let mut msg: libc::msghdr = mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = backing.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;
        let hdr = libc::CMSG_FIRSTHDR(&msg);
        (*hdr).cmsg_level = libc::SOL_SOCKET;
        (*hdr).cmsg_type = libc::SCM_RIGHTS;
        (*hdr).cmsg_len = libc::CMSG_LEN(n as u32) as _;
        std::ptr::copy_nonoverlapping(fds.as_ptr() as *const u8, libc::CMSG_DATA(hdr), n);
        let r = libc::sendmsg(control, &msg, 0);
        assert!(r >= 0, "sendmsg failed: {}", io::Error::last_os_error());
    }

    #[test]
    fn control_frame_rejects_truncated_control_message_msg_ctrunc() {
        // Boundary integrity — the ctrunc guard.
        // A sender attaches MORE fds than the receiver's fixed 64 B control buffer can hold (16 fds →
        // CMSG_SPACE(64 B) = 80 B > 64), so the kernel truncates the ancillary payload, sets MSG_CTRUNC,
        // and installs only a PARTIAL fd set. recv_control_frame must fail closed NAMING the truncation
        // (not the fd-exhaustion bound) and close every partially-installed fd.
        //
        // WHY THIS GOES RED WHEN THE GUARD IS REMOVED: neuter `ctrunc` (→ false) and this frame no longer
        // reports "truncated" — the ~12 fds that fit fall to the `received_fds.len() > 1` branch and the
        // message becomes "more than one fd", so the assert below fails. The two guards are NOT redundant:
        // a truncation that happens to deliver ≤1 fd would slip the count guard entirely — ctrunc is the
        // only thing that rejects a tampered/partial SCM_RIGHTS message whose surviving fd count looks legal.
        let (disp, exec) = control_pair();
        // 16 real, distinct fds to smuggle — dup a throwaway fd rather than open 16 socketpairs.
        let (_keep0, keep1) = control_pair();
        let base = keep1.as_raw_fd();
        let mut dups: Vec<RawFd> = Vec::new();
        for _ in 0..16 {
            let d = unsafe { libc::dup(base) };
            assert!(d >= 0, "dup failed: {}", io::Error::last_os_error());
            dups.push(d);
        }
        unsafe { send_raw_fds_oversized(disp.as_raw_fd(), b"truncate-me", &dups) };

        let err = recv_control_frame(exec.as_fd()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("truncated") && err.to_string().contains("MSG_CTRUNC"),
            "ctrunc reject must name the truncation (not the fd-exhaustion bound), got: {err}"
        );
        // Close the sender-side dups we still own; the receiver-side partial copies were closed by the guard.
        for d in dups {
            unsafe { libc::close(d) };
        }
    }

    #[test]
    fn exactly_one_fd_still_passes_after_the_guard() {
        // Regression guard: the count check must not break the happy path.
        let (disp, exec) = control_pair();
        let (guest, conn_side) = control_pair();
        unsafe { send_raw_fds(disp.as_raw_fd(), b"one", &[conn_side.as_raw_fd()]) };
        // send_raw_fds BORROWS the fd (unlike send_conn_fd), so drop the sender's
        // copy now — otherwise it stays a second writer and the guest's read_to_end
        // never sees EOF. This mirrors the real "dispatcher closes its copy" step.
        drop(conn_side);
        let handoff = recv_conn_fd(exec.as_fd()).unwrap();
        assert_eq!(handoff.payload, b"one");
        // usable connection to the guest side
        let mut received = UnixStream::from(handoff.conn);
        received.write_all(b"ok").unwrap();
        drop(received);
        let mut got = Vec::new();
        let mut g = guest;
        g.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"ok");
    }

    #[test]
    fn message_without_an_fd_fails_closed() {
        // A plain write on the control socket (no SCM_RIGHTS) must NOT be accepted
        // as a handoff — recv must refuse it rather than return a fd-less Handoff.
        let (mut disp, exec) = control_pair();
        disp.write_all(b"no fd here").unwrap();
        let err = recv_conn_fd(exec.as_fd()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn write_primitive_moves_bytes_verbatim_then_close_signals_eof() {
        use std::os::fd::IntoRawFd;
        // `C` stand-in: the executor holds `conn` (raw fd), the peer is the guest.
        let (guest_side, conn_side) = control_pair();
        let conn_fd = OwnedFd::from(conn_side).into_raw_fd();

        // writeResult: raw, byte-verbatim, writes ALL bytes.
        let result = b"framed-result-bytes";
        let n = unsafe { firelock_fd_write(conn_fd, result.as_ptr(), result.len()) };
        assert_eq!(n, result.len() as isize);

        // close: the executor's sole close of `C`.
        assert_eq!(unsafe { firelock_fd_close(conn_fd) }, 0);

        // The guest reads EXACTLY those bytes, then EOF from the close — proves
        // non-interposed write + that close is the lifecycle terminus.
        let mut guest = guest_side;
        let mut got = Vec::new();
        guest.read_to_end(&mut got).unwrap();
        assert_eq!(got, result);
    }

    #[test]
    fn write_to_a_closed_peer_fails_closed_not_silently() {
        use std::os::fd::IntoRawFd;
        let (guest_side, conn_side) = control_pair();
        let conn_fd = OwnedFd::from(conn_side).into_raw_fd();
        drop(guest_side); // peer gone → writes must EPIPE, never silently "succeed"

        // SIGPIPE would kill the process; the crate must have it disabled/ignored
        // for the write to return -EPIPE. Assert the negative errno path.
        let rc = unsafe { firelock_fd_write(conn_fd, b"x".as_ptr(), 1) };
        assert!(
            rc < 0,
            "write to a closed peer must return a negative errno, got {rc}"
        );
        unsafe {
            let _ = firelock_fd_close(conn_fd);
        }
    }

    #[test]
    fn write_rejects_null_buffer() {
        assert_eq!(
            unsafe { firelock_fd_write(-1, std::ptr::null(), 8) },
            -(libc::EINVAL as isize)
        );
    }

    // ── The receive-timeout bound itself ──────────────────────────────────────

    /// Run `f` on a scratch thread and enforce `bound` as a WALL-CLOCK CEILING on the test itself.
    ///
    /// FOUND WHILE BUILDING, NOT REASONED IN ADVANCE: mutating `SO_RCVTIMEO` away (the exact
    /// regression these tests exist to catch) does not fail the test below — it makes `recv_conn_fd`
    /// block forever, and the test process HANGS rather than going red. Measured: `cargo test` on
    /// the mutated tree produced zero output and had to be killed after 120s. A test that hangs
    /// under the regression it is meant to catch is a worse CI citizen than one that goes red,
    /// because it stalls the whole pipeline rather than reporting a failure — the same "clean red
    /// vs. hang" distinction applies to the TS-side tests for this same defect.
    ///
    /// The watchdog does not weaken the property under test: on the CORRECT tree `f` returns well
    /// inside `bound` every time (proven by the passing runs below), so the timeout never fires on
    /// green. It only converts "the fix regressed" from a silent CI hang into a named panic.
    fn bounded<F: FnOnce() + Send + 'static>(bound: std::time::Duration, f: F) {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            f();
            let _ = tx.send(());
        });
        rx.recv_timeout(bound)
            .expect("test body did not return within the watchdog bound — recv_conn_fd is likely blocking with no timeout applied (the exact regression this test exists to catch)");
    }

    #[test]
    fn recv_with_timeout_returns_eagain_on_an_idle_channel_instead_of_blocking_forever() {
        use std::time::Duration;
        bounded(Duration::from_secs(2), || {
            use std::time::Instant;
            let (_disp, exec) = control_pair();
            // Nobody ever sends on `_disp`'s peer — this is the wedge shape, deliberately: an idle
            // channel with no handoff arriving. Before this fix `recv_conn_fd` would block here for the
            // life of the test process; the assertion below is that it returns instead, in bounded time.
            set_recv_timeout(exec.as_fd(), Duration::from_millis(100)).unwrap();

            let t0 = Instant::now();
            let err =
                recv_conn_fd(exec.as_fd()).expect_err("an idle channel must not yield a Handoff");
            let elapsed = t0.elapsed();

            // THE CLAIM THAT MATTERS: it returned AT ALL, and did so close to the configured bound —
            // not instantly (which would mean the timeout was ignored and something else errored) and
            // not after a long multiple of it (which would mean the retry/backoff shape is wrong).
            assert!(
                elapsed < Duration::from_millis(500),
                "took {elapsed:?}, timeout should bound this near 100ms"
            );
            assert!(elapsed >= Duration::from_millis(50), "returned in {elapsed:?}, suspiciously before the 100ms bound — is the timeout being applied at all?");

            // AND THE ERRNO IS THE LOAD-BEARING OBSERVABLE. The TS-side accept loop distinguishes
            // "idle, try again" from "something is actually wrong" SOLELY by this errno — get it wrong
            // here and either every idle tick reads as a fault (defeating the whole point) or a genuine
            // fault reads as idle (silently swallowing a real failure).
            let errno = err.raw_os_error();
            #[cfg(target_os = "linux")]
            assert_eq!(
                errno,
                Some(libc::EAGAIN),
                "expected EAGAIN on Linux, got {errno:?}"
            );
            #[cfg(target_os = "macos")]
            assert_eq!(
                errno,
                Some(libc::EWOULDBLOCK),
                "expected EWOULDBLOCK on macOS, got {errno:?}"
            );
        });
    }

    #[test]
    fn recv_with_timeout_still_receives_a_real_handoff_within_the_bound() {
        // THE POSITIVE CONTROL. Without this, the test above could pass for a channel that
        // NEVER receives ANYTHING once timeout is set — e.g. a mistake that shuts the fd instead of
        // bounding it would also produce a fast, errno-bearing failure. This proves the timeout does
        // not break the real path: a handoff sent well within the bound still arrives intact.
        use std::time::Duration;
        let (disp, exec) = control_pair();
        let (guest_side, conn_side) = control_pair();
        set_recv_timeout(exec.as_fd(), Duration::from_secs(5)).unwrap();

        let receipt = b"receipt-bytes";
        send_conn_fd(disp.as_fd(), OwnedFd::from(conn_side), receipt).unwrap();

        let handoff = recv_conn_fd(exec.as_fd())
            .expect("a real handoff must still arrive under a generous timeout");
        assert_eq!(handoff.payload, receipt);
        drop(guest_side);
    }

    #[test]
    fn set_recv_timeout_rejects_a_bad_fd() {
        // CAUGHT BY RUNNING, NOT BY REASONING: the first version of this test passed -1 to
        // `BorrowedFd::borrow_raw`, which the standard library itself forbids (`fd != -1` is one of
        // its own safety invariants, enforced even in a release build here) — the test PANICKED
        // rather than exercising `set_recv_timeout` at all. -1 is not a "bad fd" as far as this
        // function is concerned; it is a value the safe wrapper refuses to represent. A genuinely
        // bad-but-representable fd is a large number almost certainly never open in this process.
        let never_open: RawFd = 999_999;
        let bad = unsafe { BorrowedFd::borrow_raw(never_open) };
        assert!(set_recv_timeout(bad, std::time::Duration::from_millis(100)).is_err());
    }

    #[test]
    fn set_recv_timeout_clears_o_nonblock_so_the_timeout_actually_paces_the_recv() {
        // Root cause of the EAGAIN spin. The prod control fd is `dup()`'d from a libuv socket, which shares the
        // open file description → it inherits O_NONBLOCK. On a non-blocking fd `recvmsg` returns EAGAIN
        // IMMEDIATELY and SO_RCVTIMEO is ignored, so the accept loop's "idle tick" became a ~4,700/sec
        // spin. A timed BLOCKING recv is only blocking if the fd is blocking, so
        // set_recv_timeout must clear O_NONBLOCK. (A socketpair fd is blocking by default, so force it
        // non-blocking first to model the dup'd libuv fd.)
        use std::os::fd::AsRawFd;
        let (_disp, exec) = control_pair();
        let fd = exec.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(flags >= 0, "F_GETFL failed");
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0,
            "F_SETFL(O_NONBLOCK) failed"
        );
        assert!(
            unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK != 0,
            "precondition: the fd is non-blocking (as the libuv dup would be)"
        );

        set_recv_timeout(exec.as_fd(), std::time::Duration::from_millis(100)).unwrap();

        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK,
            0,
            "set_recv_timeout MUST clear O_NONBLOCK — else SO_RCVTIMEO is ignored and recvHandoff spins EAGAIN"
        );
    }

    #[test]
    fn clear_nonblock_clears_the_flag_and_is_idempotent() {
        // The SEND-side symmetry fix. The dispatcher send fd is a libuv `dup` = O_NONBLOCK set;
        // without this clear `send_conn_fd`'s single non-retrying `sendmsg` EAGAINs under back-pressure and
        // drops the guest connection. Model the dup'd fd (force non-blocking), clear, assert blocking.
        use std::os::fd::AsRawFd;
        let (disp, _exec) = control_pair();
        let fd = disp.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(flags >= 0, "F_GETFL failed");
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0,
            "F_SETFL(O_NONBLOCK) failed"
        );
        assert!(
            unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK != 0,
            "precondition: non-blocking (as the libuv dup would be)"
        );

        clear_nonblock(disp.as_fd()).unwrap();
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK,
            0,
            "clear_nonblock MUST clear O_NONBLOCK on the send fd"
        );

        // Idempotent — clearing an already-blocking fd is a success no-op, not an error.
        clear_nonblock(disp.as_fd()).unwrap();
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK,
            0
        );
    }

    #[test]
    fn ffi_clear_nonblock_export_is_zero_on_success_and_negative_on_a_bad_fd() {
        use std::os::fd::AsRawFd;
        let (disp, _exec) = control_pair();
        assert_eq!(
            unsafe { firelock_fd_clear_nonblock(disp.as_raw_fd()) },
            0,
            "success ⇒ 0"
        );
        let never_open: RawFd = 999_999;
        assert!(
            unsafe { firelock_fd_clear_nonblock(never_open) } < 0,
            "a bad fd ⇒ negative errno (EBADF)"
        );
    }

    #[test]
    fn ffi_export_rejects_zero_timeout_rather_than_treating_it_as_unbounded() {
        // A caller that means "no timeout" must not call this function; a 0 argument is refused
        // rather than silently restoring the unbounded-block hazard this whole fix exists to close.
        assert_eq!(
            unsafe { firelock_fd_set_recv_timeout(-1, 0) },
            -(libc::EINVAL)
        );
    }

    #[test]
    fn ffi_export_sets_a_real_timeout_end_to_end() {
        use std::time::Duration;
        bounded(Duration::from_secs(2), || {
            use std::os::fd::IntoRawFd;
            use std::time::Instant;
            let (_disp, exec) = control_pair();
            let exec_fd = OwnedFd::from(exec).into_raw_fd();

            assert_eq!(unsafe { firelock_fd_set_recv_timeout(exec_fd, 80) }, 0);

            let control = unsafe { BorrowedFd::borrow_raw(exec_fd) };
            let t0 = Instant::now();
            assert!(recv_conn_fd(control).is_err());
            assert!(
                t0.elapsed() < Duration::from_millis(400),
                "the FFI export must apply the same bound as the Rust API"
            );

            unsafe {
                let _ = firelock_fd_close(exec_fd);
            }
        });
    }
}
