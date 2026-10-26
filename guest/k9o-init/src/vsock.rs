//! `AF_VSOCK` sockets via raw libc syscalls. This is the only module that needs
//! `unsafe` — the Rust std library has no vsock support and neither does Bun, so
//! k9o-init owns the syscall layer. Everything here is a thin, RAII-owned fd
//! wrapper; the byte logic that uses it lives in the safe [`crate::splice`] /
//! [`crate::proxy`] modules.
//!
//! # Safety
//! Each `unsafe` block is a single libc call whose arguments are validated
//! immediately above it (fd ≥ 0, sizes from `size_of`, addresses from a zeroed
//! `sockaddr_vm`). Return values are checked against `< 0` and mapped to
//! `io::Error::last_os_error()`. Owned fds are closed exactly once on `Drop`.

use crate::splice::Duplex;
use std::io::{self, Read, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, RawFd};

/// `VMADDR_CID_ANY` — bind on any context id (the guest listening for the host).
pub const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;

/// Run a libc call that returns an `isize`, retrying on `EINTR`.
fn eintr_retry<T: PartialOrd + Default + Copy, F: FnMut() -> T>(mut f: F) -> T {
    loop {
        let r = f();
        if r < T::default() && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return r;
    }
}

fn sockaddr_vm(cid: u32, port: u32) -> libc::sockaddr_vm {
    // SAFETY: sockaddr_vm is plain-old-data; a zeroed value is a valid one.
    let mut addr: libc::sockaddr_vm = unsafe { zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_port = port;
    addr.svm_cid = cid;
    addr
}

fn new_vsock_fd() -> io::Result<RawFd> {
    // SAFETY: socket(2) with constant, checked args.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// A connected vsock stream (owned fd; closed on drop).
pub struct VsockStream {
    fd: RawFd,
}

impl VsockStream {
    /// Dial `(cid, port)` — the guest→host gate uses `(VMADDR_CID_HOST, 9000)`.
    pub fn connect(cid: u32, port: u32) -> io::Result<Self> {
        let fd = new_vsock_fd()?;
        let stream = VsockStream { fd };
        let addr = sockaddr_vm(cid, port);
        // SAFETY: `addr` is a valid sockaddr_vm of the given size; `fd` is owned.
        let rc = eintr_retry(|| unsafe {
            libc::connect(
                fd,
                &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
                size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        });
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(stream)
    }

    fn from_fd(fd: RawFd) -> Self {
        VsockStream { fd }
    }
}

impl Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: writes at most buf.len() bytes into buf's backing storage.
        let n = eintr_retry(|| unsafe {
            libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        });
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

impl Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // SAFETY: reads at most buf.len() bytes from buf.
        let n = eintr_retry(|| unsafe {
            libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len())
        });
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Duplex for VsockStream {
    fn clone_handle(&self) -> io::Result<Box<dyn Duplex>> {
        // SAFETY: dup(2) on an owned fd; the new fd is independently owned.
        let fd = unsafe { libc::dup(self.fd) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Box::new(VsockStream { fd }))
    }

    fn shutdown_write(&self) -> io::Result<()> {
        // SAFETY: shutdown(2) on an owned fd.
        let rc = unsafe { libc::shutdown(self.fd, libc::SHUT_WR) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl AsRawFd for VsockStream {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for VsockStream {
    fn drop(&mut self) {
        // SAFETY: fd is owned and closed exactly once.
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// A listening vsock socket (owned fd; closed on drop).
pub struct VsockListener {
    fd: RawFd,
}

impl VsockListener {
    /// Bind `VMADDR_CID_ANY:port` and listen — the guest side of the
    /// host-initiated invocation channel (`port = 8000`).
    pub fn bind(port: u32) -> io::Result<Self> {
        let fd = new_vsock_fd()?;
        let listener = VsockListener { fd };
        let addr = sockaddr_vm(VMADDR_CID_ANY, port);
        // SAFETY: valid sockaddr_vm + size; fd owned.
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
                size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: listen(2) on an owned, bound fd.
        let rc = unsafe { libc::listen(fd, 128) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(listener)
    }

    /// Accept the next connection. Blocks until one arrives.
    pub fn accept(&self) -> io::Result<VsockStream> {
        // SAFETY: accept(2) on an owned listening fd; null addr out-params are valid.
        let fd = eintr_retry(|| unsafe {
            libc::accept(self.fd, std::ptr::null_mut(), std::ptr::null_mut())
        });
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(VsockStream::from_fd(fd))
    }
}

impl Drop for VsockListener {
    fn drop(&mut self) {
        // SAFETY: fd is owned and closed exactly once.
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::splice::Duplex;
    use std::thread;
    use std::time::Duration;

    /// `VMADDR_CID_LOCAL` (1) — the loopback context id. A client dialing it
    /// reaches a listener on this same host, so the whole real AF_VSOCK syscall
    /// path is exercisable in one process, no MicroVM required (needs the
    /// `vsock_loopback` kernel module).
    const VMADDR_CID_LOCAL: u32 = 1;

    /// End-to-end over the REAL `AF_VSOCK` transport via the loopback CID:
    /// `VsockListener::bind` → `accept` → `read`/`write`, dialed by the crate's
    /// own `VsockStream::connect`. This is the only coverage of the unsafe
    /// syscall layer (the rest of the crate's tests are pure logic). It **skips**
    /// (does not fail) where vsock is unavailable — CI without `vsock_loopback`,
    /// seccomp sandboxes, non-Linux — so it never breaks an unrelated build.
    #[test]
    fn real_vsock_roundtrip() {
        const PORT: u32 = 8137;

        let listener = match VsockListener::bind(PORT) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("SKIP real_vsock_roundtrip: vsock bind unavailable ({e})");
                return;
            }
        };

        // Server thread: accept one connection, read the request, reply, EOF.
        let server = thread::spawn(move || {
            let mut conn = listener.accept().expect("accept");
            let mut buf = [0u8; 32];
            let n = conn.read(&mut buf).expect("server read");
            assert_eq!(&buf[..n], b"PING/vsock", "server saw wrong request");
            conn.write_all(b"PONG/vsock").expect("server write");
            conn.shutdown_write().expect("server shutdown_write"); // client sees EOF
        });

        thread::sleep(Duration::from_millis(200)); // let the listener come up

        let mut client = match VsockStream::connect(VMADDR_CID_LOCAL, PORT) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("SKIP real_vsock_roundtrip: vsock connect unavailable ({e})");
                let _ = server.join();
                return;
            }
        };
        client.write_all(b"PING/vsock").expect("client write");

        let mut resp = Vec::new();
        client.read_to_end(&mut resp).expect("client read");
        assert_eq!(resp, b"PONG/vsock", "client got wrong response over vsock");

        server.join().expect("server thread panicked");
    }
}
