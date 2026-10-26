//! Bidirectional byte-splice between two duplex streams — the core of both the
//! invocation reverse-proxy (vsock ⇄ loopback) and the gate bridge (UDS ⇄
//! vsock). Each direction runs in its own thread; when one side reaches EOF we
//! half-close the peer's write side so it observes the end of stream, then wait
//! for the other direction to drain.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::thread;

/// A stream k9o-init can splice: readable, writable, cloneable into an
/// independent handle (so the two directions can run concurrently), and
/// half-closeable (to propagate EOF). Object-safe on purpose.
pub trait Duplex: Read + Write + Send {
    /// A second independent handle to the same underlying stream.
    fn clone_handle(&self) -> io::Result<Box<dyn Duplex>>;
    /// Shut down the write half, so the peer reading from it sees EOF.
    fn shutdown_write(&self) -> io::Result<()>;
}

impl Duplex for TcpStream {
    fn clone_handle(&self) -> io::Result<Box<dyn Duplex>> {
        Ok(Box::new(self.try_clone()?))
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

impl Duplex for UnixStream {
    fn clone_handle(&self) -> io::Result<Box<dyn Duplex>> {
        Ok(Box::new(self.try_clone()?))
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
}

/// Copy bytes both ways between `a` and `b` until both directions reach EOF.
/// Consumes both streams. Returns once both copy directions have finished.
pub fn splice_bidirectional(a: Box<dyn Duplex>, b: Box<dyn Duplex>) -> io::Result<()> {
    // Two independent handles per stream: one reader + one writer each.
    let mut a_read = a;
    let a_write = a_read.clone_handle()?;
    let mut b_read = b;
    let b_write = b_read.clone_handle()?;

    // a → b in a worker thread.
    let t = thread::spawn(move || {
        let mut b_write = b_write;
        let _ = io::copy(&mut *a_read, &mut b_write);
        let _ = b_write.shutdown_write();
    });

    // b → a on this thread.
    let mut a_write = a_write;
    let _ = io::copy(&mut *b_read, &mut a_write);
    let _ = a_write.shutdown_write();

    // Wait for the other direction so neither socket is dropped mid-copy.
    let _ = t.join();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // A UnixStream pair models one connection end; two pairs let us wire
    // client ⇄ [splice] ⇄ backend and drive both ends from the test.
    #[test]
    fn splices_bytes_both_directions_then_eofs() {
        // "client" side: test holds `client_ext`, splice holds `client_int`.
        let (client_ext, client_int) = UnixStream::pair().unwrap();
        // "backend" side: test holds `backend_ext`, splice holds `backend_int`.
        let (backend_ext, backend_int) = UnixStream::pair().unwrap();

        let splicer = thread::spawn(move || {
            splice_bidirectional(Box::new(client_int), Box::new(backend_int)).unwrap();
        });

        // client → backend
        {
            let mut c = client_ext.try_clone().unwrap();
            c.write_all(b"POST /invoke HTTP/1.1\r\n\r\nhello").unwrap();
            c.shutdown(std::net::Shutdown::Write).unwrap();
        }
        // backend reads what the client sent
        let mut got_at_backend = Vec::new();
        {
            let mut b = backend_ext.try_clone().unwrap();
            b.read_to_end(&mut got_at_backend).unwrap();
        }
        assert_eq!(got_at_backend, b"POST /invoke HTTP/1.1\r\n\r\nhello");

        // backend → client
        {
            let mut b = backend_ext;
            b.write_all(b"HTTP/1.1 200 OK\r\n\r\nresult").unwrap();
            b.shutdown(std::net::Shutdown::Write).unwrap();
        }
        let mut got_at_client = Vec::new();
        {
            let mut c = client_ext;
            c.read_to_end(&mut got_at_client).unwrap();
        }
        assert_eq!(got_at_client, b"HTTP/1.1 200 OK\r\n\r\nresult");

        splicer.join().unwrap();
    }
}
