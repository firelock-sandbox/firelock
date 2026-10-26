//! The invocation reverse-proxy. A host-initiated vsock connection carries an
//! HTTP/1.1 `POST /invoke`; k9o-init validates the request line, dials the
//! extension's own loopback invoke server, forwards the request, and splices the
//! response back. Anything else is answered with an HTTP error the host's
//! `decodeHttpResponse` can read (so a guest-side problem surfaces as a clean
//! non-2xx, never a hung vsock connection).

use crate::http::{error_response, parse_request_head, ParseResult};
use crate::splice::{splice_bidirectional, Duplex};
use std::io::{self, Read, Write};

/// Serve one host-initiated invocation connection. `dial_backend` opens a fresh
/// connection to the extension's loopback invoke server (parameterised so the
/// logic is testable without a real socket).
pub fn serve_invocation<D>(mut client: Box<dyn Duplex>, dial_backend: D) -> io::Result<()>
where
    D: FnOnce() -> io::Result<Box<dyn Duplex>>,
{
    // Read until we have a full request head (bounded inside parse_request_head).
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let head = loop {
        match parse_request_head(&buf) {
            ParseResult::Complete(h) => break h,
            ParseResult::Malformed => {
                let _ = client.write_all(&error_response(
                    400,
                    "Bad Request",
                    "K9O_INVALID_REQUEST_SHAPE",
                    "malformed HTTP request",
                ));
                return Ok(());
            }
            ParseResult::Incomplete => {
                let mut chunk = [0u8; 4096];
                let n = client.read(&mut chunk)?;
                if n == 0 {
                    // Peer closed before sending a complete head — nothing to do.
                    return Ok(());
                }
                buf.extend_from_slice(&chunk[..n]);
            }
        }
    };

    if head.method != "POST" || head.path != "/invoke" {
        let _ = client.write_all(&error_response(
            404,
            "Not Found",
            "K9O_NOT_FOUND",
            "the guest agent serves only POST /invoke",
        ));
        return Ok(());
    }

    // Dial the extension's invoke server. If it isn't up (crashed, still
    // booting, never bound), fail closed with a 503 — never hang the caller.
    let mut backend = match dial_backend() {
        Ok(b) => b,
        Err(_) => {
            let _ = client.write_all(&error_response(
                503,
                "Service Unavailable",
                "K9O_UPSTREAM_UNAVAILABLE",
                "extension invoke server is not reachable",
            ));
            return Ok(());
        }
    };

    // Hand the backend the bytes we already consumed reading the head (which may
    // include the leading body bytes), then splice the remainder both ways.
    backend.write_all(&buf)?;
    splice_bidirectional(client, backend)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::thread;

    #[test]
    fn forwards_post_invoke_and_relays_the_response() {
        let (client_ext, client_int) = UnixStream::pair().unwrap();
        // The "extension loopback server": test holds one end; dial hands the
        // proxy the other.
        let (backend_srv, backend_for_proxy) = UnixStream::pair().unwrap();

        let proxy = thread::spawn(move || {
            serve_invocation(Box::new(client_int), move || Ok(Box::new(backend_for_proxy) as Box<dyn Duplex>)).unwrap();
        });

        // Client sends the invocation.
        {
            let mut c = client_ext.try_clone().unwrap();
            c.write_all(b"POST /invoke HTTP/1.1\r\nContent-Length: 5\r\n\r\n{\"x\":1}").unwrap();
        }

        // The extension server receives the full request...
        let mut srv = backend_srv;
        let mut got = [0u8; 64];
        let n = srv.read(&mut got).unwrap();
        assert!(std::str::from_utf8(&got[..n]).unwrap().starts_with("POST /invoke HTTP/1.1"));

        // ...and replies; the reply reaches the client.
        srv.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
        srv.shutdown(std::net::Shutdown::Write).unwrap();

        let mut resp = Vec::new();
        let mut c = client_ext;
        c.read_to_end(&mut resp).unwrap();
        assert!(String::from_utf8(resp).unwrap().starts_with("HTTP/1.1 200 OK"));

        // The host closes its side once it has the response; that EOF lets the
        // request-direction of the splice finish so serve_invocation returns.
        c.shutdown(std::net::Shutdown::Write).unwrap();
        proxy.join().unwrap();
    }

    #[test]
    fn rejects_non_invoke_path_with_404() {
        let (client_ext, client_int) = UnixStream::pair().unwrap();
        let proxy = thread::spawn(move || {
            serve_invocation(Box::new(client_int), || panic!("must not dial backend")).unwrap();
        });
        {
            let mut c = client_ext.try_clone().unwrap();
            c.write_all(b"GET /health HTTP/1.1\r\n\r\n").unwrap();
        }
        let mut resp = Vec::new();
        let mut c = client_ext;
        c.read_to_end(&mut resp).unwrap();
        assert!(String::from_utf8(resp).unwrap().starts_with("HTTP/1.1 404 Not Found"));
        proxy.join().unwrap();
    }

    #[test]
    fn returns_503_when_backend_unavailable() {
        let (client_ext, client_int) = UnixStream::pair().unwrap();
        let proxy = thread::spawn(move || {
            serve_invocation(
                Box::new(client_int),
                || Err(io::Error::new(io::ErrorKind::ConnectionRefused, "down")),
            )
            .unwrap();
        });
        {
            let mut c = client_ext.try_clone().unwrap();
            c.write_all(b"POST /invoke HTTP/1.1\r\n\r\n").unwrap();
        }
        let mut resp = Vec::new();
        let mut c = client_ext;
        c.read_to_end(&mut resp).unwrap();
        let s = String::from_utf8(resp).unwrap();
        assert!(s.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(s.contains("K9O_UPSTREAM_UNAVAILABLE"));
        proxy.join().unwrap();
    }

    #[test]
    fn rejects_malformed_head_with_400() {
        let (client_ext, client_int) = UnixStream::pair().unwrap();
        let proxy = thread::spawn(move || {
            serve_invocation(Box::new(client_int), || panic!("must not dial")).unwrap();
        });
        {
            let mut c = client_ext.try_clone().unwrap();
            c.write_all(b"GARBAGE\r\n\r\n").unwrap();
        }
        let mut resp = Vec::new();
        let mut c = client_ext;
        c.read_to_end(&mut resp).unwrap();
        assert!(String::from_utf8(resp).unwrap().starts_with("HTTP/1.1 400 Bad Request"));
        proxy.join().unwrap();
    }
}
