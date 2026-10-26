//! Just enough HTTP/1.1 to gate the invocation reverse-proxy: read the request
//! line, and build error responses the host's `decodeHttpResponse`
//! (host vsock client) can parse. k9o-init never interprets the body — it
//! forwards the request to the extension and splices the response back — so this
//! is deliberately small (no chunked decoding, no header semantics).

/// The parsed request line + the byte offset just past the `\r\n\r\n` head
/// terminator, so the caller can forward the already-buffered head to the
/// backend before splicing the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub path: String,
    /// Number of bytes from the start of the buffer through the end of the
    /// `\r\n\r\n` head terminator.
    pub head_len: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseResult {
    /// A complete head was parsed.
    Complete(RequestHead),
    /// The head terminator hasn't arrived yet — read more bytes and retry.
    Incomplete,
    /// The bytes are not a valid HTTP/1.1 request head.
    Malformed,
}

const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Parse an HTTP/1.1 request head from `buf`. Returns [`ParseResult::Incomplete`]
/// until the full `...\r\n\r\n` terminator is present (bounded by
/// `MAX_HEAD_BYTES` to avoid an unbounded head from a hostile peer).
pub fn parse_request_head(buf: &[u8]) -> ParseResult {
    let term = b"\r\n\r\n";
    let end = match find(buf, term) {
        Some(i) => i + term.len(),
        None => {
            return if buf.len() > MAX_HEAD_BYTES {
                ParseResult::Malformed
            } else {
                ParseResult::Incomplete
            };
        }
    };
    // The request line is everything up to the first CRLF.
    let line_end = match find(buf, b"\r\n") {
        Some(i) => i,
        None => return ParseResult::Malformed,
    };
    let line = match std::str::from_utf8(&buf[..line_end]) {
        Ok(s) => s,
        Err(_) => return ParseResult::Malformed,
    };
    // `METHOD SP path SP HTTP/1.1`
    let mut parts = line.split(' ');
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if method.is_empty() || path.is_empty() || !version.starts_with("HTTP/1.") || parts.next().is_some() {
        return ParseResult::Malformed;
    }
    ParseResult::Complete(RequestHead {
        method: method.to_string(),
        path: path.to_string(),
        head_len: end,
    })
}

/// Build a `Connection: close` HTTP/1.1 error response with a small JSON body
/// (`{"code","message"}`) — the shape the host surfaces as a non-2xx guest
/// error.
pub fn error_response(status: u16, reason: &str, code: &str, message: &str) -> Vec<u8> {
    let body = format!(
        "{{\"code\":\"{}\",\"message\":\"{}\"}}",
        json_escape(code),
        json_escape(message),
    );
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\r\n",
        status = status,
        reason = reason,
        len = body.len(),
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// First index of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_complete_post_invoke() {
        let raw = b"POST /invoke HTTP/1.1\r\nHost: guest\r\nContent-Length: 3\r\n\r\nabc";
        match parse_request_head(raw) {
            ParseResult::Complete(h) => {
                assert_eq!(h.method, "POST");
                assert_eq!(h.path, "/invoke");
                // head_len points just past \r\n\r\n, before the body "abc".
                assert_eq!(&raw[h.head_len..], b"abc");
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn incomplete_until_terminator_arrives() {
        assert_eq!(parse_request_head(b"POST /invoke HTTP/1.1\r\nHost: g"), ParseResult::Incomplete);
        assert_eq!(parse_request_head(b"POST /invoke HTTP/1.1\r\n\r\n") , ParseResult::Complete(RequestHead {
            method: "POST".into(), path: "/invoke".into(), head_len: 25,
        }));
    }

    #[test]
    fn rejects_malformed_request_line() {
        // No HTTP version token.
        assert_eq!(parse_request_head(b"POST /invoke\r\n\r\n"), ParseResult::Malformed);
        // Extra token after the version.
        assert_eq!(parse_request_head(b"POST /invoke HTTP/1.1 extra\r\n\r\n"), ParseResult::Malformed);
    }

    #[test]
    fn error_response_is_parseable_and_escaped() {
        let r = error_response(503, "Service Unavailable", "K9O_UPSTREAM_UNAVAILABLE", "backend \"down\"\nnow");
        let s = String::from_utf8(r).unwrap();
        assert!(s.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(s.contains("Content-Type: application/json\r\n"));
        assert!(s.contains("Connection: close\r\n"));
        // body quote + newline are JSON-escaped
        assert!(s.contains("backend \\\"down\\\"\\nnow"));
        // Content-Length matches the actual body length.
        let body = s.split("\r\n\r\n").nth(1).unwrap();
        let cl: usize = s.lines().find_map(|l| l.strip_prefix("Content-Length: ")).unwrap().parse().unwrap();
        assert_eq!(cl, body.len());
    }
}
