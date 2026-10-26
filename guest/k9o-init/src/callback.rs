//! The guest side of the gate-frame classes: the extension's plugin-API calls and plain egress, carried on the ONE guest→host port.
//!
//! The extension speaks HTTP to [`crate::CALLBACK_LISTEN`] (loopback). Each request becomes exactly one gate frame:
//!
//!   * `POST /_k9o/v1/egress` with a JSON body `{url, method, headers?, bodyB64?}` → an `egress` frame;
//!   * any other request → a `callback` frame `{method, path, query?, contentType?, bodyB64?}`.
//!
//! The runtime ([`crate::runtime`]) writes the frame to `vsock cid=GATE_HOST_CID:GATE_HOST_PORT` (9000, the host's gate
//! on vsock port 9000: the same and only port the SDK's gate call uses), reads the one response frame, and answers HTTP with
//! [`response_to_http`]. This module is pure (no sockets), so every rule here is unit-tested on any host.
//!
//! Nothing here decides anything: the host's gate decides every frame. k9o-init only refuses what it cannot
//! frame (a malformed request, a chunked upload, a body over the class cap) and never adds an identity: the host binds
//! the slot's token.

use serde_json::{json, Map, Value};

/// The gate frame cap, mirrored from the host's `MAX_FRAME_BYTES` (pinned by a
/// test here).
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
/// Decoded body caps, mirrored from the host's per-class caps (the host's callback-frame and egress decision code).
pub const CALLBACK_MAX_BODY_BYTES: usize = 752 * 1024;
pub const EGRESS_MAX_BODY_BYTES: usize = 512 * 1024;
/// The egress request's JSON envelope (the body of `POST /_k9o/v1/egress`): the base64 body plus room for the URL and
/// headers, still inside one frame.
pub const EGRESS_ENVELOPE_MAX_BYTES: usize = MAX_FRAME_BYTES - 4 * 1024;
/// The request head, as the invoke proxy bounds it.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
pub const EGRESS_PATH: &str = "/_k9o/v1/egress";

/// A complete HTTP request read off the loopback connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub target: String,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReadState {
    /// Read more bytes and call again.
    Incomplete,
    Complete(HttpRequest),
    /// Answer with this status and close.
    Refuse(u16, &'static str),
}

/// Parse one HTTP/1.1 request from `buf` (one request per connection). The head is bounded; the body must be
/// `Content-Length`-delimited (no chunked upload) and within the class cap.
pub fn read_request(buf: &[u8]) -> ReadState {
    let head_end = match find(buf, b"\r\n\r\n") {
        Some(i) => i + 4,
        None => {
            return if buf.len() > MAX_HEAD_BYTES { ReadState::Refuse(431, "head_too_large") } else { ReadState::Incomplete };
        }
    };
    if head_end > MAX_HEAD_BYTES {
        return ReadState::Refuse(431, "head_too_large");
    }
    let head = match std::str::from_utf8(&buf[..head_end - 4]) {
        Ok(s) => s,
        Err(_) => return ReadState::Refuse(400, "malformed_request"),
    };
    let mut lines = head.split("\r\n");
    let mut parts = lines.next().unwrap_or("").split(' ');
    let (method, target, version) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if method.is_empty() || !target.starts_with('/') || !version.starts_with("HTTP/1.") || parts.next().is_some() {
        return ReadState::Refuse(400, "malformed_request");
    }
    let mut content_length: Option<usize> = None;
    let mut content_type: Option<String> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { return ReadState::Refuse(400, "malformed_request") };
        // RFC 9112 section 5: no whitespace between the field name and the colon (`Content-Length : 5` is refused), and only
        // SP/HTAB around the value are optional whitespace (never Unicode whitespace).
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic()) {
            return ReadState::Refuse(400, "malformed_request");
        }
        let (name, value) = (name.to_ascii_lowercase(), value.trim_matches(|c| c == ' ' || c == '\t'));
        match name.as_str() {
            "transfer-encoding" => return ReadState::Refuse(411, "chunked_not_supported"),
            "content-length" => {
                if content_length.is_some() {
                    return ReadState::Refuse(400, "malformed_request");
                }
                // Digits only: `usize::from_str` also takes a leading `+` (`+5`), which another parser on the path
                // could read differently.
                if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return ReadState::Refuse(400, "malformed_request");
                }
                match value.parse::<usize>() {
                    Ok(n) => content_length = Some(n),
                    Err(_) => return ReadState::Refuse(400, "malformed_request"),
                }
            }
            "content-type" => content_type = Some(value.to_string()),
            _ => {}
        }
    }
    let len = content_length.unwrap_or(0);
    let cap = if method == "POST" && target == EGRESS_PATH { EGRESS_ENVELOPE_MAX_BYTES } else { CALLBACK_MAX_BODY_BYTES };
    if len > cap {
        return ReadState::Refuse(413, "body_too_large");
    }
    if buf.len() < head_end + len {
        return ReadState::Incomplete;
    }
    ReadState::Complete(HttpRequest { method: method.to_string(), target: target.to_string(), content_type, body: buf[head_end..head_end + len].to_vec() })
}

/// The gate frame (its JSON, without the length prefix) for a request, or the status to refuse it with.
pub fn request_to_frame(req: &HttpRequest) -> Result<Vec<u8>, (u16, &'static str)> {
    let frame = if req.method == "POST" && req.target == EGRESS_PATH { egress_frame(req)? } else { callback_frame(req)? };
    let bytes = serde_json::to_vec(&frame).map_err(|_| (400, "malformed_request"))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err((413, "body_too_large"));
    }
    Ok(bytes)
}

fn callback_frame(req: &HttpRequest) -> Result<Value, (u16, &'static str)> {
    if req.target.contains('#') {
        return Err((400, "malformed_request"));
    }
    let (path, query) = match req.target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (req.target.as_str(), None),
    };
    let mut o = Map::new();
    o.insert("frameClass".into(), json!("callback"));
    o.insert("method".into(), json!(req.method));
    o.insert("path".into(), json!(path));
    if let Some(q) = query.filter(|q| !q.is_empty()) {
        o.insert("query".into(), json!(q));
    }
    if !req.body.is_empty() {
        // The plugin API takes JSON bodies only; `application/json; charset=utf-8` is the same media type.
        let media = req.content_type.as_deref().map(|c| c.split(';').next().unwrap_or("").trim().to_ascii_lowercase());
        if media.as_deref() != Some("application/json") {
            return Err((415, "json_body_required"));
        }
        o.insert("contentType".into(), json!("application/json"));
        o.insert("bodyB64".into(), json!(b64_encode(&req.body)));
    }
    Ok(Value::Object(o))
}

fn egress_frame(req: &HttpRequest) -> Result<Value, (u16, &'static str)> {
    let v: Value = serde_json::from_slice(&req.body).map_err(|_| (400, "malformed_request"))?;
    let o = v.as_object().ok_or((400, "malformed_request"))?;
    for k in o.keys() {
        if !matches!(k.as_str(), "url" | "method" | "headers" | "bodyB64") {
            return Err((400, "malformed_request"));
        }
    }
    let url = o.get("url").and_then(Value::as_str).ok_or((400, "malformed_request"))?;
    // Absent ⇒ GET; present but not a string ⇒ refused (never silently GET).
    let method = match o.get("method") {
        None => "GET",
        Some(m) => m.as_str().ok_or((400, "malformed_request"))?,
    };
    let mut f = Map::new();
    f.insert("frameClass".into(), json!("egress"));
    f.insert("op".into(), json!("fetch"));
    f.insert("url".into(), json!(url));
    f.insert("method".into(), json!(method));
    if let Some(h) = o.get("headers") {
        let h = h.as_object().ok_or((400, "malformed_request"))?;
        if h.values().any(|v| !v.is_string()) {
            return Err((400, "malformed_request"));
        }
        f.insert("headers".into(), Value::Object(h.clone()));
    }
    if let Some(b) = o.get("bodyB64") {
        let b = b.as_str().ok_or((400, "malformed_request"))?;
        match b64_decode(b) {
            Some(d) if d.len() <= EGRESS_MAX_BODY_BYTES => {}
            Some(_) => return Err((413, "body_too_large")),
            None => return Err((400, "malformed_request")),
        }
        f.insert("bodyB64".into(), json!(b));
    }
    Ok(Value::Object(f))
}

/// `[u32 LE len][json]`, the gate framing.
pub fn encode_frame(json: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&(json.len() as u32).to_le_bytes());
    out.extend_from_slice(json);
    out
}

/// A response frame declaring more than [`MAX_FRAME_BYTES`].
#[derive(Debug, PartialEq, Eq)]
pub struct FrameTooLarge;

/// How long the next read must be: `Some(total)` once the 4-byte prefix is in, or an error if it declares over the cap.
pub fn frame_len(buf: &[u8]) -> Result<Option<usize>, FrameTooLarge> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if n > MAX_FRAME_BYTES {
        return Err(FrameTooLarge);
    }
    Ok(Some(4 + n))
}

/// The host's response frame (its JSON) as the HTTP response the extension reads.
///
/// * `result` → its status, its `content-type`, its body; an egress result also carries `x-k9o-egress: proxied`.
/// * `refusal` → `403` with `x-k9o-refusal: <reason>` and `{"code":"K9O_GATE_REFUSED","reason":…}`: the host's gate refused,
///   which the extension can tell from an upstream's own 403 by the header. (Provisional: the code name may change.)
/// * anything else (a host whose classes are off answers a gate `deny` decision) → `503`, `x-k9o-refusal: gate_unavailable`.
pub fn response_to_http(frame_json: &[u8]) -> Vec<u8> {
    let v: Value = match serde_json::from_slice(frame_json) {
        Ok(v) => v,
        Err(_) => return refusal_http(502, "gate_response_malformed"),
    };
    match v.get("frameClass").and_then(Value::as_str) {
        Some("result") => {
            let status = v.get("status").and_then(Value::as_u64).filter(|s| (100..=599).contains(s)).unwrap_or(502) as u16;
            let body = match v.get("bodyB64").and_then(Value::as_str).and_then(b64_decode) {
                Some(b) => b,
                None => return refusal_http(502, "gate_response_malformed"),
            };
            let ct = v.get("headers").and_then(|h| h.get("content-type")).and_then(Value::as_str);
            let egress = v.get("class").and_then(Value::as_str) == Some("egress");
            let mut head = format!("HTTP/1.1 {status} {}\r\n", reason_phrase(status));
            if let Some(ct) = ct.filter(|c| !c.contains(['\r', '\n'])) {
                head.push_str(&format!("Content-Type: {ct}\r\n"));
            }
            if egress {
                head.push_str("x-k9o-egress: proxied\r\n");
            }
            head.push_str(&format!("Content-Length: {}\r\nConnection: close\r\n\r\n", body.len()));
            let mut out = head.into_bytes();
            out.extend_from_slice(&body);
            out
        }
        Some("refusal") => {
            let reason = v.get("reason").and_then(Value::as_str).filter(|r| r.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')).unwrap_or("refused");
            refusal_http(403, reason)
        }
        _ => refusal_http(503, "gate_unavailable"),
    }
}

/// A local or host refusal as HTTP.
pub fn refusal_http(status: u16, reason: &str) -> Vec<u8> {
    let body = format!("{{\"code\":\"K9O_GATE_REFUSED\",\"reason\":\"{reason}\"}}");
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nx-k9o-refusal: {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason_phrase(status),
        body.len()
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        411 => "Length Required",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Strict standard base64 (canonical padding, no whitespace); `None` when not.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    let val = |c: u8| B64.iter().position(|&x| x == c).map(|p| p as u32);
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for (i, q) in b.chunks(4).enumerate() {
        let last = i == b.len() / 4 - 1;
        let pad = q.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for (j, &c) in q.iter().enumerate() {
            n <<= 6;
            if j >= 4 - pad {
                continue;
            }
            n |= val(c)?;
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
        // Canonical: the unused low bits of a padded quad are zero.
        if (pad == 1 && n & 0xff != 0) || (pad == 2 && n & 0xffff != 0) {
            return None;
        }
    }
    Some(out)
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(raw: &str) -> HttpRequest {
        match read_request(raw.as_bytes()) {
            ReadState::Complete(r) => r,
            other => panic!("{other:?}"),
        }
    }
    fn frame(raw: &str) -> Value {
        serde_json::from_slice(&request_to_frame(&req(raw)).unwrap()).unwrap()
    }

    #[test]
    fn the_frame_cap_mirrors_gate_wire() {
        assert_eq!(MAX_FRAME_BYTES, 1024 * 1024); // host MAX_FRAME_BYTES
        assert_eq!(CALLBACK_MAX_BODY_BYTES, 752 * 1024); // host CALLBACK_FRAME_MAX_BODY_BYTES
        // The worst callback frame fits: the largest body, base64, plus a 2 KiB path, an 8 KiB query and the keys.
        let worst = HttpRequest {
            method: "POST".into(),
            target: format!("/{}?{}", "p".repeat(2047), "q".repeat(8 * 1024)),
            content_type: Some("application/json".into()),
            body: vec![b'x'; CALLBACK_MAX_BODY_BYTES],
        };
        assert!(request_to_frame(&worst).unwrap().len() <= MAX_FRAME_BYTES);
    }

    #[test]
    fn a_plugin_api_call_becomes_a_callback_frame() {
        let f = frame("POST /@acme/data/notes?limit=5 HTTP/1.1\r\nHost: x\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 2\r\n\r\n{}");
        assert_eq!(f, json!({"frameClass":"callback","method":"POST","path":"/@acme/data/notes","query":"limit=5","contentType":"application/json","bodyB64":"e30="}));
        // The exact bytes the host parses (pinned by a host-side test that the guest's frames are the host's frames).
        let bytes = request_to_frame(&req("POST /@acme/data/notes?limit=5 HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), r#"{"bodyB64":"e30=","contentType":"application/json","frameClass":"callback","method":"POST","path":"/@acme/data/notes","query":"limit=5"}"#);
        let g = frame("GET /@acme/data/notes HTTP/1.1\r\n\r\n");
        assert_eq!(g, json!({"frameClass":"callback","method":"GET","path":"/@acme/data/notes"}));
    }

    #[test]
    fn no_identity_is_forwarded_from_the_guest() {
        // An Authorization header the extension sends is not carried: the host binds the slot's token.
        let f = frame("GET /@acme/data/notes HTTP/1.1\r\nAuthorization: Bearer forged\r\nCookie: a=b\r\n\r\n");
        assert!(!serde_json::to_string(&f).unwrap().contains("forged"));
        assert!(f.get("headers").is_none());
    }

    #[test]
    fn egress_becomes_an_egress_frame_with_a_closed_envelope() {
        let body = r#"{"url":"https://api.example.com/v1","method":"POST","headers":{"accept":"application/json"},"bodyB64":"aGk="}"#;
        let raw = format!("POST /_k9o/v1/egress HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        assert_eq!(frame(&raw), json!({"frameClass":"egress","op":"fetch","url":"https://api.example.com/v1","method":"POST","headers":{"accept":"application/json"},"bodyB64":"aGk="}));
        for bad in [r#"{"url":"https://x","extra":1}"#, r#"{"method":"GET"}"#, r#"{"url":"https://x","headers":{"a":1}}"#, r#"{"url":"https://x","bodyB64":"a b"}"#, "[]"] {
            let raw = format!("POST /_k9o/v1/egress HTTP/1.1\r\nContent-Length: {}\r\n\r\n{bad}", bad.len());
            assert_eq!(request_to_frame(&req(&raw)), Err((400, "malformed_request")), "{bad}");
        }
    }

    #[test]
    fn refusals_before_any_frame() {
        assert_eq!(read_request(b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"), ReadState::Refuse(411, "chunked_not_supported"));
        assert_eq!(read_request(format!("POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n", CALLBACK_MAX_BODY_BYTES + 1).as_bytes()), ReadState::Refuse(413, "body_too_large"));
        assert_eq!(read_request(b"POST /x HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx"), ReadState::Refuse(400, "malformed_request"));
        assert_eq!(read_request(b"GET x HTTP/1.1\r\n\r\n"), ReadState::Refuse(400, "malformed_request"));
        assert_eq!(read_request(&vec![b'a'; MAX_HEAD_BYTES + 1]), ReadState::Refuse(431, "head_too_large"));
        assert_eq!(read_request(b"POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nab"), ReadState::Incomplete);
        assert_eq!(request_to_frame(&req("POST /@a/data/n HTTP/1.1\r\nContent-Type: text/plain\r\nContent-Length: 1\r\n\r\nx")), Err((415, "json_body_required")));
        assert_eq!(request_to_frame(&req("GET /@a/data/n#f HTTP/1.1\r\n\r\n")), Err((400, "malformed_request")));
    }

    #[test]
    fn header_names_and_whitespace_are_strict() {
        for raw in ["POST /x HTTP/1.1\r\nContent-Length : 5\r\n\r\nhello", "POST /x HTTP/1.1\r\n Content-Length: 5\r\n\r\nhello", "POST /x HTTP/1.1\r\n: 5\r\n\r\nhello"] {
            assert_eq!(read_request(raw.as_bytes()), ReadState::Refuse(400, "malformed_request"), "{raw:?}");
        }
        // A no-break space around the value is not optional whitespace: the value is not digits.
        assert_eq!(read_request("POST /x HTTP/1.1\r\nContent-Length: 5\u{00a0}\r\n\r\nhello".as_bytes()), ReadState::Refuse(400, "malformed_request"));
        // SP and HTAB are.
        assert!(matches!(read_request(b"POST /x HTTP/1.1\r\nContent-Length:\t5 \r\n\r\nhello"), ReadState::Complete(r) if r.body == b"hello"));
    }

    #[test]
    fn a_non_string_egress_method_is_refused() {
        for env in [r#"{"url":"https://x","method":5}"#, r#"{"url":"https://x","method":null}"#, r#"{"url":"https://x","method":["GET"]}"#] {
            let raw = format!("POST /_k9o/v1/egress HTTP/1.1\r\nContent-Length: {}\r\n\r\n{env}", env.len());
            assert_eq!(request_to_frame(&req(&raw)), Err((400, "malformed_request")), "{env}");
        }
        let env = r#"{"url":"https://x"}"#;
        let raw = format!("POST /_k9o/v1/egress HTTP/1.1\r\nContent-Length: {}\r\n\r\n{env}", env.len());
        assert_eq!(frame(&raw)["method"], json!("GET"));
    }

    #[test]
    fn content_length_is_digits_only() {
        for bad in ["+5", "-0", " 5x", "5 5", "0x5", "5.0", "", "\u{0665}"] {
            let raw = format!("POST /x HTTP/1.1\r\nContent-Length: {bad}\r\n\r\nhello");
            assert_eq!(read_request(raw.as_bytes()), ReadState::Refuse(400, "malformed_request"), "{bad:?}");
        }
        // Leading zeros are still digits; surrounding whitespace is the header's, trimmed before the check.
        assert!(matches!(read_request(b"POST /x HTTP/1.1\r\nContent-Length: 005\r\n\r\nhello"), ReadState::Complete(r) if r.body == b"hello"));
        assert!(matches!(read_request(b"POST /x HTTP/1.1\r\nContent-Length:  5 \r\n\r\nhello"), ReadState::Complete(r) if r.body == b"hello"));
        // A length too large for usize is refused, never wrapped.
        assert_eq!(read_request(b"POST /x HTTP/1.1\r\nContent-Length: 99999999999999999999999\r\n\r\n"), ReadState::Refuse(400, "malformed_request"));
    }

    /// The class is fixed by k9o-init, never by the guest.
    #[test]
    fn a_frame_class_in_the_egress_envelope_is_refused() {
        for env in [
            r#"{"frameClass":"callback","url":"https://x"}"#,
            r#"{"url":"https://x","frameClass":"egress"}"#,
            r#"{"url":"https://x","frameClass":"tool_call"}"#,
            r#"{"url":"https://x","frameClass":"telemetry"}"#,
            r#"{"url":"https://x","op":"fetch"}"#,
            r#"{"url":"https://x","class":"callback"}"#,
        ] {
            let raw = format!("POST /_k9o/v1/egress HTTP/1.1\r\nContent-Length: {}\r\n\r\n{env}", env.len());
            assert_eq!(request_to_frame(&req(&raw)), Err((400, "malformed_request")), "{env}");
        }
    }

    /// For every request, the emitted class is exactly `egress` (only `POST /_k9o/v1/egress`) or `callback`
    /// (everything else); a path, a query or a body naming another class changes nothing.
    #[test]
    fn the_emitted_class_is_only_egress_or_callback() {
        let env = r#"{"url":"https://x"}"#;
        let json_body = r#"{"frameClass":"tool_call"}"#;
        let cases: Vec<(String, &str)> = vec![
            (format!("POST /_k9o/v1/egress HTTP/1.1\r\nContent-Length: {}\r\n\r\n{env}", env.len()), "egress"),
            ("GET /_k9o/v1/egress HTTP/1.1\r\n\r\n".into(), "callback"),
            (format!("PUT /_k9o/v1/egress HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{env}", env.len()), "callback"),
            (format!("POST /_k9o/v1/egress?x=1 HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{env}", env.len()), "callback"),
            (format!("POST /_k9o/v1/egress/ HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{env}", env.len()), "callback"),
            (format!("POST /_K9O/v1/egress HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{env}", env.len()), "callback"),
            ("GET /tool_call HTTP/1.1\r\n\r\n".into(), "callback"),
            ("GET /telemetry?frameClass=egress HTTP/1.1\r\n\r\n".into(), "callback"),
            ("GET /@a/data/n?frameClass=tool_call HTTP/1.1\r\n\r\n".into(), "callback"),
            (format!("POST /@a/data/n HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{json_body}", json_body.len()), "callback"),
        ];
        for (raw, class) in cases {
            let f = frame(&raw);
            assert_eq!(f["frameClass"], json!(class), "{raw}");
            // The body never becomes frame keys: a callback carries it base64'd, so a guest `frameClass` in it is inert.
            assert_eq!(f.as_object().unwrap().keys().filter(|k| *k == "frameClass").count(), 1);
        }
    }

    #[test]
    fn responses_become_http() {
        let ok = String::from_utf8(response_to_http(br#"{"frameClass":"result","class":"callback","status":201,"headers":{"content-type":"application/json"},"bodyB64":"e30="}"#)).unwrap();
        assert!(ok.starts_with("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n"));
        assert!(ok.ends_with("Content-Length: 2\r\nConnection: close\r\n\r\n{}"));
        let eg = String::from_utf8(response_to_http(br#"{"frameClass":"result","class":"egress","status":200,"headers":{},"bodyB64":""}"#)).unwrap();
        assert!(eg.contains("x-k9o-egress: proxied\r\n"));
        let no = String::from_utf8(response_to_http(br#"{"frameClass":"refusal","class":"callback","reason":"route_not_allowed"}"#)).unwrap();
        assert!(no.starts_with("HTTP/1.1 403 Forbidden\r\n") && no.contains("x-k9o-refusal: route_not_allowed\r\n"));
        let off = String::from_utf8(response_to_http(br#"{"decision":"deny","reason":"classifier_unavailable"}"#)).unwrap();
        assert!(off.starts_with("HTTP/1.1 503") && off.contains("x-k9o-refusal: gate_unavailable"));
        // A hostile header value or reason cannot split the response.
        let inj = String::from_utf8(response_to_http(br#"{"frameClass":"result","status":200,"headers":{"content-type":"a\r\nSet-Cookie: x"},"bodyB64":""}"#)).unwrap();
        assert!(!inj.contains("Set-Cookie"));
        let inj2 = String::from_utf8(response_to_http(br#"{"frameClass":"refusal","reason":"a\r\nx: y"}"#)).unwrap();
        assert!(inj2.contains("x-k9o-refusal: refused\r\n"));
        assert!(String::from_utf8(response_to_http(b"not json")).unwrap().starts_with("HTTP/1.1 502"));
    }

    #[test]
    fn framing_and_base64() {
        assert_eq!(encode_frame(b"{}"), vec![2, 0, 0, 0, b'{', b'}']);
        assert_eq!(frame_len(&[2, 0]), Ok(None));
        assert_eq!(frame_len(&[2, 0, 0, 0]), Ok(Some(6)));
        assert_eq!(frame_len(&((MAX_FRAME_BYTES + 1) as u32).to_le_bytes()), Err(FrameTooLarge));
        for s in ["", "f", "fo", "foo", "foob", "fooba", "foobar"] {
            assert_eq!(b64_decode(&b64_encode(s.as_bytes())).unwrap(), s.as_bytes());
        }
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        for bad in ["Zg", "Zg=", "Zh==", "Z===", "Zg==Zg==", "Zm9v YmFy"] {
            assert_eq!(b64_decode(bad), None, "{bad}");
        }
    }
}
