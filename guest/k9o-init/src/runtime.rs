//! The PID-1 orchestration (Linux only). Ordering is deliberate:
//!
//!   1. mount the pseudo-filesystems,
//!   2. read the entry contract,
//!   3. `fork`+`exec` the extension **while still single-threaded** (so the
//!      child path is async-signal-safe — see [`crate::supervise`]),
//!   4. bring up the two vsock bridges in background threads,
//!   5. reap children until the extension exits, and exit with its status.

use crate::entry::EntryContract;
use crate::{
    callback, proxy, splice, supervise, sysinit, vsock, CALLBACK_LISTEN, ENTRY_CONTRACT_PATH, GATE_HOST_CID,
    GATE_HOST_PORT, GATE_UDS_PATH, INVOKE_LOOPBACK_DEFAULT, INVOKE_VSOCK_PORT,
};
use splice::Duplex;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::thread;
use std::time::Duration;

pub fn run() -> i32 {
    sysinit::mount_essentials();
    // Raise `lo` before spawning the extension: its invoke server binds loopback
    // and our reverse-proxy dials it — both need `lo` UP (a fresh FC guest boots it
    // DOWN). Without this every invoke 503s at the proxy's connect.
    sysinit::bring_loopback_up();

    let contract = match read_contract() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("k9o-init: fatal: {e}");
            return 1;
        }
    };

    let invoke_listen =
        std::env::var("K9O_INVOKE_LISTEN").unwrap_or_else(|_| INVOKE_LOOPBACK_DEFAULT.to_string());

    match contract {
        Some(contract) => {
            // Per-function VM: fork+exec the extension BEFORE spawning any thread
            // (async-signal-safety), bring up the bridges, then reap until it exits.
            let ext_pid = match supervise::spawn_extension(&contract, GATE_UDS_PATH, &invoke_listen) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("k9o-init: fatal: could not spawn extension entrypoint: {e}");
                    return 1;
                }
            };
            {
                let target = invoke_listen.clone();
                thread::spawn(move || invoke_server(&target));
            }
            thread::spawn(gate_bridge);
            thread::spawn(callback_server);
            // The core PID-1 duty: reap everything, exit with the extension's status.
            supervise::reap_until(ext_pid)
        }
        None => {
            // Warm-pool-idle: no entry contract yet (generic, not-yet-claimed VM).
            // Skip the fork+exec — there is no extension — and bring up the gate
            // bridge (+ invoke listener) so the gate path (gate_decide) is
            // live, then park as PID 1. The base snapshot is captured in THIS state;
            // a claim later delivers a per-function rootfs + contract. This keeps the
            // base rootfs minimal — no placeholder binary is baked in just to satisfy
            // the exec path, preserving the "vsock-only, nothing else" exec-seam floor.
            eprintln!(
                "k9o-init: no entry contract at {ENTRY_CONTRACT_PATH} — warm-pool-idle (gate bridge up, awaiting claim)"
            );
            {
                let target = invoke_listen.clone();
                thread::spawn(move || invoke_server(&target));
            }
            thread::spawn(gate_bridge);
            thread::spawn(callback_server);
            supervise::reap_forever()
        }
    }
}

/// Read + classify the entry contract. `Ok(None)` = the file is absent →
/// warm-pool-idle; `Ok(Some)` = per-function exec; `Err` = present-but-invalid
/// or unreadable → fatal. (Classification lives in `entry` so it is unit-tested
/// cross-platform; this Linux-only shim just supplies the real file read.)
fn read_contract() -> Result<Option<EntryContract>, String> {
    crate::entry::classify_contract(std::fs::read(ENTRY_CONTRACT_PATH))
}

/// Host → guest invocations: accept on `vsock:INVOKE_VSOCK_PORT`, reverse-proxy
/// each to the extension's loopback invoke server.
fn invoke_server(invoke_listen: &str) {
    let listener = match vsock::VsockListener::bind(INVOKE_VSOCK_PORT) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("k9o-init: invoke vsock bind(:{INVOKE_VSOCK_PORT}) failed: {e}");
            return;
        }
    };
    loop {
        match listener.accept() {
            Ok(conn) => {
                let target = invoke_listen.to_string();
                thread::spawn(move || {
                    let _ = proxy::serve_invocation(Box::new(conn), move || dial_loopback(&target));
                });
            }
            Err(e) => eprintln!("k9o-init: invoke accept error (continuing): {e}"),
        }
    }
}

/// Connect the extension's loopback invoke server, retrying briefly — the first
/// invocation can land before the extension has finished binding.
fn dial_loopback(addr: &str) -> io::Result<Box<dyn Duplex>> {
    let mut last = io::Error::new(io::ErrorKind::NotConnected, "no connection attempt made");
    for _ in 0..25 {
        match TcpStream::connect(addr) {
            Ok(s) => return Ok(Box::new(s)),
            Err(e) => {
                last = e;
                thread::sleep(Duration::from_millis(200));
            }
        }
    }
    Err(last)
}

/// Guest → host gate (the SDK's UDS fallback): accept on the gate UDS, splice
/// each connection to the host dispatcher at `vsock cid=GATE_HOST_CID:GATE_HOST_PORT`.
fn gate_bridge() {
    let _ = std::fs::remove_file(GATE_UDS_PATH); // clear any stale socket
    let listener = match UnixListener::bind(GATE_UDS_PATH) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("k9o-init: gate UDS bind({GATE_UDS_PATH}) failed: {e}");
            return;
        }
    };
    for conn in listener.incoming() {
        match conn {
            Ok(uds) => {
                thread::spawn(move || match vsock::VsockStream::connect(GATE_HOST_CID, GATE_HOST_PORT) {
                    Ok(vs) => {
                        let _ = splice::splice_bidirectional(Box::new(uds), Box::new(vs));
                    }
                    Err(e) => eprintln!("k9o-init: gate vsock dial failed: {e}"),
                });
            }
            Err(e) => eprintln!("k9o-init: gate accept error (continuing): {e}"),
        }
    }
}

/// How long one plugin-API call or egress may take end to end (the host bounds its own side at 30 s).
const CALLBACK_IO_TIMEOUT: Duration = Duration::from_secs(35);

/// Guest → host plugin-API calls and egress: accept on the loopback [`CALLBACK_LISTEN`], and turn each HTTP request
/// into ONE frame on the gate.
///
/// Invariant: "8082 dials only 9000". The one connect below is `VsockStream::connect(GATE_HOST_CID, GATE_HOST_PORT)`
/// (pinned by a host-side test). No second guest→host port exists.
fn callback_server() {
    let listener = match TcpListener::bind(CALLBACK_LISTEN) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("k9o-init: callback bind({CALLBACK_LISTEN}) failed: {e}");
            return;
        }
    };
    for conn in listener.incoming() {
        match conn {
            Ok(s) => {
                thread::spawn(move || serve_callback(s));
            }
            Err(e) => eprintln!("k9o-init: callback accept error (continuing): {e}"),
        }
    }
}

fn serve_callback(mut s: TcpStream) {
    let _ = s.set_read_timeout(Some(CALLBACK_IO_TIMEOUT));
    let _ = s.set_write_timeout(Some(CALLBACK_IO_TIMEOUT));
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    let req = loop {
        match callback::read_request(&buf) {
            callback::ReadState::Complete(r) => break r,
            callback::ReadState::Refuse(status, why) => {
                let _ = s.write_all(&callback::refusal_http(status, why));
                return;
            }
            callback::ReadState::Incomplete => match s.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            },
        }
    };
    let frame = match callback::request_to_frame(&req) {
        Ok(f) => f,
        Err((status, why)) => {
            let _ = s.write_all(&callback::refusal_http(status, why));
            return;
        }
    };
    let mut gate = match vsock::VsockStream::connect(GATE_HOST_CID, GATE_HOST_PORT) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("k9o-init: callback gate dial failed: {e}");
            let _ = s.write_all(&callback::refusal_http(503, "gate_unavailable"));
            return;
        }
    };
    if gate.write_all(&callback::encode_frame(&frame)).is_err() {
        let _ = s.write_all(&callback::refusal_http(503, "gate_unavailable"));
        return;
    }
    let mut rb: Vec<u8> = Vec::new();
    let total = loop {
        match callback::frame_len(&rb) {
            Err(callback::FrameTooLarge) => {
                let _ = s.write_all(&callback::refusal_http(502, "gate_response_malformed"));
                return;
            }
            Ok(Some(t)) if rb.len() >= t => break t,
            _ => match gate.read(&mut chunk) {
                Ok(0) | Err(_) => {
                    let _ = s.write_all(&callback::refusal_http(502, "gate_closed"));
                    return;
                }
                Ok(n) => rb.extend_from_slice(&chunk[..n]),
            },
        }
    };
    let _ = s.write_all(&callback::response_to_http(&rb[4..total]));
}
