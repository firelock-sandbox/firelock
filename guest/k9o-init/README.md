# k9o-init — the Firecracker guest agent (PID 1)

Every converted guest rootfs has this static binary injected at
`/usr/bin/k9o-init` and booted as PID 1 (`init=/usr/bin/k9o-init`). It exists
because a Bun/Node extension cannot speak either vsock direction Firecracker
needs, and because a converted image needs an init process to bring the guest up
and run the extension.

## What it does

1. **PID-1 init** (`sysinit.rs`) — mounts `/proc`, `/sys`, `/dev` (+`/dev/pts`),
   a tmpfs `/run` (for the gate socket) and `/tmp`, and creates `/run/k9o`.

2. **Host → guest invocation server** (`vsock.rs` + `proxy.rs`) — listens on
   `AF_VSOCK` port **8000** (matches `K9O_INIT_VSOCK_PORT` on
   the host side). The host dials in and sends `POST /invoke` (HTTP/1.1 over
   vsock); k9o-init validates the request line and
   reverse-proxies it to the extension's own loopback invoke server
   (`K9O_INVOKE_LISTEN`, default `127.0.0.1:8081`), splicing the response back.
   A missing/booting extension server returns a clean `503`, never a hang.

3. **Guest → host gate bridge** (`runtime.rs`) — the SDK's gate call reaches the
   host's gate dispatcher at `cid=2:9000` (vsock port 9000, the guest's only
   outbound channel) directly via `bun:ffi` on Linux (its **primary** path).
   k9o-init provides the documented **UDS fallback**: it listens on
   `/run/k9o/gate.sock` (`K9O_GATE_SOCKET`) and splices each connection to the
   same host vsock endpoint.

4. **Supervise** (`supervise.rs`) — forks + execs the extension entrypoint (from
   the entry contract) **while single-threaded** (async-signal-safe), then reaps
   every child as PID 1 and exits with the extension's status.

## The entry contract

Booting k9o-init as PID 1 erases the image's own `Entrypoint`/`Cmd`, so the
image converter records the resolved entrypoint (from the OCI runtime bundle's
`config.json`) to `/etc/k9o/entry.json`:

```json
{ "argv": ["/usr/local/bin/node", "server.js"], "env": {"PATH": "..."}, "cwd": "/app" }
```

k9o-init reads it, sets the env (plus `K9O_GATE_SOCKET` and `K9O_INVOKE_LISTEN`),
`chdir`s to `cwd`, and `execvp`s `argv`.

## Building

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# → target/x86_64-unknown-linux-musl/release/k9o-init  (static; point
#   K9O_INIT_BINARY_PATH at it on the converter host)
```

## Testing

The protocol logic (`http`, `splice`, `entry`, `proxy`) is platform-agnostic and
unit-tested on any host:

```sh
cargo test                                   # pure logic (13 tests)
cargo check --target aarch64-unknown-linux-gnu   # type-check the Linux syscall layer
```

The syscall layers (`vsock`, `sysinit`, `supervise`, `runtime`) are Linux-only
(`#[cfg(target_os = "linux")]`). End-to-end boot is exercised by a guest
smoke test against a converted guest rootfs.

## Wire constants (must match the host)

| Constant | Value | Host-side counterpart |
|---|---|---|
| invoke vsock port | `8000` | `K9O_INIT_VSOCK_PORT` |
| gate host cid:port | `2:9000` | the gate dispatcher's `GATE_PORT` and the SDK's gate client |
| gate UDS | `/run/k9o/gate.sock` | `K9O_GATE_SOCKET` (SDK default) |
| boot cmdline | `init=/usr/bin/k9o-init` | the default guest boot args |
