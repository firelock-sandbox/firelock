# Firelock native crates

Two Rust crates used by the Firelock sandbox runtime. Each builds as an `rlib` and as a
`cdylib` that the Bun/TypeScript runtime loads through `bun:ffi`.

- `fd-handoff` (`firelock-fd-handoff`): passes a guest connection file descriptor from the
  gate dispatcher to the executor over a host-internal `AF_UNIX` socket using `SCM_RIGHTS`.
  The sender's copy is closed on every path, so the executor is the sole owner. The receive
  side bounds the number of fds per message and fails closed on truncation. Builds and
  tests on Linux and macOS. Produces `libfirelock_fd_handoff.so` / `.dylib`.
- `handler-confine` (`firelock-handler-confine`): launches the credential-less handler into
  a fresh network/pid/mount namespace and a cgroup v2 leaf (`clone3`), then seals it with a
  deny-by-default seccomp-bpf filter (`SECCOMP_RET_KILL_PROCESS`). Linux only; the crate
  fails to compile elsewhere by design. Produces `libfirelock_handler_confine.so`.

## Build

```sh
cd native
cargo build --release
```

On macOS only `fd-handoff` can build: use `cargo build --release -p firelock-fd-handoff`
and `cargo test -p firelock-fd-handoff`.

## Tests

`cargo test` runs the unit tests. The kernel tests under `handler-confine/tests/` exercise
seccomp, namespaces and cgroups and need a real Linux kernel. The seal tests run
unprivileged; the launch tests need root and `FIRELOCK_CONFINE_PRIV_TESTS=1`, and print a
skip notice otherwise:

```sh
cargo test --release -p firelock-handler-confine --test seal_kernel
sudo FIRELOCK_CONFINE_PRIV_TESTS=1 cargo test --release -p firelock-handler-confine --test launch_kernel
```
