//! k9o-init entrypoint. The real orchestration is Linux-only (it runs as PID 1
//! inside a Firecracker guest); on any other host this binary is inert so the
//! crate still builds + tests everywhere.

fn main() {
    std::process::exit(run());
}

#[cfg(target_os = "linux")]
fn run() -> i32 {
    k9o_init::runtime::run()
}

#[cfg(not(target_os = "linux"))]
fn run() -> i32 {
    eprintln!("k9o-init runs only as a Linux Firecracker guest (PID 1)");
    1
}
