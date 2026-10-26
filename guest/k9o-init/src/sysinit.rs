//! PID-1 filesystem setup. A converted OCI rootfs has none of the kernel
//! pseudo-filesystems mounted; k9o-init mounts the handful the extension runtime
//! (and its own gate UDS) need, then creates `/run/k9o`. Every mount is
//! best-effort: an already-mounted or absent target is logged and skipped, never
//! fatal — a missing `/tmp` should not stop the guest from serving invocations.
//!
//! # Safety
//! Each `unsafe` block is one `mount(2)`/`mkdir(2)` call with NUL-terminated
//! `CString` arguments and a checked return value.

use std::ffi::CString;
use std::io;

fn cstr(s: &str) -> CString {
    CString::new(s).expect("mount path contains an interior NUL")
}

/// Mount one filesystem. `data` is the fs-specific options string (e.g.
/// `mode=0755`), or `None`.
fn mount(source: &str, target: &str, fstype: &str, flags: libc::c_ulong, data: Option<&str>) -> io::Result<()> {
    let src = cstr(source);
    let tgt = cstr(target);
    let fst = cstr(fstype);
    let data_c = data.map(cstr);
    let data_ptr = data_c
        .as_ref()
        .map(|c| c.as_ptr() as *const libc::c_void)
        .unwrap_or(std::ptr::null());
    // SAFETY: all pointers are valid NUL-terminated CStrings (or null for data).
    let rc = unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), flags, data_ptr) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `mkdir(path, mode)`, treating "already exists" as success.
pub fn mkdir_p(path: &str, mode: libc::mode_t) -> io::Result<()> {
    let p = cstr(path);
    // SAFETY: `p` is a valid NUL-terminated CString.
    let rc = unsafe { libc::mkdir(p.as_ptr(), mode) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EEXIST) {
            return Ok(());
        }
        return Err(e);
    }
    Ok(())
}

/// Mount `/proc`, `/sys`, `/dev`(+`/dev/pts`), `/run`, `/tmp` and create
/// `/run/k9o`. Best-effort; returns after attempting all of them.
pub fn mount_essentials() {
    // Create the mount POINTS first — a minimal base image (busybox / distroless)
    // may not ship /run or /tmp, and `mount(2)` fails with ENOENT if the target
    // directory is absent. mkdir_p is idempotent (EEXIST == ok), so pre-existing
    // points on richer bases are untouched. Without this, /run is never mounted →
    // the gate UDS bind fails and /run/k9o can't be created.
    for point in ["/proc", "/sys", "/dev", "/run", "/tmp"] {
        let _ = mkdir_p(point, 0o755);
    }
    let _ = mount("proc", "/proc", "proc", 0, None);
    let _ = mount("sysfs", "/sys", "sysfs", 0, None);
    let _ = mount("devtmpfs", "/dev", "devtmpfs", 0, None);
    let _ = mkdir_p("/dev/pts", 0o755);
    let _ = mount("devpts", "/dev/pts", "devpts", 0, None);
    // /run holds the gate UDS; give it a private tmpfs.
    let _ = mount("tmpfs", "/run", "tmpfs", 0, Some("mode=0755"));
    let _ = mount("tmpfs", "/tmp", "tmpfs", 0, None);
    if let Err(e) = mkdir_p("/run/k9o", 0o755) {
        eprintln!("k9o-init: could not create /run/k9o: {e}");
    }
}

/// Bring the loopback interface `lo` administratively UP.
///
/// The extension's invoke server binds a loopback address
/// (`INVOKE_LOOPBACK_DEFAULT` = 127.0.0.1:8081) and k9o-init's reverse-proxy dials
/// it — BOTH require `lo` to be UP. A fresh Firecracker guest boots with `lo` DOWN
/// (the kernel registers it but leaves it down for userspace to raise), and
/// nothing else in this PID-1 raised it. Without this the extension's `bind`
/// SUCCEEDS but every proxy `connect` to 127.0.0.1 fails → every invoke 503s.
///
/// Best-effort + logged (mirrors the mount policy): a failure breaks the loopback
/// invoke path but must not panic PID 1.
pub fn bring_loopback_up() {
    // SAFETY: a datagram socket used purely for the SIOCGIFFLAGS/SIOCSIFFLAGS
    // interface ioctls; `ifreq` is zeroed then its name + flags fields set; every
    // return value is checked and the fd is always closed.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            eprintln!("k9o-init: lo bring-up: socket() failed: {}", io::Error::last_os_error());
            return;
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        ifr.ifr_name[0] = b'l' as libc::c_char;
        ifr.ifr_name[1] = b'o' as libc::c_char;
        // Read current flags, OR in UP|RUNNING, write back.
        // The ioctl request type differs by libc (c_int on musl, c_ulong on glibc);
        // `as _` lets the compiler pick the right width per target.
        if libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut ifr) < 0 {
            eprintln!("k9o-init: lo bring-up: SIOCGIFFLAGS failed: {}", io::Error::last_os_error());
            libc::close(fd);
            return;
        }
        ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        if libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &ifr) < 0 {
            eprintln!("k9o-init: lo bring-up: SIOCSIFFLAGS failed: {}", io::Error::last_os_error());
        }
        libc::close(fd);
    }
}
