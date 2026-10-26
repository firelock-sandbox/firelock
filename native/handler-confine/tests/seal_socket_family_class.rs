//! REAL-KERNEL proof that the socket deny is COMPLETE-CLASS over address families —
//! not a point-check on the two families someone happened to enumerate.
//!
//! WHY THIS FILE EXISTS. `policy.rs`'s deny-class entry reads *"socket — ALL address families
//! incl AF_UNIX (complete-class; the AF_UNIX host-UDS hole)"*, and the design
//! carries it as a complete-class claim. The empirical backing was
//! `socket_af_unix_dies_sigsys` + `socket_af_inet_dies_sigsys` in `seal_kernel.rs` — **two
//! families.** Two is a sample; the claim is a class. *A review of a deny list is a complete-class
//! enumeration, not a point-check, and the predicate must come from the THREAT rather than
//! from the families that happened to get written down.*
//!
//! THE MECHANISM IS ALREADY RIGHT, AND THAT IS WORTH STATING PRECISELY so this file is not
//! mistaken for a fix. `STEADY_ALLOWLIST` does not contain `socket`, and the filter's default
//! action is `KILL_PROCESS` — so the deny **never inspects the family argument at all** and
//! cannot be family-scoped even in principle. This file does not make the deny complete; it
//! makes the completeness OBSERVABLE, which is the difference between a property and a
//! property somebody has to take on trust.
//!
//! Run: `cargo test --release --test seal_socket_family_class` on a real Linux kernel.

use firelock_handler_confine::policy::WxPosture;
use firelock_handler_confine::seccomp::seal;

#[derive(Debug, PartialEq)]
enum Outcome {
    Survived,
    KilledSigsys,
    Other(i32),
}

fn run_child<F: FnOnce()>(offend: F) -> Outcome {
    unsafe {
        let pid = libc::fork();
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            offend();
            libc::_exit(0);
        }
        let mut status: libc::c_int = 0;
        libc::waitpid(pid, &mut status, 0);
        if libc::WIFSIGNALED(status) {
            if libc::WTERMSIG(status) == libc::SIGSYS {
                Outcome::KilledSigsys
            } else {
                Outcome::Other(libc::WTERMSIG(status))
            }
        } else if libc::WIFEXITED(status) {
            match libc::WEXITSTATUS(status) {
                0 => Outcome::Survived,
                n => Outcome::Other(-n),
            }
        } else {
            Outcome::Other(-999)
        }
    }
}

/// Seal, then prove we are STILL RUNNING under it before the offending call. `_exit(42)` on a
/// failed seal and `_exit(43)` if the allowlisted probe itself died — so "the seal broke" and
/// "the child never got to the socket call" are distinguishable from a genuine SIGSYS, and a
/// per-family pass can never be the accident of a child that died early for another reason.
fn seal_and_confirm_live() {
    if seal(WxPosture::StrictNoExec).is_err() {
        unsafe { libc::_exit(42) };
    }
    // getpid is allowlisted: it must succeed under the seal. If the filter were killing
    // everything, every family below would "pass" for the wrong reason.
    let pid = unsafe { libc::syscall(libc::SYS_getpid) };
    if pid <= 0 {
        unsafe { libc::_exit(43) };
    }
}

/// Every address family Linux 6.8 defines, by number and name. Names carry no semantics here —
/// they exist so a failure says WHICH family got through rather than printing an integer.
const FAMILIES: &[(libc::c_int, &str)] = &[
    (0, "AF_UNSPEC"),
    (1, "AF_UNIX"),
    (2, "AF_INET"),
    (3, "AF_AX25"),
    (4, "AF_IPX"),
    (5, "AF_APPLETALK"),
    (6, "AF_NETROM"),
    (7, "AF_BRIDGE"),
    (8, "AF_ATMPVC"),
    (9, "AF_X25"),
    (10, "AF_INET6"),
    (11, "AF_ROSE"),
    (12, "AF_DECnet"),
    (13, "AF_NETBEUI"),
    (14, "AF_SECURITY"),
    (15, "AF_KEY"),
    (16, "AF_NETLINK"),
    (17, "AF_PACKET"),
    (18, "AF_ASH"),
    (19, "AF_ECONET"),
    (20, "AF_ATMSVC"),
    (21, "AF_RDS"),
    (22, "AF_SNA"),
    (23, "AF_IRDA"),
    (24, "AF_PPPOX"),
    (25, "AF_WANPIPE"),
    (26, "AF_LLC"),
    (27, "AF_IB"),
    (28, "AF_MPLS"),
    (29, "AF_CAN"),
    (30, "AF_TIPC"),
    (31, "AF_BLUETOOTH"),
    (32, "AF_IUCV"),
    (33, "AF_RXRPC"),
    (34, "AF_ISDN"),
    (35, "AF_PHONET"),
    (36, "AF_IEEE802154"),
    (37, "AF_CAIF"),
    (38, "AF_ALG"),
    (39, "AF_NFC"),
    (40, "AF_VSOCK"),
    (41, "AF_KCM"),
    (42, "AF_QIPCRTR"),
    (43, "AF_SMC"),
    (44, "AF_XDP"),
    (45, "AF_MCTP"),
];

// ── THE CLASS ENUMERATION ─────────────────────────────────────────────────────────────
#[test]
fn socket_dies_sigsys_for_every_address_family() {
    // Collects ALL survivors rather than asserting per-family, so a failure names the complete
    // set that got through. Stopping at the first would report one family and leave the size of
    // the hole unknown — the same "instance count is not the class" problem the enumeration
    // exists to solve.
    let mut survivors: Vec<String> = Vec::new();
    for &(family, name) in FAMILIES {
        let o = run_child(|| {
            seal_and_confirm_live();
            unsafe {
                libc::syscall(libc::SYS_socket, family, libc::SOCK_STREAM, 0);
            }
        });
        if o != Outcome::KilledSigsys {
            survivors.push(format!("{name}({family}) -> {o:?}"));
        }
    }
    assert!(
        survivors.is_empty(),
        "socket() must be denied for EVERY address family; these were not killed with SIGSYS: {survivors:?}"
    );
}

// ── The deny does not depend on the family VALUE at all ──────────────────────────────────
#[test]
fn socket_dies_sigsys_even_for_families_the_kernel_does_not_know() {
    // AF_MAX is 46 on 6.8, so these are families the kernel would reject with EAFNOSUPPORT if
    // the call ever reached it. Under the filter they die at the syscall gate FIRST. That is the
    // positive demonstration that the deny is keyed on the syscall number and never on the
    // family — i.e. no future family can be added to the kernel and slip through, which is the
    // property a point-list of today's families could never establish.
    let mut survivors: Vec<String> = Vec::new();
    for family in [46, 47, 60, 100, 255] {
        let o = run_child(|| {
            seal_and_confirm_live();
            unsafe {
                libc::syscall(libc::SYS_socket, family, libc::SOCK_STREAM, 0);
            }
        });
        if o != Outcome::KilledSigsys {
            survivors.push(format!("family {family} -> {o:?}"));
        }
    }
    assert!(
        survivors.is_empty(),
        "socket() must be denied regardless of family value, including undefined ones: {survivors:?}"
    );
}

// ── The deny does not depend on the socket TYPE either ───────────────────────────────────
#[test]
fn socket_dies_sigsys_across_socket_types_for_the_highest_risk_families() {
    // The threat families specifically: AF_UNIX reaches the Firecracker API UDS (VM-lifecycle
    // control), AF_VSOCK is the guest transport, AF_NETLINK/AF_PACKET are kernel + raw-frame
    // surfaces. SOCK_RAW is included because it is the shape that needs no connect() to matter.
    let mut survivors: Vec<String> = Vec::new();
    for &(family, name) in &[
        (1, "AF_UNIX"),
        (40, "AF_VSOCK"),
        (16, "AF_NETLINK"),
        (17, "AF_PACKET"),
    ] {
        for &(ty, tyname) in &[
            (libc::SOCK_STREAM, "SOCK_STREAM"),
            (libc::SOCK_DGRAM, "SOCK_DGRAM"),
            (libc::SOCK_RAW, "SOCK_RAW"),
        ] {
            let o = run_child(|| {
                seal_and_confirm_live();
                unsafe {
                    libc::syscall(libc::SYS_socket, family, ty, 0);
                }
            });
            if o != Outcome::KilledSigsys {
                survivors.push(format!("{name}/{tyname} -> {o:?}"));
            }
        }
    }
    assert!(
        survivors.is_empty(),
        "socket() must be denied for every (family, type): {survivors:?}"
    );
}

// ── socketpair is the second fd-creating door in the same class ───────────────────────────
#[test]
fn socketpair_dies_sigsys_for_every_family_that_supports_it() {
    // `socketpair` is listed in the same deny class and creates TWO fds without any address, so
    // a filter that covered `socket` alone would leave a local channel open. AF_UNIX is the only
    // family that really implements it, but the assertion runs the same class for the same
    // reason the enumeration above does.
    let mut survivors: Vec<String> = Vec::new();
    for &(family, name) in &[(1, "AF_UNIX"), (2, "AF_INET"), (40, "AF_VSOCK")] {
        let o = run_child(|| {
            seal_and_confirm_live();
            let mut sv: [libc::c_int; 2] = [-1, -1];
            unsafe {
                libc::syscall(
                    libc::SYS_socketpair,
                    family,
                    libc::SOCK_STREAM,
                    0,
                    sv.as_mut_ptr(),
                );
            }
        });
        if o != Outcome::KilledSigsys {
            survivors.push(format!("{name}({family}) -> {o:?}"));
        }
    }
    assert!(
        survivors.is_empty(),
        "socketpair() must be denied: {survivors:?}"
    );
}

// ── NEGATIVE CONTROL — the assertion above CAN fail ───────────────────────────────────
#[test]
fn unsealed_socket_survives_so_the_enumeration_is_not_vacuous() {
    // Without this, every assertion in this file would pass identically on a kernel where
    // `socket()` is unavailable for some unrelated reason, or in a harness where the child dies
    // before reaching the call. This proves the discriminating power directly: the SAME call, in
    // the SAME harness, with the ONLY difference being the seal, SURVIVES.
    //
    // AF_UNIX is used deliberately — it is the family the threat model cares about most and the
    // one an IP-only filter would have left open, so this also demonstrates that AF_UNIX
    // sockets are genuinely creatable on this host and the sealed result is a real refusal.
    let o = run_child(|| unsafe {
        let fd = libc::syscall(libc::SYS_socket, libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd < 0 {
            libc::_exit(44); // socket() unavailable for an unrelated reason — would invalidate the class tests
        }
        libc::close(fd as libc::c_int);
    });
    assert_eq!(
        o,
        Outcome::Survived,
        "UNSEALED socket(AF_UNIX) must succeed — otherwise the sealed assertions prove nothing"
    );
}
