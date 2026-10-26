//! The seccomp-bpf filter builder + install (the SEAL).
//!
//! Assembles a classic-BPF `sock_filter` program from [`crate::policy`] and installs it with
//! `SECCOMP_FILTER_FLAG_TSYNC` so ALL threads (incl. the pre-created pool) are covered
//! atomically. Default action = `SECCOMP_RET_KILL_PROCESS` — an UNCATCHABLE kill (a
//! `SIGSYS` a handler could trap would let a compromised handler probe/continue). Structure:
//!
//!   1. load `arch`; if != x86_64 → KILL (blocks i386/x32 syscall-ABI confusion).
//!   2. load `nr`; if the x32 bit (0x4000_0000) is set → KILL.
//!   3. per allowlisted syscall: `JEQ nr → RET_ALLOW` (arg-filtered ones get an inline block).
//!   4. default → `RET_KILL_PROCESS`.
//!
//! Arg-filters (only where the discriminant is a SCALAR register — seccomp-bpf can't deref a
//! pointer): `mmap` prot/flags, `mprotect` prot, `fcntl` cmd. Under [`WxPosture::StrictNoExec`]
//! the `mmap`/`mprotect` blocks deny `PROT_EXEC` (W^X); under [`WxPosture::JitRelaxed`] they
//! permit it (a JIT handler needs exec pages) — the contingent W^X leg.

use crate::policy::{ArgFilter, WxPosture, STEADY_ALLOWLIST};
use libc::{c_int, c_ulong};

// ── seccomp / BPF ABI constants (stable kernel ABI; defined here so the build never depends
//    on a given libc version exporting them) ─────────────────────────────────────────────
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const SECCOMP_SET_MODE_FILTER: c_ulong = 1;
const SECCOMP_FILTER_FLAG_TSYNC: c_ulong = 1;

// seccomp_data field byte offsets: { u32 nr; u32 arch; u64 ip; u64 args[6]; }
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const fn off_arg(n: u32) -> u32 {
    16 + n * 8 // args[] starts at 16; low 32 bits of arg n (little-endian) at 16 + n*8
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}
const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Build the classic-BPF program for `posture`. Pure (no syscalls); private to the seal
/// (`SockFilter` is a private ABI type — callers install via [`seal`]).
fn build_filter(posture: WxPosture) -> Vec<SockFilter> {
    let mut p: Vec<SockFilter> = Vec::new();

    // 1. arch gate — wrong arch is an uncatchable kill.
    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH));
    p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0)); // eq → skip the kill
    p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // 2. load nr; kill any x32-ABI syscall (high bit set) — else an x32 alias could dodge a
    //    number-matched allow/deny.
    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));
    p.push(jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1)); // >= x32 bit → fall to kill
    p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // 3. allowlist. `nr` is already in the accumulator; each block re-loads it first so a
    //    preceding arg-filter block (which clobbers the accumulator with an arg word) doesn't
    //    corrupt the next nr compare.
    for rule in STEADY_ALLOWLIST {
        let nr = rule.k_nr();
        match rule.filter {
            None => {
                // [JEQ nr → ALLOW] : match ⇒ fall to RET_ALLOW; miss ⇒ skip it.
                p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));
                p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
                p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
            }
            Some(ArgFilter::Mmap) => emit_mmap_block(&mut p, nr, posture),
            Some(ArgFilter::Mprotect) => emit_mprotect_block(&mut p, nr, posture),
            Some(ArgFilter::FcntlCmd) => emit_fcntl_block(&mut p, nr),
        }
    }

    // 4. default — deny-by-default kill (the complete-class mechanism).
    p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    p
}

// mmap: require MAP_ANONYMOUS; under StrictNoExec additionally require PROT_EXEC clear.
// Layout (offsets relative to block start s):
//   s+0 LD nr
//   s+1 JEQ mmap ? continue : skip block
//   s+2 LD flags(arg3)
//   s+3 JSET MAP_ANONYMOUS ? continue : KILL      (anon required)
//   s+4 LD prot(arg2)
//   s+5 JSET PROT_EXEC ? KILL : ALLOW             (strict only; relaxed → ALLOW unconditionally)
//   s+6 RET_ALLOW
//   s+7 RET_KILL   (inline miss/deny target)
fn emit_mmap_block(p: &mut Vec<SockFilter>, nr: u32, posture: WxPosture) {
    let anon = libc::MAP_ANONYMOUS as u32;
    let exec = libc::PROT_EXEC as u32;
    if posture == WxPosture::StrictNoExec {
        // 8-instruction block; s+7 is the inline KILL.
        p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR)); // s+0
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 6)); // s+1: miss → skip s+2..s+7
        p.push(stmt(BPF_LD | BPF_W | BPF_ABS, off_arg(3))); // s+2 flags
        p.push(jump(BPF_JMP | BPF_JSET | BPF_K, anon, 0, 3)); // s+3: anon set→cont; clear→KILL(s+7)
        p.push(stmt(BPF_LD | BPF_W | BPF_ABS, off_arg(2))); // s+4 prot
        p.push(jump(BPF_JMP | BPF_JSET | BPF_K, exec, 1, 0)); // s+5: exec set→KILL(s+7); clear→ALLOW
        p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)); // s+6
        p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)); // s+7
    } else {
        // JitRelaxed: anon still required (no file-backed maps), PROT_EXEC permitted.
        p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR)); // s+0
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 4)); // s+1: miss → skip s+2..s+5
        p.push(stmt(BPF_LD | BPF_W | BPF_ABS, off_arg(3))); // s+2 flags
        p.push(jump(BPF_JMP | BPF_JSET | BPF_K, anon, 0, 1)); // s+3: anon set→ALLOW; clear→KILL(s+5)
        p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)); // s+4
        p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)); // s+5
    }
}

// mprotect: under StrictNoExec deny adding PROT_EXEC (no RW→RX flip); relaxed → allow.
fn emit_mprotect_block(p: &mut Vec<SockFilter>, nr: u32, posture: WxPosture) {
    if posture == WxPosture::StrictNoExec {
        let exec = libc::PROT_EXEC as u32;
        p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR)); // s+0
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 4)); // s+1: miss → skip s+2..s+5
        p.push(stmt(BPF_LD | BPF_W | BPF_ABS, off_arg(2))); // s+2 prot
        p.push(jump(BPF_JMP | BPF_JSET | BPF_K, exec, 1, 0)); // s+3: exec set→KILL(s+5); clear→ALLOW
        p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)); // s+4
        p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)); // s+5
    } else {
        p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
        p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }
}

// fcntl: allow only cmd ∈ {F_GETFL, F_SETFL, F_GETFD, F_SETFD} (arg0 = cmd, scalar).
fn emit_fcntl_block(p: &mut Vec<SockFilter>, nr: u32) {
    let cmds: [u32; 4] = [
        libc::F_GETFL as u32,
        libc::F_SETFL as u32,
        libc::F_GETFD as u32,
        libc::F_SETFD as u32,
    ];
    // Block after s+1 = [LD cmd][JEQ×n][RET_KILL][RET_ALLOW] = n+3 instructions. Terminals are
    // ordered KILL-then-ALLOW: a no-match falls THROUGH the last JEQ into RET_KILL; a match
    // JUMPS OVER the RET_KILL to RET_ALLOW. (The earlier ALLOW-then-KILL order let a no-match
    // fall into ALLOW — the F_SETLK-survived bug.)
    let n = cmds.len();
    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR)); // s+0
    p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, (n as u8) + 3)); // s+1: miss fcntl → skip block
    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, off_arg(1))); // s+2: cmd (fcntl's cmd is arg index 1)
    for (i, cmd) in cmds.iter().enumerate() {
        // JEQ_i at s+3+i; RET_ALLOW at s+4+n → jt = (s+4+n)-(s+3+i)-1 = n-i. Miss (jf=0) falls
        // to the next JEQ, and the last one falls into RET_KILL at s+3+n.
        let jt = (n - i) as u8;
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *cmd, jt, 0)); // s+3+i
    }
    p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)); // s+3+n: denied cmd (fall-through)
    p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)); // s+4+n: allowed cmd (jump target)
}

/// Errno of the last failed op — the confinement install is fail-closed (a caller that can't
/// seal must NOT proceed to read a guest byte; the executor treats a non-zero return as fatal).
#[derive(Debug)]
pub struct SealError {
    pub op: &'static str,
    pub errno: c_int,
}

/// Install the steady-state filter for `posture` — THE SEAL (Phase B, before first guest byte).
/// Sets `no_new_privs` (required to install a filter unprivileged; also prevents a suid-exec
/// dodge) then `seccomp(SET_MODE_FILTER, TSYNC, &prog)`. TSYNC covers every thread in the
/// group atomically or fails (so a pre-created sibling can never stay unconfined). After this
/// returns `Ok`, only the allowlist survives — everything else is an uncatchable kill.
pub fn seal(posture: WxPosture) -> Result<(), SealError> {
    // SAFETY: direct prctl/seccomp syscalls; the program Vec outlives the seccomp() call.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(SealError {
                op: "prctl(NO_NEW_PRIVS)",
                errno: errno(),
            });
        }
        let prog_vec = build_filter(posture);
        let fprog = SockFprog {
            len: prog_vec.len() as u16,
            filter: prog_vec.as_ptr(),
        };
        let rc = libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC,
            &fprog as *const SockFprog,
        );
        if rc != 0 {
            return Err(SealError {
                op: "seccomp(SET_MODE_FILTER, TSYNC)",
                errno: errno(),
            });
        }
    }
    Ok(())
}

fn errno() -> c_int {
    // SAFETY: __errno_location is always valid.
    unsafe { *libc::__errno_location() }
}
