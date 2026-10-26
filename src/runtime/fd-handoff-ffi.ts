/**
 * `bun:ffi` binding for the exec substrate (`firelock-fd-handoff` cdylib).
 *
 * The dispatcher (SEND side) and the executor (RECV side) are TypeScript;
 * the SCM_RIGHTS fd-passing lives in the Rust `firelock-fd-handoff` crate (which gets
 * the cmsg construction + the exactly-one-fd / MSG_CTRUNC fail-closed guards
 * right, and is real-fd unit-tested). This loads its cdylib and wraps the two
 * C-ABI entry points — using a standard dlopen pattern.
 *
 *   - `sendHandoff(controlFd, connFd, payload)` — the dispatcher: forward the
 *     guest connection fd `C` + the handoff envelope (see `handoff-envelope.ts`)
 *     to the executor. Takes ownership of `connFd` — the native side closes the
 *     sender's copy on EVERY path, so structural single-use holds. Do NOT use
 *     `connFd` after this call.
 *   - `recvHandoff(controlFd)` — the executor: receive `{ connFd, payload }`. The
 *     returned `connFd` is now owned by this process (close it after writing the
 *     result). `payload` is the handoff envelope to `decodeHandoffEnvelope`.
 *
 * The substrate stays parse-free: it moves `payload` bytes opaquely; the envelope
 * structure lives entirely in `handoff-envelope.ts`.
 */

import { dlopen, FFIType, ptr, suffix, read } from "bun:ffi";
import { HANDOFF_MAX_ENVELOPE_BYTES } from "./handoff-envelope.ts";

function resolveLibraryPath(): string {
  const explicit = process.env.K9O_FD_HANDOFF_LIB_PATH;
  if (explicit !== undefined && explicit.length > 0) return explicit;
  // Default to the cargo build output in the shared cargo target directory (override with K9O_CARGO_TARGET_DIR).
  const base = process.env.K9O_CARGO_TARGET_DIR ?? `${process.env.HOME}/work/.shared-cargo-target`;
  return `${base}/release/libfirelock_fd_handoff.${suffix}`;
}

/**
 * 🔴 THE dlopen IS LAZY, AND THAT IS LOAD-BEARING.
 *
 * This used to run at MODULE SCOPE — the library was opened at import, not at first use. That
 * silently falsified the invariant the dispatcher states in its own header: *"the app image /
 * CI, which carry no executor runtime, are unaffected and never require the `.so` at import."* That
 * was true while nothing in the app graph imported the seam; a later change wired the seam bootstrap into
 * the app, so the graph now reaches this module and an eager open became fatal for any context
 * without the library. CI found it (an end-to-end suite died at import with ERR_DLOPEN_FAILED), but the
 * same shape is a PRODUCTION fragility: an app image missing the `.so` would fail at BOOT, on an
 * import it never meant to depend on.
 *
 * Resolving on first use restores the stated invariant and keeps non-exec contexts free of the
 * native dependency. It does NOT weaken the exec path: the first real send/recv still fails closed
 * if the library is missing or unopenable.
 *
 * 🔴 The property eagerness DID buy — a missing library failing the executor at STARTUP rather than at
 * first invoke — is preserved deliberately by {@link loadFdHandoffLibrary}, which the host's
 * bootstrap calls during bring-up. Lazy-by-default plus an explicit force-resolve at the one place that must
 * fail fast is strictly better than eager-everywhere: it keeps the loud startup failure exactly
 * where the sidecar deploy depends on it, without imposing the dependency on every importer.
 */
type FdHandoffSymbols = ReturnType<typeof openLibrary>["symbols"];

function openLibrary() {
  return dlopen(resolveLibraryPath(), {
  // int firelock_fd_handoff_send(int control_fd, int conn_fd, const u8* payload, usize len)
  firelock_fd_handoff_send: {
    args: [FFIType.i32, FFIType.i32, FFIType.ptr, FFIType.u64],
    returns: FFIType.i32,
  },
  // int firelock_fd_handoff_recv(int control_fd, u8* payload_out, usize cap, usize* len_out)
  firelock_fd_handoff_recv: {
    args: [FFIType.i32, FFIType.ptr, FFIType.u64, FFIType.ptr],
    returns: FFIType.i32,
  },
  // Demuxing recv: rc = 1 handoff (fd in *fd_out) / 0 data frame / <0 -errno. NEW symbol
  // (ABI-skew discipline). The fd guards (CLOEXEC/ctrunc/exhaustion) are enforced native-side in recv_control_frame.
  firelock_control_recv: {
    args: [FFIType.i32, FFIType.ptr, FFIType.u64, FFIType.ptr, FFIType.ptr],
    returns: FFIType.i32,
  },
  // isize firelock_fd_write(int fd, const u8* buf, usize len)
  firelock_fd_write: {
    args: [FFIType.i32, FFIType.ptr, FFIType.u64],
    returns: FFIType.i64,
  },
  // int firelock_fd_close(int fd)
  firelock_fd_close: {
    args: [FFIType.i32],
    returns: FFIType.i32,
  },
  // int firelock_fd_set_recv_timeout(int control_fd, u32 timeout_ms) (bounds a wedged recvHandoff)
  firelock_fd_set_recv_timeout: {
    args: [FFIType.i32, FFIType.u32],
    returns: FFIType.i32,
  },
  // int firelock_fd_clear_nonblock(int control_fd) — U3/U4 send-side symmetry (clears O_NONBLOCK on the
  // dispatcher SEND fd, mirroring the recv-side clear inside set_recv_timeout).
  firelock_fd_clear_nonblock: {
    args: [FFIType.i32],
    returns: FFIType.i32,
  },
  });
}

let cached: FdHandoffSymbols | null = null;

/** Resolve (and memoise) the native symbols. Throws if the library cannot be opened. */
function syms(): FdHandoffSymbols {
  if (cached === null) cached = openLibrary().symbols;
  return cached;
}

/**
 * Force the library to resolve NOW, so a missing/unopenable `.so` fails LOUDLY AT STARTUP instead of
 * at the first handoff. Called by the host bootstrap: the sidecar must not come up "healthy" and
 * then fail on the first real invocation — a sidecar that cannot start is the loud, immediate signal
 * the deploy gate depends on. Safe to call repeatedly (memoised).
 */
export function loadFdHandoffLibrary(): void {
  syms();
}

/** A native call failed; `errno` is the positive errno the native side returned. */
export class FdHandoffError extends Error {
  readonly errno: number;
  constructor(op: string, errno: number) {
    super(`firelock-fd-handoff ${op} failed: errno ${errno}`);
    this.name = "FdHandoffError";
    this.errno = errno;
  }
}

/**
 * Dispatcher SEND. Passes `connFd` + `payload` to the executor over `controlFd`
 * (the host-internal AF_UNIX control socket). Consumes `connFd` (native side
 * closes the sender's copy). Throws {@link FdHandoffError} on failure.
 *
 * 🔴 `onRelinquish` marks the POINT OF NO RETURN for `connFd`. The native
 * `firelock_fd_handoff_send` takes the fd by value and closes the sender's copy on EVERY path — the
 * error return included. So the moment we invoke it, `connFd` is gone regardless of outcome, and the
 * caller must NOT `close()`/`destroy()` it (that would double-close a possibly-reused descriptor).
 * The two throws BELOW `onRelinquish` mean the fd IS relinquished; the two guards ABOVE it (empty
 * payload, and a `syms()` dlopen failure) throw with the fd STILL the caller's — `onRelinquish` has
 * not fired, so the caller keeps ownership. This callback is how the caller learns which case it is,
 * because the throw alone cannot distinguish them. Replaces the old `detachGuestFd` handle-poke,
 * which was inert on Bun (getter-only `_handle.fd`; `destroy()` closes an internal fd anyway).
 */
export function sendHandoff(
  controlFd: number,
  connFd: number,
  payload: Uint8Array,
  onRelinquish?: () => void,
): void {
  if (payload.length === 0) throw new FdHandoffError("send", /* EINVAL */ 22); // pre-native: fd still ours
  const send = syms().firelock_fd_handoff_send; // resolve the lib FIRST — a dlopen throw here is pre-native
  onRelinquish?.(); // native is about to take ownership; from here connFd is closed on every path
  const rc = Number(send(controlFd, connFd, ptr(payload), BigInt(payload.length)));
  if (rc !== 0) throw new FdHandoffError("send", -rc); // post-native: fd already closed by the native side
}

/**
 * Executor RECV. Receives `{ connFd, payload }` on `controlFd`. The returned
 * `connFd` is owned by this process — close it after writing the result. Throws
 * {@link FdHandoffError} on failure (incl. the fail-closed guards: not-exactly-one
 * fd, MSG_CTRUNC).
 */
export function recvHandoff(controlFd: number): { connFd: number; payload: Uint8Array } {
  const buf = new Uint8Array(HANDOFF_MAX_ENVELOPE_BYTES);
  const lenOut = new BigUint64Array(1); // usize out-param
  const rc = Number(syms().firelock_fd_handoff_recv(controlFd, ptr(buf), BigInt(buf.length), ptr(lenOut)));
  if (rc < 0) throw new FdHandoffError("recv", -rc);
  const n = Number(lenOut[0]);
  return { connFd: rc, payload: buf.slice(0, n) };
}

/** A demuxed control-channel frame: a HANDOFF (guest conn fd + byte-clean payload) or a data frame
 *  (no fd). The executor's accept loop calls this instead of {@link recvHandoff} to discriminate handoff vs data
 *  by fd-presence (the A2 demux). The native side enforces CLOEXEC / MSG_CTRUNC-reject / fd-exhaustion. */
export type ControlFrame =
  | { readonly kind: "handoff"; readonly connFd: number; readonly payload: Uint8Array }
  | { readonly kind: "data"; readonly payload: Uint8Array };

export function recvControlFrame(controlFd: number): ControlFrame {
  const buf = new Uint8Array(HANDOFF_MAX_ENVELOPE_BYTES);
  const lenOut = new BigUint64Array(1);
  const fdOut = new Int32Array(1);
  const rc = Number(syms().firelock_control_recv(controlFd, ptr(buf), BigInt(buf.length), ptr(lenOut), ptr(fdOut)));
  if (rc < 0) throw new FdHandoffError("control_recv", -rc);
  const payload = buf.slice(0, Number(lenOut[0]));
  // rc === 1 → handoff (fd_out set); rc === 0 → data frame (no fd).
  return rc === 1 ? { kind: "handoff", connFd: fdOut[0]!, payload } : { kind: "data", payload };
}

/**
 * Write the executor's framed result (or refusal) back on the handed-off
 * connection `connFd`. RAW write — the substrate moves these exact bytes verbatim,
 * never re-frames or buffers, so the byte path stays non-interposed (the executor's isolation topology). Writes ALL of `bytes` (native side loops on partial writes).
 * Throws {@link FdHandoffError} on failure. Does NOT close `connFd` — call
 * {@link closeConn} after the last write.
 */
export function writeConn(connFd: number, bytes: Uint8Array): void {
  if (bytes.length === 0) return;
  const rc = Number(syms().firelock_fd_write(connFd, ptr(bytes), BigInt(bytes.length)));
  if (rc < 0) throw new FdHandoffError("write", -rc);
  if (rc !== bytes.length) throw new FdHandoffError("write", /* EPIPE — short write, peer closed */ 32);
}

/**
 * Close the handed-off connection `connFd` after the result is written. The executor
 * is its sole owner post-{@link recvHandoff} (structural single-use), so this is the
 * one close of that fd. Throws {@link FdHandoffError} on failure.
 */
export function closeConn(connFd: number): void {
  const rc = Number(syms().firelock_fd_close(connFd));
  if (rc < 0) throw new FdHandoffError("close", -rc);
}

/**
 * `errno` value that means "the receive timed out, nothing arrived" — EAGAIN on Linux, and the
 * SAME numeric value doubles as EWOULDBLOCK there (POSIX permits but does not require the two to
 * be distinct; Linux defines them identically). macOS gives them distinct values, and since the
 * kernel is free to return either for a timed-out `recvmsg`, the accept loop must accept both.
 *
 * 🔴 NOT `11` HARDCODED AT THE CALL SITE. The prior form of this fix (the tripwire in
 * `exec-accept-loop.test.ts`) used the literal `11` because that is Linux's value and Linux is the
 * only place the executor actually runs (topology: dedicated executor process, Firecracker/Linux). A
 * named export here still lets a macOS dev run pick up `EWOULDBLOCK` (35) without the accept loop
 * needing to know it is platform-dependent — `process.platform` is checked ONCE, here, not at every
 * call site that might need to recognise an idle tick.
 */
export const EAGAIN: 11 = 11;
export const EWOULDBLOCK: number = process.platform === "darwin" ? 35 : EAGAIN;

/**
 * Bound every future `recvHandoff` on `controlFd` to at most `timeoutMs` so a wedged receive cannot hang forever.
 *
 * A `recvHandoff` that would otherwise block forever (an idle executor, nothing arriving) instead
 * throws {@link FdHandoffError} with `errno` `EAGAIN`/`EWOULDBLOCK` after `timeoutMs`. This is a
 * SOCKET-LEVEL setting (`SO_RCVTIMEO`) applied once, not a per-call deadline — a JS-side deadline
 * cannot substitute, because `recvHandoff` blocks the thread and a racing `setTimeout` never fires.
 *
 * Call ONCE, after `controlFd` is established (accept or socketpair) and before the accept loop
 * starts. `timeoutMs` must be > 0 — the native side refuses `0` rather than silently treating it as
 * "no timeout", which would restore the original unbounded-block hazard invisibly.
 *
 * ⚠️ The caller (the accept loop) MUST treat an `EAGAIN`/`EWOULDBLOCK` `receiveFault` as an IDLE TICK
 * — do not accumulate it toward the persistent-fault terminal, or an idle executor with no traffic will
 * exhaust the budget and crash-loop. See `exec-accept-loop.ts`'s tripwire for why this is the shape
 * that must not regress.
 */
export function setRecvTimeout(controlFd: number, timeoutMs: number): void {
  if (!(timeoutMs > 0)) throw new FdHandoffError("set_recv_timeout", /* EINVAL */ 22);
  const rc = Number(syms().firelock_fd_set_recv_timeout(controlFd, timeoutMs));
  if (rc !== 0) throw new FdHandoffError("set_recv_timeout", -rc);
}

/**
 * Clear `O_NONBLOCK` on the dispatcher's SEND control fd (U3/U4). The fd is `dup`'d from a libuv/Bun socket
 * and inherits `O_NONBLOCK`, but nothing cleared it — so `send_conn_fd`'s single non-retrying `sendmsg`
 * EAGAINs under back-pressure and drops the guest connection. Call ONCE at seam setup so the send BLOCKS
 * like the recv side (which clears it via {@link setRecvTimeout}). Idempotent. Must be done in native code:
 * `bun:ffi` cannot call the variadic `fcntl(F_SETFL, …)` (the flag would silently no-op — measured).
 */
export function clearNonblock(controlFd: number): void {
  const rc = Number(syms().firelock_fd_clear_nonblock(controlFd));
  if (rc !== 0) throw new FdHandoffError("clear_nonblock", -rc);
}
