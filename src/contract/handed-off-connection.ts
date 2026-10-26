import type { Duplex } from "node:stream";

/**
 * The membrane → handler boundary.
 *
 * Firelock's whole job is: confine the guest, accept its single vsock connection, and hand that
 * connection off to a handler. What crosses the boundary is exactly one thing — the connected guest
 * stream. Firelock reads NOTHING off it: no framing, no header, no body. "The fd handoff IS the
 * contract" (docs/wire-contract.md). Everything above the bytes is the handler's.
 *
 * The stream is modeled as a Node `Duplex` because that is what the fd relay actually delivers: once the
 * substrate carve lands, the SCM_RIGHTS-received fd is wrapped as a `net.Socket` (a Duplex) and handed
 * over here. Modeling it as a stream — rather than a bag of `readFrame()`/`writeResult()` methods — keeps
 * the boundary faithful to "a connected socket, nothing interpreted" and lets a handler feed it to a real
 * HTTP parser instead of inventing one.
 *
 * A handler is any {@link ExecHandler}. Two exist in this ecosystem:
 *   • the OSS default — an HTTP reverse proxy (see ../handlers/http-reverse-proxy) that pumps the stream
 *     into the runtime's own HTTP server and forwards upstream. Usable on its own, day one.
 *   • the platform handler (proprietary, not in this repo) — reads an adjudicated frame, verifies a
 *     capability receipt, brokers a credentialled egress. Firelock cannot tell them apart, and does not
 *     try: it hands over the stream and is done.
 */
export interface HandedOffConnection {
  /** The connected guest stream — raw, full-duplex bytes. The handler owns everything from here. */
  readonly socket: Duplex;

  /** Release the connection (single-use). Idempotent; always called by the accept loop in a `finally`. */
  close(): Promise<void>;
}
