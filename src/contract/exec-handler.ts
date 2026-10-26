import type { HandedOffConnection } from "./handed-off-connection.ts";

/**
 * An `ExecHandler` is what Firelock hands each confined guest connection to. It is the ONE injection
 * seam of the membrane: Firelock owns confinement + the fd relay and knows nothing about protocols; the
 * handler owns everything from the stream onward (parse, route, govern the body, respond).
 *
 * Contract:
 *   • NEVER throws. Every path returns an {@link ExecOutcome}. A handler that threw would let one poisoned
 *     guest connection kill the accept loop; the loop treats a thrown handler as a fail-closed
 *     `handler_error` outcome, but handlers must not rely on that.
 *   • Single-use. The connection is consumed once and closed by the loop in a `finally`.
 *   • Fail-closed. When in doubt, write a refusal on the connection and return a non-egressed outcome —
 *     never leak upstream detail to the guest.
 *
 * The returned {@link ExecOutcome} is a TRANSPORT-level result (did the exchange complete, or fail before
 * one). A handler that parses an application protocol (like the HTTP reverse proxy) surfaces richer
 * per-request detail — status, refusal class — through its own `onOutcome` hook, fired from where that
 * detail is actually known. The loop's return value stays coarse and honest by design.
 */
export type ExecHandler = (conn: HandedOffConnection) => Promise<ExecOutcome>;

/**
 * The result of handling one guest connection — telemetry/forensics only (Firelock does not adjudicate,
 * so this is never an authorization record). `egressed: true` means the exchange completed; `status`
 * is present when the handler parsed a response status (e.g. the reverse proxy's `onOutcome` path) and
 * absent for a pure transport-level completion. `egressed: false` carries a fail-closed reason.
 */
export type ExecOutcome =
  | { egressed: true; status?: number; upstream?: string }
  | { egressed: false; failure: ExecFailure };

/** Why a handler refused or could not complete — coarse, non-sensitive classes for telemetry. */
export type ExecFailure =
  /** The guest bytes were not a well-formed request for this handler's protocol. */
  | { kind: "malformed_request"; detail?: string }
  /** No upstream is configured/registered for this request. */
  | { kind: "no_upstream" }
  /** The upstream was unreachable or the transport failed. */
  | { kind: "upstream_error"; detail?: string }
  /** The upstream returned a redirect the handler refuses to follow (SSRF / credential-resend guard). */
  | { kind: "redirect_blocked"; detail?: string }
  /** The request exceeded a configured bound (e.g. body over the cap). */
  | { kind: "bounds_exceeded"; detail?: string }
  /** The handler itself faulted at the transport layer (connect/pump error) — surfaced fail-closed. */
  | { kind: "handler_error"; detail?: string };
