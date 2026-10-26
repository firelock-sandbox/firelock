# Firelock wire contract

Firelock's public contract is a **transport primitive**, not an application protocol. There is no frame
format to implement, no crypto, no header/body split in the contract itself. A guest connection arrives on
the single egress; Firelock hands its file descriptor to the handler; the handler owns everything from
there. This document is the whole contract.

## 1. Ingress — host → guest (vsock, port 8000)

The host invokes a loaded function inside the guest by connecting to the guest agent over vsock:

```
host → guest:  CONNECT 8000\n
guest → host:  OK <host-port>\n
```

The `firelock-init` guest agent serves port 8000 and runs the loaded function. Ingress is **host-initiated**
and is not a guest egress — it does not count against the single-egress guarantee.

## 2. Egress — the single guest-initiated vsock port

Firelock listens on **exactly one** egress port. When the guest opens an outbound vsock connection to it,
Firelock:

1. accepts the connection, and
2. **`SCM_RIGHTS`-hands the connected file descriptor to the handler.**

Firelock reads **nothing** off the connection — no framing, no header, no body. **The fd handoff IS the
contract.** The moment the fd is handed off, Firelock is out of the loop.

A second egress channel is deliberately not part of the contract. One listener is trivially auditable; N is
not. If a future need is real, a second channel must earn its own confinement proof.

## 3. The handler owns everything from the fd

The handler receives the fd as a [`HandedOffConnection`](../src/contract/handed-off-connection.ts):

```ts
interface HandedOffConnection {
  readonly socket: Duplex;   // the connected guest stream — raw, full-duplex bytes, nothing interpreted
  close(): Promise<void>;    // single-use; the loop closes in a finally
}
```

The boundary is a raw, full-duplex socket, not a bag of request/response methods — Firelock hands over a
connected stream and interprets none of it. This keeps the boundary faithful to "a connected socket,
nothing interpreted," and lets a handler feed it straight into a real parser (an HTTP server, in the OSS
default's case) instead of Firelock inventing its own framing.

A handler is any [`ExecHandler`](../src/contract/exec-handler.ts) —
`(conn: HandedOffConnection) => Promise<ExecOutcome>`. It reads and writes bytes on the socket, decides
what they mean, and does whatever it wants (proxy, adjudicate, inspect, govern the body). It must **never
throw** — every path returns an outcome, so one poisoned connection cannot kill the accept loop.

> **This boundary is byte/fd-level and language-agnostic — by design.** A handler is whatever process (or
> in-process routine) receives the SCM_RIGHTS-relayed fd; it need not share Firelock's language or runtime.
> The `HandedOffConnection` shape in this repo's TS is one *binding* of the contract, not the contract
> itself. The flagship default handler is native Rust; a TS/Bun convenience handler ships alongside it;
> both bind this same fd handoff. Nothing above assumes a JS runtime, so the low-memory (all-native)
> profile is a drop-in, not a reimplementation.

## 4. One handler pins one protocol

Firelock is protocol-agnostic — it never sees the protocol. **A handler speaks exactly one.** The OSS default
handler speaks **HTTP** (a reverse proxy to one upstream). The proprietary Kilimanjaro handler speaks its own
adjudicated frame protocol. **Never both in one handler:** a handler that accepts two protocols is a
parser-differential evasion surface, and — more fundamentally — the confined guest must not be able to pick
its route or privilege level by choosing a protocol. The guest speaks one protocol; the handler decides
routing; no route is both guest-selectable and capability-bearing-without-adjudication.

## 5. The confinement contract

`exec_seam_confined` ⇒ the guest's **only** guest-initiated egress is the one seam port. This is enforced,
fail-closed, by [`assertFirelockTopology`](../src/contract/topology-invariant.ts): a VM with any network
interface, or without exactly one vsock device, is refused before it is seeded, loaded, or trusted. This is
the entire structural guarantee Firelock publishes:

- **Zero network interfaces** — IP-less by construction (no NIC, no code path to add one). *Load-bearing leg.*
- **Firecracker's built-in seccomp filters** — close the non-vsock syscall families.
- **One vsock device / one host socket per VM** — close the multi-channel path.

Each leg is independently testable (a negative control per leg), the bar every un-bypassable claim carries.

## Not in the contract (the handler's / the platform's, above the relay)

The application protocol (HTTP, or the proprietary frame), any framing, the payload/streaming model,
capability receipts and their keys, policy evaluation, credential brokering, body-inspection modes — all of
these live **above** Firelock, in the handler. Firelock forwards an fd and never sees a frame.

## Payload bounds (handler concern, stated for integrators)

Firelock does not cap payloads (it never reads them). Handlers should. For reference, the Kilimanjaro handler
uses: `SCM_RIGHTS` envelope ≤ 64 KiB, frame ≤ 1 MiB, per-request egress body ≤ 1 MiB. The OSS reverse-proxy
handler defaults to a 1 MiB request-body cap (`maxBodyBytes`).
