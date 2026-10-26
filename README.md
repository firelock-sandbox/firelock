# Firelock

**A Firecracker-microVM execution shell.** Firelock confines an untrusted guest to a *single,
guest-initiated vsock egress* and relays that connection to a handler you choose. The confinement is the
product; the handler is yours — and a working **HTTP reverse-proxy handler ships as the default**, so the
shell does something useful on its own, day one.

> **Handlers bind a language-agnostic wire contract (the fd handoff), so a handler can be written in any
> language.** The flagship default reverse-proxy handler is **native Rust** (over `httparse`) — small,
> auditable, and the basis of the low-memory profile (host-side membrane + handler in ~2–5 MB, no JS
> runtime; see [Roadmap](#roadmap)). A **TS/Bun convenience handler** ships alongside it for integrators
> already running in that runtime. Both are drop-in over the same contract.

Firelock was built and maintained by the [Kilimanjaro](https://kilimanjaro.dev) engineering team, and is 
to Kilimanjaro what Firecracker is to Firelock: an independent, Apache-2.0 building block you *import*,
not a branded feature. It has no dependency on any Kilimanjaro account or service.

> **Status: 1.1.0.** This repository carries the whole sandbox: the **confinement/relay contract**, the
> **OSS default handler**, the **TypeScript runtime** (`src/runtime`: Firecracker client and pool, jailer,
> vsock, fd-handoff FFI bindings, per-invocation VM), the **native crates** (`native/`: the `SCM_RIGHTS`
> fd-handoff transport and handler confinement with seccomp) and the **guest init** (`guest/k9o-init`, the
> in-VM PID 1). See [docs/wire-contract.md](docs/wire-contract.md) for the relay contract.

## Every agent has a pulse. Now you can watch it.

Every serverless platform, sandbox, and function runtime forces the same trade-off: seal the workload down
and you go blind — a box strong enough to be safe is a box you can no longer watch. Instrument it and you
punch a hole in the seal — a sidecar that talks to the network is a sidecar an attacker can talk to as well.

Firelock refuses that trade. The guest microVM has **no network interface at all**, so nothing inside it can
reach anything you didn't explicitly route through the one deliberate seam. And because that seam is the
*same* channel everything else rides out on, watching what's happening inside doesn't require opening a
second hole. Sealed by construction. Visible by design.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/sealed-heart-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/sealed-heart.png">
  <img alt="The Sealed Heart — a precision-machined mechanical heart, glowing blue, hermetically sealed inside a crystal-clear glass chamber, with one thin fibre-optic cable carrying its heartbeat out to the one audited channel on the outside, communicating that the guest runs sealed away where nothing can reach it while its live signal is the one thing you can watch." src="docs/assets/sealed-heart.png">
</picture>

## The idea

```
  ┌──────────────────────────────┐
  │  Guest microVM (Firecracker) │   your untrusted code — agent, function, WASM module
  │  • ZERO network interfaces   │   IP-less by construction: no NIC, no code path to add one
  │  • EXACTLY ONE vsock egress  │
  └──────────────┬───────────────┘
                 │  the guest's ONLY way out
                 ▼
  ┌──────────────────────────────┐   ══ FIRELOCK (the membrane) ══
  │  fd-forwarder                │   accept the connection · SCM_RIGHTS the fd to the handler
  │  reads nothing, routes       │   confinement = the one egress. Done.
  │  nothing, sees no body       │
  └──────────────┬───────────────┘
                 │  (the fd)
                 ▼
  ┌──────────────────────────────┐   ══ HANDLER (yours) ══
  │  ExecHandler                 │   OSS default = an HTTP reverse proxy to one upstream.
  │                              │   Replace with your own policy/gate/streaming when you need it.
  └──────────────────────────────┘
```

Firelock guarantees exactly one thing: the guest can get out **only** through the seam. Everything after the
fd handoff — parsing, routing, credential injection, body governance — is the handler's, and Firelock cannot
see any of it (it forwarded the fd and stopped).

## The runtime gap

Three trade-offs every sandbox or serverless runtime forces on you. Three answers Firelock is built around.

### The blind sandbox → kernel-native visibility

Seal a workload properly and you lose sight of it — a sandbox strong enough to be safe is usually a sandbox
you can no longer watch. Firelock's design keeps resource and lifecycle signals emitting from *inside* the
sealed guest, riding out over the same seam as everything else. No sidecar to install — observability isn't
bolted on beside the confinement, it travels the same one channel.

### The leaky sidecar → one audited egress

The usual way to instrument a sealed box is to punch a hole in it: a monitoring agent that talks to the
network. That hole is exactly the path an attacker wants — the more ways data can leave, the less any single
one can be trusted. Firelock gives the guest **exactly one** vsock egress channel it can ever dial out on.
Proxied traffic, telemetry, whatever the handler forwards — all of it leaves the same single, auditable way.
Never a second, unaudited path.

### The open network → network-less by construction

A workload with a network stack can reach anything the network can — an intranet, a database, a domain it
resolves at runtime. A compromised guest with a NIC is a guest that can exfiltrate. Firelock's guest has
**zero virtual network interfaces** — no tun/tap, no bridge, no TCP/IP stack — so it structurally cannot scan
a LAN, resolve a domain, or reach anything the operator didn't explicitly wire through the one seam. Isolation
by construction, not a firewall rule to maintain.

## The confinement guarantee

A Firelock-confined microVM has **zero network interfaces** and **exactly one vsock device**. That is
asserted, fail-closed, in one place — [`assertFirelockTopology`](src/contract/topology-invariant.ts):

```
  ZERO network interfaces (no NIC, no add-interface code path)  → closes IP egress   [BY CONSTRUCTION]
  Firecracker's built-in seccomp filters                        → closes non-vsock families
  ONE vsock device / one host socket per VM                     → closes multi-channel
  ─────────────────────────────────────────────────────────────────────────────────
  = exactly one guest-initiated egress, and it is the seam.
```

"Could not check" is never "it is fine": an unreadable or ambiguous VM config is *refused*, not waved
through. The IP-less property is structural, not a deployment toggle. Firelock's isolation claim is
**"no network interface — by construction"** — a structural property you can check, not a claim of
mathematical unhackability.

## What's in the box

- **Network-less microVM.** Zero NICs on the guest — no tun/tap, no bridge, no TCP/IP stack. This is the
  `assertFirelockTopology` invariant above, and it ships today.
- **A single audited egress.** Exactly one vsock seam, one fd handoff, one place to audit — never a claim of
  zero-leak, since data *does* leave through that seam by design. That's the confinement/relay contract in
  this repo today; see [docs/wire-contract.md](docs/wire-contract.md).
- **Fast warm starts.** In the platform Firelock was extracted from, a pre-warmed pool of Firecracker
  snapshots resumes a slot in **~17 ms** and tears it down after a single use. That pre-warmed-pool
  orchestration layer is not yet part of this repository — what ships here today is the confinement/relay
  contract those snapshots run inside, not a benchmarked pool of its own.
- **A runaway-resource circuit-breaker** *(design intent, not yet implemented in `src/`)*. The platform this
  was extracted from tears down a workload that saturates its resource budget autonomously, before it
  becomes an incident — a circuit-breaker, not a claim of catching every possible runaway (an infinite loop
  under budget still runs). This repo doesn't yet ship that teardown logic; track it under
  [Roadmap](#roadmap).

Any telemetry or audit trail a handler emits over the seam is only as trustworthy as the handler makes it —
Firelock's own contribution is that the seam itself can't be tampered with silently: a topology check that
would let a second channel exist is refused outright, so the confinement record is **tamper-evident**, not a
guarantee that no handler could ever misbehave.

## Quickstart — the TS/Bun convenience reverse proxy

> This is the **TS/Bun convenience** handler (the flagship default is native Rust — see [Roadmap](#roadmap)).
> It exists so a TS/Bun integrator can stand the shell up in their own runtime. It is kept deliberately
> simple and is drop-in interchangeable with the Rust handler over the same wire contract.

The handler forwards every request a confined guest makes to **one upstream you configure**, with a
credential you supply injected host-side (the guest never holds it). The guest controls the method, path,
headers, and body — never the upstream host.

```ts
import { createHttpReverseProxy } from "firelock/handlers/http-reverse-proxy";

// Point it at one upstream; give it a credential to present.
const proxy = createHttpReverseProxy({
  upstreamBaseUrl: "https://mcp.internal.example",
  // Defaults to `Authorization: Bearer $FIRELOCK_UPSTREAM_CREDENTIAL` if you omit this.
  credential: { header: "authorization", value: `Bearer ${process.env.MCP_TOKEN}` },
  maxBodyBytes: 1024 * 1024,
});

// `proxy.handle` is an ExecHandler: Firelock calls it with each confined guest's connection.
// The runtime's own HTTP parser does the parsing — the pump is byte-pure.
// (The vsock fd-forwarder is the native fd-handoff crate in native/fd-handoff.)
```

What the default handler enforces, fail-closed:

- **Fixed upstream origin** — the guest's path is appended to `upstreamBaseUrl`; it can never move the host
  (SSRF-closed by construction).
- **Injected credential** — set host-side; any guest-supplied `Authorization` is dropped first, so the guest
  can neither read nor override it.
- **Redirects refused** — a `3xx` is not followed (following it would re-send your credential to an unvetted
  host).
- **Bounded body** — requests over the cap are refused, not buffered unboundedly. A refused request denies
  that **one** call; it never tears down or restarts the guest VM as a side effect.

To do more than proxy — policy, adjudication, streaming, body inspection — implement your own
[`ExecHandler`](src/contract/exec-handler.ts) over the same [`HandedOffConnection`](src/contract/handed-off-connection.ts)
boundary. A policy or governance layer is a perfectly natural thing to put behind that boundary — that's
exactly how the proprietary Kilimanjaro handler plugs in — but Firelock itself has no dependency on one, and
never requires or bundles one. Bring the handler you want; Firelock can't tell the difference.

## Roadmap

- **Native Rust flagship handler.** The default reverse-proxy handler becomes a native Rust binary over
  `httparse` — smaller and more auditable than any runtime-hosted handler, and dependency-free (a static
  binary, Firecracker's "runnable with no exotic runtime" bar). The TS handler remains a convenience.
- **Low-memory profile (host-side ~2–5 MB, no JS runtime).** A fully-native membrane: Rust fd-forwarder
  lifecycle (the SCM_RIGHTS relay is already Rust) + a Rust `firelock-init` guest agent + the Rust handler.
  One language end-to-end, single-digit-MB footprint, faster cold start. Targets edge / dense-multi-tenant
  / sovereign-on-modest-hardware deployments.
- **Runaway-resource circuit-breaker.** Autonomous teardown of a guest that saturates its resource budget,
  carried over from the platform this repo was extracted from — not yet implemented here.
- **Guest-side micro-runtime (mid–long term).** For budgets that must include the *guest* running compute,
  a micro WASM runtime (WAMR / wasm3, tens-to-hundreds of KB) in place of Wasmtime, for a whole confined
  compute unit in a few MB. A deliberate fork in the WASI story; scoped as a special case.

The wire contract (the fd handoff) is the language-agnostic boundary that keeps all of this drop-in — see
[docs/wire-contract.md](docs/wire-contract.md).

## Develop

```bash
bun install
bun run typecheck
bun test
```

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
