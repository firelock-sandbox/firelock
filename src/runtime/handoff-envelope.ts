/**
 * Host-internal handoff envelope (Model A).
 *
 * On `allow`, the dispatcher side hands the guest connection fd `C` to the
 * executor side via the SCM_RIGHTS fd-handoff (`firelock-fd-handoff`), together with a
 * `payload`. The substrate moves that `payload` byte-faithfully and PARSE-FREE —
 * it never inspects it (that parse-free property is the substrate's security
 * guarantee). This module defines the STRUCTURE the
 * dispatcher packs into that payload and the executor unpacks — a small, explicit,
 * length-delimited binary envelope carrying TWO distinct fields:
 *
 *   [0] receipt   — the signed decision receipt (the trust anchor; the
 *                   executor verifies it, JWS + typ-pinned + binding).
 *   [1] rawFrame  — the RAW adjudicated frame bytes, PREFIX-EXCLUDED, byte-faithful.
 *                   This is the digest preimage: the executor checks
 *                   SHA-256(rawFrame) === receipt.input_sha256 (Model A). A DISTINCT
 *                   field — never concatenated/folded (Model-A condition 1).
 *
 * NO resolved-metadata field: the cleanest design DROPS
 * it — the executor re-derives `{tool,input}` from the digest-verified `rawFrame`
 * post-verify and takes binding fields from its own server-authoritative context,
 * so a forwarded hint is redundant surface. If ever needed it returns as its own
 * distinct, explicitly non-authoritative field (never merged into rawFrame).
 *
 * Both producer (the dispatcher side) and consumer (the executor side) are
 * TypeScript, so they share THIS ONE codec — no parallel hand-rolled framing that
 * could drift. The substrate (Rust `firelock-fd-handoff`) never sees this structure.
 *
 * Sizing: `HANDOFF_MAX_ENVELOPE_BYTES` (= the substrate
 * `MAX_PAYLOAD`, 64 KiB) caps the WHOLE envelope, so `rawFrame`'s effective max is
 * `64 KiB − header − 2 length-prefixes − receipt` — far above any real gate request
 * `{tool,input}` (<1 KiB). The executor bounds `rawFrame ≤ 64 KiB`; since
 * `rawFrame ⊂ envelope ≤ 64 KiB` that always holds, so a lying length can't exceed
 * the cap before the digest check.
 *
 * Framing is DEFENSE-IN-DEPTH, not a trust boundary: the
 * signed digest is the anchor — a mis-frame yields bytes ≠ adjudicated → digest
 * mismatch → refuse. The fail-closed decode below is belt-and-braces, not the
 * security guarantee.
 */

/** ASCII "K9HO" — envelope magic (fail-closed guard against a garbled payload). */
export const HANDOFF_MAGIC = Uint8Array.from([0x4b, 0x39, 0x48, 0x4f]);
export const HANDOFF_VERSION = 1;
/** Must equal the substrate MAX_PAYLOAD (firelock-fd-handoff `MAX_PAYLOAD`). */
export const HANDOFF_MAX_ENVELOPE_BYTES = 64 * 1024;
const HEADER_BYTES = 6; // magic(4) + version(1) + fieldCount(1)
const FIELD_COUNT = 2;

export type HandoffEnvelope = {
  /** The signed decision receipt (opaque to this codec). */
  receipt: Uint8Array;
  /** The raw adjudicated frame bytes — prefix-excluded, byte-faithful (digest preimage). */
  rawFrame: Uint8Array;
};

export class HandoffEnvelopeError extends Error {
  constructor(msg: string) {
    super(`handoff envelope: ${msg}`);
    this.name = "HandoffEnvelopeError";
  }
}

/**
 * Pack the two fields into the wire envelope. Field order is fixed
 * (receipt, rawFrame); each is length-prefixed (4-byte LE u32, matching the gate
 * frame's length convention). Throws if the result would exceed the substrate
 * payload cap.
 */
export function encodeHandoffEnvelope(env: HandoffEnvelope): Uint8Array {
  const fields = [env.receipt, env.rawFrame];
  const total = HEADER_BYTES + fields.reduce((n, f) => n + 4 + f.length, 0);
  if (total > HANDOFF_MAX_ENVELOPE_BYTES) {
    throw new HandoffEnvelopeError(
      `encoded size ${total} exceeds MAX ${HANDOFF_MAX_ENVELOPE_BYTES}`,
    );
  }
  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer);
  out.set(HANDOFF_MAGIC, 0);
  out[4] = HANDOFF_VERSION;
  out[5] = FIELD_COUNT;
  let off = HEADER_BYTES;
  for (const f of fields) {
    dv.setUint32(off, f.length, true); // little-endian
    off += 4;
    out.set(f, off);
    off += f.length;
  }
  return out;
}

/**
 * Unpack a wire envelope. Fail-closed on any malformation — bad magic/version,
 * wrong field count, a length that overruns the buffer, or trailing bytes — so a
 * garbled/hostile payload can never be misread as a valid handoff. (Authorization
 * still rests on the digest + signed receipt; this is defense-in-depth framing.)
 */
export function decodeHandoffEnvelope(bytes: Uint8Array): HandoffEnvelope {
  if (bytes.length < HEADER_BYTES) throw new HandoffEnvelopeError("shorter than header");
  if (bytes.length > HANDOFF_MAX_ENVELOPE_BYTES) {
    throw new HandoffEnvelopeError(`length ${bytes.length} exceeds MAX ${HANDOFF_MAX_ENVELOPE_BYTES}`);
  }
  for (let i = 0; i < HANDOFF_MAGIC.length; i++) {
    if (bytes[i] !== HANDOFF_MAGIC[i]) throw new HandoffEnvelopeError("bad magic");
  }
  if (bytes[4] !== HANDOFF_VERSION) throw new HandoffEnvelopeError(`unsupported version ${bytes[4]}`);
  if (bytes[5] !== FIELD_COUNT) throw new HandoffEnvelopeError(`expected ${FIELD_COUNT} fields, got ${bytes[5]}`);

  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const out: Uint8Array[] = [];
  let off = HEADER_BYTES;
  for (let i = 0; i < FIELD_COUNT; i++) {
    if (off + 4 > bytes.length) throw new HandoffEnvelopeError(`truncated length prefix for field ${i}`);
    const len = dv.getUint32(off, true);
    off += 4;
    if (off + len > bytes.length) throw new HandoffEnvelopeError(`field ${i} length ${len} overruns buffer`);
    // subarray = zero-copy, byte-faithful view (no reserialize).
    out.push(bytes.subarray(off, off + len));
    off += len;
  }
  if (off !== bytes.length) throw new HandoffEnvelopeError("trailing bytes after last field");
  return { receipt: out[0]!, rawFrame: out[1]! };
}
