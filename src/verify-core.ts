/**
 * The verification core. Everything here operates on PUBLIC material only:
 * the world-readable envelope in Firestore, and the trust anchor served from
 * fosterrx.com/.well-known. No credential exists anywhere in this server,
 * which is not a deployment choice but the product's argument - verification
 * that required Foster Rx's permission would not be verification.
 *
 * Verdict discipline, enforced by type:
 *   - not_found is NOT invalid. An unpublished certificate is a fact about
 *     the register, never a claim about any artifact.
 *   - tool_fault is NOT invalid. A network failure or malformed response is
 *     a fact about this tool's run and says nothing about the certificate.
 *   - signature_invalid is the only negative claim about an artifact, and it
 *     is made only after real Ed25519 arithmetic over the signed bytes.
 */
import { createPublicKey, verify as edVerify } from "node:crypto";

export const FIRESTORE_BASE =
  "https://firestore.googleapis.com/v1/projects/fosterrx-prod/databases/foster-rx-synth/documents";
export const TRUST_ANCHOR_URL =
  "https://fosterrx.com/.well-known/angis-signing-key-v1.pub";
export const VERIFY_PAGE_BASE = "https://fosterrx.com/verify/";

/** Both issued identifier shapes. A pattern inferred from only one of them
 *  has previously rejected every real certificate. */
const ID_HEX16 = /^FRXS-[0-9A-Fa-f]{16}$/;
const ID_UUID =
  /^FRXS-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;

export function idShape(id: string): "hex16" | "uuid" | null {
  if (ID_HEX16.test(id)) return "hex16";
  if (ID_UUID.test(id)) return "uuid";
  return null;
}

export type Envelope = {
  canonical_form_b64: string;
  signature_hex: string;
  signature_algorithm: string;
  signing_key_fingerprint: string;
};

export type FetchOutcome =
  | { kind: "found"; envelope: Envelope }
  | { kind: "not_found" }
  | { kind: "fault"; detail: string };

export async function fetchEnvelope(certId: string): Promise<FetchOutcome> {
  try {
    const res = await fetch(
      `${FIRESTORE_BASE}/public_envelopes/${encodeURIComponent(certId)}`,
      { headers: { "User-Agent": "fosterrx-verify-mcp/1.0" } },
    );
    if (res.status === 404) return { kind: "not_found" };
    if (!res.ok)
      return { kind: "fault", detail: `envelope read returned HTTP ${res.status}` };
    const doc = (await res.json()) as {
      fields?: Record<string, { stringValue?: string }>;
    };
    const f = doc.fields ?? {};
    const env: Partial<Envelope> = {
      canonical_form_b64: f.canonical_form_b64?.stringValue,
      signature_hex: f.signature_hex?.stringValue,
      signature_algorithm: f.signature_algorithm?.stringValue,
      signing_key_fingerprint: f.signing_key_fingerprint?.stringValue,
    };
    for (const k of [
      "canonical_form_b64",
      "signature_hex",
      "signature_algorithm",
      "signing_key_fingerprint",
    ] as const) {
      if (typeof env[k] !== "string")
        return { kind: "fault", detail: `envelope is missing ${k}` };
    }
    return { kind: "found", envelope: env as Envelope };
  } catch (e) {
    return { kind: "fault", detail: `envelope fetch failed: ${String(e)}` };
  }
}

export async function fetchAnchorPem(): Promise<
  { kind: "ok"; pem: string } | { kind: "fault"; detail: string }
> {
  try {
    const res = await fetch(TRUST_ANCHOR_URL, {
      headers: { "User-Agent": "fosterrx-verify-mcp/1.0" },
    });
    if (!res.ok)
      return { kind: "fault", detail: `trust anchor returned HTTP ${res.status}` };
    return { kind: "ok", pem: await res.text() };
  } catch (e) {
    return { kind: "fault", detail: `trust anchor fetch failed: ${String(e)}` };
  }
}

export function verifySignature(
  pem: string,
  canonicalB64: string,
  signatureHex: string,
): { kind: "verified" } | { kind: "signature_invalid" } | { kind: "fault"; detail: string } {
  try {
    const key = createPublicKey(pem);
    const data = Buffer.from(canonicalB64, "base64");
    const sig = Buffer.from(signatureHex, "hex");
    return edVerify(null, data, key, sig)
      ? { kind: "verified" }
      : { kind: "signature_invalid" };
  } catch (e) {
    return { kind: "fault", detail: `verification could not run: ${String(e)}` };
  }
}

/** The canonical, decoded for display. Failure here is a display fault,
 *  never a statement about the certificate - the verdict derives from the
 *  bytes, not from whether this parse succeeded. */
export function decodeCanonical(
  canonicalB64: string,
): { kind: "ok"; record: Record<string, unknown> } | { kind: "fault"; detail: string } {
  try {
    const record = JSON.parse(
      Buffer.from(canonicalB64, "base64").toString("utf8"),
    ) as Record<string, unknown>;
    return { kind: "ok", record };
  } catch (e) {
    return { kind: "fault", detail: `canonical decode failed: ${String(e)}` };
  }
}
