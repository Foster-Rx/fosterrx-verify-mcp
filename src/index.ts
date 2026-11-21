/**
 * fosterrx-verify-mcp-server
 *
 * Read-only forever. Every tool here observes public material - the
 * world-readable certificate envelope and the published trust anchor - and
 * none can mutate anything: there is no write path in this codebase and no
 * credential for one to use. That is the product's argument in server form:
 * verification the reader performs, not verification the issuer reports.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import express from "express";
import { z } from "zod";
import {
  TRUST_ANCHOR_URL,
  VERIFY_PAGE_BASE,
  decodeCanonical,
  fetchAnchorPem,
  fetchEnvelope,
  idShape,
  verifySignature,
} from "./verify-core.js";

const READ_ONLY = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

const CertIdSchema = z.object({
  certificate_id: z
    .string()
    .describe(
      "Foster Rx certificate identifier. Two issued shapes are valid: " +
        "FRXS- followed by 16 hex characters (e.g. FRXS-5330F9E368BA4536), or " +
        "FRXS- followed by a UUID. Both are in circulation; both are accepted.",
    ),
}).strict();

function shapeError(id: string): string {
  return (
    `'${id}' matches neither issued identifier shape (FRXS-<16 hex> or FRXS-<uuid>). ` +
    `This is a statement about the input string only - no lookup was performed and ` +
    `nothing was concluded about any certificate.`
  );
}

/**
 * One McpServer per request. An McpServer can be connected to only one
 * transport at a time, so a single shared instance throws "Already connected
 * to a transport" as soon as two requests overlap (FRXP-53).
 */
function buildServer(): McpServer {
  const server = new McpServer({ name: "fosterrx-verify-mcp-server", version: "1.0.0" });

  server.registerTool(
    "fosterrx_verify_certificate",
    {
      title: "Verify a Foster Rx certificate",
      description: `Cryptographically verify a Foster Rx certificate using only public material: the world-readable certificate envelope and the Ed25519 trust anchor published at ${TRUST_ANCHOR_URL}. No credential is used and none exists in this server.

  Args:
    - certificate_id (string): e.g. "FRXS-5330F9E368BA4536". Both issued shapes accepted.

  Returns structured data:
    {
      "verdict": "verified" | "signature_invalid" | "not_found" | "tool_fault",
      "verdict_meaning": string,      // plain-English gloss of exactly what was and was not established
      "certificate_id": string,
      "signature_algorithm": string,  // as recorded in the envelope
      "signing_key_fingerprint": string,
      "verify_page": string,          // the human-facing page for the same check
      "record": { ... }               // key fields decoded from the SIGNED canonical, verbatim
    }

  Verdict discipline (important):
    - "not_found" means no envelope is published under that id. It is a fact about the public register and NEVER a claim that any certificate is invalid.
    - "tool_fault" means this tool could not complete its run (network, malformed response). It says nothing about the certificate.
    - "signature_invalid" is asserted only after real Ed25519 arithmetic failed over the signed bytes.
    - "verified" means the signature checks against the live published trust anchor - the same key every browser loads.`,
      inputSchema: CertIdSchema,
      annotations: READ_ONLY,
    },
    async ({ certificate_id }) => {
      const fail = (verdict: string, meaning: string, extra: Record<string, unknown> = {}) => {
        const output = { verdict, verdict_meaning: meaning, certificate_id, ...extra };
        return {
          content: [{ type: "text" as const, text: JSON.stringify(output, null, 2) }],
          structuredContent: output,
        };
      };

      if (idShape(certificate_id) === null)
        return fail("tool_fault", shapeError(certificate_id));

      const env = await fetchEnvelope(certificate_id);
      if (env.kind === "not_found")
        return fail(
          "not_found",
          "No envelope is published under this identifier. This is a fact about the public register, not a claim that any certificate is invalid.",
          { verify_page: VERIFY_PAGE_BASE + certificate_id },
        );
      if (env.kind === "fault") return fail("tool_fault", env.detail);

      const anchor = await fetchAnchorPem();
      if (anchor.kind === "fault") return fail("tool_fault", anchor.detail);

      const sig = verifySignature(
        anchor.pem,
        env.envelope.canonical_form_b64,
        env.envelope.signature_hex,
      );
      if (sig.kind === "fault") return fail("tool_fault", sig.detail);

      const decoded = decodeCanonical(env.envelope.canonical_form_b64);
      const rec = decoded.kind === "ok" ? decoded.record : {};
      const rr = (rec["human_review_record"] ?? {}) as Record<string, unknown>;
      const ns = (rec["narrative_synthesis"] ?? {}) as Record<string, unknown>;

      const output = {
        verdict: sig.kind,
        verdict_meaning:
          sig.kind === "verified"
            ? "The Ed25519 signature verifies over the signed canonical bytes against the live published trust anchor - the same key every browser loads. The record fields below come from those signed bytes."
            : "Ed25519 verification FAILED over the signed bytes against the live trust anchor. The envelope's signature does not match its content under the published key.",
        certificate_id,
        signature_algorithm: env.envelope.signature_algorithm,
        signing_key_fingerprint: env.envelope.signing_key_fingerprint,
        verify_page: VERIFY_PAGE_BASE + certificate_id,
        record: {
          certificate_id: rec["certificate_id"],
          kind: rec["kind"],
          status: rec["status"],
          issued_at: rec["issued_at"],
          license_tier: rec["license_tier"],
          reviewer_role: rr["reviewer_role"],
          review_decision: rr["decision"],
          narrative_summary: ns["summary"],
        },
        ...(decoded.kind === "fault"
          ? {
              record_display_note:
                "The canonical decoded incompletely for display. That is a fault of this rendering and says nothing about the certificate - the verdict above derives from the signed bytes themselves.",
            }
          : {}),
      };
      return {
        content: [{ type: "text" as const, text: JSON.stringify(output, null, 2) }],
        structuredContent: output,
      };
    },
  );

  server.registerTool(
    "fosterrx_get_certificate_record",
    {
      title: "Get a certificate's signed record, verbatim",
      description: `Fetch and decode the full signed canonical record of a published Foster Rx certificate - every field exactly as the issuer signed it, including the human review record and narrative synthesis, which are world-readable by design. Performs NO signature verification: use fosterrx_verify_certificate for a verdict. Values are verbatim; nothing is renamed or improved on.

  Args:
    - certificate_id (string): both issued shapes accepted.

  Returns: { "certificate_id": string, "envelope_meta": {...}, "signed_record": {...full canonical...} } or a not_found/tool_fault outcome with the same discipline as the verify tool.`,
      inputSchema: CertIdSchema,
      annotations: READ_ONLY,
    },
    async ({ certificate_id }) => {
      const out = (o: Record<string, unknown>) => ({
        content: [{ type: "text" as const, text: JSON.stringify(o, null, 2) }],
        structuredContent: o,
      });
      if (idShape(certificate_id) === null)
        return out({ outcome: "tool_fault", detail: shapeError(certificate_id) });
      const env = await fetchEnvelope(certificate_id);
      if (env.kind === "not_found")
        return out({
          outcome: "not_found",
          detail:
            "No envelope is published under this identifier - a fact about the register, not a claim about any certificate.",
        });
      if (env.kind === "fault") return out({ outcome: "tool_fault", detail: env.detail });
      const decoded = decodeCanonical(env.envelope.canonical_form_b64);
      if (decoded.kind === "fault")
        return out({
          outcome: "tool_fault",
          detail:
            decoded.detail +
            " This is a fault of this tool's decoding and says nothing about the certificate.",
        });
      return out({
        outcome: "ok",
        certificate_id,
        envelope_meta: {
          signature_algorithm: env.envelope.signature_algorithm,
          signing_key_fingerprint: env.envelope.signing_key_fingerprint,
          signature_present: env.envelope.signature_hex.length > 0,
        },
        signed_record: decoded.record,
      });
    },
  );

  server.registerTool(
    "fosterrx_get_trust_anchor",
    {
      title: "Get the published trust anchor",
      description: `Fetch the Ed25519 public key Foster Rx publishes at ${TRUST_ANCHOR_URL} - the key every verification (this server's, the browser's, and any independent reader's) checks against. Returns the PEM verbatim plus instructions for verifying a certificate with no Foster Rx software at all, which is the point.`,
      inputSchema: z.object({}).strict(),
      annotations: READ_ONLY,
    },
    async () => {
      const anchor = await fetchAnchorPem();
      const output =
        anchor.kind === "ok"
          ? {
              outcome: "ok",
              trust_anchor_url: TRUST_ANCHOR_URL,
              public_key_pem: anchor.pem,
              independent_verification:
                "Fetch the envelope (a public Firestore document), base64-decode canonical_form_b64, and check the Ed25519 signature (signature_hex) over those bytes against this key. Any cryptography library can do it; no Foster Rx credential or software is required.",
            }
          : { outcome: "tool_fault", detail: anchor.detail };
      return {
        content: [{ type: "text" as const, text: JSON.stringify(output, null, 2) }],
        structuredContent: output,
      };
    },
  );

  return server;
}

const app = express();
app.use(express.json());
app.get("/healthz", (_req, res) => { res.status(200).send("ok"); });
app.post("/mcp", async (req, res) => {
  const server = buildServer();
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  res.on("close", () => {
    void transport.close();
    void server.close();
  });
  // Express 4 does not catch a rejected async handler; unhandled, it ends the
  // process and every request in flight on the instance is answered 503.
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    console.error("mcp request failed:", e);
    if (!res.headersSent)
      res.status(500).json({
        jsonrpc: "2.0",
        error: { code: -32603, message: "Internal server error" },
        id: null,
      });
  }
});
const port = parseInt(process.env.PORT ?? "8080", 10);
app.listen(port, () => console.error(`fosterrx-verify-mcp on :${port}/mcp`));
