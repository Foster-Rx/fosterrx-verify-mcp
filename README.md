# fosterrx-verify-mcp-server

A read-only MCP server that verifies Foster Rx certificates using **public
material only**: the world-readable certificate envelope and the Ed25519 trust
anchor published at `https://fosterrx.com/.well-known/angis-signing-key-v1.pub`.

**No credential exists anywhere in this codebase.** That is not a deployment
choice but the product's argument in server form: verification that required
Foster Rx's permission would not be verification. This repository being public
and auditable is part of the same argument.

## Tools

| Tool | What it does |
|---|---|
| `fosterrx_verify_certificate` | Real Ed25519 verification of the signed canonical bytes against the live trust anchor. Verdicts: `verified` / `signature_invalid` / `not_found` / `tool_fault`. |
| `fosterrx_get_certificate_record` | The full signed canonical, decoded verbatim. No verification performed; nothing renamed or improved on. |
| `fosterrx_get_trust_anchor` | The published public key, plus instructions for verifying with no Foster Rx software at all. |

## Verdict discipline

- **`not_found` is not invalid.** An unpublished certificate is a fact about
  the public register, never a claim about any artifact.
- **`tool_fault` is not invalid.** A network failure or malformed input is a
  fact about this tool's run and says nothing about the certificate.
- **`signature_invalid`** is asserted only after Ed25519 arithmetic failed
  over the signed bytes under the published key.
- Both issued identifier shapes are accepted (`FRXS-<16 hex>` and
  `FRXS-<uuid>`); a pattern inferred from only one of them has previously
  rejected every real certificate.

## Run

```bash
npm ci && npm run build
PORT=8080 node dist/index.js     # MCP endpoint at POST /mcp, health at /healthz
```

## Deploy (Cloud Run)

```bash
gcloud run deploy fosterrx-verify-mcp --source . \
  --region us-east4 --project fosterrx-prod --allow-unauthenticated
```

Public, unauthenticated, by design: it can only read what the world can
already read.

## Verify with your own AI

This server is public. Anyone can register it and verify any published
Foster Rx certificate — no account, no permission:

1. In Claude (or any MCP client): add a custom connector with URL
   `https://fosterrx-verify-mcp-630726936307.us-east4.run.app/mcp`
2. Ask: `verify FRXS-5330F9E368BA4536`
3. The reader gets the cryptographic verdict — not the issuer's word.
