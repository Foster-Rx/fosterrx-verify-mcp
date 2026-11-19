# fosterrx-verify-mcp-server

A read-only MCP server for checking Foster Rx signed records. It uses **public
material only**: the world-readable record envelope and the Ed25519 public key
published at `https://fosterrx.com/.well-known/angis-signing-key-v1.pub`.

**No credential exists anywhere in this codebase.** Checking a record does not
need Foster Rx's permission, so the server holds nothing that would grant it.
The code is public so that anyone can read what it does.

Records are identified by a certificate id such as `FRXS-5330F9E368BA4536`.

## Tools

| Tool | What it does |
|---|---|
| `fosterrx_verify_certificate` | Checks the Ed25519 signature over the signed canonical bytes against the live public key. Verdicts: `verified` / `signature_invalid` / `not_found` / `tool_fault`. |
| `fosterrx_get_certificate_record` | Returns the full signed canonical record, decoded verbatim. It does not check the signature, and it renames nothing. |
| `fosterrx_get_trust_anchor` | Returns the published public key, with instructions for checking a record using no Foster Rx software at all. |

## Verdict discipline

- **`not_found` is not invalid.** It means no record is published under that
  id. It is a fact about the public register and says nothing about any file.
- **`tool_fault` is not invalid.** A network failure or malformed input is a
  fact about this tool's run and says nothing about the record.
- **`signature_invalid`** is returned only after the Ed25519 check has failed
  over the signed bytes under the published key.
- Both issued identifier shapes are accepted: `FRXS-<16 hex>` and
  `FRXS-<uuid>`.

## Run

```bash
npm ci && npm run build
PORT=8080 node dist/index.js     # MCP endpoint at POST /mcp, health at /healthz
```

The server is public and unauthenticated by design. It can only read what
anyone can already read.

## Check a record with your own AI

Anyone can add this server to an AI assistant and check any published Foster
Rx record. No account or permission is needed.

1. In Claude (or any MCP client), add a custom connector with the URL
   `https://fosterrx-verify-mcp-630726936307.us-east4.run.app/mcp`
2. Ask: `check record FRXS-5330F9E368BA4536`
3. The assistant returns the result of the signature check, which rests on the
   public key and not on the issuer's word.

## Contact

- General: info@fosterrx.com
- Security reports: security@fosterrx.com
