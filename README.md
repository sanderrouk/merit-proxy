# mp — Merit proxy

A small compiled Rust CLI that lets agents call Merit Aktiva using project
aliases. A local TOML lookup maps each alias to a 1Password Environment. The CLI
reads `op environment read <id>` over private pipes into memory, signs the exact
request bytes, makes the HTTPS call, and returns a redacted response.

There are no invoice/customer/report models to maintain. Give it an endpoint
and JSON from the [Merit reference manual](https://api.merit.ee/connecting-robots/reference-manual/).
New endpoints work as long as they use Merit's existing signed JSON protocol
with POST or GET. File helpers insert PDFs into JSON attachments and inspect or
save returned attachments without agents handling base64. Projects can restrict
API calls to an explicit read allowlist.

**Security scope:** credentials stay out of the CLI's output, diagnostics and
lookup file. This does not isolate an agent with unrestricted shell access under
your OS account: it can run `op` itself, replace the binary or inspect processes.
For that stronger boundary, the credential holder needs a separate OS identity
or trusted broker and a constrained agent tool interface. See [SECURITY.md](SECURITY.md).

## Build and install

Requires Rust 1.89+ and 1Password CLI with `op environment read` support.
macOS and Linux are the supported platforms. Your installed CLI can be checked
without retrieving credentials with `op environment read --help`.

```sh
cargo build --release --locked
./target/release/mp --help

# Optional: install to ~/.cargo/bin/mp
cargo install --path . --locked
```

Runtime is one executable plus the existing `op` installation. No Python, Node,
server, or background daemon is needed. Every authenticated invocation launches
`op`; 1Password authorization and the API request dominate that latency. Secrets
are not cached by this CLI; 1Password manages its own session/cache policy.

## Register projects

In each project's **1Password Environment**, add these values:

| Variable | Value |
| --- | --- |
| `MERIT_API_ID` | That company's Merit API ID |
| `MERIT_API_KEY` | That company's Merit API key |

Use a dedicated Environment containing only the credentials needed for this
integration. Copy its Environment ID in the 1Password app. Never paste the actual
API ID or key into an agent conversation or CLI argument.

```sh
mp projects add rouk --environment YOUR_ROUK_ENVIRONMENT_ID
mp projects add other --environment YOUR_OTHER_ENVIRONMENT_ID
mp projects list
mp -p rouk doctor
mp -p rouk doctor --auth
```

`projects add` creates the lookup if needed. `doctor` validates it and checks CLI
support; `--auth` also checks that both credential variables can be loaded. Neither
doctor mode contacts Merit or verifies that the credentials are accepted by Merit.
Desktop authorization can prompt through 1Password. Existing service-account or
session-based CLI authentication is also passed to `op`.

The lookup defaults to `$XDG_CONFIG_HOME/merit/config.toml`, or
`~/.config/merit/config.toml`. There is no automatic project-directory config
discovery. Use `--config /absolute/path/config.toml` for a separate lookup.

```sh
mp config path
mp config init                        # optional; creates an empty lookup
mp projects add rouk --environment NEW_ENVIRONMENT_ID --replace
mp projects remove other              # removes only the local mapping
```

The [example lookup](config.example.toml) shows the complete schema. Credentials
never belong in it. Files are written atomically with private permissions, and
concurrent updates are locked. Unknown fields and shared-writable configs fail
closed. Existing aliases require `--replace` to avoid accidental company changes.

Optional project settings:

```sh
mp projects add rouk \
  --environment YOUR_ENVIRONMENT_ID \
  --api-id-var MERIT_ACTIVA_ID \
  --api-key-var MERIT_ACTIVA_KEY \
  --account my.1password.com \
  --api-version v2 \
  --region ee
```

Credential variable names use normal environment-variable syntax: a letter or
underscore followed by letters, digits or underscores. Existing names such as
`API_ID` and `ApiKey` work too; values are read from the private pipe, never from
the caller’s environment. `ee` uses `aktiva.merit.ee`; `pl` uses
`program.360ksiegowosc.pl`. Both use HTTPS. Arbitrary origins are deliberately
unsupported.

## Read-only projects

Data retrieval, generated sales invoice PDFs and existing document attachments
are available in read-only mode:

```sh
# Register a project as read-only.
mp projects add rouk --environment YOUR_ENVIRONMENT_ID --read-only

# Change only the access mode of an existing mapping.
mp projects set-access rouk read-only
mp projects policy rouk
mp projects list

# Read data and download a PDF.
mp -p rouk getcustomers --data '{}'
mp -p rouk /api/v2/getsalesinvpdf --data '{"Id":"INVOICE_GUID"}' --save-pdf invoice.pdf

# Explicitly enable writes when wanted.
mp projects set-access rouk read-write
```

The corresponding TOML setting is `read_only = true` under the project. New
projects without `--read-only`, and older configs without the field, retain
read-write access. `projects add --replace` preserves the existing mode and
additional read rules unless explicitly supplied; `--read-write` on `add` can
explicitly change the mode.

Read-only checks happen before reading request files, loading credentials or
contacting Merit, and are repeated at the transport boundary. A denial returns
exit code **7**, including during `--dry-run`. PDF upload flags are also denied.
Saving a downloaded attachment locally is permitted; read-only refers to Merit
operations, not local output files.

The [bundled allowlist](read-endpoints.txt) contains reviewed **exact method,
API version and path** rules for customer/vendor/item reads, invoice lists and
details, invoice PDFs, ledger reads and selected reports. Unknown endpoints,
versions and methods are denied. Prefixes such as `get` and the HTTP method
alone never establish that an operation is safe. Most Merit reads use POST;
the [accounts endpoint](https://api.merit.ee/connecting-robots/reference-manual/accounts-list/)
documents GET, used as follows:

```sh
mp -p rouk /api/v2/accounts --method GET --data '{}'
```

You can extend the allowlist without rebuilding the binary after verifying the
operation in Merit's documentation. Add `read_endpoints` to the project's TOML:

```toml
read_only = true
read_endpoints = ["POST /api/v2/new_read_endpoint"]
```

`projects add --read-endpoint 'POST /api/v2/new_read_endpoint'` also accepts
repeatable rules. These are trusted declarations by the config owner, not an
automatic determination of server behavior; never add a write operation. There
are no wildcard rules or per-request bypass flags. `projects policy NAME` shows
the combined allowlist without accessing credentials.

This is a local configuration policy. Someone who can edit the lookup, change
access mode, or add another writable alias for the same Environment can relax
it. Restrict those capabilities in the calling tool/broker when the agent must
be unable to change policy. Enabling read-only does not alter permissions on the
underlying Merit API key or 1Password Environment.

## Make requests

The interface is `mp -p PROJECT ENDPOINT [options]`. `--project` is the long form
of `-p`. The flag resolves the project’s Environment ID in the lookup for each
invocation. For example, `mp -p rouk getcustomers --data '{}'` loads only the
configured `rouk` Environment before making the signed request.

`mp --project rouk request ENDPOINT [options]` is also supported. Use this explicit
form, or a full `/api/vN/...` path, for endpoints named like management commands
(`config`, `projects`, `doctor`, `request`, `help`). Project/request flags may appear
before or after the endpoint. Request options are rejected on management commands.

```sh
# Bare endpoint uses the project's default API version (v1 unless configured).
mp -p rouk getcustomers --data '{}'

# Explicit paths select an API version without editing config.
mp -p rouk /api/v2/getinvoices --file request.json

# Inline JSON, @file, and stdin all work.
mp -p rouk getcustomers --data '{"Name":"Example"}'
mp -p rouk getcustomers --data @request.json
printf '%s' '{}' | mp -p rouk getcustomers --data @-

# Validate input before loading credentials or making a request.
mp -p rouk /api/v2/getinvoices --file request.json --dry-run

# Emit the API body as JSON for a pipeline.
mp -p rouk getcustomers --data '{}' --body-only | jq .
```

Check the Merit manual for endpoint versions and payload fields. These examples
show the transport interface; the CLI intentionally does not validate business
schemas or choose API versions automatically. Full `/api/vN/...` paths override
`--api-version` and the project's default. The version syntax accepts future
numeric versions without a code change.

Requests default to POST; `--method GET` explicitly selects GET. Both sign and
send the supplied body without moving JSON fields into query parameters.
Omitted data sends a zero-byte body; `--data '{}'` sends
exactly `{}`. Without `--attach-pdf`, JSON is validated but is **not reserialized** before signing or
transmission: whitespace, trailing newlines, Unicode and decimal formatting are
preserved. Input is limited to 16 MiB and responses to 32 MiB. Files/stdin are
preferable for sensitive business data because inline arguments can appear in
shell history or process listings.

The request command requires an explicit project every time. It accepts only
relative endpoint paths, with no query string, fragment, percent encoding, dot
segments, custom headers or URL overrides. Auth query parameters are constructed
inside the proxy and are never returned.

### Upload PDFs and retrieve attachments

Merit transfers PDFs as base64 strings in JSON. `mp` handles the encoding and
decoding while keeping the generic endpoint interface:

```sh
# Attach a PDF to a purchase document awaiting approval.
# purchase.json must contain the invoice fields required by Merit.
mp -p rouk /api/v2/sendpurchorder --file purchase.json --attach-pdf receipt.pdf

# Generate and download the PDF for an existing sales invoice.
mp -p rouk /api/v2/getsalesinvpdf --data '{"Id":"INVOICE_GUID"}' --save-pdf invoice.pdf

# Inspect an existing purchase attachment without printing its base64 content.
mp -p rouk /api/v2/getpurchorder \
  --data '{"Id":"INVOICE_GUID","SkipAttachment":false}' --list-pdfs

# Save that attachment to a path chosen by the caller.
mp -p rouk /api/v2/getpurchorder \
  --data '{"Id":"INVOICE_GUID","SkipAttachment":false}' \
  --save-pdf /Attachment/FileContent=receipt.pdf

# Inspect any attachment type, then download it (PDF, image, or other binary).
mp -p rouk /api/v2/getpurchorder \
  --data '{"Id":"INVOICE_GUID","SkipAttachment":false}' --list-attachments
mp -p rouk /api/v2/getpurchorder \
  --data '{"Id":"INVOICE_GUID","SkipAttachment":false}' --save-attachment receipt.bin

# Retrieve an existing sales invoice attachment.
mp -p rouk /api/v2/getinvoice --data '{"Id":"INVOICE_GUID","AddAttachment":true}' \
  --save-attachment receipt.bin

# Ledger attachment content is nested inside Header in the documented v1 response.
mp -p rouk /api/v1/getglbatch --data '{"Id":"BATCH_GUID","AddAttachment":true}' \
  --save-attachment /Header/FileContent=attachment.bin

# Validate the complete upload without accessing 1Password or Merit.
mp -p rouk /api/v2/sendpurchorder --file purchase.json \
  --attach-pdf receipt.pdf --dry-run
```

The helpers are independent of endpoint names:

| Flag | Behavior |
| --- | --- |
| `--attach-pdf [POINTER=]PATH` | Insert `{FileName, FileContent}` at `/Attachment` by default; filename comes from the local basename |
| `--save-pdf [POINTER=]PATH` | Decode `/FileContent` by default and save to the supplied local path |
| `--list-pdfs` | Inspect all returned `FileContent` strings and return PDF metadata without saving files |
| `--save-attachment [POINTER=]PATH` | Decode any base64 attachment; default pointer is `/Attachment/FileContent` |
| `--list-attachments` | Inspect all returned `FileContent` strings, including non-PDF files, without saving |
| `--overwrite` | Allow replacing existing **local output files**; requires a save flag |

Pointers use JSON Pointer syntax, for example `/Documents/0/Attachment` for an
upload or `/Documents/0/Attachment/FileContent` for a download. Escape `~` as
`~0` and `/` as `~1` inside field names. Repeat upload/download flags for multiple
fields. Supply `POINTER=PATH` explicitly if the local filename contains `=`.
Upload targets must be missing, null, or an empty object; parent objects and array
entries must already exist. Existing attachment data is never silently replaced.

Uploads require a `.pdf` filename and check for a `%PDF-` header and `%%EOF` trailer;
this is a format check, not full PDF validation. Files are limited to 12 MiB each
and the complete base64-expanded JSON must fit the 16 MiB request limit. Adding
attachments reserializes the JSON before signing; number precision is preserved.
The entire response, including base64, remains limited to 32 MiB.

With save/list flags, `attachments` contains each processed file's JSON pointer,
original filename, decoded size, SHA-256 hash, `is_pdf` format check, and
`saved_to` when saved. `pdfs` contains the PDF subset. Selected `FileContent`
values become `null` in `body`, so agents do not receive large base64 strings.
Legacy JSON-string envelopes are unwrapped for these operations. These flags
cannot be combined with `--body-only`. Without them, the normal API body is returned.
`--list-pdfs` additionally requires every discovered file to pass the PDF format
check. Use `--list-attachments` for mixed formats; the two listing flags are
mutually exclusive. Invalid or redacted base64 fails before publishing files.
Generic downloads preserve decoded bytes exactly and never render or execute them.
The CLI retrieves only attachments exposed by the selected Merit endpoint;
use its documented `AddAttachment`/`SkipAttachment` fields to request content.

Download directories must already exist. Files are staged privately (0600) and
published atomically. Existing destinations require `--overwrite`; symlinks and
non-regular destinations are rejected. Response filenames are metadata only and
never determine output paths. All selected files are validated and staged before
publishing any. A failure while publishing multiple files can leave earlier files
saved. HTTP error responses never create attachment outputs. An extraction or disk
error can happen **after the API operation succeeded**; check before retrying.

The documented purchase endpoints accept PDFs while creating documents, and
retrieval endpoints return attached or generated invoice PDFs. The reviewed
reference manual does not document a standalone attachment-delete or attachment-
replacement endpoint. `mp` does not invent one or delete an invoice to remove its
PDF. Any supported future endpoint can still use the generic request interface.
`--overwrite` changes local files only.

### Output and exit codes

Default stdout is a single JSON envelope:

```json
{
  "ok": true,
  "project": "rouk",
  "status": 200,
  "headers": {},
  "body": [],
  "pdfs": [],
  "attachments": [],
  "meta": {
    "request_id": "...",
    "elapsed_ms": 480,
    "credentials_ms": 310,
    "http_ms": 160,
    "response_bytes": 2,
    "redacted": false
  },
  "error": null
}
```

JSON responses retain their types and number precision. Non-JSON responses become
a JSON string. Legacy JSON-inside-a-string responses retain their outer string
type. The body is the redacted API response, not a byte-for-byte response archive.
`ok` means HTTP 2xx; any business-level error inside a 2xx body must be interpreted
by the caller.

Non-2xx replies still return an envelope and redacted body, with `ok: false` and
exit code 5. With `--body-only`, only the body goes to stdout and HTTP error
metadata goes to stderr. Local/config/provider/transport failures return a JSON
error on stderr with empty stdout. Help and argument syntax errors use normal
Clap formatting.

| Exit | Meaning |
| --- | --- |
| 0 | Success, including a successful dry run |
| 2 | Invalid arguments, config, endpoint or input JSON |
| 3 | 1Password or credential-loading failure |
| 4 | Timeout, connection failure, incomplete/oversized response, invalid requested attachment |
| 5 | HTTP response outside 200–299 |
| 6 | Local I/O or internal failure |
| 7 | Project read-only policy denied the request |

There are **no automatic retries**, including on 429 or network failures.
Generic endpoints may create or modify accounting records. A timeout, response
read failure, or output/logging failure can occur after a write succeeded; check
Merit before retrying. `retry-after` and Merit's three rate-limit headers are
returned in `headers`; calls across separate CLI processes are not globally paced.
Merit documents a limit of 100 requests/minute, so agents should coordinate usage.

## Debugging

```sh
mp -p rouk doctor
mp -p rouk --debug doctor --auth
mp -p rouk --debug getcustomers --data '{}' --dry-run
mp --debug --log-file ./merit-debug.jsonl \
  -p rouk getcustomers --data '{}' --timeout 30
```

Debug events are JSON lines on stderr; `--log-file` appends the same events to a
0600 file, even without `--debug`. Logs contain a correlation ID, project alias,
unsigned origin/path, request size and SHA-256 hash, HTTP status, timing and rate
limits. PDF uploads add filename, size and hash metadata; extraction logs counts.
They never deliberately record PDF contents, request/response bodies, API IDs, keys,
signatures, full signed URLs, environment dumps or raw 1Password diagnostics.
Body hashes can still identify known input; treat logs as private operational data.

`credentials_ms` measures 1Password loading; `http_ms` covers the API request;
`elapsed_ms` covers the full command. The default HTTP timeout is 30 seconds
(1–300 allowed). `--auth-timeout` independently limits 1Password loading to 120
seconds by default (1–600 allowed). An authorization timeout is exit code 3 and
occurs before any Merit request is sent.

| Symptom | Check |
| --- | --- |
| CLI lacks Environment support | Install an `op` release that supports `environment read --help` |
| Credential loading fails | Unlock 1Password; enable CLI integration; verify Environment ID, account and access |
| Missing ID/key variable | Check the names in the Environment against `api_id_var` / `api_key_var` |
| HTTP 401/403 | Verify credentials, company/license access and the machine's UTC clock |
| HTTP 404 | Check the endpoint spelling and API version |
| HTTP 429 | Read `headers.retry-after` and coordinate calls before trying again |
| HTTP 3xx | Redirect was refused; verify the selected region and contact Merit if needed |
| Connection error | Check DNS/connectivity; system proxies and custom CA overrides are intentionally ignored |

Raw provider output and third-party error chains are suppressed because they can
contain credentials or signed URLs. There is no unsafe verbose/cURL export mode.
Do not use `op run -- printenv` to debug through an agent.

## Agent integration

Give the agent [docs/agent-usage.md](docs/agent-usage.md), the executable path and
the project aliases it is authorized to use. It can look up schemas in Merit's
manual and call the generic request interface. Read-only projects enforce their
configured method/path allowlist. Read-write projects can call any supported
endpoint; authorization for an individual business operation remains with the
caller. Use the calling tool or broker to restrict changes to project policy.

## Development

```sh
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --release --locked
```

Tests use fake `op` executables and loopback HTTP servers with synthetic secrets.
They require local socket access, not real 1Password/Merit credentials. Production
builds have no test-origin or insecure-TLS switch. CI runs the checks on macOS
and Linux. Live authentication is a separate setup check, not part of the suite.

Sources checked for the implementation:

- [Merit authentication and signing](https://api.merit.ee/connecting-robots/reference-manual/authentication/)
- [Merit origins and versions](https://api.merit.ee/connecting-robots/reference-manual/endpoints/)
- [Merit rate-limit behavior](https://api.merit.ee/connecting-robots/reference-manual/rate-limiter/)
- [Purchase documents awaiting approval and PDF uploads](https://api.merit.ee/connecting-robots/reference-manual/purchase-invoices/create-purchase-order/)
- [Purchase invoice details and attachments](https://api.merit.ee/connecting-robots/reference-manual/purchase-invoices/get-purchase-invoice-details/)
- [Sales invoice PDF generation](https://api.merit.ee/connecting-robots/reference-manual/sales-invoices/create-sales-invoice/get-sales-invoice-pdf/)
- [1Password Environments](https://www.1password.dev/environments)
