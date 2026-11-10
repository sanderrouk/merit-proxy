# Credential boundary

`mp` keeps credentials out of agent output, diagnostics, command arguments and
new process environments. It is not a sandbox for arbitrary code running as the
same OS user.

## Data flow

1. `mp -p rouk ENDPOINT` resolves `rouk` in the local TOML lookup. The lookup stores
   an Environment ID, credential variable names, and optional account/region/version.
2. The proxy checks the project's read-only policy against the exact HTTP method
   and versioned endpoint before reading payload files or loading secrets. It then
   validates JSON, PDF uploads and download paths. Uploads are base64-encoded into
   JSON, then the resulting exact bytes are signed and sent.
3. It invokes the installed 1Password CLI without a shell:
   `op --format human-readable --encoding UTF-8 --no-color [--account ACCOUNT] environment read ID`.
   The CLI executable is resolved only from absolute PATH entries. Stdout and
   stderr are captured through private bounded pipes. No raw provider output is
   forwarded to the caller.
4. Literal `KEY=value` lines are parsed in memory, following Handhold lab’s
   approach. No shell evaluation, dotenv file, `op run`, environment-variable
   assignment, or second proxy process is involved. Only the selected API ID and
   key are retained. The raw provider buffers are zeroed when released.
5. The proxy signs `ApiId + UTC timestamp + exact body` with HMAC-SHA256, using
   the key as literal ASCII bytes, then base64-encodes the result. The key is not
   transmitted. The API ID and signature are URL-encoded query parameters to Merit.
6. The response is redacted before output. Credentials are dropped after the call;
   there is no credential cache maintained by the proxy. 1Password manages its
   own authentication and caching policy.

## Protections

- Missing credentials fail closed; ambient shell variables are never a fallback.
  Fetched values are not put in the proxy’s or any child’s environment. Even
  fetched entries named `PATH` or `OP_DEBUG` remain inert data.
- Provider inheritance is restricted to OS context and necessary 1Password
  authentication context. Ambient Merit, proxy, loader, and debug settings are
  not passed to `op`. Output format and encoding are explicitly selected.
- The parser rejects invalid/duplicate variable names, quote-wrapped values,
  malformed/multiline output, more than 512 variables or more than 16 MiB. It
  preserves equals signs and shell metacharacters literally.
- Provider output has a byte limit and a deadline. On timeout/overflow, the Unix
  process group is killed. Stderr is bounded and mapped only to reviewed hints:
  app integration, sign-in, Environment lookup, declined access or exit status.
  Parser errors never echo source lines, names or values.
- Config cannot specify arbitrary executables, origins, headers, secret values
  or shell commands. Config errors do not echo source lines. Updates are atomic,
  serialized and private; shared-writable configs are refused.
- Requests use HTTPS with WebPKI roots, no proxy, no redirects and no retries.
  Relative endpoint validation prevents query/path injection and external hosts.
  The allowed origins are the documented Estonian and Polish Merit origins.
- Read-only projects allow only reviewed method/path pairs from the bundled list
  or explicit project `read_endpoints`. Unknown methods, versions, paths and PDF
  upload flags are denied with exit 7. The transport repeats the policy check.
  GET is not inherently allowed, and `get` prefixes are not treated as permission.
  Downloads to local files remain allowed. There is no per-request bypass flag.
- No option exports credentials, signatures, full signed URLs, raw provider
  output or signed cURL commands. Third-party error strings and panic messages
  are suppressed because they can contain secrets.
- Response redaction covers known API ID, API key and per-request signature in
  raw, form-URL-encoded and base64 forms. JSON escapes are decoded before
  redaction; nested JSON string documents are inspected too. Arbitrary
  transformation/fragmentation cannot be exhaustively recognized. This is
  defense in depth, not protection against a malicious Merit service encoding
  secrets in an unexpected way.
- Base64 strings are decoded and checked for known credential patterns before
  output or saving. A match redacts the entire field, and requested extraction
  fails closed. This does not detect arbitrary PDF encodings, compressed streams,
  encrypted content or other transformed representations of secrets.
- Attachment downloads use caller-selected paths, never filenames supplied by Merit.
  Outputs are private (0600), staged, then atomically published. Existing files
  require `--overwrite`, and destination symlinks/non-regular files are rejected.
  HTTP errors do not write attachments. PDF-specific flags additionally check the
  header and trailer. Generic attachment downloads preserve any decoded file
  format; the proxy does not sanitize, render or execute downloaded contents.
- Only rate-limit headers are returned. Redirect locations, cookies and arbitrary
  headers are withheld. Terminal control characters are removed from response text.
- Debug logs contain metadata and body hashes, never request/response bodies or
  credentials. New logs are private; non-private and symlink log files are refused.
- Credential strings and raw provider buffers use zeroing wrappers where practical.
  Libraries can retain copies; this does not guarantee resistance to memory
  inspection or core dumps.

## Trust assumptions and limits

Trust the installed binary, `op`, the toolchain/dependencies, config, PATH,
1Password Environment and OS account. Use a dedicated Environment containing
only this integration’s credentials, and protect the lookup’s parent directory.
The proxy uses the CLI’s desktop authorization or existing service-account/session
authentication; it does not bypass 1Password approval.

An agent with unrestricted same-user shell access can run `op` directly, replace
the binary, change PATH/config or inspect process memory. Private pipes and
in-memory values prevent accidental exposure; they do not remove those powers.
For actual isolation, run the credential/signing component under a separate OS
identity or host, expose a narrow tool/IPC interface, and keep credentials,
provider authentication and trusted files inaccessible to the agent. No such
broker or OS sandbox is installed here.

Read-write projects can create, update and delete financial records. Read-only
is an opt-in local configuration policy, not a change to the Merit key's scope or
1Password permissions. Existing configs default to read-write for compatibility.
The owner must trust the allowlist's classifications and review any custom rules.
An agent able to edit config, run `projects set-access`, replace the binary, or
add a writable alias to the same Environment can relax the policy. Restrict these
capabilities in the calling tool/broker for an enforced agent boundary, and use
credentials scoped to the intended integration. The CLI does not establish user
authorization for each individual accounting operation.

Business data is intentionally returned to the caller, including requested attachment
downloads. Credential redaction does not hide customer/accounting information.
Logs also reveal project aliases, endpoint names, upload filenames and hashes;
protect logs, downloaded files and captured stdout. Treat attachment contents as
untrusted business data, not agent instructions.
