#![cfg(unix)]

use serde_json::Value;
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Output, Stdio},
};
use tempfile::TempDir;

struct Fixture {
    root: TempDir,
    config: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("config.toml");
        Self { root, config }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mp"));
        command
            .env_clear()
            .env("HOME", self.root.path())
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.root.path().display()),
            )
            .arg("--config")
            .arg(&self.config);
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }

    fn add(&self, name: &str, environment: &str) {
        let output = self.run(&["projects", "add", name, "--environment", environment]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn op(&self, script: &str) {
        let path = self.root.path().join("op");
        fs::write(&path, format!("#!/bin/sh\n{script}")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

const FAKE_OP: &str = r#"
[ "$1" = --format ] && [ "$2" = human-readable ] || exit 80
[ "$3" = --encoding ] && [ "$4" = UTF-8 ] && [ "$5" = --no-color ] || exit 81
shift 5
if [ "$1" = --account ]; then
  [ "$2" = test-account ] || exit 82
  shift 2
fi
[ "$1" = environment ] && [ "$2" = read ] || exit 83
if [ "$3" = --help ]; then echo 'Usage: op environment read <environmentID>'; exit 0; fi
[ "$#" = 3 ] || exit 84
[ -z "$MERIT_API_ID" ] && [ -z "$MERIT_API_KEY" ] || exit 85
[ "$OP_DEBUG" = false ] || exit 86
[ -z "$HTTPS_PROXY" ] && [ -z "$SSLKEYLOGFILE" ] && [ -z "$OP_FORMAT" ] || exit 87
case "$3" in
  env-a) printf '%s\n' 'MERIT_API_ID=canary-private-id-A' 'MERIT_API_KEY=canary-private+/key-A==' ;;
  env-b) printf '%s\n' 'MERIT_API_ID=canary-private-id-B' ;;
  env-c) printf '%s\n' 'API_ID=canary-private-id-C' 'ApiKey=canary-private-key-C' ;;
  *) exit 88 ;;
esac
"#;

#[test]
fn multiple_projects_and_private_atomic_config() {
    let f = Fixture::new();
    f.add("alpha", "env-a");
    f.add("beta", "env-b");
    let listed = json(&f.run(&["projects", "list"]));
    assert_eq!(listed["projects"]["alpha"]["environment"], "env-a");
    assert_eq!(listed["projects"]["beta"]["environment"], "env-b");
    assert_eq!(
        fs::metadata(&f.config).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        f.run(&["projects", "add", "alpha", "--environment", "env-b"])
            .status
            .code(),
        Some(2)
    );
    assert!(
        f.run(&[
            "projects",
            "add",
            "alpha",
            "--environment",
            "env-b",
            "--replace"
        ])
        .status
        .success()
    );
    assert!(f.run(&["projects", "remove", "beta"]).status.success());
    assert!(
        json(&f.run(&["projects", "list"]))["projects"]
            .get("beta")
            .is_none()
    );
    let out = f.run(&[
        "projects",
        "add",
        "versioned",
        "--environment",
        "env-c",
        "--api-version",
        "v2",
        "--region",
        "pl",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = f.run(&["-p", "versioned", "getcustomers", "--dry-run"]);
    assert_eq!(json(&out)["request"]["path"], "/api/v2/getcustomers");
    assert_eq!(
        json(&out)["request"]["origin"],
        "https://program.360ksiegowosc.pl"
    );
}

#[test]
fn parallel_project_writers_do_not_lose_mappings() {
    let f = Fixture::new();
    let mut children: Vec<_> = (0..8)
        .map(|n| {
            f.command()
                .args([
                    "projects",
                    "add",
                    &format!("p{n}"),
                    "--environment",
                    "env-a",
                ])
                .stdout(Stdio::null())
                .spawn()
                .unwrap()
        })
        .collect();
    for child in &mut children {
        assert!(child.wait().unwrap().success());
    }
    assert_eq!(
        json(&f.run(&["projects", "list"]))["projects"]
            .as_object()
            .unwrap()
            .len(),
        8
    );
}

#[test]
fn dry_run_does_not_invoke_op_or_expose_body() {
    let f = Fixture::new();
    f.add("alpha", "env-a");
    f.op("echo op-was-called >&2; exit 99");
    let out = f.run(&[
        "--debug",
        "-p",
        "alpha",
        "/api/v2/FutureEndpoint",
        "--data",
        "{\"private_customer\":\"body-canary\",\"amount\":1.2300}",
        "--dry-run",
    ]);
    assert!(out.status.success());
    assert_eq!(json(&out)["request"]["path"], "/api/v2/FutureEndpoint");
    assert_eq!(json(&out)["credentials"], "not_accessed");
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!all.contains("body-canary") && !all.contains("op-was-called"));
}

#[test]
fn pdf_dry_run_builds_signed_payload_without_op_or_leaking_content() {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let f = Fixture::new();
    f.add("alpha", "env-a");
    f.op("touch \"$HOME/op-was-called\"; exit 99");
    let pdf = include_bytes!("fixtures/blank.pdf");
    let path = f.root.path().join("receipt.pdf");
    fs::write(&path, pdf).unwrap();
    let saved = f.root.path().join("future.pdf");
    for explicit in [false, true] {
        let mut cmd = f.command();
        cmd.args(["--debug", "-p", "alpha", "--dry-run", "--attach-pdf"])
            .arg(&path)
            .arg("--save-pdf")
            .arg(&saved)
            .arg("--list-pdfs");
        if explicit {
            cmd.arg("request");
        }
        let out = cmd
            .args(["/api/v2/sendpurchorder", "--data", "{\"Amount\":1.2300}"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let result = json(&out);
        assert_eq!(result["credentials"], "not_accessed");
        assert_eq!(result["request"]["pdf_uploads"][0]["bytes"], pdf.len());
        assert_eq!(
            result["request"]["pdf_uploads"][0]["file_name"],
            "receipt.pdf"
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode(pdf);
        let mut expected: Value = serde_json::from_str("{\"Amount\":1.2300}").unwrap();
        expected["Attachment"] =
            serde_json::json!({"FileName":"receipt.pdf", "FileContent":encoded});
        assert_eq!(
            result["request"]["body_sha256"],
            format!("{:x}", Sha256::digest(expected.to_string().as_bytes()))
        );
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!all.contains(&encoded));
        assert!(!saved.exists());
        assert!(!f.root.path().join("op-was-called").exists());
    }
}

#[test]
fn pdf_preflight_errors_happen_before_credentials_or_network() {
    let f = Fixture::new();
    f.add("alpha", "env-a");
    f.op("touch \"$HOME/op-was-called\"; exit 99");
    let path = f.root.path().join("invalid.pdf");
    fs::write(&path, b"not pdf").unwrap();
    for flag in ["--attach-pdf", "--save-pdf"] {
        let out = f
            .command()
            .args(["-p", "alpha", "getcustomers", flag])
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }
    assert!(!f.root.path().join("op-was-called").exists());
    assert_eq!(fs::read(path).unwrap(), b"not pdf");
}

#[test]
fn pdf_flags_cannot_be_silently_ignored_on_admin_commands() {
    let f = Fixture::new();
    for args in [
        vec!["projects", "list", "--list-pdfs"],
        vec!["config", "path", "--attach-pdf", "receipt.pdf"],
        vec!["doctor", "--save-pdf", "invoice.pdf"],
        vec!["-p", "alpha", "getcustomers", "--body-only", "--list-pdfs"],
        vec!["-p", "alpha", "getcustomers", "--overwrite"],
        vec![
            "-p",
            "alpha",
            "getcustomers",
            "--save-pdf",
            "bad~pointer=file.pdf",
        ],
    ] {
        assert_eq!(f.run(&args).status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn stdin_and_file_inputs_have_identical_exact_byte_hashes() {
    let f = Fixture::new();
    f.add("alpha", "env-a");
    let body = "{\n  \"name\": \"Õie\", \"amount\": 1.2300\n}\n";
    let body_path = f.root.path().join("body.json");
    fs::write(&body_path, body).unwrap();
    let file = f
        .command()
        .args(["-p", "alpha", "getcustomers", "--dry-run", "--file"])
        .arg(body_path)
        .output()
        .unwrap();
    let mut child = f
        .command()
        .args(["-p", "alpha", "getcustomers", "--dry-run", "--data", "@-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(body.as_bytes())
        .unwrap();
    let stdin = child.wait_with_output().unwrap();
    assert!(file.status.success() && stdin.status.success());
    assert_eq!(
        json(&file)["request"]["body_sha256"],
        json(&stdin)["request"]["body_sha256"]
    );
    assert_eq!(json(&file)["request"]["request_bytes"], body.len());
}

#[test]
fn validates_before_secrets_are_loaded() {
    let f = Fixture::new();
    f.add("alpha", "env-a");
    f.op("echo op-was-called >&2; exit 99");
    for endpoint in [
        "https://evil.test",
        "//evil.test/x",
        "../get",
        "get?signature=canary",
        "get%2Fxx",
        "get#xx",
    ] {
        let out = f.run(&["-p", "alpha", endpoint]);
        assert_eq!(out.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&out.stderr).contains("op-was-called"));
    }
    let out = f.run(&[
        "-p",
        "alpha",
        "getcustomers",
        "--data",
        "invalid-secret-canary",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("invalid-secret-canary"));
}

#[test]
fn private_pipe_uses_selected_environment_and_ignores_ambient_credentials() {
    let f = Fixture::new();
    f.add("alpha", "env-a");
    f.add("beta", "env-b");
    f.op(FAKE_OP);
    let out = f
        .command()
        .env("MERIT_API_ID", "ambient-id")
        .env("MERIT_API_KEY", "ambient-key")
        .env("OP_DEBUG", "true")
        .env("HTTPS_PROXY", "https://evil.test")
        .env("SSLKEYLOGFILE", "/tmp/never-created")
        .args(["--debug", "-p", "alpha", "doctor", "--auth"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(json(&out)["credentials"], "available");
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!all.contains("canary-private") && !all.contains("ambient-key"));
    let out = f
        .command()
        .env("MERIT_API_KEY", "ambient-key")
        .args(["-p", "beta", "doctor", "--auth"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("API key variable is missing"));
}

#[test]
fn custom_variable_names_and_read_only_doctor() {
    let f = Fixture::new();
    let added = f.run(&[
        "projects",
        "add",
        "custom",
        "--environment",
        "env-c",
        "--api-id-var",
        "API_ID",
        "--api-key-var",
        "ApiKey",
        "--account",
        "test-account",
    ]);
    assert!(added.status.success());
    f.op(FAKE_OP);
    assert_eq!(
        json(&f.run(&["--project", "custom", "doctor"]))["credentials"],
        "not_checked"
    );
    assert_eq!(
        json(&f.run(&["--project", "custom", "doctor", "--auth"]))["credentials"],
        "available"
    );
}

#[test]
fn raw_provider_errors_and_invalid_environment_output_never_escape() {
    let f = Fixture::new();
    f.add("alpha", "env-a");
    for script in [
        "echo raw-secret-canary; echo stderr-secret-canary >&2; exit 1",
        "echo raw-secret-canary; echo stderr-secret-canary >&2; exit 0",
    ] {
        f.op(script);
        let out = f.run(&["--debug", "-p", "alpha", "getcustomers"]);
        assert_eq!(out.status.code(), Some(3));
        assert!(out.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&out.stderr).contains("secret-canary"));
    }
}

#[test]
fn invalid_config_does_not_echo_secret_values() {
    let f = Fixture::new();
    fs::write(
        &f.config,
        "[projects.alpha]\nenvironment = 'env-a'\napi_key = 'never-print-this-secret'",
    )
    .unwrap();
    let out = f.run(&["projects", "list"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("never-print-this-secret"));
}

#[test]
fn rejects_shared_writable_config_and_insecure_or_symlink_logs() {
    let f = Fixture::new();
    f.add("alpha", "env-a");
    fs::set_permissions(&f.config, fs::Permissions::from_mode(0o666)).unwrap();
    assert_eq!(f.run(&["projects", "list"]).status.code(), Some(2));
    let log = f.root.path().join("log");
    fs::write(&log, "").unwrap();
    fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        f.command()
            .arg("--log-file")
            .arg(&log)
            .args(["config", "path"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(6)
    );
    let link = f.root.path().join("link");
    std::os::unix::fs::symlink(log, &link).unwrap();
    assert_eq!(
        f.command()
            .arg("--log-file")
            .arg(link)
            .args(["config", "path"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(6)
    );
}

#[test]
fn project_flags_work_with_direct_and_explicit_invocations() {
    let f = Fixture::new();
    f.add("rouk", "env-a");
    f.op("echo op-was-called >&2; exit 99");
    let variants = [
        vec!["-p", "rouk", "getcustomers", "--data", "{}", "--dry-run"],
        vec![
            "--project",
            "rouk",
            "getcustomers",
            "--data",
            "{}",
            "--dry-run",
        ],
        vec![
            "getcustomers",
            "--project",
            "rouk",
            "--data",
            "{}",
            "--dry-run",
        ],
        vec![
            "-p",
            "rouk",
            "request",
            "getcustomers",
            "--data",
            "{}",
            "--dry-run",
        ],
        vec![
            "-p",
            "rouk",
            "--dry-run",
            "--data",
            "{}",
            "request",
            "getcustomers",
        ],
    ];
    for args in variants {
        let out = f.run(&args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(json(&out)["request"]["project"], "rouk");
        assert_eq!(json(&out)["request"]["path"], "/api/v1/getcustomers");
        assert_eq!(json(&out)["request"]["request_bytes"], 2);
        assert_eq!(json(&out)["credentials"], "not_accessed");
    }
}

#[test]
fn missing_or_unknown_project_fails_before_provider_access() {
    let f = Fixture::new();
    f.add("rouk", "env-a");
    f.op("echo op-was-called >&2; exit 99");
    for args in [
        vec!["getcustomers"],
        vec!["-p", "missing", "getcustomers"],
        vec!["doctor", "--auth"],
        vec!["-p", "rouk"],
        vec!["--dry-run", "-p", "rouk", "doctor", "--auth"],
    ] {
        let out = f.run(&args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(!String::from_utf8_lossy(&out.stderr).contains("op-was-called"));
    }
}

#[test]
fn literal_environment_parsing_never_evaluates_shell_code_or_logs_secrets() {
    let f = Fixture::new();
    f.add("rouk", "env-a");
    let marker = f.root.path().join("must-not-exist");
    f.op(&format!(
        r#"
if [ "$8" = --help ]; then echo 'op environment read'; exit 0; fi
cat <<'SECRETS'
MERIT_API_ID=canary-private-id
MERIT_API_KEY=canary+key/with=padding==
EMPTY=
UNRELATED=a$(touch '{}')`uname` # literal
PATH=/never/use/this
OP_DEBUG=true
SECRETS
"#,
        marker.display()
    ));
    let log = f.root.path().join("debug.jsonl");
    let out = f
        .command()
        .arg("--log-file")
        .arg(&log)
        .args(["--debug", "-p", "rouk", "doctor", "--auth"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(json(&out)["credentials"], "available");
    assert!(!marker.exists());
    let traces = format!(
        "{}{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
        fs::read_to_string(&log).unwrap()
    );
    assert!(!traces.contains("canary") && !traces.contains("UNRELATED"));
    assert_eq!(
        fs::metadata(log).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn environment_parser_fails_closed_on_ambiguous_or_invalid_data() {
    let f = Fixture::new();
    f.add("rouk", "env-a");
    let prefix = "MERIT_API_ID=canary-private-id\nMERIT_API_KEY=canary-private-key\n";
    let cases = [
        format!("{prefix}MERIT_API_KEY=another-secret-canary"),
        format!("{prefix}UNRELATED=\"secret-canary\""),
        format!("{prefix}UNRELATED='secret-canary'"),
        format!("{prefix}multiline-secret-canary"),
        format!("{prefix}2BAD=secret-canary"),
        format!(
            "{prefix}{}",
            (0..513)
                .map(|n| format!("VAR_{n}=secret-canary\n"))
                .collect::<String>()
        ),
    ];
    for content in cases {
        f.op(&format!("if [ \"$8\" = --help ]; then echo 'op environment read'; exit 0; fi\ncat <<'SECRETS'\n{content}\nSECRETS\n"));
        let out = f.run(&["--debug", "-p", "rouk", "doctor", "--auth"]);
        assert_eq!(out.status.code(), Some(3));
        assert!(out.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&out.stderr).contains("canary"));
    }
}

#[test]
fn provider_errors_explain_the_fix_without_forwarding_raw_diagnostics() {
    let f = Fixture::new();
    f.add("rouk", "env-a");
    for (message, expected) in [
        (
            "connecting to desktop app canary-private-key",
            "Integrate with 1Password CLI",
        ),
        ("environment not found canary-private-key", "copy its ID"),
        ("session expired canary-private-key", "unlock"),
        ("access denied canary-private-key", "declined"),
        ("unexpected canary-private-key", "exit status 7"),
    ] {
        f.op(&format!("printf '%s\\n' '{message}' >&2\nexit 7\n"));
        let out = f.run(&["-p", "rouk", "getcustomers"]);
        assert_eq!(out.status.code(), Some(3));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(expected), "{stderr}");
        assert!(!stderr.contains("canary"));
    }
}

#[test]
fn provider_format_is_fixed_and_crlf_values_are_supported() {
    let f = Fixture::new();
    f.add("rouk", "env-a");
    f.op(FAKE_OP);
    let out = f
        .command()
        .env("OP_FORMAT", "json")
        .args(["-p", "rouk", "doctor", "--auth"])
        .output()
        .unwrap();
    assert!(out.status.success());
    f.op("if [ \"$8\" = --help ]; then echo 'op environment read'; exit 0; fi\nprintf 'MERIT_API_ID=canary-id\\r\\nMERIT_API_KEY=canary-key==\\r\\n'");
    assert!(f.run(&["-p", "rouk", "doctor", "--auth"]).status.success());
}

#[test]
fn read_only_projects_allow_data_pdf_and_attachment_reads_but_deny_writes_before_auth() {
    let f = Fixture::new();
    let add = f.run(&[
        "projects",
        "add",
        "rouk",
        "--environment",
        "env-a",
        "--read-only",
    ]);
    assert!(
        add.status.success(),
        "{}",
        String::from_utf8_lossy(&add.stderr)
    );
    assert_eq!(
        json(&f.run(&["projects", "list"]))["projects"]["rouk"]["read_only"],
        true
    );
    f.op("touch \"$HOME/op-was-called\"; exit 99");
    for endpoint in [
        "sendinvoice",
        "deleteinvoice",
        "getAndDelete",
        "/api/v2/sendpurchorder",
        "/api/v99/getcustomers",
        "/api/v1/getcustomers/delete",
        "/api/v1/GetCustomers",
    ] {
        for explicit in [false, true] {
            let mut args = vec!["-p", "rouk"];
            if explicit {
                args.push("request");
            }
            args.extend([endpoint, "--file", "/nonexistent/body.json"]);
            let out = f.run(&args);
            assert_eq!(
                out.status.code(),
                Some(7),
                "{args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(out.stdout.is_empty());
            assert_eq!(
                serde_json::from_slice::<Value>(&out.stderr).unwrap()["error"]["code"],
                "read_only"
            );
        }
    }
    assert_eq!(
        f.run(&[
            "-p",
            "rouk",
            "getcustomers",
            "--attach-pdf",
            "/nonexistent.pdf"
        ])
        .status
        .code(),
        Some(7)
    );
    assert_eq!(
        f.run(&["-p", "rouk", "getcustomers", "--method", "GET"])
            .status
            .code(),
        Some(7)
    );
    assert_eq!(
        f.run(&[
            "-p",
            "rouk",
            "getcustomers",
            "--api-version",
            "v99",
            "--dry-run"
        ])
        .status
        .code(),
        Some(7)
    );
    for endpoint in [
        "getcustomers",
        "getvendors",
        "/api/v2/getinvoices",
        "/api/v2/getinvoice",
        "/api/v2/getpurchorder",
        "/api/v2/getsalesinvpdf",
        "getglbatch",
    ] {
        let target = f.root.path().join("download.pdf");
        let out = f
            .command()
            .args([
                "-p",
                "rouk",
                endpoint,
                "--data",
                "{}",
                "--dry-run",
                "--save-pdf",
            ])
            .arg(&target)
            .arg("--list-attachments")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{endpoint}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(json(&out)["request"]["read_only"], true);
        assert!(!target.exists());
    }
    let out = f.run(&[
        "-p",
        "rouk",
        "--method",
        "get",
        "request",
        "/api/v2/accounts",
        "--data",
        "{}",
        "--dry-run",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(json(&out)["request"]["method"], "GET");
    assert!(!f.root.path().join("op-was-called").exists());
    // A real allowed invocation reaches only the fake provider, which stops before HTTP.
    assert_eq!(
        f.run(&["-p", "rouk", "/api/v2/getpurchorder", "--list-attachments"])
            .status
            .code(),
        Some(3)
    );
    assert!(f.root.path().join("op-was-called").exists());
}

#[test]
fn access_changes_preserve_mapping_and_replace_preserves_read_only_policy() {
    let f = Fixture::new();
    f.add("alpha", "env-a");
    f.add("beta", "env-b");
    // Existing configurations without the new field retain their historical access.
    let old = fs::read_to_string(&f.config)
        .unwrap()
        .replace("read_only = false\n", "");
    fs::write(&f.config, old).unwrap();
    assert_eq!(
        json(&f.run(&["projects", "list"]))["projects"]["alpha"]["read_only"],
        false
    );
    assert!(
        f.run(&["projects", "set-access", "alpha", "read-only"])
            .status
            .success()
    );
    let list = json(&f.run(&["projects", "list"]));
    assert_eq!(list["projects"]["alpha"]["environment"], "env-a");
    assert_eq!(list["projects"]["alpha"]["read_only"], true);
    assert_eq!(list["projects"]["beta"]["read_only"], false);
    assert!(
        f.run(&[
            "projects",
            "add",
            "alpha",
            "--environment",
            "env-c",
            "--replace"
        ])
        .status
        .success()
    );
    assert_eq!(
        json(&f.run(&["projects", "list"]))["projects"]["alpha"]["read_only"],
        true
    );
    assert!(
        f.run(&["projects", "set-access", "alpha", "read-write"])
            .status
            .success()
    );
    assert!(
        f.run(&["-p", "alpha", "FutureWrite", "--dry-run"])
            .status
            .success()
    );
    assert!(
        f.run(&["projects", "set-access", "missing", "read-only"])
            .status
            .code()
            == Some(2)
    );
}

#[test]
fn additional_read_rules_are_exact_validated_and_visible_without_rebuilding() {
    let f = Fixture::new();
    let out = f.run(&[
        "projects",
        "add",
        "rouk",
        "--environment",
        "env-a",
        "--read-only",
        "--read-endpoint",
        "POST /api/v42/newreport",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        f.run(&["-p", "rouk", "/api/v42/newreport", "--dry-run"])
            .status
            .success()
    );
    assert_eq!(
        f.run(&[
            "-p",
            "rouk",
            "/api/v42/newreport",
            "--method",
            "GET",
            "--dry-run"
        ])
        .status
        .code(),
        Some(7)
    );
    assert_eq!(
        f.run(&["-p", "rouk", "/api/v43/newreport", "--dry-run"])
            .status
            .code(),
        Some(7)
    );
    let policy = json(&f.run(&["projects", "policy", "rouk"]));
    assert_eq!(policy["read_only"], true);
    assert!(
        policy["read_endpoints"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("POST /api/v42/newreport"))
    );
    assert!(
        f.run(&[
            "projects",
            "add",
            "rouk",
            "--environment",
            "env-a",
            "--replace"
        ])
        .status
        .success()
    );
    assert!(
        f.run(&["-p", "rouk", "/api/v42/newreport", "--dry-run"])
            .status
            .success()
    );
    for rule in [
        "* /api/v1/getcustomers",
        "POST /api/v1/*",
        "getcustomers",
        "GET https://evil.test",
        "POST /api/v1/../deleteinvoice",
        "GET /api/v2/accounts?x=1",
        "post /api/v2/report",
    ] {
        assert_eq!(
            f.run(&[
                "projects",
                "add",
                "invalid",
                "--environment",
                "env-a",
                "--read-only",
                "--read-endpoint",
                rule
            ])
            .status
            .code(),
            Some(2),
            "{rule}"
        );
    }
}

#[test]
fn generic_attachment_download_flags_preflight_and_combine_with_pdf_flags() {
    let f = Fixture::new();
    f.add("rouk", "env-a");
    let pdf = f.root.path().join("output.pdf");
    let binary = f.root.path().join("output.bin");
    let out = f
        .command()
        .args(["-p", "rouk", "--save-attachment"])
        .arg(&binary)
        .args([
            "--list-attachments",
            "request",
            "/api/v2/getpurchorder",
            "--save-pdf",
        ])
        .arg(&pdf)
        .arg("--dry-run")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!binary.exists() && !pdf.exists());
    for args in [
        vec!["projects", "list", "--list-attachments"],
        vec!["doctor", "--save-attachment", "file.bin"],
        vec![
            "-p",
            "rouk",
            "getcustomers",
            "--body-only",
            "--save-attachment",
            "file.bin",
        ],
        vec![
            "-p",
            "rouk",
            "getcustomers",
            "--list-pdfs",
            "--list-attachments",
        ],
    ] {
        assert_eq!(f.run(&args).status.code(), Some(2));
    }
    fs::write(&binary, b"existing").unwrap();
    let out = f
        .command()
        .args(["-p", "rouk", "getcustomers", "--save-attachment"])
        .arg(&binary)
        .args(["--overwrite", "--dry-run"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(fs::read(binary).unwrap(), b"existing");
}
