use std::{
    collections::BTreeMap,
    io::Read,
    time::{Duration, Instant},
};

use chrono::Utc;
use reqwest::{blocking::Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::{
    config::{Project, validate_version},
    error::{Result, SafeError},
    policy::{self, Method},
    redact::Redactor,
    signing,
};

pub const MAX_BODY: usize = 16 * 1024 * 1024;
pub const MAX_RESPONSE: usize = 32 * 1024 * 1024;

pub struct Request {
    pub project: Project,
    pub method: Method,
    pub path: String,
    pub body: String,
    pub timeout: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Value,
    pub response_bytes: usize,
    pub http_ms: u128,
    pub redacted: bool,
}

pub struct Credentials {
    pub id: Zeroizing<String>,
    pub key: Zeroizing<String>,
}

impl Credentials {
    pub fn new(id: Zeroizing<String>, key: Zeroizing<String>) -> Result<Self> {
        if id.is_empty() || key.is_empty() || id.starts_with("op://") || key.starts_with("op://") {
            return Err(SafeError::auth(
                "Merit credentials are empty or unresolved secret references",
            ));
        }
        if id.len() > 4096
            || key.len() > 4096
            || !key.is_ascii()
            || id.chars().any(char::is_control)
            || key.chars().any(char::is_whitespace)
        {
            return Err(SafeError::auth(
                "Merit credentials have an invalid format; check the values in 1Password",
            ));
        }
        Ok(Self { id, key })
    }
}

pub fn resolve_path(endpoint: &str, default_version: &str) -> Result<String> {
    validate_version(default_version)?;
    let path = endpoint.strip_prefix('/').unwrap_or(endpoint);
    if path.is_empty()
        || path.len() > 512
        || path.split('/').any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
    {
        return Err(SafeError::input(
            "endpoint must be a relative Merit path; URLs, queries, fragments, percent escapes and dot segments are forbidden",
        ));
    }
    if path.starts_with("api/") {
        let mut segments = path.split('/');
        segments.next();
        validate_version(segments.next().unwrap_or(""))?;
        if segments.next().is_none() {
            return Err(SafeError::input("API path must include an endpoint"));
        }
        Ok(format!("/{path}"))
    } else {
        Ok(format!("/api/{default_version}/{path}"))
    }
}

pub fn validate_body(body: &[u8]) -> Result<()> {
    if body.len() > MAX_BODY {
        return Err(SafeError::input("request body exceeds 16 MiB"));
    }
    if !body.is_empty() {
        serde_json::from_slice::<Value>(body).map_err(|_| SafeError::input("request body must be valid UTF-8 JSON; the parser message is suppressed to avoid echoing data"))?;
    }
    Ok(())
}

pub fn client(timeout: u64) -> Result<Client> {
    if !(1..=300).contains(&timeout) {
        return Err(SafeError::input(
            "timeout must be between 1 and 300 seconds",
        ));
    }
    Client::builder()
        .https_only(true)
        .redirect(Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .connect_timeout(Duration::from_secs(timeout.min(10)))
        .timeout(Duration::from_secs(timeout))
        .user_agent(concat!("merit-proxy/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| SafeError::new("transport_setup", "cannot initialize HTTPS transport", 4))
}

pub fn execute(request: &Request, credentials: &Credentials) -> Result<Reply> {
    request.project.validate()?;
    validate_body(request.body.as_bytes())?;
    if resolve_path(&request.path, &request.project.api_version)? != request.path {
        return Err(SafeError::input("invalid request endpoint"));
    }
    policy::authorize(&request.project, request.method, &request.path, false)?;
    let client = client(request.timeout)?;
    send(
        &client,
        &format!("{}{}", request.project.region.origin(), request.path),
        request.body.as_bytes(),
        credentials,
        request.method,
    )
}

fn send(
    client: &Client,
    endpoint_url: &str,
    body: &[u8],
    credentials: &Credentials,
    method: Method,
) -> Result<Reply> {
    let started = Instant::now();
    let timestamp = Utc::now().format("%Y%m%d%H%M%S").to_string();
    let signature = signing::sign(&credentials.id, &credentials.key, &timestamp, body);
    let mut redactor = Redactor::default();
    redactor.add(&credentials.id);
    redactor.add(&credentials.key);
    redactor.add(&signature);
    let response = client
        .request(method.http(), endpoint_url)
        .query(&[
            ("ApiId", credentials.id.as_str()),
            ("timestamp", timestamp.as_str()),
            ("signature", signature.as_str()),
        ])
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .body(body.to_vec())
        .send()
        .map_err(safe_transport_error)?;
    let status = response.status().as_u16();
    // Do not expose Location, Set-Cookie or arbitrary headers, which may echo credentials.
    let mut headers = BTreeMap::new();
    for name in [
        "retry-after",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
    ] {
        if let Some(value) = response.headers().get(name).and_then(|h| h.to_str().ok()) {
            headers.insert(name.into(), redactor.text(value));
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    response.take((MAX_RESPONSE + 1) as u64).read_to_end(&mut bytes)
        .map_err(|_| SafeError::new("response_read", "could not read the full response; request may have completed; check Merit before retrying writes", 4))?;
    if bytes.len() > MAX_RESPONSE {
        return Err(SafeError::new(
            "response_limit",
            "response exceeds 32 MiB; narrow the query; request may have completed",
            4,
        ));
    }
    let value = redactor.response(&bytes);
    let redacted = value.to_string().contains("[REDACTED]")
        || headers.values().any(|v| v.contains("[REDACTED]"));
    Ok(Reply {
        status,
        headers,
        body: value,
        response_bytes: bytes.len(),
        http_ms: started.elapsed().as_millis(),
        redacted,
    })
}

fn safe_transport_error(error: reqwest::Error) -> SafeError {
    if error.is_timeout() {
        SafeError::new(
            "timeout",
            "HTTPS request timed out; it may have completed; check Merit before retrying writes",
            4,
        )
    } else if error.is_connect() {
        SafeError::new(
            "connection",
            "HTTPS connection failed; check DNS, connectivity and TLS trust",
            4,
        )
    } else {
        SafeError::new(
            "transport",
            "HTTPS request failed; it may have completed; check Merit before retrying writes",
            4,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        thread,
    };

    fn credentials() -> Credentials {
        Credentials {
            id: Zeroizing::new("private-api-id".into()),
            key: Zeroizing::new("private+/api-key==".into()),
        }
    }

    fn mock_client() -> Client {
        // Only test code can select a non-Merit origin or permit plaintext HTTP.
        Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap()
    }

    fn server(
        response: impl FnOnce(String, Vec<u8>) -> String + Send + 'static,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://{}/api/v1/getcustomers",
            listener.local_addr().unwrap()
        );
        let handle = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut first = String::new();
            reader.read_line(&mut first).unwrap();
            let mut length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            socket.write_all(response(first, body).as_bytes()).unwrap();
        });
        (url, handle)
    }

    fn http(status: u16, headers: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
            body.len()
        )
    }

    #[test]
    fn wire_signature_covers_exact_bytes_and_echoed_auth_is_redacted() {
        let body = "{\n \"name\":\"Õie\", \"amount\":1.2300\n}\n";
        let (url, handle) = server(move |request_line, received| {
            assert_eq!(received, body.as_bytes());
            assert!(request_line.starts_with("POST /api/v1/getcustomers?"));
            let target = request_line.split_whitespace().nth(1).unwrap();
            let parsed = reqwest::Url::parse(&format!("https://example.invalid{target}")).unwrap();
            let params: BTreeMap<_, _> = parsed.query_pairs().into_owned().collect();
            assert_eq!(params.len(), 3);
            assert_eq!(params["ApiId"], "private-api-id");
            assert_eq!(params["timestamp"].len(), 14);
            assert_eq!(
                params["signature"],
                *signing::sign(
                    "private-api-id",
                    "private+/api-key==",
                    &params["timestamp"],
                    &received
                )
            );
            let payload = serde_json::json!({"echo_url":target,"signature":params["signature"],"key":"private+/api-key==","amount":1.23}).to_string();
            http(200, "Content-Type: application/json\r\n", &payload)
        });
        let reply = send(
            &mock_client(),
            &url,
            body.as_bytes(),
            &credentials(),
            Method::Post,
        )
        .unwrap();
        handle.join().unwrap();
        assert_eq!(reply.status, 200);
        assert!(reply.redacted);
        assert_eq!(reply.body["signature"], "[REDACTED]");
        assert_eq!(reply.body["key"], "[REDACTED]");
        assert!(!reply.body.to_string().contains("private-api-id"));
        assert!(
            reply.body["echo_url"]
                .as_str()
                .unwrap()
                .contains("signature=[REDACTED]")
        );
    }

    #[test]
    fn pdf_upload_is_signed_and_returned_pdf_survives_redaction_and_disk_roundtrip() {
        use crate::attachments::{self, FileSpec};
        use base64::Engine;
        let bytes = include_bytes!("../tests/fixtures/blank.pdf");
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.pdf");
        let destination = dir.path().join("download.pdf");
        std::fs::write(&source, bytes).unwrap();
        let mut body = r#"{"InvoiceNo":"test-123","Amount":1.2300}"#.to_owned();
        attachments::attach(
            &mut body,
            &[FileSpec {
                require_pdf: true,
                pointer: "/Attachment".into(),
                path: source,
            }],
        )
        .unwrap();
        let (url, handle) = server(move |request_line, received| {
            let payload: Value = serde_json::from_slice(&received).unwrap();
            assert_eq!(payload["Amount"].to_string(), "1.2300");
            let encoded = payload["Attachment"]["FileContent"].as_str().unwrap();
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .unwrap(),
                bytes
            );
            let target = request_line.split_whitespace().nth(1).unwrap();
            let parsed = reqwest::Url::parse(&format!("https://example.invalid{target}")).unwrap();
            let params: BTreeMap<_, _> = parsed.query_pairs().into_owned().collect();
            assert_eq!(
                params["signature"],
                *signing::sign(
                    "private-api-id",
                    "private+/api-key==",
                    &params["timestamp"],
                    &received
                )
            );
            http(200, "Content-Type: application/json\r\n", &serde_json::json!({"FileName":"invoice.pdf","FileContent":encoded,"echo":"private-api-id"}).to_string())
        });
        let mut reply = send(
            &mock_client(),
            &url,
            body.as_bytes(),
            &credentials(),
            Method::Post,
        )
        .unwrap();
        handle.join().unwrap();
        assert!(reply.redacted);
        let pdfs = attachments::receive(
            &mut reply.body,
            &[FileSpec {
                require_pdf: true,
                pointer: "/FileContent".into(),
                path: destination.clone(),
            }],
            crate::attachments::Listing::None,
            false,
        )
        .unwrap();
        assert_eq!(std::fs::read(destination).unwrap(), bytes);
        assert_eq!(pdfs[0].bytes, bytes.len());
        assert_eq!(reply.body["echo"], "[REDACTED]");
        assert!(reply.body["FileContent"].is_null());
    }

    #[test]
    fn reflected_credentials_inside_pdf_cannot_be_saved() {
        use base64::Engine;
        let (url, handle) = server(|_, _| {
            let encoded = base64::engine::general_purpose::STANDARD
                .encode(b"%PDF-1.4\nprivate+/api-key==\n%%EOF");
            http(
                200,
                "",
                &serde_json::json!({"FileContent":encoded}).to_string(),
            )
        });
        let mut reply = send(&mock_client(), &url, b"{}", &credentials(), Method::Post).unwrap();
        handle.join().unwrap();
        assert!(reply.redacted);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("refused.pdf");
        assert!(
            crate::attachments::receive(
                &mut reply.body,
                &[crate::attachments::FileSpec {
                    require_pdf: true,
                    pointer: "/FileContent".into(),
                    path: path.clone()
                }],
                crate::attachments::Listing::None,
                false
            )
            .is_err()
        );
        assert!(!path.exists());
    }

    #[test]
    fn redirects_are_not_followed_and_location_is_not_exposed() {
        let (url, handle) = server(|_, _| {
            http(
                302,
                "Location: http://127.0.0.1:1/secret-canary\r\n",
                "redirect",
            )
        });
        let reply = send(&mock_client(), &url, b"", &credentials(), Method::Post).unwrap();
        handle.join().unwrap();
        assert_eq!(reply.status, 302);
        assert!(reply.headers.is_empty());
        assert!(
            !serde_json::to_string(&reply)
                .unwrap()
                .contains("secret-canary")
        );
    }

    #[test]
    fn rate_limits_and_non_json_errors_are_available_without_secrets() {
        let (url, handle) = server(|_, _| {
            http(
                429,
                "Retry-After: 2\r\nX-RateLimit-Remaining: 0\r\nSet-Cookie: secret-canary\r\n",
                "error private-api-id private+/api-key==",
            )
        });
        let reply = send(&mock_client(), &url, b"{}", &credentials(), Method::Post).unwrap();
        handle.join().unwrap();
        assert_eq!(reply.status, 429);
        assert_eq!(reply.headers["retry-after"], "2");
        assert_eq!(reply.headers.len(), 2);
        assert_eq!(reply.body, "error [REDACTED] [REDACTED]");
    }

    #[test]
    fn transport_errors_do_not_contain_a_signed_url() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        drop(listener);
        let error = send(&mock_client(), &url, b"{}", &credentials(), Method::Post).unwrap_err();
        assert_eq!(error.code, "connection");
        let text = serde_json::to_string(&error).unwrap();
        assert!(
            !text.contains("private") && !text.contains("signature") && !text.contains("http://")
        );
    }

    #[test]
    fn get_method_preserves_body_signature_and_redaction() {
        let body = "{\"UsageFilter\":1}";
        let (url, handle) = server(move |line, received| {
            assert!(line.starts_with("GET /api/v1/getcustomers?"));
            assert_eq!(received, body.as_bytes());
            let target = line.split_whitespace().nth(1).unwrap();
            let url = reqwest::Url::parse(&format!("https://example.invalid{target}")).unwrap();
            let params: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
            assert_eq!(
                params["signature"],
                *signing::sign(
                    "private-api-id",
                    "private+/api-key==",
                    &params["timestamp"],
                    &received
                )
            );
            http(200, "", r#"{"echo":"private-api-id","Code":"1000"}"#)
        });
        let reply = send(
            &mock_client(),
            &url,
            body.as_bytes(),
            &credentials(),
            Method::Get,
        )
        .unwrap();
        handle.join().unwrap();
        assert!(reply.redacted);
        assert_eq!(reply.body["Code"], "1000");
    }

    #[test]
    fn transport_rechecks_read_only_policy_before_building_a_client() {
        let project: Project =
            toml::from_str("environment = 'synthetic'\nread_only = true").unwrap();
        let request = Request {
            project,
            method: Method::Post,
            path: "/api/v1/deleteinvoice".into(),
            body: "{}".into(),
            timeout: 1,
        };
        let error = execute(&request, &credentials()).unwrap_err();
        assert_eq!(error.exit_code, 7);
    }

    #[test]
    fn production_transport_rejects_plain_http() {
        assert!(
            client(1)
                .unwrap()
                .post("http://127.0.0.1:1")
                .send()
                .is_err()
        );
    }

    #[test]
    fn rejects_url_and_path_injection() {
        for path in [
            "https://evil.test/get",
            "//evil.test",
            "../get",
            "get?ApiId=bad",
            "get#x",
            "get%2f..",
            "get\\x",
            "get//x",
            "/api/v1",
            "get\n",
        ] {
            assert!(resolve_path(path, "v1").is_err(), "{path}");
        }
        assert_eq!(
            resolve_path("FutureEndpoint", "v2").unwrap(),
            "/api/v2/FutureEndpoint"
        );
        assert_eq!(
            resolve_path("/api/v42/new/endpoint", "v1").unwrap(),
            "/api/v42/new/endpoint"
        );
    }

    #[test]
    fn preserves_json_bytes_and_accepts_empty_body() {
        for body in [
            b"".as_slice(),
            b"{\n \"amount\": 1.2300\n}\n",
            b"[1,2]",
            b"null",
        ] {
            validate_body(body).unwrap();
        }
        assert!(validate_body(b"not-json").is_err());
    }
}
