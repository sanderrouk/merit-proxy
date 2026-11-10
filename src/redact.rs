use base64::Engine;
use serde_json::Value;
use zeroize::Zeroizing;

/// Defense in depth for servers that echo a signed URL or a credential.
/// No Debug implementation: the patterns themselves contain secrets.
#[derive(Default)]
pub struct Redactor {
    patterns: Zeroizing<Vec<String>>,
}

impl Redactor {
    pub fn add(&mut self, secret: &str) {
        if secret.is_empty() {
            return;
        }
        let encoded: String =
            reqwest::Url::parse_with_params("https://example.invalid", [("s", secret)])
                .expect("fixed valid URL")
                .query()
                .expect("query exists")[2..]
                .into();
        let mut lower_hex = encoded.clone().into_bytes();
        for i in 0..lower_hex.len().saturating_sub(2) {
            if lower_hex[i] == b'%' {
                lower_hex[i + 1].make_ascii_lowercase();
                lower_hex[i + 2].make_ascii_lowercase();
            }
        }
        self.patterns.extend([
            secret.to_owned(),
            encoded,
            String::from_utf8(lower_hex).expect("URL encoding is ASCII"),
            base64::engine::general_purpose::STANDARD.encode(secret),
        ]);
        // Match longest first so a short API ID cannot partially mask a longer secret.
        self.patterns.sort_by_key(|s| std::cmp::Reverse(s.len()));
        self.patterns.dedup();
    }

    pub fn text(&self, text: &str) -> String {
        let mut result = text.to_owned();
        for pattern in self.patterns.iter() {
            result = result.replace(pattern, "[REDACTED]");
        }
        // CLI output must not carry terminal-control sequences.
        result
            .chars()
            .filter(|c| !c.is_control() || matches!(c, '\n' | '\t' | '\r'))
            .collect()
    }

    pub fn value(&self, value: Value) -> Value {
        self.value_at(value, 0)
    }

    fn value_at(&self, value: Value, depth: usize) -> Value {
        match value {
            Value::String(s) => {
                // An attachment may contain an echoed credential inside its base64 envelope.
                // Refuse that payload instead of rewriting and corrupting its bytes.
                let compact = Zeroizing::new(
                    s.bytes()
                        .filter(|b| !b.is_ascii_whitespace())
                        .collect::<Vec<_>>(),
                );
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&compact) {
                    let decoded = Zeroizing::new(decoded);
                    if self
                        .patterns
                        .iter()
                        .any(|p| decoded.windows(p.len()).any(|w| w == p.as_bytes()))
                    {
                        return Value::String("[REDACTED]".into());
                    }
                }
                // Some Merit deployments return a JSON document inside a JSON string.
                // Decode it for redaction, but preserve its original outer type.
                let s = if depth < 4 {
                    match serde_json::from_str::<Value>(&s) {
                        Ok(v @ (Value::Object(_) | Value::Array(_))) => {
                            self.value_at(v, depth + 1).to_string()
                        }
                        _ => s,
                    }
                } else {
                    s
                };
                Value::String(self.text(&s))
            }
            Value::Object(map) => Value::Object(
                map.into_iter()
                    .map(|(k, v)| (self.text(&k), self.value_at(v, depth)))
                    .collect(),
            ),
            Value::Array(values) => Value::Array(
                values
                    .into_iter()
                    .map(|v| self.value_at(v, depth))
                    .collect(),
            ),
            Value::Number(n) if self.text(&n.to_string()) != n.to_string() => {
                Value::String("[REDACTED]".into())
            }
            value => value,
        }
    }

    pub fn response(&self, bytes: &[u8]) -> Value {
        match serde_json::from_slice(bytes) {
            Ok(value) => self.value(value),
            Err(_) => Value::String(self.text(&String::from_utf8_lossy(bytes))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn masks_plain_encoded_and_json_escaped_secrets() {
        let mut redactor = Redactor::default();
        redactor.add("abc+/==");
        redactor.add("private-id");
        let response = redactor.response(br#"{"url":"?signature=abc%2B%2F%3D%3D","id":"private\u002did","private-id":"abc+/=="}"#);
        assert_eq!(
            response,
            json!({"url":"?signature=[REDACTED]","id":"[REDACTED]","[REDACTED]":"[REDACTED]"})
        );
    }

    #[test]
    fn masks_nested_json_and_strips_terminal_escapes() {
        let mut r = Redactor::default();
        r.add("secret-key");
        let nested = json!(r#"{"key":"secret\u002dkey"}"#);
        assert!(!r.value(nested).to_string().contains("secret"));
        assert!(!r.text("\u{1b}[31mhello").contains('\u{1b}'));
    }

    #[test]
    fn refuses_credentials_inside_encoded_pdfs_but_preserves_other_pdf_bytes() {
        let mut r = Redactor::default();
        r.add("credential-canary");
        for bytes in [
            b"%PDF-1.4\ncredential-canary\n%%EOF".as_slice(),
            b"%PDF-\xff\ncredential-canary\n%%EOF",
        ] {
            let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
            assert_eq!(
                r.value(json!({"FileContent":encoded}))["FileContent"],
                "[REDACTED]"
            );
        }
        let safe = base64::engine::general_purpose::STANDARD
            .encode(include_bytes!("../tests/fixtures/blank.pdf"));
        assert_eq!(r.value(json!({"FileContent":safe}))["FileContent"], safe);
    }

    #[test]
    fn refuses_credentials_in_any_base64_attachment_not_just_pdf() {
        let mut r = Redactor::default();
        r.add("credential-canary");
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(b"\x89PNG\x00credential-canary\xff");
        assert_eq!(
            r.value(json!({"arbitrary_field":encoded}))["arbitrary_field"],
            "[REDACTED]"
        );
    }
}
