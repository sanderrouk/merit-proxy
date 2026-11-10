use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    error::{Result, SafeError},
    transport::MAX_BODY,
};

const MAX_UPLOAD: usize = MAX_BODY / 4 * 3;

#[derive(Clone)]
pub struct FileSpec {
    pub pointer: String,
    pub path: PathBuf,
    pub require_pdf: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Listing {
    None,
    Pdf,
    Attachments,
}

#[derive(Serialize)]
pub struct FileInfo {
    pub field: String,
    pub file_name: Option<String>,
    pub bytes: usize,
    pub sha256: String,
    pub is_pdf: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_to: Option<PathBuf>,
}

pub fn parse_upload(s: &str) -> std::result::Result<FileSpec, String> {
    parse_file(s, "/Attachment")
}
pub fn parse_download(s: &str) -> std::result::Result<FileSpec, String> {
    parse_file(s, "/FileContent")
}

pub fn parse_attachment(s: &str) -> std::result::Result<FileSpec, String> {
    let mut file = parse_file(s, "/Attachment/FileContent")?;
    file.require_pdf = false;
    Ok(file)
}

fn parse_file(s: &str, default_pointer: &str) -> std::result::Result<FileSpec, String> {
    let (pointer, path) = s.split_once('=').unwrap_or((default_pointer, s));
    if path.is_empty() || path == "-" {
        return Err("use a local file path, optionally preceded by JSON_POINTER=; stdin/stdout are not download destinations".into());
    }
    pointer_tokens(pointer).map_err(|_| "invalid JSON pointer; use /Attachment or /Attachment/FileContent (escape ~ as ~0 and / as ~1)".to_string())?;
    Ok(FileSpec {
        pointer: pointer.into(),
        path: path.into(),
        require_pdf: true,
    })
}

fn pointer_tokens(pointer: &str) -> Result<Vec<String>> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    if !pointer.starts_with('/') || pointer.len() > 2048 || pointer.chars().any(char::is_control) {
        return Err(SafeError::input("invalid PDF JSON pointer"));
    }
    pointer[1..]
        .split('/')
        .map(|part| {
            let mut out = String::new();
            let mut chars = part.chars();
            while let Some(c) = chars.next() {
                if c == '~' {
                    match chars.next() {
                        Some('0') => out.push('~'),
                        Some('1') => out.push('/'),
                        _ => return Err(SafeError::input("invalid PDF JSON pointer escape")),
                    }
                } else {
                    out.push(c);
                }
            }
            Ok(out)
        })
        .collect()
}

fn pdf_bytes(bytes: &[u8]) -> bool {
    bytes.starts_with(b"%PDF-")
        && bytes[bytes.len().saturating_sub(1024)..]
            .windows(5)
            .any(|w| w == b"%%EOF")
}

fn info(field: &str, file_name: Option<String>, bytes: &[u8]) -> FileInfo {
    FileInfo {
        field: field.into(),
        file_name,
        bytes: bytes.len(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
        is_pdf: pdf_bytes(bytes),
        saved_to: None,
    }
}

pub fn attach(body: &mut String, files: &[FileSpec]) -> Result<Vec<FileInfo>> {
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let mut value: Value = if body.is_empty() {
        json!({})
    } else {
        serde_json::from_str(body)
            .map_err(|_| SafeError::input("PDF uploads require a JSON body"))?
    };
    let mut metadata = Vec::new();
    for file in files {
        let name = file
            .path
            .file_name()
            .and_then(|s| s.to_str())
            .filter(|s| !s.chars().any(char::is_control))
            .ok_or_else(|| {
                SafeError::input("PDF upload requires a UTF-8 filename without control characters")
            })?;
        if !name.to_ascii_lowercase().ends_with(".pdf") {
            return Err(SafeError::input(
                "PDF upload filename must have a .pdf extension",
            ));
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let source = options
            .open(&file.path)
            .map_err(|_| SafeError::input("cannot open PDF upload file"))?;
        if !source
            .metadata()
            .map_err(|_| SafeError::input("cannot inspect PDF upload file"))?
            .is_file()
        {
            return Err(SafeError::input("PDF upload must be a regular file"));
        }
        let mut bytes = Zeroizing::new(Vec::new());
        source
            .take((MAX_UPLOAD + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| SafeError::input("cannot read PDF upload file"))?;
        if bytes.len() > MAX_UPLOAD {
            return Err(SafeError::input(
                "PDF upload exceeds the 12 MiB raw-file limit",
            ));
        }
        if !pdf_bytes(&bytes) {
            return Err(SafeError::input(
                "upload is not a PDF with a %PDF- header and %%EOF trailer",
            ));
        }
        let attachment = json!({"FileName":name,"FileContent":STANDARD.encode(&bytes)});
        insert_attachment(&mut value, &file.pointer, attachment)?;
        metadata.push(info(&file.pointer, Some(name.into()), &bytes));
        // Bound the total expanded JSON too, including multiple PDFs and the business payload.
        *body = serde_json::to_string(&value)
            .map_err(|_| SafeError::input("cannot encode PDF attachment body"))?;
        crate::transport::validate_body(body.as_bytes())?;
    }
    Ok(metadata)
}

fn insert_attachment(body: &mut Value, pointer: &str, attachment: Value) -> Result<()> {
    pointer_tokens(pointer)?;
    if let Some(target) = body.pointer_mut(pointer) {
        if !target.is_null() && !target.as_object().is_some_and(|o| o.is_empty()) {
            return Err(SafeError::input(
                "PDF attachment field already has data; remove it from the JSON body before attaching a file",
            ));
        }
        *target = attachment;
        return Ok(());
    }
    let (parent, _) = pointer.rsplit_once('/').ok_or_else(|| {
        SafeError::input("PDF attachment must target an empty JSON object or a field")
    })?;
    let key = pointer_tokens(pointer)?.pop().expect("nonempty pointer");
    match body.pointer_mut(parent) {
        Some(Value::Object(object)) => {
            object.insert(key, attachment);
            Ok(())
        }
        _ => Err(SafeError::input(
            "PDF attachment parent must already exist; create nested objects or null array entries in the JSON body",
        )),
    }
}

pub fn validate_outputs(files: &[FileSpec], overwrite: bool) -> Result<()> {
    let mut fields = BTreeSet::new();
    let mut destinations = BTreeSet::new();
    for file in files {
        if !fields.insert(&file.pointer) {
            return Err(SafeError::input(
                "each attachment response field can be saved only once per request",
            ));
        }
        let parent = file
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = fs::canonicalize(parent)
            .map_err(|_| SafeError::input("download destination directory must already exist"))?;
        if !parent.is_dir() {
            return Err(SafeError::input(
                "download destination parent must be a directory",
            ));
        }
        let filename = file
            .path
            .file_name()
            .ok_or_else(|| SafeError::input("download destination must include a filename"))?;
        if !destinations.insert(parent.join(filename)) {
            return Err(SafeError::input("attachment output paths must be distinct"));
        }
        match fs::symlink_metadata(&file.path) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
                return Err(SafeError::input(
                    "download destination cannot be a symlink or non-regular file",
                ));
            }
            Ok(_) if !overwrite => {
                return Err(SafeError::input(
                    "download destination already exists; choose a new path or use --overwrite",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(SafeError::input("cannot inspect download destination")),
        }
    }
    Ok(())
}

fn response_error(message: &str) -> SafeError {
    SafeError::new(
        "pdf_response",
        &format!("API request has completed; {message}"),
        4,
    )
}

fn decode(value: &Value, require_pdf: bool) -> Result<Zeroizing<Vec<u8>>> {
    let text = value.as_str().ok_or_else(|| {
        response_error("selected attachment response field is missing or is not a base64 string")
    })?;
    let compact = Zeroizing::new(
        text.bytes()
            .filter(|b| !b.is_ascii_whitespace())
            .collect::<Vec<_>>(),
    );
    let bytes = Zeroizing::new(STANDARD.decode(&compact).map_err(|_| {
        response_error(
            "selected attachment response field is invalid base64 or was redacted; no attachment was written",
        )
    })?);
    if require_pdf && !pdf_bytes(&bytes) {
        return Err(response_error(
            "selected response field is not a PDF with a %PDF- header and %%EOF trailer; no attachment was written",
        ));
    }
    Ok(bytes)
}

fn unwrapped(body: &Value) -> Value {
    let mut value = body.clone();
    for _ in 0..4 {
        let Value::String(text) = &value else {
            break;
        };
        match serde_json::from_str::<Value>(text) {
            Ok(next @ (Value::Object(_) | Value::Array(_) | Value::String(_))) => value = next,
            _ => break,
        }
    }
    value
}

fn filename(body: &Value, pointer: &str) -> Option<String> {
    let (parent, _) = pointer.rsplit_once('/')?;
    let object = body.pointer(parent)?.as_object()?;
    object
        .get("FileName")
        .or_else(|| object.get("Filename"))?
        .as_str()
        .map(str::to_owned)
}

fn discover(value: &Value, pointer: &str, fields: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (name, value) in map {
                let child = format!("{pointer}/{}", name.replace('~', "~0").replace('/', "~1"));
                if name == "FileContent" && value.is_string() {
                    fields.insert(child.clone());
                }
                discover(value, &child, fields);
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                discover(value, &format!("{pointer}/{index}"), fields);
            }
        }
        _ => {}
    }
}

/// Validate and stage all requested files before publishing each file atomically.
/// A response's filename is metadata only; output paths always come from the caller.
pub fn receive(
    body: &mut Value,
    files: &[FileSpec],
    list: Listing,
    overwrite: bool,
) -> Result<Vec<FileInfo>> {
    if files.is_empty() && list == Listing::None {
        return Ok(Vec::new());
    }
    validate_outputs(files, overwrite)?;
    let mut value = unwrapped(body);
    let mut fields: BTreeSet<String> = files.iter().map(|f| f.pointer.clone()).collect();
    if list != Listing::None {
        discover(&value, "", &mut fields);
    }
    let mut prepared = Vec::new();
    for field in fields {
        let destination = files.iter().find(|f| f.pointer == field);
        let selected = value.pointer(&field).ok_or_else(|| {
            response_error(
                "selected attachment response field does not exist; check the JSON pointer",
            )
        })?;
        let bytes = decode(
            selected,
            destination.is_some_and(|f| f.require_pdf) || list == Listing::Pdf,
        )?;
        let mut metadata = info(&field, filename(&value, &field), &bytes);
        let staged = if let Some(destination) = destination {
            let parent = destination
                .path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(|_| {
                SafeError::io("cannot create attachment output; API request has completed")
            })?;
            tmp.write_all(&bytes)
                .and_then(|_| tmp.as_file().sync_all())
                .map_err(|_| {
                    SafeError::io("cannot write attachment output; API request has completed")
                })?;
            metadata.saved_to = Some(destination.path.clone());
            Some(tmp)
        } else {
            None
        };
        prepared.push((metadata, staged));
        *value.pointer_mut(&field).expect("selected field exists") = Value::Null;
    }
    let mut result = Vec::new();
    for (metadata, staged) in prepared {
        if let Some(tmp) = staged {
            let path = metadata
                .saved_to
                .as_ref()
                .expect("staged attachment has destination");
            let published = if overwrite {
                tmp.persist(path)
            } else {
                tmp.persist_noclobber(path)
            };
            published.map_err(|_| SafeError::io("cannot publish attachment output; API request has completed and earlier attachment outputs may already have been saved"))?;
        }
        result.push(metadata);
    }
    *body = value;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    const PDF: &[u8] = include_bytes!("../tests/fixtures/blank.pdf");

    fn field(pointer: &str, path: PathBuf) -> FileSpec {
        FileSpec {
            pointer: pointer.into(),
            path,
            require_pdf: true,
        }
    }

    fn response() -> Value {
        json!({"Attachment":{"Filename":"../../untrusted.pdf","FileContent":STANDARD.encode(PDF)},"Id":"invoice-123"})
    }

    #[test]
    fn attaches_binary_pdf_without_changing_number_precision() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt.pdf");
        fs::write(&path, PDF).unwrap();
        let mut body = r#"{"Amount":1.2300,"Id":123456789012345678901234567890}"#.to_owned();
        let metadata = attach(&mut body, &[field("/Attachment", path)]).unwrap();
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["Amount"].to_string(), "1.2300");
        assert_eq!(parsed["Id"].to_string(), "123456789012345678901234567890");
        assert_eq!(parsed["Attachment"]["FileName"], "receipt.pdf");
        assert_eq!(
            STANDARD
                .decode(parsed["Attachment"]["FileContent"].as_str().unwrap())
                .unwrap(),
            PDF
        );
        assert_eq!(metadata[0].bytes, PDF.len());
        assert_eq!(metadata[0].sha256, format!("{:x}", Sha256::digest(PDF)));
    }

    #[test]
    fn nested_pointers_and_arrays_do_not_overwrite_existing_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt.PDF");
        fs::write(&path, PDF).unwrap();
        let mut body = r#"{"Documents":[null],"a/b":{"~":{}}}"#.to_owned();
        let files = [
            field("/Documents/0", path.clone()),
            field("/a~1b/~0", path.clone()),
        ];
        assert_eq!(attach(&mut body, &files).unwrap().len(), 2);
        assert!(attach(&mut body, &files).is_err());
        assert!(attach(&mut body, &[field("/absent/nested", path)]).is_err());
        for pointer in ["/bad~", "/bad~2", "Attachment", "/bad\n"] {
            assert!(pointer_tokens(pointer).is_err());
        }
    }

    #[test]
    fn rejects_non_pdf_oversized_and_non_regular_uploads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt.pdf");
        for content in [b"not a PDF".as_slice(), b"%PDF-1.4\ntruncated"] {
            fs::write(&path, content).unwrap();
            assert!(attach(&mut String::new(), &[field("/Attachment", path.clone())]).is_err());
        }
        fs::File::create(&path)
            .unwrap()
            .set_len((MAX_UPLOAD + 1) as u64)
            .unwrap();
        let error = attach(&mut String::new(), &[field("/Attachment", path)])
            .err()
            .unwrap();
        assert!(error.message.contains("12 MiB"));
        let directory = dir.path().join("directory.pdf");
        fs::create_dir(&directory).unwrap();
        assert!(attach(&mut String::new(), &[field("/Attachment", directory)]).is_err());
    }

    #[test]
    fn saves_exact_bytes_privately_and_ignores_server_filename() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chosen.pdf");
        let mut body = response();
        let metadata = receive(
            &mut body,
            &[field("/Attachment/FileContent", path.clone())],
            Listing::None,
            false,
        )
        .unwrap();
        assert_eq!(fs::read(&path).unwrap(), PDF);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        assert_eq!(
            metadata[0].file_name.as_deref(),
            Some("../../untrusted.pdf")
        );
        assert_eq!(metadata[0].saved_to.as_ref(), Some(&path));
        assert!(body["Attachment"]["FileContent"].is_null());
        assert_eq!(body["Id"], "invoice-123");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn lists_nested_legacy_json_without_writing_or_emitting_base64() {
        let mut body = json!(json!({"docs":[response(), {"FileName":"second.pdf","FileContent":STANDARD.encode(PDF)}]}).to_string());
        let metadata = receive(&mut body, &[], Listing::Pdf, false).unwrap();
        assert_eq!(metadata.len(), 2);
        assert!(
            metadata
                .iter()
                .all(|m| m.bytes == PDF.len() && m.saved_to.is_none())
        );
        assert_eq!(metadata[0].field, "/docs/0/Attachment/FileContent");
        assert!(!body.to_string().contains(&STANDARD.encode(PDF)));
        let mut empty = json!({"Header":{"FileExists":false},"Attachment":null});
        assert!(
            receive(&mut empty, &[], Listing::Pdf, false)
                .unwrap()
                .is_empty()
        );
        let mut invalid = json!({"FileContent":"not-base64"});
        assert!(receive(&mut invalid, &[], Listing::Pdf, false).is_err());
    }

    #[test]
    fn refuses_clobber_and_symlinks_but_allows_explicit_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("existing.pdf");
        fs::write(&path, b"existing data").unwrap();
        let files = [field("/Attachment/FileContent", path.clone())];
        assert!(receive(&mut response(), &files, Listing::None, false).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"existing data");
        receive(&mut response(), &files, Listing::None, true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), PDF);
        #[cfg(unix)]
        {
            let link = dir.path().join("symlink.pdf");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(validate_outputs(&[field("/FileContent", link)], true).is_err());
        }
    }

    #[test]
    fn validates_all_downloads_before_publishing_any() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.pdf");
        let second = dir.path().join("second.pdf");
        for bad in [
            Value::Null,
            json!("invalid-base64"),
            json!(STANDARD.encode(b"not PDF")),
        ] {
            let mut body = json!({"a":STANDARD.encode(PDF),"b":bad});
            let files = [field("/a", first.clone()), field("/b", second.clone())];
            assert!(receive(&mut body, &files, Listing::None, false).is_err());
            assert!(!first.exists() && !second.exists());
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        }
        assert!(
            receive(
                &mut response(),
                &[field("/missing", first)],
                Listing::None,
                false
            )
            .is_err()
        );
    }

    #[test]
    fn detects_duplicate_outputs_and_accepts_wrapped_base64() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.pdf");
        assert!(
            validate_outputs(
                &[
                    field("/a", path.clone()),
                    field("/b", dir.path().join("./output.pdf"))
                ],
                false
            )
            .is_err()
        );
        assert!(
            validate_outputs(
                &[
                    field("/a", path.clone()),
                    field("/a", dir.path().join("other.pdf"))
                ],
                false
            )
            .is_err()
        );
        let encoded = STANDARD.encode(PDF);
        let wrapped = encoded
            .as_bytes()
            .chunks(76)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n");
        assert_eq!(&*decode(&json!(wrapped), true).unwrap(), PDF);
    }

    #[test]
    fn generic_attachments_preserve_binary_bytes_and_support_mixed_listing() {
        let bytes = b"\x89PNG\r\n\x1a\n\x00\xff\x80synthetic-binary";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chosen.bin");
        let mut body = json!({"Attachment":{"FileName":"../../elsewhere.png","FileContent":STANDARD.encode(bytes)}, "Other":{"FileName":"invoice.pdf","FileContent":STANDARD.encode(PDF)}});
        let file = FileSpec {
            pointer: "/Attachment/FileContent".into(),
            path: path.clone(),
            require_pdf: false,
        };
        let result = receive(&mut body, &[file], Listing::Attachments, false).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        assert_eq!(result.len(), 2);
        assert!(!result[0].is_pdf && result[1].is_pdf);
        assert!(
            body["Attachment"]["FileContent"].is_null() && body["Other"]["FileContent"].is_null()
        );
        assert_eq!(result[0].sha256, format!("{:x}", Sha256::digest(bytes)));
        assert!(decode(&json!(STANDARD.encode(bytes)), true).is_err());
    }

    #[test]
    fn generic_downloads_share_no_clobber_redaction_and_staging_checks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("attachment.bin");
        let file = FileSpec {
            pointer: "/Attachment/FileContent".into(),
            path: path.clone(),
            require_pdf: false,
        };
        for value in [json!("[REDACTED]"), json!("broken base64!"), Value::Null] {
            assert!(
                receive(
                    &mut json!({"Attachment":{"FileContent":value}}),
                    std::slice::from_ref(&file),
                    Listing::None,
                    false
                )
                .is_err()
            );
            assert!(!path.exists());
        }
        fs::write(&path, b"existing").unwrap();
        assert!(
            receive(
                &mut response(),
                std::slice::from_ref(&file),
                Listing::None,
                false
            )
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), b"existing");
    }
}
