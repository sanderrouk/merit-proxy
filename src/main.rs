mod attachments;
mod config;
mod error;
mod policy;
mod provider;
mod redact;
mod signing;
mod transport;

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Instant,
};

use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{
    config::{Config, Project, Region},
    error::{Result, SafeError},
};

#[derive(Parser)]
#[command(
    name = "mp",
    version,
    about = "Call any Merit Aktiva endpoint without exposing its credentials",
    arg_required_else_help = true,
    subcommand_precedence_over_arg = true,
    after_help = "Examples:\n  mp projects add rouk --environment YOUR_ENVIRONMENT_ID\n  mp -p rouk doctor --auth\n  mp -p rouk getcustomers --data '{}'\n  mp --project rouk --debug /api/v2/getinvoices --file request.json\n\nEndpoint schemas: https://api.merit.ee/connecting-robots/reference-manual/"
)]
struct Cli {
    /// Project alias from the local lookup (required for API requests)
    #[arg(short = 'p', long, global = true)]
    project: Option<String>,
    /// Lookup file (default: $XDG_CONFIG_HOME/merit/config.toml or ~/.config/merit/config.toml)
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Emit safe JSON diagnostic events to stderr; never log bodies or signed URLs
    #[arg(long, global = true)]
    debug: bool,
    /// Append the same safe diagnostic events to a private JSONL file
    #[arg(long, global = true)]
    log_file: Option<PathBuf>,
    /// Time budget for 1Password authorization, in addition to the HTTP timeout
    #[arg(long, global = true, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..=600))]
    auth_timeout: u64,
    #[command(subcommand)]
    command: Option<Commands>,
    #[command(flatten)]
    request: Request,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage the local non-secret configuration
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// List or register project aliases and 1Password Environment IDs
    Projects {
        #[command(subcommand)]
        command: ProjectCommand,
    },
    /// Check configuration and op support; --auth checks credentials without calling Merit
    Doctor {
        #[arg(long)]
        auth: bool,
    },
    /// Send signed JSON, optionally uploading PDFs or saving attachments; no automatic retries
    Request(Request),
}

#[derive(Subcommand)]
enum ConfigCommand {
    Init,
    Path,
}

#[derive(Subcommand)]
enum ProjectCommand {
    List,
    Add {
        name: String,
        #[arg(long)]
        environment: String,
        #[arg(long, default_value = "MERIT_API_ID")]
        api_id_var: String,
        #[arg(long, default_value = "MERIT_API_KEY")]
        api_key_var: String,
        #[arg(long, value_enum, default_value = "ee")]
        region: Region,
        #[arg(long, default_value = "v1")]
        api_version: String,
        #[arg(long)]
        account: Option<String>,
        /// Restrict this project to reviewed read endpoints
        #[arg(long, conflicts_with = "read_write")]
        read_only: bool,
        /// Explicitly allow writes (replacement otherwise preserves existing access)
        #[arg(long, conflicts_with = "read_only")]
        read_write: bool,
        /// Additional reviewed read rule, e.g. 'POST /api/v2/newread'; repeatable
        #[arg(long, value_name = "METHOD /api/vN/endpoint")]
        read_endpoint: Vec<String>,
        /// Explicitly replace an existing alias
        #[arg(long)]
        replace: bool,
    },
    Remove {
        name: String,
    },
    /// Change only the project's access mode
    SetAccess {
        name: String,
        #[arg(value_enum)]
        access: policy::Access,
    },
    /// Show the effective exact read allowlist and access mode
    Policy {
        name: String,
    },
}

#[derive(Args)]
struct Request {
    /// Endpoint name or /api/vN/endpoint path; full URLs are forbidden
    endpoint: Option<String>,
    /// HTTP method; GET also signs the exact JSON body when supplied
    #[arg(
        long,
        global = true,
        value_enum,
        ignore_case = true,
        default_value = "POST"
    )]
    method: policy::Method,
    /// JSON text, @path, or @- / - for stdin; omitted means an empty body
    #[arg(short = 'd', long, global = true, conflicts_with = "file")]
    data: Option<String>,
    /// Read exact JSON bytes from a file (use - for stdin)
    #[arg(long, global = true)]
    file: Option<PathBuf>,
    /// Version for a bare endpoint; a full /api/vN/... path takes precedence
    #[arg(long, global = true)]
    api_version: Option<String>,
    #[arg(long, global = true, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=300))]
    timeout: u64,
    /// Validate inputs and show unsigned metadata; never access 1Password or Merit
    #[arg(long, global = true)]
    dry_run: bool,
    /// Emit only the redacted API body as JSON; retain meaningful exit codes
    #[arg(long, global = true)]
    body_only: bool,
    /// Attach a PDF as {FileName, FileContent}; default JSON pointer is /Attachment
    #[arg(long, global = true, value_name = "[POINTER=]PATH", value_parser = attachments::parse_upload)]
    attach_pdf: Vec<attachments::FileSpec>,
    /// Save a base64 PDF response field; default JSON pointer is /FileContent
    #[arg(long, global = true, value_name = "[POINTER=]PATH", value_parser = attachments::parse_download, conflicts_with = "body_only")]
    save_pdf: Vec<attachments::FileSpec>,
    /// Save any base64 attachment; default JSON pointer is /Attachment/FileContent
    #[arg(long, global = true, value_name = "[POINTER=]PATH", value_parser = attachments::parse_attachment, conflicts_with = "body_only")]
    save_attachment: Vec<attachments::FileSpec>,
    /// Return PDF metadata and suppress FileContent payloads in the response
    #[arg(long, global = true, conflicts_with = "body_only")]
    list_pdfs: bool,
    /// Inspect any returned FileContent attachments, including non-PDF files
    #[arg(long, global = true, conflicts_with_all = ["body_only", "list_pdfs"])]
    list_attachments: bool,
    /// Replace existing download files (never follows destination symlinks)
    #[arg(long, global = true)]
    overwrite: bool,
}

struct Diagnostics {
    stderr: bool,
    file: Option<File>,
    request_id: String,
}

impl Diagnostics {
    fn new(cli: &Cli) -> Result<Self> {
        let file = cli
            .log_file
            .as_ref()
            .map(|path| {
                let mut opts = OpenOptions::new();
                opts.create(true).append(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
                }
                let file = opts
                    .open(path)
                    .map_err(|_| SafeError::io("cannot open diagnostic log"))?;
                let metadata = file
                    .metadata()
                    .map_err(|_| SafeError::io("cannot inspect diagnostic log"))?;
                if !metadata.is_file() {
                    return Err(SafeError::io("diagnostic log must be a regular file"));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if metadata.permissions().mode() & 0o077 != 0 {
                        return Err(SafeError::io(
                            "diagnostic log must have private permissions (0600)",
                        ));
                    }
                }
                Ok(file)
            })
            .transpose()?;
        Ok(Self {
            stderr: cli.debug,
            file,
            request_id: format!(
                "{}-{}",
                Utc::now().format("%Y%m%dT%H%M%S%.9fZ"),
                std::process::id()
            ),
        })
    }

    fn event(&mut self, event: &str, metadata: Value) -> Result<()> {
        let line = json!({"time":Utc::now().to_rfc3339(), "request_id":self.request_id, "event":event, "meta":metadata}).to_string() + "\n";
        if self.stderr {
            std::io::stderr()
                .lock()
                .write_all(line.as_bytes())
                .map_err(|_| SafeError::io("cannot write diagnostics to stderr"))?;
        }
        if let Some(file) = &mut self.file {
            file.write_all(line.as_bytes()).map_err(|_| {
                SafeError::io("cannot write diagnostic log; request may have completed")
            })?;
        }
        Ok(())
    }
}

fn output(value: &Value) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, value)
        .map_err(|_| SafeError::io("cannot write output; request may have completed"))?;
    stdout
        .write_all(b"\n")
        .map_err(|_| SafeError::io("cannot write output; request may have completed"))
}

fn main() -> ExitCode {
    // Third-party panic messages may contain secret-bearing data.
    std::panic::set_hook(Box::new(|_| {}));
    let cli = Cli::parse();
    let mut diagnostics = match Diagnostics::new(&cli) {
        Ok(d) => d,
        Err(error) => return fail(error),
    };
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(cli, &mut diagnostics)))
            .unwrap_or_else(|_| {
                Err(SafeError::new(
                    "internal",
                    "internal failure; request may have completed",
                    6,
                ))
            });
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let _ = diagnostics.event(
                "failed",
                json!({"code":error.code, "message":error.message}),
            );
            fail(error)
        }
    }
}

fn fail(error: SafeError) -> ExitCode {
    eprintln!("{}", json!({"ok":false,"error":error}));
    ExitCode::from(error.exit_code)
}

fn run(cli: Cli, diagnostics: &mut Diagnostics) -> Result<u8> {
    if matches!(
        cli.command,
        Some(Commands::Config { .. } | Commands::Projects { .. } | Commands::Doctor { .. })
    ) && (cli.request.endpoint.is_some()
        || cli.request.data.is_some()
        || cli.request.file.is_some()
        || (cli.request.api_version.is_some()
            && !matches!(
                cli.command,
                Some(Commands::Projects {
                    command: ProjectCommand::Add { .. }
                })
            ))
        || cli.request.dry_run
        || cli.request.body_only
        || !cli.request.attach_pdf.is_empty()
        || !cli.request.save_pdf.is_empty()
        || !cli.request.save_attachment.is_empty()
        || cli.request.list_pdfs
        || cli.request.list_attachments
        || cli.request.overwrite
        || cli.request.method != policy::Method::Post
        || cli.request.timeout != 30)
    {
        return Err(SafeError::input(
            "request options apply only to API invocations; remove them from config, projects or doctor commands",
        ));
    }
    let path = match cli.config {
        Some(path) => path,
        None => config::default_path()?,
    };
    match cli.command {
        Some(Commands::Config {
            command: ConfigCommand::Path,
        }) => output(&json!({"path":path}))?,
        Some(Commands::Config {
            command: ConfigCommand::Init,
        }) => {
            config::update(&path, |old| {
                if old.is_some() {
                    return Err(SafeError::config(
                        "config already exists; use `mp projects add`",
                    ));
                }
                Ok(Config::default())
            })?;
            output(&json!({"ok":true,"path":path}))?;
        }
        Some(Commands::Projects { command }) => projects(&path, command)?,
        Some(Commands::Doctor { auth }) => {
            let project = cli.project;
            if auth && project.is_none() {
                return Err(SafeError::input("--auth requires -p / --project"));
            }
            let config = Config::load(&path)?;
            let selected = project
                .as_deref()
                .map(|name| config.project(name))
                .transpose()?;
            provider::check_op()?;
            let mut result = json!({"ok":true,"config":"valid","op":"supports_environments","project":project,"credentials":"not_checked","network":"not_checked"});
            if let Some(selected) = &selected {
                result["read_only"] = json!(selected.read_only);
            }
            if auth {
                diagnostics.event("credentials_started", json!({"project":project}))?;
                provider::load(
                    &selected.expect("project validated above"),
                    cli.auth_timeout,
                )?;
                result["credentials"] = json!("available");
                diagnostics.event("credentials_ready", json!({"project":project}))?;
            }
            output(&result)?;
        }
        Some(Commands::Request(request)) => {
            return request_api(
                &path,
                cli.project.as_deref(),
                request,
                cli.auth_timeout,
                diagnostics,
            );
        }
        None => {
            return request_api(
                &path,
                cli.project.as_deref(),
                cli.request,
                cli.auth_timeout,
                diagnostics,
            );
        }
    }
    Ok(0)
}

fn projects(path: &Path, command: ProjectCommand) -> Result<()> {
    match command {
        ProjectCommand::List => output(&json!({"projects":Config::load(path)?.projects})),
        ProjectCommand::Add {
            name,
            environment,
            api_id_var,
            api_key_var,
            region,
            api_version,
            account,
            read_only,
            read_write,
            read_endpoint,
            replace,
        } => {
            if !config::identifier(&name) {
                return Err(SafeError::input(
                    "project alias must contain only letters, digits, hyphens or underscores",
                ));
            }
            let mut project = Project {
                environment,
                api_id_var,
                api_key_var,
                region,
                api_version,
                account,
                read_only,
                read_endpoints: read_endpoint,
            };
            project.validate()?;
            config::update(path, |old| {
                let mut config = old.unwrap_or_default();
                if config.projects.contains_key(&name) && !replace {
                    return Err(SafeError::config(
                        "project already exists; use --replace to change its mapping",
                    ));
                }
                if let Some(existing) = config.projects.get(&name) {
                    if !read_only && !read_write {
                        project.read_only = existing.read_only;
                    }
                    if project.read_endpoints.is_empty() {
                        project.read_endpoints = existing.read_endpoints.clone();
                    }
                }
                config.projects.insert(name.clone(), project);
                Ok(config)
            })?;
            output(&json!({"ok":true,"project":name}))
        }
        ProjectCommand::Remove { name } => {
            config::update(path, |old| {
                let mut config = old.ok_or_else(|| SafeError::config("config does not exist"))?;
                if config.projects.remove(&name).is_none() {
                    return Err(SafeError::config("unknown project"));
                }
                Ok(config)
            })?;
            output(&json!({"ok":true,"project":name,"removed":true}))
        }
        ProjectCommand::SetAccess { name, access } => {
            let read_only = matches!(access, policy::Access::ReadOnly);
            config::update(path, |old| {
                let mut config = old.ok_or_else(|| SafeError::config("config does not exist"))?;
                config
                    .projects
                    .get_mut(&name)
                    .ok_or_else(|| SafeError::config("unknown project"))?
                    .read_only = read_only;
                Ok(config)
            })?;
            output(&json!({"ok":true,"project":name,"read_only":read_only}))
        }
        ProjectCommand::Policy { name } => {
            let project = Config::load(path)?.project(&name)?;
            let reads: std::collections::BTreeSet<_> = policy::built_in_reads()
                .map(str::to_owned)
                .chain(project.read_endpoints.iter().cloned())
                .collect();
            output(&json!({"project":name,"read_only":project.read_only,"read_endpoints":reads}))
        }
    }
}

fn read_body(request: &Request) -> Result<String> {
    let source = request
        .file
        .clone()
        .or_else(|| {
            request
                .data
                .as_deref()
                .and_then(|s| s.strip_prefix('@'))
                .map(PathBuf::from)
        })
        .or_else(|| {
            request
                .data
                .as_deref()
                .filter(|s| *s == "-")
                .map(PathBuf::from)
        });
    let bytes = if let Some(path) = source {
        let reader: Box<dyn Read> = if path == Path::new("-") {
            Box::new(std::io::stdin())
        } else {
            Box::new(
                File::open(path).map_err(|_| SafeError::input("cannot open request body file"))?,
            )
        };
        let mut bytes = Vec::new();
        reader
            .take((transport::MAX_BODY + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| SafeError::input("cannot read request body"))?;
        bytes
    } else {
        request.data.as_deref().unwrap_or("").as_bytes().to_vec()
    };
    transport::validate_body(&bytes)?;
    String::from_utf8(bytes).map_err(|_| SafeError::input("request body must be UTF-8"))
}

fn request_api(
    config_path: &Path,
    project_name: Option<&str>,
    request: Request,
    auth_timeout: u64,
    diagnostics: &mut Diagnostics,
) -> Result<u8> {
    let started = Instant::now();
    let project_name = project_name.ok_or_else(|| {
        SafeError::input("API requests require -p / --project; use `mp projects list`")
    })?;
    let endpoint = request.endpoint.as_deref().ok_or_else(|| {
        SafeError::input(
            "provide a Merit endpoint, for example `mp -p rouk getcustomers --data '{}'`",
        )
    })?;
    let project = Config::load(config_path)?.project(project_name)?;
    let path = transport::resolve_path(
        endpoint,
        request
            .api_version
            .as_deref()
            .unwrap_or(&project.api_version),
    )?;
    policy::authorize(
        &project,
        request.method,
        &path,
        !request.attach_pdf.is_empty(),
    )?;
    let mut body = read_body(&request)?;
    let uploads = attachments::attach(&mut body, &request.attach_pdf)?;
    let downloads: Vec<_> = request
        .save_pdf
        .iter()
        .chain(&request.save_attachment)
        .cloned()
        .collect();
    if request.overwrite && downloads.is_empty() {
        return Err(SafeError::input(
            "--overwrite requires --save-pdf or --save-attachment",
        ));
    }
    attachments::validate_outputs(&downloads, request.overwrite)?;
    let metadata = json!({"project":project_name,"method":request.method,"read_only":project.read_only,"origin":project.region.origin(),"path":path,"request_bytes":body.len(),"body_sha256":format!("{:x}", Sha256::digest(body.as_bytes())),"pdf_uploads":uploads});
    diagnostics.event("request_validated", metadata.clone())?;
    if request.dry_run {
        output(
            &json!({"ok":true,"dry_run":true,"request":metadata,"credentials":"not_accessed","network":"not_accessed"}),
        )?;
        return Ok(0);
    }
    diagnostics.event("credentials_started", json!({"project":project_name}))?;
    let credential_started = Instant::now();
    let credentials = provider::load(&project, auth_timeout)?;
    let credentials_ms = credential_started.elapsed().as_millis();
    diagnostics.event(
        "credentials_ready",
        json!({"project":project_name,"credentials_ms":credentials_ms}),
    )?;
    let mut reply = transport::execute(
        &transport::Request {
            project,
            method: request.method,
            path,
            body,
            timeout: request.timeout,
        },
        &credentials,
    )?;
    drop(credentials);
    let status = reply.status;
    let ok = (200..300).contains(&status);
    let mut meta = json!({"request_id":diagnostics.request_id,"elapsed_ms":started.elapsed().as_millis(),"credentials_ms":credentials_ms,"http_ms":reply.http_ms,"response_bytes":reply.response_bytes,"redacted":reply.redacted});
    diagnostics.event(
        "request_finished",
        json!({"status":status,"ok":ok,"timing":meta,"rate_limit":reply.headers}),
    )?;
    let files = if ok {
        attachments::receive(
            &mut reply.body,
            &downloads,
            if request.list_attachments {
                attachments::Listing::Attachments
            } else if request.list_pdfs {
                attachments::Listing::Pdf
            } else {
                attachments::Listing::None
            },
            request.overwrite,
        )?
    } else {
        Vec::new()
    };
    let pdfs: Vec<_> = files.iter().filter(|f| f.is_pdf).collect();
    if ok && (!downloads.is_empty() || request.list_pdfs || request.list_attachments) {
        diagnostics.event(
            "pdfs_processed",
            json!({"pdf_count":pdfs.len(),"attachment_count":files.len(),"saved_count":downloads.len()}),
        )?;
    }
    meta["elapsed_ms"] = json!(started.elapsed().as_millis());
    let error = if ok {
        Value::Null
    } else {
        json!({"code":"http_status", "message":match status {
            300..=399 => "Merit returned a redirect; it was not followed",
            401 | 403 => "Merit rejected authorization; check credentials, company access, license and system UTC clock",
            404 => "Merit endpoint was not found; check API version and spelling",
            429 => "Merit rate limit reached; consult response headers before retrying",
            _ => "Merit rejected the request; inspect the redacted response body"
        }})
    };
    if request.body_only {
        output(&reply.body)?;
        if !ok {
            eprintln!("{}", json!({"ok":false,"status":status,"error":error}));
        }
    } else {
        output(
            &json!({"ok":ok,"project":project_name,"status":status,"headers":reply.headers,"body":reply.body,"pdfs":pdfs,"attachments":files,"meta":meta,"error":error}),
        )?;
    }
    Ok(if ok { 0 } else { 5 })
}
