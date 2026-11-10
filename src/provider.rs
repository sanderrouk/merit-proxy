use std::{
    collections::BTreeSet,
    env, fs,
    io::Read,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use zeroize::Zeroizing;

use crate::{
    config::{Project, environment_variable_name},
    error::{Result, SafeError},
    transport::Credentials,
};

const MAX_ENVIRONMENT_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENVIRONMENT_VARIABLES: usize = 512;

fn op_path() -> Result<PathBuf> {
    let paths = env::var_os("PATH").unwrap_or_default();
    for dir in env::split_paths(&paths).filter(|p| p.is_absolute()) {
        let path = dir.join("op");
        if let Ok(metadata) = fs::metadata(&path) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o111 == 0 {
                    continue;
                }
            }
            if metadata.is_file() {
                return Ok(path);
            }
        }
    }
    Err(SafeError::auth(
        "1Password CLI was not found on an absolute PATH entry; install op with `environment read` support",
    ))
}

fn op_command() -> Result<Command> {
    let mut command = Command::new(op_path()?);
    command.env_clear();
    // Never inherit ambient Merit credentials, logging, proxy or loader settings.
    for (name, value) in env::vars_os() {
        let name_text = name.to_string_lossy();
        if matches!(
            name_text.as_ref(),
            "HOME"
                | "USER"
                | "LOGNAME"
                | "PATH"
                | "TMPDIR"
                | "XDG_CONFIG_HOME"
                | "XDG_RUNTIME_DIR"
                | "OP_ACCOUNT"
                | "OP_SERVICE_ACCOUNT_TOKEN"
        ) || name_text.starts_with("OP_SESSION_")
        {
            command.env(name, value);
        }
    }
    command.env("OP_DEBUG", "false");
    // The parser consumes literal KEY=value lines, independent of caller settings.
    command.args([
        "--format",
        "human-readable",
        "--encoding",
        "UTF-8",
        "--no-color",
    ]);
    Ok(command)
}

pub fn check_op() -> Result<()> {
    let mut command = op_command()?;
    command.args(["environment", "read", "--help"]);
    let output = capture(command, Duration::from_secs(10))?;
    if output.status != Some(0)
        || !String::from_utf8_lossy(&output.stdout).contains("op environment read")
    {
        return Err(SafeError::auth(
            "installed op does not support `environment read`; install a release with Environment support",
        ));
    }
    Ok(())
}

pub fn load(project: &Project, timeout: u64) -> Result<Credentials> {
    project.validate()?;
    let mut command = op_command()?;
    if let Some(account) = &project.account {
        command.arg("--account").arg(account);
    }
    command
        .args(["environment", "read"])
        .arg(&project.environment);
    let output = capture(command, Duration::from_secs(timeout))?;
    if output.status != Some(0) {
        return Err(explain_failure(&output.stderr, output.status));
    }
    parse_credentials(&output.stdout, project)
}

/// Matches Handhold lab's literal KEY=value parser; nothing is evaluated as shell
/// code or installed in the process environment. Only the selected pair survives.
fn parse_credentials(bytes: &[u8], project: &Project) -> Result<Credentials> {
    if bytes.len() > MAX_ENVIRONMENT_BYTES {
        return Err(SafeError::auth("1Password Environment exceeds 16 MiB"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| {
        SafeError::auth("1Password Environment output is not UTF-8; raw output suppressed")
    })?;
    let mut names = BTreeSet::new();
    let mut id = None;
    let mut key = None;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let (name, value) = line.split_once('=').ok_or_else(|| SafeError::auth("1Password Environment output must contain literal KEY=value lines; multiline values are unsupported"))?;
        if !environment_variable_name(name) {
            return Err(SafeError::auth(
                "1Password Environment contains an invalid variable name; raw output suppressed",
            ));
        }
        if !names.insert(name) {
            return Err(SafeError::auth(
                "1Password Environment contains a duplicate variable; raw output suppressed",
            ));
        }
        if names.len() > MAX_ENVIRONMENT_VARIABLES {
            return Err(SafeError::auth(
                "1Password Environment exceeds 512 variables",
            ));
        }
        if value.len() >= 2
            && (value.starts_with('"') && value.ends_with('"')
                || value.starts_with('\'') && value.ends_with('\''))
        {
            return Err(SafeError::auth(
                "1Password Environment contains a quote-wrapped value; store raw values in 1Password",
            ));
        }
        if name == project.api_id_var {
            id = Some(Zeroizing::new(value.to_owned()));
        }
        if name == project.api_key_var {
            key = Some(Zeroizing::new(value.to_owned()));
        }
    }
    Credentials::new(
        id.ok_or_else(|| SafeError::auth("API ID variable is missing from the selected 1Password Environment; check api_id_var"))?,
        key.ok_or_else(|| SafeError::auth("API key variable is missing from the selected 1Password Environment; check api_key_var"))?,
    )
}

fn explain_failure(stderr: &[u8], status: Option<i32>) -> SafeError {
    let text = Zeroizing::new(String::from_utf8_lossy(stderr).to_lowercase());
    let message = if text.contains("connecting to desktop app")
        || text.contains("couldn't connect to the 1password desktop app")
    {
        "Open the 1Password desktop app and enable Settings > Developer > Integrate with 1Password CLI"
    } else if text.contains("not currently signed in")
        || text.contains("session expired")
        || text.contains("not signed in")
    {
        "Not signed in to 1Password; unlock the desktop app and retry"
    } else if text.contains("not found")
        || text.contains("no environment")
        || text.contains("isn't an environment")
    {
        "1Password Environment was not found; verify the account and copy its ID from Developer > Environments > Manage environment"
    } else if ["denied", "cancelled", "canceled", "rejected"]
        .iter()
        .any(|word| text.contains(word))
    {
        "1Password access was declined; retry when ready to approve access"
    } else {
        return SafeError::auth(&format!(
            "1Password could not read the Environment (exit status {}); check CLI integration and Environment access; raw output suppressed",
            status.map_or_else(|| "unknown".into(), |n| n.to_string())
        ));
    };
    SafeError::auth(message)
}

struct Captured {
    status: Option<i32>,
    stdout: Zeroizing<Vec<u8>>,
    stderr: Zeroizing<Vec<u8>>,
}

fn read_bounded(
    mut reader: impl Read,
    limit: usize,
    overflow: Option<Arc<AtomicBool>>,
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut buffer = Zeroizing::new([0u8; 8192]);
    loop {
        let n = reader.read(&mut buffer[..])?;
        if n == 0 {
            break;
        }
        let keep = n.min(limit.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&buffer[..keep]);
        if keep < n
            && let Some(flag) = &overflow
        {
            flag.store(true, Ordering::Relaxed);
        }
    }
    Ok(bytes)
}

/// Private bounded pipes; never forward raw stdout/stderr to the agent.
fn capture(mut command: Command, timeout: Duration) -> Result<Captured> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|_| SafeError::auth("could not start 1Password CLI"))?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let overflow = Arc::new(AtomicBool::new(false));
    let out_overflow = Arc::clone(&overflow);
    let out_reader =
        thread::spawn(move || read_bounded(stdout, MAX_ENVIRONMENT_BYTES, Some(out_overflow)));
    let err_reader = thread::spawn(move || read_bounded(stderr, 4096, None));
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if started.elapsed() < timeout && !overflow.load(Ordering::Relaxed) => {
                thread::sleep(Duration::from_millis(10))
            }
            _ => {
                #[cfg(unix)]
                {
                    // SAFETY: the child owns the dedicated process group created above.
                    unsafe {
                        libc::kill(-(child.id() as i32), libc::SIGKILL);
                    }
                }
                let _ = child.kill();
                let _ = child.wait();
                break Err(SafeError::new(
                    "provider_timeout",
                    "1Password did not finish before --auth-timeout; unlock the desktop app and retry; no Merit request was sent",
                    3,
                ));
            }
        }
    };
    #[cfg(unix)]
    {
        // Also close pipes held by descendants after an early provider exit.
        // SAFETY: the child was spawned into a dedicated process group above.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
    }
    let stdout = out_reader
        .join()
        .map_err(|_| SafeError::io("could not collect 1Password output"))?
        .map_err(|_| SafeError::io("could not read 1Password output"))?;
    let stderr = err_reader
        .join()
        .map_err(|_| SafeError::io("could not collect 1Password diagnostics"))?
        .map_err(|_| SafeError::io("could not read 1Password diagnostics"))?;
    if overflow.load(Ordering::Relaxed) {
        return Err(SafeError::auth(
            "1Password Environment exceeds 16 MiB; raw output suppressed",
        ));
    }
    Ok(Captured {
        status: status?.code(),
        stdout,
        stderr,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn provider_deadline_kills_children_that_hold_pipes_open() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30 & wait"]);
        let started = Instant::now();
        let error = capture(command, Duration::from_millis(100)).err().unwrap();
        assert_eq!(error.code, "provider_timeout");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn provider_exit_cleans_up_orphan_pipe_writers() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "sleep 30 & exit 1"]);
        let started = Instant::now();
        let output = capture(command, Duration::from_secs(1)).unwrap();
        assert_eq!(output.status, Some(1));
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
