use std::{
    collections::BTreeMap,
    env, fs,
    io::Write,
    path::{Path, PathBuf},
};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::error::{Result, SafeError};

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Region {
    #[default]
    Ee,
    Pl,
}

impl Region {
    pub fn origin(self) -> &'static str {
        match self {
            Self::Ee => "https://aktiva.merit.ee",
            Self::Pl => "https://program.360ksiegowosc.pl",
        }
    }
}

fn api_id_var() -> String {
    "MERIT_API_ID".into()
}
fn api_key_var() -> String {
    "MERIT_API_KEY".into()
}
fn api_version() -> String {
    "v1".into()
}
fn schema_version() -> u32 {
    1
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub environment: String,
    #[serde(default = "api_id_var")]
    pub api_id_var: String,
    #[serde(default = "api_key_var")]
    pub api_key_var: String,
    #[serde(default)]
    pub region: Region,
    #[serde(default = "api_version")]
    pub api_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_endpoints: Vec<String>,
}

impl Project {
    pub fn validate(&self) -> Result<()> {
        if !identifier(&self.environment) {
            return Err(SafeError::config(
                "environment must be a 1Password Environment ID (letters, digits, hyphens or underscores)",
            ));
        }
        for name in [&self.api_id_var, &self.api_key_var] {
            if !environment_variable_name(name) {
                return Err(SafeError::config(
                    "credential variable names must start with a letter or underscore and contain only letters, digits and underscores",
                ));
            }
        }
        if self.api_id_var == self.api_key_var {
            return Err(SafeError::config(
                "API ID and API key must use different environment variable names",
            ));
        }
        validate_version(&self.api_version)?;
        if self.read_endpoints.len() > 512 {
            return Err(SafeError::config(
                "at most 512 additional read endpoints are allowed",
            ));
        }
        for rule in &self.read_endpoints {
            crate::policy::validate_rule(rule)?;
        }
        if self.account.as_ref().is_some_and(|s| {
            s.is_empty() || s.len() > 255 || s.chars().any(char::is_control) || s.starts_with('-')
        }) {
            return Err(SafeError::config("invalid 1Password account selector"));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "schema_version")]
    pub version: u32,
    #[serde(default)]
    pub projects: BTreeMap<String, Project>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            projects: BTreeMap::new(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = fs::metadata(path).map_err(|_| {
            SafeError::config("cannot read config; run `mp config init` or set --config")
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(SafeError::config(
                    "config is writable by another user; set its permissions to 0600",
                ));
            }
        }
        if metadata.len() > 1024 * 1024 {
            return Err(SafeError::config("config exceeds 1 MiB"));
        }
        let text = fs::read_to_string(path)
            .map_err(|_| SafeError::config("cannot read config as UTF-8"))?;
        let config: Self = toml::from_str(&text).map_err(|_| {
            SafeError::config("invalid config TOML or unknown fields; see config.example.toml")
        })?;
        if config.version != 1 {
            return Err(SafeError::config("unsupported config version"));
        }
        for (name, project) in &config.projects {
            if !identifier(name) {
                return Err(SafeError::config(
                    "project aliases must contain only letters, digits, hyphens or underscores",
                ));
            }
            project.validate()?;
        }
        Ok(config)
    }

    pub fn project(&self, name: &str) -> Result<Project> {
        self.projects
            .get(name)
            .cloned()
            .ok_or_else(|| SafeError::config("unknown project; use `mp projects list`"))
    }
}

pub fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn environment_variable_name(s: &str) -> bool {
    s.len() <= 128
        && s.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub fn validate_version(s: &str) -> Result<()> {
    if s.len() < 2
        || s.len() > 8
        || !s.starts_with('v')
        || !s[1..].bytes().all(|b| b.is_ascii_digit())
    {
        return Err(SafeError::input(
            "API version must be v followed by digits, for example v1 or v2",
        ));
    }
    Ok(())
}

pub fn default_path() -> Result<PathBuf> {
    if let Some(root) = env::var_os("XDG_CONFIG_HOME") {
        let root = PathBuf::from(root);
        if !root.is_absolute() {
            return Err(SafeError::config(
                "XDG_CONFIG_HOME must be an absolute path",
            ));
        }
        return Ok(root.join("merit/config.toml"));
    }
    env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".config/merit/config.toml"))
        .ok_or_else(|| SafeError::config("HOME is unavailable; pass --config"))
}

/// Serialize writers and atomically replace the lookup. No credentials are stored here.
pub fn update(path: &Path, change: impl FnOnce(Option<Config>) -> Result<Config>) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|_| SafeError::io("cannot create config directory"))?;
    let lock_path = path.with_extension("toml.lock");
    let mut options = fs::OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options
        .open(lock_path)
        .map_err(|_| SafeError::io("cannot open config lock"))?;
    lock.lock()
        .map_err(|_| SafeError::io("cannot lock config"))?;
    let old = if path
        .try_exists()
        .map_err(|_| SafeError::io("cannot inspect config"))?
    {
        Some(Config::load(path)?)
    } else {
        None
    };
    let new = change(old)?;
    let content =
        toml::to_string_pretty(&new).map_err(|_| SafeError::io("cannot serialize config"))?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| SafeError::io("cannot create temporary config"))?;
    tmp.write_all(content.as_bytes())
        .and_then(|_| tmp.as_file().sync_all())
        .map_err(|_| SafeError::io("cannot write config"))?;
    tmp.persist(path)
        .map_err(|_| SafeError::io("cannot replace config"))?;
    Ok(())
}
