use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::{
    config::Project,
    error::{Result, SafeError},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    #[default]
    #[value(name = "POST")]
    Post,
    #[value(name = "GET")]
    Get,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Post => "POST",
            Self::Get => "GET",
        }
    }

    pub fn http(self) -> reqwest::Method {
        match self {
            Self::Post => reqwest::Method::POST,
            Self::Get => reqwest::Method::GET,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Access {
    ReadOnly,
    ReadWrite,
}

pub fn built_in_reads() -> impl Iterator<Item = &'static str> {
    include_str!("../read-endpoints.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

pub fn validate_rule(rule: &str) -> Result<()> {
    let Some((method, path)) = rule.split_once(' ') else {
        return Err(SafeError::config(
            "read_endpoints entries must be METHOD /api/vN/endpoint",
        ));
    };
    if !matches!(method, "GET" | "POST")
        || !path.starts_with("/api/")
        || crate::transport::resolve_path(path, "v1").ok().as_deref() != Some(path)
    {
        return Err(SafeError::config(
            "read_endpoints require GET or POST and an exact /api/vN/endpoint path; no wildcards",
        ));
    }
    Ok(())
}

pub fn authorize(project: &Project, method: Method, path: &str, uploads: bool) -> Result<()> {
    if !project.read_only {
        return Ok(());
    }
    if uploads {
        return Err(SafeError::new(
            "read_only",
            "project is read-only; attachment uploads are disabled",
            7,
        ));
    }
    let rule = format!("{} {path}", method.as_str());
    if built_in_reads().any(|allowed| allowed == rule)
        || project
            .read_endpoints
            .iter()
            .any(|allowed| allowed == &rule)
    {
        return Ok(());
    }
    Err(SafeError::new(
        "read_only",
        "project is read-only; this method and endpoint version are not in its reviewed read allowlist",
        7,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bundled_rules_are_exact_unique_and_valid() {
        let mut seen = std::collections::BTreeSet::new();
        for rule in built_in_reads() {
            validate_rule(rule).unwrap();
            assert!(seen.insert(rule), "duplicate {rule}");
        }
        assert!(seen.contains("POST /api/v2/getsalesinvpdf"));
        assert!(seen.contains("POST /api/v2/getpurchorder"));
        assert!(seen.contains("GET /api/v2/accounts"));
    }
}
