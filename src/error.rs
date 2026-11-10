use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, SafeError>;

/// Only static, reviewed messages cross the credential process boundary.
/// Never wrap third-party errors: reqwest errors may contain the signed URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeError {
    pub code: String,
    pub message: String,
    pub exit_code: u8,
}

impl SafeError {
    pub fn new(code: &str, message: &str, exit_code: u8) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            exit_code,
        }
    }

    pub fn input(message: &str) -> Self {
        Self::new("invalid_input", message, 2)
    }
    pub fn config(message: &str) -> Self {
        Self::new("configuration", message, 2)
    }
    pub fn auth(message: &str) -> Self {
        Self::new("credentials", message, 3)
    }
    pub fn io(message: &str) -> Self {
        Self::new("local_io", message, 6)
    }
}
