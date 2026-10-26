//! The guest entry contract: how k9o-init learns what to `exec`.
//!
//! Firecracker boots k9o-init as PID 1 (`init=/usr/bin/k9o-init`), which erases
//! the OCI image's own `Entrypoint`/`Cmd`. So the converter resolves them from
//! the image config and writes them to [`crate::ENTRY_CONTRACT_PATH`] as JSON;
//! k9o-init reads it and execs the extension's real process with the recorded
//! argv, environment, and working directory.

use serde::Deserialize;
use std::collections::BTreeMap;

/// The resolved extension entrypoint. `argv[0]` is the program; the rest are its
/// arguments (OCI `Entrypoint` ++ `Cmd`). `env`/`cwd` come from the image config.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct EntryContract {
    pub argv: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: Option<String>,
}

#[derive(Debug)]
pub enum EntryError {
    Parse(String),
    EmptyArgv,
}

impl std::fmt::Display for EntryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntryError::Parse(e) => write!(f, "entry contract is not valid JSON: {e}"),
            EntryError::EmptyArgv => write!(f, "entry contract argv is empty — nothing to exec"),
        }
    }
}

impl EntryContract {
    /// Parse + validate the contract bytes. A contract with no `argv[0]` is
    /// fatal: there is no extension process to run.
    pub fn parse(bytes: &[u8]) -> Result<EntryContract, EntryError> {
        let c: EntryContract =
            serde_json::from_slice(bytes).map_err(|e| EntryError::Parse(e.to_string()))?;
        if c.argv.is_empty() || c.argv[0].is_empty() {
            return Err(EntryError::EmptyArgv);
        }
        Ok(c)
    }
}

/// Classify a read of the entry-contract file into the boot decision:
///   - `Ok(Some)` — a valid contract is present → the per-function exec path.
///   - `Ok(None)` — the file is **absent** → warm-pool-idle (generic, not yet
///     claimed): k9o-init boots straight to the gate bridge and parks, so the
///     base rootfs needs NO placeholder binary baked in just to satisfy exec.
///   - `Err`      — the file exists but is unreadable, or present-but-corrupt →
///     **fatal**. Only outright *absence* means idle; a present contract MUST be
///     valid (a corrupt or unreadable contract must never silently degrade to
///     idle, which would mask a real provisioning fault).
pub fn classify_contract(read: std::io::Result<Vec<u8>>) -> Result<Option<EntryContract>, String> {
    match read {
        Ok(bytes) => EntryContract::parse(&bytes).map(Some).map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!(
            "cannot read entry contract {}: {e}",
            crate::ENTRY_CONTRACT_PATH
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_contract() {
        let json = br#"{
            "argv": ["/usr/local/bin/node", "server.js"],
            "env": {"NODE_ENV": "production", "PORT": "8081"},
            "cwd": "/app"
        }"#;
        let c = EntryContract::parse(json).unwrap();
        assert_eq!(c.argv, vec!["/usr/local/bin/node", "server.js"]);
        assert_eq!(c.env.get("NODE_ENV").map(String::as_str), Some("production"));
        assert_eq!(c.cwd.as_deref(), Some("/app"));
    }

    #[test]
    fn env_and_cwd_default_when_absent() {
        let c = EntryContract::parse(br#"{"argv":["/app/run"]}"#).unwrap();
        assert!(c.env.is_empty());
        assert_eq!(c.cwd, None);
    }

    #[test]
    fn rejects_empty_argv() {
        assert!(matches!(EntryContract::parse(br#"{"argv":[]}"#), Err(EntryError::EmptyArgv)));
        assert!(matches!(EntryContract::parse(br#"{"argv":[""]}"#), Err(EntryError::EmptyArgv)));
    }

    #[test]
    fn rejects_bad_json() {
        assert!(matches!(EntryContract::parse(b"not json"), Err(EntryError::Parse(_))));
    }

    // --- classify_contract: the warm-pool-idle boot decision ---

    #[test]
    fn classify_absent_contract_is_idle() {
        // File not found → warm-pool-idle (Ok(None)), NOT fatal.
        let read = Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(matches!(classify_contract(read), Ok(None)));
    }

    #[test]
    fn classify_valid_contract_is_some() {
        let read = Ok(br#"{"argv":["/app/run"]}"#.to_vec());
        let c = classify_contract(read).unwrap().unwrap();
        assert_eq!(c.argv, vec!["/app/run"]);
    }

    #[test]
    fn classify_present_but_corrupt_is_fatal_not_idle() {
        // A present-but-unparseable or empty-argv contract must NOT silently idle —
        // it's a real provisioning fault → Err.
        assert!(classify_contract(Ok(b"not json".to_vec())).is_err());
        assert!(classify_contract(Ok(br#"{"argv":[]}"#.to_vec())).is_err());
    }

    #[test]
    fn classify_non_notfound_io_error_is_fatal() {
        // A permission/other error on a present file is fatal, NOT idle.
        let read = Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        assert!(classify_contract(read).is_err());
    }
}
