//! Runtime settings and TOML configuration loading support.

use serde::Deserialize;
use std::path::PathBuf;

/// Resolve the normal XDG or `~/.config` configuration path if it exists.
pub(crate) fn default_config_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .or_else(|| {
            std::env::var_os("USERPROFILE").map(|home| PathBuf::from(home).join(".config"))
        })?;
    let path = base.join("onionmint").join("config.toml");
    path.is_file().then_some(path)
}

#[derive(Default)]
/// Fully resolved application settings after TOML and CLI processing.
pub(crate) struct Config {
    /// Address prefixes used by the search engine.
    pub(crate) filters: Vec<String>,
    /// Optional file containing additional filters.
    pub(crate) filter_file: Option<PathBuf>,
    /// Root directory for generated key directories.
    pub(crate) output_dir: PathBuf,
    /// Optional name/YAML output file and whether to truncate it.
    pub(crate) output_file: Option<(PathBuf, bool)>,
    /// Number of parallel search workers.
    pub(crate) threads: usize,
    /// Number of matching keys to write; zero means unlimited.
    pub(crate) limit: u64,
    /// Number of consecutive filters required on each matching address.
    pub(crate) words: usize,
    /// Suppress the startup banner and routine status output.
    pub(crate) quiet: bool,
    /// Print each found address to stderr.
    pub(crate) verbose: bool,
    /// Suppress printed names while still writing key directories.
    pub(crate) names_only: bool,
    /// Include the output directory in printed names.
    pub(crate) include_dir: bool,
    /// Write generated key records as YAML rather than key directories.
    pub(crate) yaml: bool,
    /// Use unprefixed raw key bytes in YAML mode.
    pub(crate) raw_yaml: bool,
    /// Optional YAML import path; `-` means stdin.
    pub(crate) yaml_input: Option<PathBuf>,
    /// Optional hostname selector for YAML import.
    pub(crate) yaml_hostname: Option<String>,
    /// Optional statistics period in seconds.
    pub(crate) stats_interval: Option<u64>,
    /// Keep statistics cumulative instead of reporting per-period rates.
    pub(crate) stats_total: bool,
    /// Remove duplicate filters after normalization.
    pub(crate) dedup: bool,
    /// Passphrase for deterministic search; cleared after seed derivation.
    pub(crate) passphrase: Option<String>,
    /// Optional file used to resume and persist deterministic seed progress.
    pub(crate) checkpoint: Option<PathBuf>,
    /// Restart with a fresh seed after every deterministic match.
    pub(crate) skip_near: bool,
    /// Annotate later matches from the same deterministic seed.
    pub(crate) warn_near: bool,
}

#[derive(Default, Deserialize)]
#[serde(default)]
/// TOML-backed subset of configuration; CLI-only values are not persisted.
pub(crate) struct FileConfig {
    /// Address prefixes supplied by the configuration file.
    pub(crate) filters: Vec<String>,
    /// Optional file containing address prefixes.
    pub(crate) filter_file: Option<PathBuf>,
    /// Root directory for generated key directories.
    pub(crate) output_dir: Option<PathBuf>,
    /// Optional file receiving generated names or YAML records.
    pub(crate) output_file: Option<PathBuf>,
    /// Replace an existing output file instead of appending to it.
    pub(crate) overwrite_output: bool,
    /// Number of parallel search workers.
    pub(crate) threads: Option<usize>,
    /// Maximum number of matching keys; zero means unlimited.
    pub(crate) keys: Option<u64>,
    /// Number of consecutive filter prefixes required for a match.
    pub(crate) words: Option<usize>,
    /// Suppress the startup banner and routine status output.
    pub(crate) quiet: bool,
    /// Print each found address to stderr.
    pub(crate) verbose: bool,
    /// Suppress printed names while still writing key directories.
    pub(crate) names_only: bool,
    /// Include the output directory in printed names.
    pub(crate) include_dir: bool,
    /// Write generated key records as YAML rather than creating directories.
    pub(crate) yaml: bool,
    /// Use unprefixed raw key bytes in YAML mode.
    pub(crate) raw_yaml: bool,
    /// Remove duplicate filters after normalization.
    pub(crate) dedup: bool,
    /// Optional period, in seconds, for search statistics.
    pub(crate) stats_interval: Option<u64>,
    /// Keep statistics cumulative instead of reporting interval rates.
    pub(crate) stats_total: bool,
}
