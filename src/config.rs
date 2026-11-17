use serde::Deserialize;
use std::path::PathBuf;

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
pub(crate) struct Config {
    pub(crate) filters: Vec<String>,
    pub(crate) filter_file: Option<PathBuf>,
    pub(crate) output_dir: PathBuf,
    pub(crate) output_file: Option<(PathBuf, bool)>,
    pub(crate) threads: usize,
    pub(crate) limit: u64,
    pub(crate) words: usize,
    pub(crate) quiet: bool,
    pub(crate) verbose: bool,
    pub(crate) names_only: bool,
    pub(crate) include_dir: bool,
    pub(crate) yaml: bool,
    pub(crate) raw_yaml: bool,
    pub(crate) dedup: bool,
}

#[derive(Default, Deserialize)]
#[serde(default)]
pub(crate) struct FileConfig {
    pub(crate) filters: Vec<String>,
    pub(crate) filter_file: Option<PathBuf>,
    pub(crate) output_dir: Option<PathBuf>,
    pub(crate) output_file: Option<PathBuf>,
    pub(crate) overwrite_output: bool,
    pub(crate) threads: Option<usize>,
    pub(crate) keys: Option<u64>,
    pub(crate) words: Option<usize>,
    pub(crate) quiet: bool,
    pub(crate) verbose: bool,
    pub(crate) names_only: bool,
    pub(crate) include_dir: bool,
    pub(crate) yaml: bool,
    pub(crate) raw_yaml: bool,
    pub(crate) dedup: bool,
}
