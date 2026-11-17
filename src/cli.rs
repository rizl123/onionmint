use crate::config::{Config, FileConfig, default_config_path};
use crate::crypto::ALPHABET;
use std::fs::{self, File};
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::thread;

fn help(program: &str) {
    const HELP: &str = r#"onionmint — Tor v3 onion vanity address generator

Usage:
  @PROGRAM@ FILTER [FILTER ...] [OPTION ...]
  @PROGRAM@ -f FILTERFILE [FILTER ...] [OPTION ...]

Filters
  Filters are case-insensitive base32 prefixes of the onion address.
  Valid characters are a-z and 2-7. The maximum filter length is 52 chars.
  A leading ^ is accepted and ignored. Use -N to require consecutive
  matching prefixes, for example: -N 2 neko cat.

Configuration
  By default, settings are loaded from:
    $XDG_CONFIG_HOME/onionmint/config.toml
  or, when XDG_CONFIG_HOME is unset:
    ~/.config/onionmint/config.toml
  If this file does not exist, built-in defaults are used. -c/--config loads
  a specific TOML file instead. Command-line options are applied after config;
  command-line filters replace filters from the config.

  Supported TOML keys:
    filters          = ["prefix", ...]   default: []
    filter_file      = "filters.txt"     default: unset
    output_dir       = "./keys"          default: .
    output_file      = "names.txt"       default: stdout
    overwrite_output = false             default: false (append)
    threads          = 4                 default: available CPU count
    keys             = 10                default: 0 (unlimited)
    words            = 1                 default: 1
    quiet            = false
    verbose          = false
    names_only       = false
    include_dir      = false
    yaml             = false
    raw_yaml         = false
    dedup            = false

Options
  -c, --config FILE   Load the specified TOML config instead of the default.
  -f FILE             Load filters from a file. Blank lines and lines starting
                      with # or // are ignored. Can be combined with filters.
  -D                  Deduplicate filters.
  -q                  Suppress status and diagnostic messages on stderr.
  -v                  Print each generated address to stderr as it is found.
  -x                  Do not print address names in filesystem output mode.
  -o FILE             Append names (or YAML records with -y) to FILE.
  -O FILE             Write names (or YAML records with -y) to FILE, replacing
                      its previous contents.
  -F                  Include the output directory in printed address names.
  -d DIR              Store key directories under DIR (default: current dir).
  -t N, -j N           Use N worker threads (default: available CPU count).
  -n N                 Stop after N matching keys. 0 means unlimited.
  -N N                 Require N consecutive matching filter prefixes.
  -y                  Write generated keys as YAML instead of creating folders.
  --rawyaml            With -y, omit Tor's key-file prefixes from encoded keys.
  -Z, -z, -B           Accepted for compatibility; have no effect.
  -h, --help           Show this complete help text.
  -V, --version        Show version and project acknowledgement.

Output
  Filesystem mode creates <address>.onion/ containing:
    hs_ed25519_secret_key
    hs_ed25519_public_key
    hostname
  On Unix, the secret key file is created with permissions 0600. Onion names
  are printed to stdout unless -x is set; -o/-O redirects that list.
  YAML mode writes records to stdout or to the file selected by -o/-O.
  Status output is plain text without color.

Examples
  @PROGRAM@ neko
  @PROGRAM@ -d ./keys -t 4 -n 2 neko
  @PROGRAM@ -f filters.txt -N 2
  @PROGRAM@ -c ~/.config/onionmint/config.toml
  @PROGRAM@ -y -n 1 neko > key-record.yaml

About this rewrite
  onionmint is an AI-assisted Rust rewrite of mkp224o. It uses no assembly
  and no libsodium. The original C project's batching optimization,
  passphrase/checkpoint mode, YAML import, and statistics are not implemented.
  Original project: https://github.com/cathugger/mkp224o

Respect for the original project
  I respect the work behind mkp224o and require all onionmint users to respect
  the original authors' work and acknowledge mkp224o as the source project.
"#;
    let program = Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("onionmint");
    print!("{}", HELP.replace("@PROGRAM@", program));
}

fn version() {
    println!("onionmint {}", env!("CARGO_PKG_VERSION"));
    println!("AI-assisted Rust rewrite of mkp224o; no assembly or libsodium.");
    println!("I respect the original authors' work and require users to acknowledge it.");
    println!("Original project: https://github.com/cathugger/mkp224o");
}

pub(crate) fn parse_args() -> Result<Config, String> {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    let program = std::env::args()
        .next()
        .unwrap_or_else(|| "onionmint".into());
    parse_args_from(raw_args, &program, default_config_path())
}

pub(crate) fn parse_args_from(
    raw_args: Vec<String>,
    program: &str,
    default_path: Option<PathBuf>,
) -> Result<Config, String> {
    let mut config_path = None;
    let mut cli_args = Vec::with_capacity(raw_args.len());
    let mut index = 0;
    while index < raw_args.len() {
        let arg = &raw_args[index];
        if arg == "--config" || arg == "-c" {
            index += 1;
            let path = raw_args.get(index).ok_or("-c/--config requires a path")?;
            config_path = Some(PathBuf::from(path));
        } else if let Some(path) = arg.strip_prefix("--config=") {
            config_path = Some(PathBuf::from(path));
        } else if arg.starts_with("-c") && arg.len() > 2 {
            config_path = Some(PathBuf::from(&arg[2..]));
        } else {
            cli_args.push(arg.clone());
        }
        index += 1;
    }

    let config_path = config_path.or(default_path);
    for arg in &cli_args {
        if arg == "--" {
            break;
        }
        if arg == "--help" || arg == "--usage" || arg == "-h" {
            help(&program);
            std::process::exit(0);
        }
        if arg == "--version" || arg == "-V" {
            version();
            std::process::exit(0);
        }
    }
    let mut cfg = Config {
        threads: thread::available_parallelism().map_or(1, usize::from),
        words: 1,
        output_dir: PathBuf::from("."),
        ..Default::default()
    };
    if let Some(path) = &config_path {
        let source = fs::read_to_string(path)
            .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
        let file: FileConfig = toml::from_str(&source)
            .map_err(|e| format!("invalid config {}: {e}", path.display()))?;
        cfg.filters = file.filters;
        cfg.filter_file = file.filter_file;
        cfg.output_dir = file.output_dir.unwrap_or(cfg.output_dir);
        cfg.output_file = file.output_file.map(|path| (path, file.overwrite_output));
        cfg.threads = file.threads.unwrap_or(cfg.threads);
        cfg.limit = file.keys.unwrap_or(cfg.limit);
        cfg.words = file.words.unwrap_or(cfg.words);
        cfg.quiet = file.quiet;
        cfg.verbose = file.verbose;
        cfg.names_only = file.names_only;
        cfg.include_dir = file.include_dir;
        cfg.yaml = file.yaml;
        cfg.raw_yaml = file.raw_yaml;
        cfg.dedup = file.dedup;
    }
    let mut it = cli_args.into_iter().peekable();
    let mut cli_filters_supplied = false;
    while let Some(arg) = it.next() {
        if arg == "--" {
            if !cli_filters_supplied {
                cfg.filters.clear();
                cfg.filter_file = None;
            }
            cfg.filters.extend(it);
            break;
        }
        if arg == "--rawyaml" {
            cfg.raw_yaml = true;
            continue;
        }
        if arg.starts_with('-') && arg != "-" {
            let mut chars = arg[1..].chars().peekable();
            while let Some(ch) = chars.next() {
                let mut value = || -> Result<String, String> {
                    let rest: String = chars.by_ref().collect();
                    if !rest.is_empty() {
                        Ok(rest)
                    } else {
                        it.next()
                            .ok_or_else(|| format!("-{ch} requires an argument"))
                    }
                };
                match ch {
                    'f' => {
                        if !cli_filters_supplied {
                            cfg.filters.clear();
                            cfg.filter_file = None;
                            cli_filters_supplied = true;
                        }
                        cfg.filter_file = Some(value()?.into());
                    }
                    'q' => cfg.quiet = true,
                    'v' => cfg.verbose = true,
                    'x' => cfg.names_only = true,
                    'F' => cfg.include_dir = true,
                    'D' => cfg.dedup = true,
                    'y' => cfg.yaml = true,
                    'Z' | 'z' | 'B' => {}
                    'd' => cfg.output_dir = value()?.into(),
                    't' | 'j' => {
                        cfg.threads = value()?
                            .parse()
                            .map_err(|_| "invalid thread count".to_string())?
                    }
                    'n' => {
                        cfg.limit = value()?
                            .parse()
                            .map_err(|_| "invalid key count".to_string())?
                    }
                    'N' => {
                        cfg.words = value()?
                            .parse()
                            .map_err(|_| "invalid word count".to_string())?
                    }
                    'o' | 'O' => cfg.output_file = Some((value()?.into(), ch == 'O')),
                    _ => return Err(format!("unrecognised argument: -{ch}")),
                }
            }
        } else {
            if !cli_filters_supplied {
                cfg.filters.clear();
                cfg.filter_file = None;
                cli_filters_supplied = true;
            }
            cfg.filters.push(arg);
        }
    }
    if let Some(path) = cfg.filter_file.take() {
        let file = File::open(&path)
            .map_err(|e| format!("failed to load filter file {}: {e}", path.display()))?;
        for line in io::BufReader::new(file).lines() {
            let line = line.map_err(|e| format!("failed to read filter file: {e}"))?;
            let value = line.trim_end_matches('\r');
            if !value.is_empty() && !value.starts_with('#') && !value.starts_with("//") {
                cfg.filters.push(value.to_owned());
            }
        }
    }
    if cfg.raw_yaml && !cfg.yaml {
        return Err("--rawyaml requires -y".into());
    }
    if cfg.words == 0 || cfg.threads == 0 {
        return Err("thread count and word count must be positive".into());
    }
    let mut good = Vec::new();
    for f in cfg.filters {
        let f = f.strip_prefix('^').unwrap_or(&f).to_ascii_lowercase();
        if f.bytes().any(|c| !ALPHABET.contains(&c)) {
            eprintln!("filter \"{f}\" is not valid base32 string");
        } else if f.len() > 52 {
            eprintln!("filter \"{f}\" is too long");
        } else if !f.is_empty() {
            good.push(f);
        }
    }
    if cfg.dedup {
        good.sort();
        good.dedup();
    }
    cfg.filters = good;
    if cfg.filters.is_empty() {
        return Err("no valid filters specified".into());
    }
    Ok(cfg)
}
