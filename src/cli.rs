use crate::config::{Config, FileConfig, default_config_path};
use crate::crypto::ALPHABET;
use crate::help::{help, version};
use std::fs::{self, File};
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::thread;

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
        cfg.stats_interval = file.stats_interval;
        cfg.stats_total = file.stats_total;
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
        if arg == "--checkpoint" {
            cfg.checkpoint = Some(it.next().ok_or("--checkpoint requires a path")?.into());
            continue;
        }
        if arg == "--skipnear" {
            cfg.skip_near = true;
            cfg.warn_near = false;
            continue;
        }
        if arg == "--warnnear" {
            cfg.warn_near = true;
            cfg.skip_near = false;
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
                    's' => cfg.stats_interval = Some(10),
                    'S' => {
                        cfg.stats_interval = Some(
                            value()?
                                .parse()
                                .map_err(|_| "invalid statistics interval")?,
                        )
                    }
                    'T' => cfg.stats_total = true,
                    'p' => cfg.passphrase = Some(value()?),
                    'P' => {
                        cfg.passphrase =
                            Some(std::env::var("PASSPHRASE").map_err(
                                |_| "store passphrase in PASSPHRASE environment variable",
                            )?)
                    }
                    'Y' => {
                        cfg.yaml_input =
                            Some(if it.peek().is_some_and(|arg| !arg.starts_with('-')) {
                                match it.next().unwrap().as_str() {
                                    "" => PathBuf::from("-"),
                                    path => path.into(),
                                }
                            } else {
                                PathBuf::from("-")
                            });
                        if it.peek().is_some_and(|arg| !arg.starts_with('-')) {
                            cfg.yaml_hostname = it.next().filter(|host| !host.is_empty());
                        }
                    }
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
    if cfg.raw_yaml && !cfg.yaml && cfg.yaml_input.is_none() {
        return Err("--rawyaml requires -y or -Y".into());
    }
    if cfg.yaml && cfg.yaml_input.is_some() {
        return Err("-y and -Y cannot be used together".into());
    }
    if cfg
        .yaml_hostname
        .as_ref()
        .is_some_and(|host| host.len() != 62)
    {
        return Err("bad onion argument length".into());
    }
    if cfg.stats_interval == Some(0) {
        return Err("statistics interval must be positive".into());
    }
    if cfg.checkpoint.is_some() && cfg.passphrase.is_none() {
        return Err("--checkpoint requires passphrase".into());
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
    if cfg.filters.is_empty() && cfg.yaml_input.is_none() {
        return Err("no valid filters specified".into());
    }
    Ok(cfg)
}
