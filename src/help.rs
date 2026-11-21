//! Terminal help and version text.
//!
//! This text documents the supported CLI surface and is kept in sync with the
//! README configuration and usage sections.

use std::path::Path;

/// Print usage help, substituting the executable's displayed name.
pub(crate) fn help(program: &str) {
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
    keys             = 10                 default: 0 (unlimited)
    words            = 1                 default: 1
    quiet            = false
    verbose          = false
    names_only       = false
    include_dir      = false
    yaml             = false
    raw_yaml         = false
    dedup            = false
    stats_interval   = 10                 default: unset
    stats_total      = false

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
  -Y [FILE [HOST]]    Import YAML keys from FILE (or stdin) into key folders.
  --rawyaml            With -y or -Y, omit Tor's key-file prefixes in key data.
  -s                  Print search statistics every 10 seconds.
  -S SECONDS          Set the statistics reporting interval.
  -T                  Report cumulative statistics instead of interval rates.
  -p PASSPHRASE       Derive a repeatable search seed from a passphrase.
  -P                  Read the passphrase from PASSPHRASE in the environment.
  --checkpoint FILE   Resume and periodically save deterministic search progress.
  --skipnear           Start a new deterministic seed after every match.
  --warnnear           Mark subsequent matches from a deterministic seed.
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
  and no libsodium. The original C project's batched point compression is
  not implemented, so throughput can differ from mkp224o.
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

/// Print the package version and the project's attribution notice.
pub(crate) fn version() {
    println!("onionmint {}", env!("CARGO_PKG_VERSION"));
    println!("AI-assisted Rust rewrite of mkp224o; no assembly or libsodium.");
    println!("I respect the original authors' work and require users to acknowledge it.");
    println!("Original project: https://github.com/cathugger/mkp224o");
}
