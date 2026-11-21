# onionmint

`onionmint` is an AI-assisted Rust rewrite of [mkp224o](https://github.com/cathugger/mkp224o), a vanity address generator for Tor v3 onion services. It uses no handwritten assembly and no libsodium. The cryptographic primitives come from `curve25519-dalek`, `sha2`, and `sha3`.

## License and acknowledgment

Onionmint is distributed under the MIT License; see the [LICENSE file](https://github.com/rizl123/onionmint/blob/main/LICENSE). It is based on the approach and work of [mkp224o](https://github.com/cathugger/mkp224o), whose authors are acknowledged here.

## Build

Rust and Cargo are required.

```sh
cargo build --release
```

## Generate addresses

Pass one or more case-insensitive base32 prefixes. Onionmint writes a Tor-compatible key directory for every match:

```sh
cargo run --release -- neko
cargo run --release -- -d ./keys -t 4 -n 2 neko
```

Each directory contains `hs_ed25519_secret_key`, `hs_ed25519_public_key`, and `hostname`. On Unix, the secret key file is created with permissions `0600`. The generator uses all available CPU threads by default and runs until interrupted unless `-n` sets a key limit.

## Configuration

Onionmint loads user defaults from `$XDG_CONFIG_HOME/onionmint/config.toml`. If `XDG_CONFIG_HOME` is unset, it looks in `~/.config/onionmint/config.toml`. A missing default config is normal; built-in defaults are used. Select another file with `-c FILE` or `--config FILE`.

Copy [onionmint.example.toml](onionmint.example.toml) to the user config directory to get started:

```sh
mkdir -p ~/.config/onionmint
cp onionmint.example.toml ~/.config/onionmint/config.toml
```

Config values act as defaults. CLI options are applied afterward; command-line filters replace configured filters. Supported TOML keys:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `filters` | array of strings | `[]` | Base32 address prefixes |
| `filter_file` | string | unset | File with one filter per line |
| `output_dir` | string | `"."` | Directory for generated key folders |
| `output_file` | string | unset | Append onion names, or YAML records in YAML mode |
| `overwrite_output` | boolean | `false` | Truncate `output_file` instead of appending |
| `threads` | integer | CPU count | Worker threads |
| `keys` | integer | `0` | Number of matches; `0` means unlimited |
| `words` | integer | `1` | Consecutive matching prefixes required |
| `quiet` | boolean | `false` | Suppress status output on stderr |
| `verbose` | boolean | `false` | Print a line for each generated key |
| `names_only` | boolean | `false` | Suppress printed onion names; key files are still written |
| `include_dir` | boolean | `false` | Include output directory in printed names |
| `yaml` | boolean | `false` | Write generated key records as YAML |
| `raw_yaml` | boolean | `false` | Omit Tor key prefixes in YAML output |
| `dedup` | boolean | `false` | Remove duplicate filters |
| `stats_interval` | integer | unset | Print statistics every N seconds; `0` is invalid |
| `stats_total` | boolean | `false` | Report cumulative instead of interval statistics |

## Command-line options

| Option | Meaning |
| --- | --- |
| `-c FILE`, `--config FILE` | Use a specific TOML config |
| `-f FILE` | Load filters from a file |
| `-d DIR` | Set key output directory |
| `-t N`, `-j N` | Set worker thread count |
| `-n N` | Stop after generating N keys; `0` means unlimited |
| `-N N` | Require N consecutive matching prefixes |
| `-o FILE` | Append names to a file |
| `-O FILE` | Overwrite names file |
| `-D` | Deduplicate filters |
| `-q` | Suppress status output on stderr |
| `-v` | Print a line for each generated key |
| `-x` | Suppress printed onion names |
| `-F` | Include output directory in printed names |
| `-y` | Write key records as YAML |
| `-Y [FILE [HOST]]` | Import keys from YAML file or stdin into key directories |
| `--rawyaml` | Read or write unprefixed keys with `-y` or `-Y` |
| `-s` | Print search statistics every 10 seconds |
| `-S SECONDS` | Set the statistics reporting interval |
| `-T` | Report cumulative statistics instead of interval rates |
| `-p PASSPHRASE` | Derive a repeatable seed using Argon2id |
| `-P` | Read the passphrase from the `PASSPHRASE` environment variable |
| `--checkpoint FILE` | Resume and save deterministic search progress |
| `--skipnear` | Start a new deterministic seed after a match |
| `--warnnear` | Mark additional matches found from the same deterministic seed |
| `-h`, `--help` | Show help |
| `-V`, `--version` | Show version |

Filter files contain one prefix per line; blank lines and lines starting with `#` or `//` are ignored.

## Console output and implementation notes

Status is shown on stderr as a compact plain-text summary with no color. Onion names remain plain text on stdout or in the selected output file.

For speed, onionmint derives an initial Ed25519 point from a random seed, then advances through candidate scalars by adding the corresponding multiple of the base point. This avoids a full scalar multiplication for every candidate. YAML import (`-Y`) and export (`-y`) support Tor-prefixed keys and raw key bytes. Passphrase mode uses the same Argon2id parameters and deterministic seed progression as mkp224o. The original C program's batched point compression remains unimplemented, so throughput can differ.

Run the dependency-free search microbenchmark with `cargo bench --bench search`. It measures candidate point advancement and filter matching; use it as a baseline when changing the hot search loop.
