# Agent guidance

## Project

- `onionmint` is an AI-assisted Rust rewrite of mkp224o for generating Tor v3 onion vanity addresses.
- Keep the implementation free of handwritten assembly and libsodium dependencies.
- Preserve compatibility with Tor's v3 onion checksum, base32 address encoding, and `hs_ed25519_*` key files.
- Keep generated secret key material out of logs. On Unix, secret key files must remain owner-readable and owner-writable only (`0600`).

## Configuration and CLI

- User configuration is TOML at `$XDG_CONFIG_HOME/onionmint/config.toml`, falling back to `~/.config/onionmint/config.toml`.
- Missing default config is normal; use built-in defaults. An explicitly selected config path should report read or parse errors.
- CLI arguments are applied after config values. CLI filters replace configured filters when supplied.
- Keep `onionmint.example.toml` and the configuration section in `README.md` aligned with supported settings and behavior.
- Keep status output plain text without color. Onion names on stdout and in output files should remain machine-readable.

## Development

- The binary entry point is `src/main.rs`; CLI/configuration, key search, and output code live in `src/cli.rs`, `src/config.rs`, `src/crypto.rs`, and `src/output.rs`.
- Update `Cargo.toml` and `Cargo.lock` together when changing dependencies.
- Format with `cargo fmt` and check compilation with `cargo check` after Rust changes.
- Avoid adding dependencies when the standard library or existing crates are sufficient.
- Keep every `.rs` file to at most 300 lines; split larger modules into focused files.
- Use TDD for behavior changes: write or update a test first, run it to confirm it fails for the expected reason, implement the change, then rerun the relevant tests.
