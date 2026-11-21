//! Key-file creation and machine-readable result output.
//!
//! Filesystem output uses Tor's `hs_ed25519_*` key-file prefixes and creates
//! secret key files with owner-only permissions on Unix. YAML and name output
//! are serialized separately from status messages, which go to stderr.

use crate::config::Config;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const PUB_PREFIX: &[u8; 32] = b"== ed25519v1-public: type0 ==\0\0\0";
const SEC_PREFIX: &[u8; 32] = b"== ed25519v1-secret: type0 ==\0\0\0";

/// Print a plain-text summary of the active search settings to stderr.
pub(crate) fn print_banner(cfg: &Config) {
    let rule = "────────────────────────────────────────";
    eprintln!("onionmint {}", env!("CARGO_PKG_VERSION"));
    eprintln!("{rule}");
    eprintln!("  filters   {}", cfg.filters.join(", "));
    eprintln!("  workers   {}", cfg.threads);
    if cfg.yaml {
        eprintln!("  output    YAML on stdout or -o file");
    } else {
        eprintln!("  output    {}", cfg.output_dir.display());
    }
    if cfg.limit == 0 {
        eprintln!("  target    unlimited");
    } else {
        eprintln!("  target    {} key(s)", cfg.limit);
    }
    eprintln!("{rule}");
}

#[cfg(unix)]
fn write_secret(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    if let Err(error) = file.write_all(data) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}
#[cfg(not(unix))]
fn write_secret(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(error) = file.write_all(data) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

fn write_new(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(error) = file.write_all(data) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
/// Emit one result using the standard output policy without a proximity mark.
pub(crate) fn emit(
    cfg: &Config,
    name: &str,
    pk: &[u8; 32],
    sk: &[u8; 64],
    output: &Mutex<Option<File>>,
) -> io::Result<()> {
    emit_with_warning(cfg, name, pk, sk, output, false)
}

/// Write one generated result as YAML or as a Tor key directory.
///
/// The optional `near` flag annotates a result that follows another match
/// from the same deterministic seed. Secret key bytes are never logged.
pub(crate) fn emit_with_warning(
    cfg: &Config,
    name: &str,
    pk: &[u8; 32],
    sk: &[u8; 64],
    output: &Mutex<Option<File>>,
    near: bool,
) -> io::Result<()> {
    if cfg.yaml {
        let mut pubkey = Vec::from(&PUB_PREFIX[..]);
        pubkey.extend_from_slice(pk);
        let mut seckey = Vec::from(&SEC_PREFIX[..]);
        seckey.extend_from_slice(sk);
        let (pubdata, secdata) = if cfg.raw_yaml {
            (pk.to_vec(), sk.to_vec())
        } else {
            (pubkey, seckey)
        };
        let record = format!(
            "---\nhostname: {name}\nhs_ed25519_public_key: {}\nhs_ed25519_secret_key: {}\ntime: {}\n",
            base64(&pubdata),
            base64(&secdata),
            utc_timestamp()
        );
        let mut out = output.lock().unwrap();
        if let Some(file) = out.as_mut() {
            file.write_all(record.as_bytes())?;
            file.flush()?;
        } else {
            io::stdout().write_all(record.as_bytes())?;
        }
    } else {
        write_key_files(&cfg.output_dir, name, pk, sk)?;
    }
    if !cfg.names_only && !cfg.yaml {
        let warning = if near { " warn:near" } else { "" };
        let line = if cfg.include_dir {
            format!("{}{warning}\n", cfg.output_dir.join(name).display())
        } else {
            format!("{name}{warning}\n")
        };
        let mut out = output.lock().unwrap();
        if let Some(file) = out.as_mut() {
            file.write_all(line.as_bytes())?;
            file.flush()?;
        } else {
            io::stdout().write_all(line.as_bytes())?;
        }
    }
    Ok(())
}

fn utc_timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (seconds / 86_400) as i64;
    let day_seconds = seconds % 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} Z")
}

/// Create `<hostname>.onion/` with Tor-compatible key files and permissions.
pub(crate) fn write_key_files(
    output_dir: &Path,
    name: &str,
    pk: &[u8; 32],
    sk: &[u8; 64],
) -> io::Result<()> {
    let dir = output_dir.join(name);
    fs::create_dir_all(&dir)?;
    let mut sec = Vec::from(&SEC_PREFIX[..]);
    sec.extend_from_slice(sk);
    let mut pubkey = Vec::from(&PUB_PREFIX[..]);
    pubkey.extend_from_slice(pk);
    let secret_path = dir.join("hs_ed25519_secret_key");
    let public_path = dir.join("hs_ed25519_public_key");
    let hostname_path = dir.join("hostname");
    let mut created = Vec::new();
    let result = (|| {
        write_secret(&secret_path, &sec)?;
        created.push(secret_path.clone());
        write_new(&public_path, &pubkey)?;
        created.push(public_path.clone());
        write_new(&hostname_path, format!("{name}\n").as_bytes())?;
        created.push(hostname_path.clone());
        Ok(())
    })();
    if let Err(error) = result {
        for path in created {
            let _ = fs::remove_file(path);
        }
        return Err(error);
    }
    Ok(())
}

/// Encode bytes using standard padded Base64.
pub(crate) fn base64(data: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = ((c[0] as u32) << 16)
            | ((c.get(1).copied().unwrap_or(0) as u32) << 8)
            | c.get(2).copied().unwrap_or(0) as u32;
        out.push(A[((n >> 18) & 63) as usize] as char);
        out.push(A[((n >> 12) & 63) as usize] as char);
        out.push(if c.len() > 1 {
            A[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            A[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}
