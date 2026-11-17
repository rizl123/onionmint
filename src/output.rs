use crate::config::Config;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Mutex;

const PUB_PREFIX: &[u8; 32] = b"== ed25519v1-public: type0 ==\0\0\0";
const SEC_PREFIX: &[u8; 32] = b"== ed25519v1-secret: type0 ==\0\0\0";

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
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(data)
}
#[cfg(not(unix))]
fn write_secret(path: &Path, data: &[u8]) -> io::Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?
        .write_all(data)
}

pub(crate) fn emit(
    cfg: &Config,
    name: &str,
    pk: &[u8; 32],
    sk: &[u8; 64],
    output: &Mutex<Option<File>>,
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
            "---\nhostname: {name}\nhs_ed25519_public_key: {}\nhs_ed25519_secret_key: {}\n",
            base64(&pubdata),
            base64(&secdata)
        );
        let mut out = output.lock().unwrap();
        if let Some(file) = out.as_mut() {
            file.write_all(record.as_bytes())?;
            file.flush()?;
        } else {
            io::stdout().write_all(record.as_bytes())?;
        }
    } else {
        let dir = cfg.output_dir.join(name);
        fs::create_dir_all(&dir)?;
        let mut sec = Vec::from(&SEC_PREFIX[..]);
        sec.extend_from_slice(sk);
        let mut pubkey = Vec::from(&PUB_PREFIX[..]);
        pubkey.extend_from_slice(pk);
        write_secret(&dir.join("hs_ed25519_secret_key"), &sec)?;
        fs::write(dir.join("hs_ed25519_public_key"), pubkey)?;
        fs::write(dir.join("hostname"), format!("{name}\n"))?;
    }
    if !cfg.names_only && !cfg.yaml {
        let line = if cfg.include_dir {
            format!("{}\n", cfg.output_dir.join(name).display())
        } else {
            format!("{name}\n")
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
