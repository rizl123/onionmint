use crate::output::write_key_files;
use std::fs;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Mutex;

const PUB_PREFIX: &[u8] = b"== ed25519v1-public: type0 ==\0\0\0";
const SEC_PREFIX: &[u8] = b"== ed25519v1-secret: type0 ==\0\0\0";

#[derive(Default)]
struct Record {
    hostname: Option<String>,
    public: Option<Vec<u8>>,
    secret: Option<Vec<u8>>,
}

pub(crate) fn import(
    input: Option<&Path>,
    selected_host: Option<&str>,
    raw: bool,
    output_dir: &Path,
    names_only: bool,
    include_dir: bool,
    output: &Mutex<Option<File>>,
) -> Result<(), String> {
    let mut source = String::new();
    if let Some(path) = input.filter(|path| *path != Path::new("-")) {
        source = fs::read_to_string(path)
            .map_err(|error| format!("failed to open input file: {error}"))?;
    } else {
        io::stdin()
            .read_to_string(&mut source)
            .map_err(|error| format!("failed to read YAML input: {error}"))?;
    }
    let mut record = Record::default();
    let mut imported = 0;
    for line in source.lines().chain(std::iter::once("---")) {
        let line = line.trim_end_matches(['\r', ' ']);
        if line.starts_with("---") {
            if record.hostname.is_some() || record.public.is_some() || record.secret.is_some() {
                imported += import_record(
                    &record,
                    selected_host,
                    raw,
                    output_dir,
                    names_only,
                    include_dir,
                    output,
                )?;
            }
            record = Record::default();
            continue;
        }
        let line = line.trim_start();
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value
            .trim()
            .strip_prefix("!binary")
            .unwrap_or(value.trim())
            .trim();
        match key.trim() {
            "hostname" => record.hostname = Some(value.to_owned()),
            "hs_ed25519_public_key" => record.public = Some(decode_base64(value)?),
            "hs_ed25519_secret_key" => record.secret = Some(decode_base64(value)?),
            _ => {}
        }
    }
    if imported == 0 && selected_host.is_some() {
        return Err("hostname wasn't found in input".into());
    }
    Ok(())
}

fn import_record(
    record: &Record,
    selected_host: Option<&str>,
    raw: bool,
    output_dir: &Path,
    names_only: bool,
    include_dir: bool,
    output: &Mutex<Option<File>>,
) -> Result<usize, String> {
    let host = record.hostname.as_deref().ok_or("incomplete YAML record")?;
    if host.len() != 62
        || !host.ends_with(".onion")
        || !host[..56]
            .bytes()
            .all(|byte| b"abcdefghijklmnopqrstuvwxyz234567".contains(&byte))
    {
        return Err("invalid hostname syntax".into());
    }
    if selected_host.is_some_and(|selected| selected != host) {
        return Ok(0);
    }
    let public = record.public.as_ref().ok_or("incomplete YAML record")?;
    let secret = record.secret.as_ref().ok_or("incomplete YAML record")?;
    let public = normalize_key(public, PUB_PREFIX, 32, raw, "public")?;
    let secret = normalize_key(secret, SEC_PREFIX, 64, raw, "secret")?;
    let pk: [u8; 32] = public.try_into().map_err(|_| "invalid public key length")?;
    let sk: [u8; 64] = secret.try_into().map_err(|_| "invalid secret key length")?;
    write_key_files(output_dir, host, &pk, &sk)
        .map_err(|error| format!("could not create directory for key output: {error}"))?;
    if !names_only {
        let line = if include_dir {
            format!("{}\n", output_dir.join(host).display())
        } else {
            format!("{host}\n")
        };
        let mut output = output.lock().unwrap();
        if let Some(file) = output.as_mut() {
            file.write_all(line.as_bytes())
                .map_err(|error| format!("failed to write output: {error}"))?;
        } else {
            io::stdout()
                .write_all(line.as_bytes())
                .map_err(|error| format!("failed to write output: {error}"))?;
        }
    }
    Ok(1)
}

fn normalize_key(
    bytes: &[u8],
    prefix: &[u8],
    key_len: usize,
    raw: bool,
    kind: &str,
) -> Result<Vec<u8>, String> {
    if raw {
        if bytes.len() != key_len {
            return Err(format!("invalid {kind} key syntax"));
        }
        let mut result = prefix.to_vec();
        result.extend_from_slice(bytes);
        return Ok(result);
    }
    if bytes.len() != prefix.len() + key_len || !bytes.starts_with(prefix) {
        return Err(format!("invalid {kind} key syntax"));
    }
    Ok(bytes.to_vec())
}

fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    if !value.len().is_multiple_of(4) {
        return Err("invalid base64 syntax".into());
    }
    for (index, chunk) in value.as_bytes().chunks_exact(4).enumerate() {
        let final_chunk = index + 1 == value.len() / 4;
        let padding = if chunk[3] == b'=' {
            if chunk[2] == b'=' { 2 } else { 1 }
        } else {
            0
        };
        if !final_chunk && padding != 0
            || padding == 2 && (chunk[2] != b'=' || chunk[1] == b'=')
            || padding == 1 && chunk[2] == b'='
            || chunk[2] == b'=' && chunk[3] != b'='
            || chunk[..2].contains(&b'=')
        {
            return Err("invalid base64 syntax".into());
        }
        let digit = |byte| match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => 0,
        };
        let values = [
            digit(chunk[0]),
            digit(chunk[1]),
            digit(chunk[2]),
            digit(chunk[3]),
        ];
        if chunk
            .iter()
            .zip(values)
            .any(|(byte, value)| *byte != b'=' && value == 0 && *byte != b'A')
        {
            return Err("invalid base64 syntax".into());
        }
        let buffer = (u32::from(values[0]) << 18)
            | (u32::from(values[1]) << 12)
            | (u32::from(values[2]) << 6)
            | u32::from(values[3]);
        output.push((buffer >> 16) as u8);
        if padding < 2 {
            output.push((buffer >> 8) as u8);
        }
        if padding == 0 {
            output.push(buffer as u8);
        }
        if padding == 2 && values[1] & 0x0f != 0 || padding == 1 && values[2] & 0x03 != 0 {
            return Err("invalid base64 syntax".into());
        }
    }
    Ok(output)
}
