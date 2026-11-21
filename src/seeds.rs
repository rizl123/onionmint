use argon2::{Algorithm, Argon2, Params, Version};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub(crate) struct SeedState {
    origin: [u8; 32],
    current: [u8; 32],
    checkpoint: Option<PathBuf>,
}

impl SeedState {
    pub(crate) fn new(passphrase: &str, checkpoint: Option<PathBuf>) -> Result<Self, String> {
        let params = Params::new(65_536, 48, 1, Some(32))
            .map_err(|error| format!("invalid Argon2 parameters: {error}"))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut origin = [0; 32];
        argon
            .hash_password_into(passphrase.as_bytes(), &[0; 16], &mut origin)
            .map_err(|error| format!("could not derive passphrase seed: {error}"))?;
        let mut current = origin;
        if let Some(path) = &checkpoint {
            apply_checkpoint(path, &mut current)?;
        }
        Ok(Self {
            origin,
            current,
            checkpoint,
        })
    }

    pub(crate) fn next_seed(&mut self) -> [u8; 32] {
        increment(&mut self.current);
        self.current
    }

    pub(crate) fn save_checkpoint(&self) -> Result<(), String> {
        let Some(path) = &self.checkpoint else {
            return Ok(());
        };
        let mut offset = self.current;
        let mut borrow = 0u16;
        for (byte, origin) in offset.iter_mut().zip(self.origin) {
            let subtrahend = u16::from(origin) + borrow;
            let value = u16::from(*byte).wrapping_sub(subtrahend);
            borrow = u16::from(u16::from(*byte) < subtrahend);
            *byte = value as u8;
        }
        write_checkpoint(path, &offset)
    }
}

fn apply_checkpoint(path: &Path, current: &mut [u8; 32]) -> Result<(), String> {
    let Ok(mut file) = OpenOptions::new().read(true).open(path) else {
        return if path.exists() {
            Err(format!("failed to read checkpoint {}", path.display()))
        } else {
            Ok(())
        };
    };
    let mut offset = [0; 32];
    file.read_exact(&mut offset)
        .map_err(|_| "failed to read checkpoint file".to_owned())?;
    let mut trailing = [0; 1];
    if file.read(&mut trailing).map_err(|e| e.to_string())? != 0 {
        return Err("invalid checkpoint file length".into());
    }
    add(current, &offset);
    Ok(())
}

fn write_checkpoint(path: &Path, bytes: &[u8; 32]) -> Result<(), String> {
    let mut temp = path.as_os_str().to_owned();
    temp.push(".tmp");
    let temp = PathBuf::from(temp);
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .map_err(|error| format!("could not save checkpoint {}: {error}", path.display()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("could not save checkpoint {}: {error}", path.display()))?;
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("could not protect checkpoint {}: {error}", path.display()))?;
    }
    fs::rename(&temp, path)
        .map_err(|error| format!("could not save checkpoint {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            if let Ok(directory) = OpenOptions::new().read(true).open(parent) {
                let _ = directory.sync_all();
            }
        }
    }
    Ok(())
}

fn increment(bytes: &mut [u8; 32]) {
    for byte in bytes {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}

fn add(bytes: &mut [u8; 32], offset: &[u8; 32]) {
    let mut carry = 0u16;
    for (byte, addend) in bytes.iter_mut().zip(offset) {
        let sum = u16::from(*byte) + u16::from(*addend) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
    }
}
