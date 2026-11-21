//! Ed25519 candidate generation, Tor v3 onion encoding, and filter matching.
//!
//! A cursor starts from a clamped Ed25519 scalar and advances by adding
//! eight times the base point. This preserves the search sequence while
//! avoiding a fresh scalar multiplication for every candidate.

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest as _, Sha256, Sha512};
use sha3::Sha3_256;

/// Lowercase RFC 4648 base32 alphabet used by Tor v3 onion names.
pub(crate) const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// A normalized filter represented as base32 symbols and comparison bits.
#[derive(Clone)]
pub(crate) struct FilterBits {
    symbols: Vec<u8>,
    bits: usize,
}

/// Incremental Ed25519 key candidate cursor.
///
/// `scalar_bytes` and `prefix` are the expanded Ed25519 secret key halves;
/// `point` is the public point corresponding to the scalar.
pub(crate) struct KeyCursor {
    scalar_bytes: [u8; 32],
    prefix: [u8; 32],
    point: EdwardsPoint,
}

impl KeyCursor {
    /// Create a cursor from 32 bytes drawn from the OS random source.
    pub(crate) fn random() -> Self {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("operating system random source failed");
        Self::from_seed(&seed)
    }

    /// Expand a 32-byte Ed25519 seed into the scalar, prefix, and public point.
    pub(crate) fn from_seed(seed: &[u8; 32]) -> Self {
        let digest = Sha512::digest(seed);
        let mut scalar_bytes: [u8; 32] = digest[..32].try_into().unwrap();
        scalar_bytes[0] &= 248;
        scalar_bytes[31] &= 127;
        scalar_bytes[31] |= 64;
        let prefix = digest[32..].try_into().unwrap();
        let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
        let point = EdwardsPoint::mul_base(&scalar);
        Self {
            scalar_bytes,
            prefix,
            point,
        }
    }

    /// Randomize the secret key's prefix while preserving its public key.
    pub(crate) fn reseed_prefix(&mut self) {
        let mut random = [0; 32];
        getrandom::getrandom(&mut random).expect("operating system random source failed");
        let mut hash = Sha256::new();
        hash.update(self.prefix);
        hash.update(random);
        self.prefix = hash.finalize().into();
    }

    /// Return the compressed Ed25519 public key for the current scalar.
    pub(crate) fn public_key(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }

    /// Return the 64-byte expanded secret key for the current candidate.
    pub(crate) fn secret_key(&self) -> [u8; 64] {
        let mut secret = [0u8; 64];
        secret[..32].copy_from_slice(&self.scalar_bytes);
        secret[32..].copy_from_slice(&self.prefix);
        secret
    }

    /// Advance to scalar + 8 and add the corresponding point to the cursor.
    ///
    /// Returns `false` when adding eight would leave the clamped scalar range;
    /// the worker should then start from a new seed.
    pub(crate) fn advance(&mut self, step_point: &EdwardsPoint) -> bool {
        let mut carry = 8u16;
        for byte in &mut self.scalar_bytes {
            let sum = *byte as u16 + carry;
            *byte = sum as u8;
            carry = sum >> 8;
            if carry == 0 {
                break;
            }
        }
        if self.scalar_bytes[0] & 7 != 0 || (self.scalar_bytes[31] & 0xc0) != 0x40 {
            return false;
        }
        self.point += step_point;
        true
    }
}

impl FilterBits {
    /// Parse a validated lowercase base32 filter into comparison symbols.
    pub(crate) fn parse(filter: &str) -> Self {
        let symbols: Vec<u8> = filter
            .bytes()
            .map(|byte| ALPHABET.iter().position(|&c| c == byte).unwrap() as u8)
            .collect();
        let bits = (symbols.len() * 5).min(256);
        Self { symbols, bits }
    }
}

/// Convert validated filter strings into their bit-oriented representation.
pub(crate) fn parse_filters(filters: &[String]) -> Vec<FilterBits> {
    filters
        .iter()
        .map(|filter| FilterBits::parse(filter))
        .collect()
}

/// Encode bytes as lowercase RFC 4648 base32 without padding.
pub(crate) fn base32(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8 + 4) / 5);
    let mut acc = 0u32;
    let mut bits = 0;
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits != 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Build a checksummed v3 onion service name from a 32-byte public key.
pub(crate) fn onion_name(pubkey: &[u8; 32]) -> String {
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(pubkey);
    h.update([3]);
    let digest = h.finalize();
    let mut address = [0u8; 35];
    address[..32].copy_from_slice(pubkey);
    address[32..34].copy_from_slice(&digest[..2]);
    address[34] = 3;
    format!("{}.onion", base32(&address))
}

fn matches_filter_at(pubkey: &[u8; 32], filter: &FilterBits, offset: usize) -> bool {
    if filter.bits == 0 || offset + filter.bits > 256 {
        return false;
    }
    for (index, &expected) in filter.symbols.iter().enumerate() {
        let local_bit = index * 5;
        if local_bit >= filter.bits {
            break;
        }
        let width = (filter.bits - local_bit).min(5);
        let bit = offset + local_bit;
        let byte_index = bit / 8;
        let shift = bit % 8;
        let pair = ((pubkey[byte_index] as u16) << 8)
            | pubkey.get(byte_index + 1).copied().unwrap_or(0) as u16;
        let found = ((pair >> (11 - shift)) & 0x1f) as u8;
        let ignored_low_bits = 5 - width;
        if (found >> ignored_low_bits) != (expected >> ignored_low_bits) {
            return false;
        }
    }
    true
}

fn matches_words_from(
    pubkey: &[u8; 32],
    filters: &[FilterBits],
    offset: usize,
    words_left: usize,
) -> bool {
    if words_left == 0 {
        return true;
    }
    filters.iter().any(|filter| {
        matches_filter_at(pubkey, filter, offset)
            && matches_words_from(pubkey, filters, offset + filter.bits, words_left - 1)
    })
}

/// Test whether a compressed public key matches the requested filter sequence.
///
/// `words` controls how many consecutive filters must match; filters may be
/// selected in any order at each position.
pub(crate) fn matches_public_key(pubkey: &[u8; 32], filters: &[FilterBits], words: usize) -> bool {
    words > 0 && matches_words_from(pubkey, filters, 0, words)
}

#[cfg(test)]
pub(crate) fn matches_filter(address: &str, filters: &[String], words: usize) -> bool {
    let host = address.trim_end_matches(".onion");
    filters.iter().any(|f| prefix_match(host, f) && words == 1)
        || (words > 1
            && filters.iter().any(|f| {
                if !prefix_match(host, f) {
                    return false;
                }
                let mut pos = f.len();
                for _ in 1..words {
                    if pos >= host.len() {
                        return false;
                    }
                    let Some(next) = filters.iter().find(|next| prefix_match(&host[pos..], next))
                    else {
                        return false;
                    };
                    pos += next.len();
                }
                true
            }))
}

#[cfg(test)]
pub(crate) fn prefix_match(value: &str, filter: &str) -> bool {
    if filter.len() <= 51 {
        return value.starts_with(filter);
    }
    if value.len() < 52 || !value.starts_with(&filter[..51]) {
        return false;
    }
    let got = ALPHABET
        .iter()
        .position(|&c| c == value.as_bytes()[51])
        .unwrap_or(0);
    let want = ALPHABET
        .iter()
        .position(|&c| c == filter.as_bytes()[51])
        .unwrap_or(0);
    (got & 0b1_0000) == (want & 0b1_0000)
}
