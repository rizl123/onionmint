#[path = "../src/crypto.rs"]
#[allow(dead_code)]
mod crypto;

use crypto::{KeyCursor, matches_public_key, parse_filters};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let iterations = 1_000_000u64;
    let filters = parse_filters(&["onion".to_owned()]);
    let step = EdwardsPoint::mul_base(&Scalar::from(8u64));
    let mut cursor = KeyCursor::random();
    let start = Instant::now();
    let mut matches = 0u64;

    for _ in 0..iterations {
        let key = black_box(cursor.public_key());
        matches += u64::from(matches_public_key(&key, &filters, 1));
        if !cursor.advance(&step) {
            cursor = KeyCursor::random();
        }
    }

    let elapsed = start.elapsed();
    println!(
        "{iterations} candidates in {elapsed:?} ({:.0} candidates/s, {matches} matches)",
        iterations as f64 / elapsed.as_secs_f64()
    );
}
