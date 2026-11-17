mod cli;
mod config;
mod crypto;
mod output;

use std::fs::{self, OpenOptions};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use crate::cli::parse_args;
use crate::crypto::{KeyCursor, matches_public_key, onion_name, parse_filters};
use crate::output::{emit, print_banner};

fn claim_match(done: &AtomicU64, limit: u64, stop: &AtomicBool) -> bool {
    if limit == 0 {
        done.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    let mut current = done.load(Ordering::Relaxed);
    loop {
        if current >= limit {
            stop.store(true, Ordering::Relaxed);
            return false;
        }
        match done.compare_exchange_weak(current, current + 1, Ordering::SeqCst, Ordering::Relaxed)
        {
            Ok(_) => {
                if current + 1 == limit {
                    stop.store(true, Ordering::Relaxed);
                }
                return true;
            }
            Err(actual) => current = actual,
        }
    }
}

fn run() -> Result<(), String> {
    let cfg = parse_args()?;
    if !cfg.quiet {
        print_banner(&cfg);
    }
    if !cfg.yaml {
        fs::create_dir_all(&cfg.output_dir)
            .map_err(|e| format!("cannot create output directory: {e}"))?;
    }
    let out = if let Some((path, overwrite)) = &cfg.output_file {
        Some(
            OpenOptions::new()
                .create(true)
                .write(true)
                .append(!overwrite)
                .truncate(*overwrite)
                .open(path)
                .map_err(|e| format!("failed to open output file: {e}"))?,
        )
    } else {
        None
    };
    let output = Arc::new(Mutex::new(out));
    let filters = Arc::new(parse_filters(&cfg.filters));
    let done = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let cfg = Arc::new(cfg);
    let step_point = EdwardsPoint::mul_base(&Scalar::from(8u64));
    let mut handles = Vec::new();
    for _ in 0..cfg.threads {
        let (cfg, filters, done, stop, output) = (
            cfg.clone(),
            filters.clone(),
            done.clone(),
            stop.clone(),
            output.clone(),
        );
        handles.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let mut cursor = KeyCursor::random();
                loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let pk = cursor.public_key();
                    if matches_public_key(&pk, &filters, cfg.words) {
                        if !claim_match(&done, cfg.limit, &stop) {
                            break;
                        }
                        let name = onion_name(&pk);
                        let sk = cursor.secret_key();
                        if let Err(e) = emit(&cfg, &name, &pk, &sk, &output) {
                            eprintln!("failed to write key {name}: {e}");
                            stop.store(true, Ordering::Relaxed);
                        }
                        if cfg.verbose {
                            eprintln!("  found #{:06}  {}", done.load(Ordering::Relaxed), name);
                        }
                        break;
                    }
                    if !cursor.advance(&step_point) {
                        break;
                    }
                }
            }
        }));
    }
    for h in handles {
        h.join().map_err(|_| "worker thread panicked".to_string())?;
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests;
