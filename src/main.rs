mod cli;
mod config;
mod crypto;
mod help;
mod output;
mod seeds;
mod yaml_input;

use std::fs::{self, OpenOptions};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;

use crate::cli::parse_args;
use crate::crypto::{KeyCursor, matches_public_key, onion_name, parse_filters};
use crate::output::{emit_with_warning, print_banner};
use crate::seeds::SeedState;

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
    let mut cfg = parse_args()?;
    let seed_state = cfg
        .passphrase
        .as_deref()
        .map(|passphrase| SeedState::new(passphrase, cfg.checkpoint.clone()))
        .transpose()?;
    cfg.passphrase = None;
    if seed_state.is_some() && cfg.limit != 1 && !cfg.skip_near && !cfg.warn_near && !cfg.quiet {
        eprintln!(
            "CAUTION: avoid using keys generated with the same password for unrelated\n         services, as one leaked key may help regenerate related keys. Use --skipnear or --warnnear to silence this warning."
        );
    }
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
    if let Some(input) = &cfg.yaml_input {
        return yaml_input::import(
            Some(input),
            cfg.yaml_hostname.as_deref(),
            cfg.raw_yaml,
            &cfg.output_dir,
            cfg.names_only,
            cfg.include_dir,
            output.as_ref(),
        );
    }
    let filters = Arc::new(parse_filters(&cfg.filters));
    let done = Arc::new(AtomicU64::new(0));
    let calculated = Arc::new(AtomicU64::new(0));
    let restarted = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, stop.clone())
        .map_err(|error| format!("failed to install interrupt handler: {error}"))?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, stop.clone())
        .map_err(|error| format!("failed to install termination handler: {error}"))?;
    let cfg = Arc::new(cfg);
    let seed_state = seed_state.map(|state| Arc::new(Mutex::new(state)));
    let started = std::time::Instant::now();
    let reporter = cfg.stats_interval.map(|interval| {
        let stop = stop.clone();
        let done = done.clone();
        let calculated = calculated.clone();
        let restarted = restarted.clone();
        let total = cfg.stats_total;
        thread::spawn(move || {
            let mut previous_calculated = 0;
            let mut previous_done = 0;
            let mut previous_restarted = 0;
            let mut previous_time = std::time::Instant::now();
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(std::time::Duration::from_millis(100));
                if previous_time.elapsed().as_secs() < interval || stop.load(Ordering::Relaxed) {
                    continue;
                }
                let now = std::time::Instant::now();
                let current_calculated = calculated.load(Ordering::Relaxed);
                let current_done = done.load(Ordering::Relaxed);
                let current_restarted = restarted.load(Ordering::Relaxed);
                let (calc, success, rest, elapsed) = if total {
                    (
                        current_calculated,
                        current_done,
                        current_restarted,
                        started.elapsed().as_secs_f64(),
                    )
                } else {
                    (
                        current_calculated - previous_calculated,
                        current_done - previous_done,
                        current_restarted - previous_restarted,
                        now.duration_since(previous_time).as_secs_f64(),
                    )
                };
                let elapsed = elapsed.max(f64::EPSILON);
                eprintln!(
                    ">calc/sec:{:8.3}, succ/sec:{:8.3}, rest/sec:{:8.3}, elapsed:{:5.6}sec",
                    calc as f64 / elapsed,
                    success as f64 / elapsed,
                    rest as f64 / elapsed,
                    started.elapsed().as_secs_f64()
                );
                previous_calculated = current_calculated;
                previous_done = current_done;
                previous_restarted = current_restarted;
                previous_time = now;
            }
        })
    });
    let checkpoint_worker = seed_state.as_ref().and_then(|state| {
        cfg.checkpoint.as_ref().map(|_| {
            let state = state.clone();
            let stop = stop.clone();
            thread::spawn(move || {
                let mut elapsed = std::time::Duration::ZERO;
                while !stop.load(Ordering::Relaxed) {
                    thread::sleep(std::time::Duration::from_millis(100));
                    elapsed += std::time::Duration::from_millis(100);
                    if elapsed >= std::time::Duration::from_secs(300) {
                        if let Err(error) = state.lock().unwrap().save_checkpoint() {
                            eprintln!("{error}");
                        }
                        elapsed = std::time::Duration::ZERO;
                    }
                }
                if let Err(error) = state.lock().unwrap().save_checkpoint() {
                    eprintln!("{error}");
                }
            })
        })
    });
    let step_point = EdwardsPoint::mul_base(&Scalar::from(8u64));
    let mut handles = Vec::new();
    for _ in 0..cfg.threads {
        let (cfg, filters, done, stop, output, calculated, restarted, seed_state) = (
            cfg.clone(),
            filters.clone(),
            done.clone(),
            stop.clone(),
            output.clone(),
            calculated.clone(),
            restarted.clone(),
            seed_state.clone(),
        );
        handles.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let mut cursor = seed_state.as_ref().map_or_else(KeyCursor::random, |state| {
                    KeyCursor::from_seed(&state.lock().unwrap().next_seed())
                });
                restarted.fetch_add(1, Ordering::Relaxed);
                let mut near = false;
                let mut seed_candidates = 0usize;
                loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let pk = cursor.public_key();
                    calculated.fetch_add(1, Ordering::Relaxed);
                    seed_candidates += 1;
                    if matches_public_key(&pk, &filters, cfg.words) {
                        if !claim_match(&done, cfg.limit, &stop) {
                            break;
                        }
                        let name = onion_name(&pk);
                        if seed_state.is_some() {
                            cursor.reseed_prefix();
                        }
                        let sk = cursor.secret_key();
                        if let Err(e) =
                            emit_with_warning(&cfg, &name, &pk, &sk, &output, near && cfg.warn_near)
                        {
                            eprintln!("failed to write key {name}: {e}");
                            stop.store(true, Ordering::Relaxed);
                        }
                        if cfg.verbose {
                            eprintln!("  found #{:06}  {}", done.load(Ordering::Relaxed), name);
                        }
                        if seed_state.is_none() || cfg.skip_near {
                            break;
                        }
                        near = true;
                    }
                    if seed_state.is_some() && seed_candidates >= (1 << 21) {
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
    if let Some(reporter) = reporter {
        let _ = reporter.join();
    }
    if let Some(worker) = checkpoint_worker {
        let _ = worker.join();
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
