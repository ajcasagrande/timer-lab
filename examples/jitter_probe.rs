// SPDX-License-Identifier: Apache-2.0
//! Measure real per-OS timer accuracy and prove the hybrid coarse+spin sleep
//! improves on the raw OS backend on every platform. For a spread of requested
//! durations, sleep N times with each method and print the overshoot
//! (actual - requested) distribution in microseconds.

use std::time::Instant;
use timer_lab::{backend_name, sleep_ns, sleep_ns_hybrid};

async fn measure(req_ns: i64, iters: usize, hybrid: bool) -> Vec<f64> {
    let mut overshoot_us = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        if hybrid {
            sleep_ns_hybrid(req_ns).await;
        } else {
            sleep_ns(req_ns).await;
        }
        let elapsed_ns = start.elapsed().as_nanos() as i64;
        overshoot_us.push((elapsed_ns - req_ns) as f64 / 1_000.0);
    }
    overshoot_us.sort_by(|a, b| a.partial_cmp(b).unwrap());
    overshoot_us
}

fn pct(sorted: &[f64], q: f64) -> f64 {
    sorted[((sorted.len() as f64 - 1.0) * q).round() as usize]
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    const ITERS: usize = 400;
    let durations_us: [u64; 6] = [50, 100, 250, 500, 1_000, 5_000];

    println!("backend: {}   (coarse = raw OS timer, hybrid = coarse+spin)", backend_name());
    println!("iterations per row: {ITERS}");
    println!(
        "{:>9} | {:>11} {:>11} | {:>11} {:>11}",
        "req(us)", "coarse p50", "coarse p99", "hybrid p50", "hybrid p99"
    );
    println!("{}", "-".repeat(63));

    for &d_us in &durations_us {
        let req_ns = (d_us * 1_000) as i64;
        let coarse = measure(req_ns, ITERS, false).await;
        let hybrid = measure(req_ns, ITERS, true).await;
        println!(
            "{:>9} | {:>11.1} {:>11.1} | {:>11.1} {:>11.1}",
            d_us,
            pct(&coarse, 0.50),
            pct(&coarse, 0.99),
            pct(&hybrid, 0.50),
            pct(&hybrid, 0.99),
        );
    }
}
