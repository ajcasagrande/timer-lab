// SPDX-License-Identifier: Apache-2.0
//! Measure real per-OS timer accuracy: for a spread of requested durations,
//! sleep N times and print the overshoot (actual - requested) distribution.
//! This is the payoff of running on real macOS/Windows hardware — it answers
//! "does kqueue+NOTE_CRITICAL actually land near the Linux timerfd, and how
//! coarse is the Windows waitable timer" with numbers CI can archive.

use std::time::Instant;
use timer_lab::{backend_name, sleep_ns};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    const ITERS: usize = 500;
    let durations_us: [u64; 6] = [50, 100, 250, 500, 1_000, 5_000];

    println!("backend: {}", backend_name());
    println!("iterations per row: {ITERS}");
    println!(
        "{:>10} {:>12} {:>12} {:>12}",
        "req(us)", "p50 over(us)", "p99 over(us)", "max over(us)"
    );

    for &d_us in &durations_us {
        let req_ns = (d_us * 1_000) as i64;
        let mut overshoot_us: Vec<f64> = Vec::with_capacity(ITERS);
        for _ in 0..ITERS {
            let start = Instant::now();
            sleep_ns(req_ns).await;
            let elapsed_ns = start.elapsed().as_nanos() as i64;
            overshoot_us.push((elapsed_ns - req_ns) as f64 / 1_000.0);
        }
        overshoot_us.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let pct = |q: f64| overshoot_us[((overshoot_us.len() as f64 - 1.0) * q).round() as usize];
        println!(
            "{:>10} {:>12.1} {:>12.1} {:>12.1}",
            d_us,
            pct(0.50),
            pct(0.99),
            pct(1.0)
        );
    }
}
