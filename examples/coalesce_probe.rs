// SPDX-License-Identifier: Apache-2.0
//! Micro-bench: aiperf's one-turn-per-tick pacing vs a batch-drain-per-wakeup.
//!
//! When the pacer falls behind (high rate / saturation), the two differ by
//! exactly one `yield_now().await` per arrival: `per_tick` yields once per due
//! arrival (aiperf's model), `batch` yields once per wakeup and drains the rest
//! in a tight loop. This measures that yield tax per arrival and how much
//! per-arrival dispatch work it takes to make it disappear — i.e. whether the
//! "in practice equivalent" claim holds.

use std::hint::black_box;
use std::time::Instant;

/// Cheap deterministic work kernel standing in for per-arrival dispatch cost.
#[inline]
fn mix(seed: &mut u64, iters: u32) {
    for _ in 0..iters {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
    }
}

/// One `yield_now` per arrival (aiperf: yield, then handle one due turn).
async fn per_tick(n: usize, work: u32) -> u64 {
    let mut s = 0x9E37_79B9_7F4A_7C15u64;
    for _ in 0..n {
        tokio::task::yield_now().await;
        mix(&mut s, work);
        black_box(s);
    }
    s
}

/// One `yield_now` per wakeup; all currently-due arrivals drained in a tight
/// loop (batch coalescing). At full saturation that is a single wakeup.
async fn batch(n: usize, work: u32) -> u64 {
    let mut s = 0x9E37_79B9_7F4A_7C15u64;
    let mut i = 0;
    while i < n {
        tokio::task::yield_now().await;
        while i < n {
            mix(&mut s, work);
            black_box(s);
            i += 1;
        }
    }
    s
}

async fn time_ns_per_arrival<F, Fut>(f: F, n: usize) -> f64
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = u64>,
{
    // one warmup, then measure
    black_box(f().await);
    let start = Instant::now();
    black_box(f().await);
    start.elapsed().as_nanos() as f64 / n as f64
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    const N: usize = 500_000;
    let work_levels: [u32; 5] = [0, 16, 64, 256, 1024];

    println!("=== coalesce micro-bench: per-tick yield vs batch drain ===");
    println!("N = {N} arrivals, fully saturated (all deadlines past)");
    println!(
        "{:>10} {:>14} {:>14} {:>14} {:>10}",
        "work(iter)", "per_tick(ns)", "batch(ns)", "yield_tax(ns)", "ratio"
    );

    for &work in &work_levels {
        let pt = time_ns_per_arrival(|| per_tick(N, work), N).await;
        let bt = time_ns_per_arrival(|| batch(N, work), N).await;
        println!(
            "{:>10} {:>14.2} {:>14.2} {:>14.2} {:>10.2}",
            work,
            pt,
            bt,
            pt - bt,
            pt / bt
        );
    }
}
