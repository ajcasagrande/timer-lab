// SPDX-License-Identifier: Apache-2.0
//! The load-bearing invariant every backend must uphold: a sleep never returns
//! early. Coalescing/jitter may delay a wake but must never shorten it.

use std::time::Instant;
use timer_lab::{backend_name, sleep_ns, sleep_ns_hybrid};

#[tokio::test]
async fn sleeps_at_least_requested() {
    for &ns in &[50_000i64, 250_000, 1_000_000, 5_000_000] {
        let start = Instant::now();
        sleep_ns(ns).await;
        let elapsed = start.elapsed().as_nanos() as i64;
        assert!(
            elapsed >= ns,
            "backend {}: requested {ns} ns but slept only {elapsed} ns",
            backend_name()
        );
    }
}

#[tokio::test]
async fn hybrid_sleeps_at_least_requested() {
    for &ns in &[50_000i64, 250_000, 1_000_000, 5_000_000] {
        let start = Instant::now();
        sleep_ns_hybrid(ns).await;
        let elapsed = start.elapsed().as_nanos() as i64;
        assert!(
            elapsed >= ns,
            "hybrid on {}: requested {ns} ns but slept only {elapsed} ns",
            backend_name()
        );
    }
}

#[tokio::test]
async fn zero_and_negative_return_fast() {
    let start = Instant::now();
    sleep_ns(0).await;
    sleep_ns(-1).await;
    assert!(
        start.elapsed().as_millis() < 50,
        "non-positive durations must resolve promptly"
    );
}
