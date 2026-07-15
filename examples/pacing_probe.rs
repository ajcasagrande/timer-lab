// SPDX-License-Identifier: Apache-2.0
//! Arrival-pacing accuracy: the metric that actually matters for a load
//! generator. For each arrival pattern (constant / Poisson / gamma) and a sweep
//! of target rates, generate a schedule of expected arrival times, then drive it
//! with four pacing strategies and measure how far actual arrivals stray from
//! expected — per-arrival error and, crucially, *cumulative drift*.
//!
//! The four strategies isolate two independent axes:
//!   * timer quality:  relative_tokio (1 ms wheel)  vs  relative_coarse (OS timer)
//!   * schedule model: relative_* (gaps accumulate)  vs  absolute_* (self-correct)
//! plus absolute_hybrid (absolute + spin tail) as the precise-but-CPU-hungry bound.
//!
//! The point: absolute_coarse should hold ~zero drift at feasible rates for *no*
//! extra CPU, proving the spin from jitter_probe is unnecessary for pacing.

use std::f64::consts::PI;
use std::time::{Duration, Instant};
use timer_lab::{backend_name, sleep_ns, sleep_ns_hybrid};

/// Deterministic SplitMix64 — reproducible schedules with no rng dependency.
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform in the open interval (0, 1).
    fn uniform(&mut self) -> f64 {
        ((self.next_u64() >> 11) as f64 + 0.5) * (1.0 / (1u64 << 53) as f64)
    }
    /// Standard normal via Box-Muller.
    fn normal(&mut self) -> f64 {
        (-2.0 * self.uniform().ln()).sqrt() * (2.0 * PI * self.uniform()).cos()
    }
    /// Gamma(shape, scale) via Marsaglia-Tsang (mean = shape*scale).
    fn gamma(&mut self, shape: f64, scale: f64) -> f64 {
        if shape < 1.0 {
            let u = self.uniform();
            return self.gamma(shape + 1.0, scale) * u.powf(1.0 / shape);
        }
        let d = shape - 1.0 / 3.0;
        let c = 1.0 / (9.0 * d).sqrt();
        loop {
            let x = self.normal();
            let mut v = 1.0 + c * x;
            if v <= 0.0 {
                continue;
            }
            v = v * v * v;
            let u = self.uniform();
            if u < 1.0 - 0.0331 * x * x * x * x || u.ln() < 0.5 * x * x + d * (1.0 - v + v.ln()) {
                return d * v * scale;
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Pattern {
    Constant,
    Poisson,
    Gamma,
}

const GAMMA_SHAPE: f64 = 0.5; // < 1 → burstier than Poisson (CV ≈ 1.41)

impl Pattern {
    fn name(self) -> &'static str {
        match self {
            Pattern::Constant => "constant",
            Pattern::Poisson => "poisson",
            Pattern::Gamma => "gamma(k=0.5)",
        }
    }
    fn id(self) -> u64 {
        match self {
            Pattern::Constant => 1,
            Pattern::Poisson => 2,
            Pattern::Gamma => 3,
        }
    }
}

#[derive(Clone, Copy)]
enum Variant {
    RelativeTokio,
    RelativeCoarse,
    AbsoluteCoarse,
    AbsoluteHybrid,
}

impl Variant {
    fn name(self) -> &'static str {
        match self {
            Variant::RelativeTokio => "relative_tokio",
            Variant::RelativeCoarse => "relative_coarse",
            Variant::AbsoluteCoarse => "absolute_coarse",
            Variant::AbsoluteHybrid => "absolute_hybrid",
        }
    }
}

/// Cumulative expected arrival offsets (ns from t0) for `n` arrivals at `rate`.
fn schedule(pattern: Pattern, rate: f64, n: usize) -> Vec<i64> {
    let mut rng = Rng(0x1234_5678_9ABC_DEF0 ^ (rate as u64) ^ (pattern.id() << 40));
    let mut t = 0.0f64;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let gap = match pattern {
            Pattern::Constant => 1.0 / rate,
            Pattern::Poisson => -rng.uniform().ln() / rate,
            // scale chosen so mean gap = 1/rate regardless of shape.
            Pattern::Gamma => rng.gamma(GAMMA_SHAPE, 1.0 / (rate * GAMMA_SHAPE)),
        };
        t += gap;
        out.push((t * 1e9) as i64);
    }
    out
}

/// Drive `sched` with `variant`, returning actual arrival offsets (ns from t0).
async fn run(variant: Variant, sched: &[i64]) -> Vec<i64> {
    let mut actual = Vec::with_capacity(sched.len());
    let t0 = Instant::now();
    match variant {
        Variant::RelativeTokio | Variant::RelativeCoarse => {
            let mut prev = 0i64;
            for &exp in sched {
                let gap = (exp - prev).max(0);
                prev = exp;
                match variant {
                    Variant::RelativeTokio => {
                        tokio::time::sleep(Duration::from_nanos(gap as u64)).await
                    }
                    _ => sleep_ns(gap).await,
                }
                actual.push(t0.elapsed().as_nanos() as i64);
            }
        }
        Variant::AbsoluteCoarse | Variant::AbsoluteHybrid => {
            for &exp in sched {
                let remaining = exp - t0.elapsed().as_nanos() as i64;
                if remaining > 0 {
                    match variant {
                        Variant::AbsoluteHybrid => sleep_ns_hybrid(remaining).await,
                        _ => sleep_ns(remaining).await,
                    }
                }
                actual.push(t0.elapsed().as_nanos() as i64);
            }
        }
    }
    actual
}

/// (err_p50_ms, err_p99_ms, final_drift_ms) of actual vs expected.
fn stats(actual: &[i64], sched: &[i64]) -> (f64, f64, f64) {
    let mut abs_err: Vec<f64> = actual
        .iter()
        .zip(sched)
        .map(|(a, e)| (a - e).abs() as f64 / 1e6)
        .collect();
    let drift = (actual.last().unwrap() - sched.last().unwrap()) as f64 / 1e6;
    abs_err.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p = |q: f64| abs_err[(((abs_err.len() - 1) as f64) * q).round() as usize];
    (p(0.50), p(0.99), drift)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let rates = [100.0, 500.0, 2_000.0, 10_000.0, 50_000.0];
    let variants = [
        Variant::RelativeTokio,
        Variant::RelativeCoarse,
        Variant::AbsoluteCoarse,
        Variant::AbsoluteHybrid,
    ];

    println!("=== pacing accuracy: actual vs expected arrival times ===");
    println!("backend: {}", backend_name());
    println!("err = |actual-expected| per arrival (ms); drift = final cumulative (ms, signed)");

    for pattern in [Pattern::Constant, Pattern::Poisson, Pattern::Gamma] {
        println!("\npattern = {}", pattern.name());
        println!(
            "{:>7} {:>6}  {:<16} {:>11} {:>11} {:>11}",
            "rate", "N", "variant", "err_p50", "err_p99", "drift"
        );
        for &rate in &rates {
            let n = ((rate * 0.4) as usize).clamp(100, 2000);
            let sched = schedule(pattern, rate, n);
            for &variant in &variants {
                let actual = run(variant, &sched).await;
                let (p50, p99, drift) = stats(&actual, &sched);
                println!(
                    "{:>7} {:>6}  {:<16} {:>11.3} {:>11.3} {:>11.3}",
                    rate as u64,
                    n,
                    variant.name(),
                    p50,
                    p99,
                    drift
                );
            }
        }
    }
}
