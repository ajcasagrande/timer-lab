// SPDX-License-Identifier: Apache-2.0
//! Does growing the process descriptor/handle table stall threads, and does
//! pre-expanding it from a single-threaded startup avoid the stall?
//!
//! Background: on Linux, allocating the 65th descriptor makes the kernel grow
//! the fd table (`expand_fdtable`, `fs/file.c`). If the `files_struct` is shared
//! with other threads it calls `synchronize_rcu()` first, blocking the caller
//! for a grace period (milliseconds). A single-threaded process skips that wait.
//! This probe measures the stall on each OS with three controls, each run in a
//! FRESH child process (fd-table state is per-process):
//!
//! * `cold`   -- fill the table to just below 64 entries, park `THREADS` threads,
//!               release them together; each allocates one timer primitive
//!               (timerfd on Linux, kqueue on macOS, waitable timer on Windows).
//!               The allocation that crosses slot 64 grows the table while
//!               threads are alive.
//! * `pre`    -- identical, but a single-threaded startup first grows the table
//!               (dup to a high fd and close it; Windows: create+close many
//!               handles), as a startup reservation would.
//! * `single` -- no other threads exist while the same allocations run.
//!
//! Output is a table of the slowest allocation per run (p50 / p90 / max over
//! `RUNS` runs) and how many runs exceeded 1 ms. It is a probe, never a gate.
//!
//! Usage: `cargo run --release --example fdtable_probe`

use std::sync::{Arc, Barrier};
use std::time::Instant;

const THREADS: usize = 8;
const RUNS: usize = 40;
/// Fill the table until the next descriptor would be slot 60, so `THREADS`
/// allocations land on slots 60..68 and one of them crosses slot 64.
const FILL_TO: i64 = 59;

#[cfg(unix)]
mod os {
    pub fn name() -> &'static str {
        if cfg!(target_os = "linux") {
            "timerfd_create"
        } else {
            "kqueue"
        }
    }

    pub fn filler() -> i64 {
        unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) as i64 }
    }

    pub fn alloc() -> i64 {
        #[cfg(target_os = "linux")]
        unsafe {
            libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC) as i64
        }
        #[cfg(not(target_os = "linux"))]
        unsafe {
            libc::kqueue() as i64
        }
    }

    /// Grow the table once, from the single-threaded main thread.
    pub fn pre_expand() {
        unsafe {
            let mut rl = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl);
            let want: libc::rlim_t = 4096;
            let target = if rl.rlim_max < want { rl.rlim_max } else { want };
            if rl.rlim_cur < target {
                rl.rlim_cur = target;
                libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
            }
            let fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            if fd >= 0 {
                let hi = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 1023);
                if hi >= 0 {
                    libc::close(hi);
                }
                libc::close(fd);
            }
        }
    }

    /// Slot number that triggers a table grow (descriptor >= 64).
    pub fn crosses(h: i64) -> bool {
        h >= 64
    }
}

#[cfg(windows)]
mod os {
    use std::ptr::null;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Threading::{
        CreateEventW, CreateWaitableTimerExW, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
        TIMER_ALL_ACCESS,
    };

    pub fn name() -> &'static str {
        "CreateWaitableTimerExW"
    }

    pub fn filler() -> i64 {
        unsafe { CreateEventW(null(), 0, 0, null()) as usize as i64 }
    }

    pub fn alloc() -> i64 {
        unsafe {
            CreateWaitableTimerExW(
                null(),
                null(),
                CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                TIMER_ALL_ACCESS,
            ) as usize as i64
        }
    }

    /// Windows has no POSIX fd table; the analogue is growing the handle table.
    pub fn pre_expand() {
        let mut hs: Vec<HANDLE> = Vec::with_capacity(4096);
        for _ in 0..4096 {
            let h = unsafe { CreateEventW(null(), 0, 0, null()) };
            if !h.is_null() {
                hs.push(h);
            }
        }
        for h in hs {
            unsafe { CloseHandle(h) };
        }
    }

    /// Handle values carry no "slot 64" meaning on Windows.
    pub fn crosses(_h: i64) -> bool {
        false
    }
}

struct Sample {
    handle: i64,
    ns: u128,
}

fn child(mode: &str) {
    if mode == "pre" {
        os::pre_expand();
    }
    // Fill the table to just below slot 64 (single-threaded, no grow yet).
    #[cfg(unix)]
    {
        loop {
            let h = os::filler();
            if h < 0 || h >= FILL_TO {
                break;
            }
        }
    }
    #[cfg(windows)]
    {
        for _ in 0..FILL_TO {
            os::filler();
        }
    }

    let samples: Vec<Sample> = if mode == "single" {
        (0..THREADS)
            .map(|_| {
                let t0 = Instant::now();
                let h = os::alloc();
                Sample {
                    handle: h,
                    ns: t0.elapsed().as_nanos(),
                }
            })
            .collect()
    } else {
        let barrier = Arc::new(Barrier::new(THREADS + 1));
        let joins: Vec<_> = (0..THREADS)
            .map(|_| {
                let b = barrier.clone();
                std::thread::spawn(move || {
                    b.wait();
                    let t0 = Instant::now();
                    let h = os::alloc();
                    Sample {
                        handle: h,
                        ns: t0.elapsed().as_nanos(),
                    }
                })
            })
            .collect();
        barrier.wait();
        joins.into_iter().map(|j| j.join().unwrap()).collect()
    };

    let max_ns = samples.iter().map(|s| s.ns).max().unwrap_or(0);
    let cross_ns = samples
        .iter()
        .filter(|s| os::crosses(s.handle))
        .map(|s| s.ns)
        .max()
        .unwrap_or(0);
    let max_handle = samples.iter().map(|s| s.handle).max().unwrap_or(-1);
    let failed = samples.iter().filter(|s| s.handle < 0).count();
    println!("RESULT max_ns={max_ns} cross_ns={cross_ns} max_handle={max_handle} failed={failed}");
}

fn field(line: &str, key: &str) -> u128 {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(key))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn pct(sorted: &[u128], q: f64) -> u128 {
    sorted[((sorted.len() as f64 - 1.0) * q).round() as usize]
}

fn kernel() -> String {
    #[cfg(unix)]
    {
        if let Ok(o) = std::process::Command::new("uname").arg("-sr").output() {
            return String::from_utf8_lossy(&o.stdout).trim().to_string();
        }
    }
    std::env::consts::OS.to_string()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "child" {
        child(&args[2]);
        return;
    }

    let exe = std::env::current_exe().expect("current_exe");
    let cpus = std::thread::available_parallelism().map_or(0, |n| n.get());
    println!(
        "### fd-table expansion probe ({}, {}, {} cpus, primitive `{}`)\n",
        std::env::consts::OS,
        kernel(),
        cpus,
        os::name()
    );
    println!(
        "{THREADS} threads release together on a table filled to ~{FILL_TO} entries; \
         slowest allocation per fresh process, {RUNS} processes per mode.\n"
    );
    println!("| mode | p50 | p90 | max | runs >1ms | slot>=64 alloc p50 |");
    println!("|---|---:|---:|---:|---:|---:|");

    let mut p50s = std::collections::BTreeMap::new();
    for mode in ["cold", "pre", "single"] {
        let mut max_ns = Vec::new();
        let mut cross_ns = Vec::new();
        for _ in 0..RUNS {
            let out = std::process::Command::new(&exe)
                .args(["child", mode])
                .output()
                .expect("spawn child");
            let text = String::from_utf8_lossy(&out.stdout);
            let line = text.lines().find(|l| l.starts_with("RESULT")).unwrap_or("");
            max_ns.push(field(line, "max_ns="));
            cross_ns.push(field(line, "cross_ns="));
        }
        max_ns.sort_unstable();
        cross_ns.sort_unstable();
        let over = max_ns.iter().filter(|&&n| n > 1_000_000).count();
        let us = |n: u128| format!("{:.1} us", n as f64 / 1_000.0);
        println!(
            "| {mode} | {} | {} | {} | {over}/{RUNS} | {} |",
            us(pct(&max_ns, 0.5)),
            us(pct(&max_ns, 0.9)),
            us(*max_ns.last().unwrap()),
            us(pct(&cross_ns, 0.5)),
        );
        p50s.insert(mode, pct(&max_ns, 0.5));
    }
    let cold = p50s["cold"].max(1) as f64;
    println!(
        "\ncold/pre p50 ratio = {:.1}x, cold/single p50 ratio = {:.1}x",
        cold / p50s["pre"].max(1) as f64,
        cold / p50s["single"].max(1) as f64
    );
}
