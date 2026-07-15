# timer-lab

An ultra-light micro-lab for one question: **how precise is an async ns-sleep on
Linux vs macOS vs Windows?** It exists to validate the three OS timer backends on
real hardware via free GitHub Actions runners — the paths a Linux-only dev box
structurally cannot exercise (macOS kqueue-in-kqueue readability; Windows
high-resolution waitable timer).

## Backends

| OS | Primitive | Reactor-integrated? |
|----|-----------|---------------------|
| Linux | `timerfd_create` + `AsyncFd` | yes |
| macOS | `kqueue` `EVFILT_TIMER` (`NOTE_NSECONDS \| NOTE_CRITICAL`) + `AsyncFd` | yes |
| Windows | `CreateWaitableTimerExW` (high-res) + `WaitForSingleObject` on blocking pool | no (thread-per-sleep) |
| other | `tokio::time` | n/a |

All degrade to `tokio::time` on syscall failure instead of panicking.

## Run locally

```bash
cargo test -- --nocapture          # the "never returns early" invariant
cargo run --example jitter_probe   # overshoot p50/p99/max per requested duration
```

## CI

`.github/workflows/ci.yml` runs build + test + jitter probe on `ubuntu-latest`,
`macos-latest` (ARM64), `macos-13` (Intel), and `windows-latest`. Public repos get
unlimited free Actions minutes on all four.

## Push to a fresh public repo

```bash
cd ~/projects/timer-lab
git init && git add -A && git commit -m "timer-lab: cross-platform ns-sleep micro-lab"
gh repo create timer-lab --public --source=. --push   # or set a remote manually
```

The `jitter_probe` numbers in each runner's log are the deliverable: they show
whether kqueue + `NOTE_CRITICAL` lands near the Linux timerfd before you port the
backend into aiperf's `real_clock.rs`.
