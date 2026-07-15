// SPDX-License-Identifier: Apache-2.0
//! Cross-platform nanosecond-precision async sleep — a self-contained micro-lab
//! for validating the three OS timer backends that a Linux-only CI/dev box can't
//! exercise:
//!
//! * **Linux** — a `CLOCK_MONOTONIC` `timerfd` armed one-shot and awaited through
//!   tokio's IO reactor (`tokio::io::unix::AsyncFd`). ns request granularity.
//! * **macOS** — a `kqueue` holding one `EVFILT_TIMER | EV_ONESHOT` change with
//!   `NOTE_NSECONDS | NOTE_CRITICAL`, awaited the same way (a sub-kqueue is
//!   readable when its timer fires; tokio's mio reactor watches it). `NOTE_CRITICAL`
//!   opts out of macOS timer coalescing / App Nap so accuracy approaches the Linux
//!   timerfd instead of the coarse `tokio::time` wheel.
//! * **Windows** — a `CreateWaitableTimerExW` high-resolution waitable timer
//!   (Win10 1803+), waited on a blocking-pool thread via `WaitForSingleObject`.
//!   No reactor-integrated primitive exists, so this trades a pool thread per
//!   in-flight sleep for sub-ms resolution.
//!
//! Every backend degrades to `tokio::time` (the 1 ms wheel) on any syscall
//! failure rather than panicking — the same degrade-don't-panic contract used in
//! aiperf's production `real_clock.rs`.

use std::time::Duration;

/// Human-readable name of the timer backend compiled into this build.
pub fn backend_name() -> &'static str {
    #[cfg(target_os = "linux")]
    return "linux-timerfd";
    #[cfg(target_os = "macos")]
    return "macos-kqueue-evfilt_timer";
    #[cfg(windows)]
    return "windows-waitable-timer-highres";
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    return "tokio-time-fallback";
}

// ---------------------------------------------------------------------------
// Linux: timerfd
// ---------------------------------------------------------------------------

/// Sleep for `duration_ns` on the platform's most precise timer, falling back to
/// `tokio::time` for whatever time remains on any syscall failure. Non-positive
/// durations resolve after a single yield.
#[cfg(target_os = "linux")]
pub async fn sleep_ns(duration_ns: i64) {
    if duration_ns <= 0 {
        tokio::task::yield_now().await;
        return;
    }
    let started = std::time::Instant::now();
    if linux::timerfd_sleep_ns(duration_ns).await.is_ok() {
        return;
    }
    let remaining = (duration_ns as u128).saturating_sub(started.elapsed().as_nanos());
    if remaining > 0 {
        tokio::time::sleep(Duration::from_nanos(remaining as u64)).await;
    } else {
        tokio::task::yield_now().await;
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use tokio::io::unix::AsyncFd;

    const NANOS_PER_SEC: i64 = 1_000_000_000;

    /// Arm a one-shot monotonic `timerfd` and await its expiration via the reactor.
    pub async fn timerfd_sleep_ns(duration_ns: i64) -> std::io::Result<()> {
        let owned = unsafe {
            let fd = libc::timerfd_create(
                libc::CLOCK_MONOTONIC,
                libc::TFD_NONBLOCK | libc::TFD_CLOEXEC,
            );
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let owned = OwnedFd::from_raw_fd(fd);
            let spec = libc::itimerspec {
                it_interval: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: libc::timespec {
                    tv_sec: (duration_ns / NANOS_PER_SEC) as libc::time_t,
                    tv_nsec: (duration_ns % NANOS_PER_SEC) as libc::c_long,
                },
            };
            if libc::timerfd_settime(fd, 0, &spec, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            owned
        };

        let afd = AsyncFd::new(owned)?;
        loop {
            let mut guard = afd.readable().await?;
            let raw = afd.get_ref().as_raw_fd();
            let res = guard.try_io(|_| {
                let mut buf = [0u8; 8];
                let n = unsafe { libc::read(raw, buf.as_mut_ptr() as *mut libc::c_void, 8) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
            match res {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// macOS: kqueue EVFILT_TIMER
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
pub async fn sleep_ns(duration_ns: i64) {
    if duration_ns <= 0 {
        tokio::task::yield_now().await;
        return;
    }
    let started = std::time::Instant::now();
    if macos::kqueue_sleep_ns(duration_ns).await.is_ok() {
        return;
    }
    let remaining = (duration_ns as u128).saturating_sub(started.elapsed().as_nanos());
    if remaining > 0 {
        tokio::time::sleep(Duration::from_nanos(remaining as u64)).await;
    } else {
        tokio::task::yield_now().await;
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use tokio::io::unix::AsyncFd;

    /// Arm a one-shot `EVFILT_TIMER` on a fresh kqueue and await readability. A
    /// sub-kqueue becomes readable to tokio's (kqueue-based) reactor when it has a
    /// pending event, so this mirrors the Linux timerfd path exactly.
    pub async fn kqueue_sleep_ns(duration_ns: i64) -> std::io::Result<()> {
        let owned = unsafe {
            let kq = libc::kqueue();
            if kq < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let owned = OwnedFd::from_raw_fd(kq);
            // kqueue() takes no flags (unlike timerfd_create's TFD_* args), so set
            // CLOEXEC and non-blocking explicitly.
            libc::fcntl(kq, libc::F_SETFD, libc::FD_CLOEXEC);
            let fl = libc::fcntl(kq, libc::F_GETFL);
            libc::fcntl(kq, libc::F_SETFL, fl | libc::O_NONBLOCK);

            let change = libc::kevent {
                ident: 1,
                filter: libc::EVFILT_TIMER,
                flags: libc::EV_ADD | libc::EV_ONESHOT,
                // NOTE_NSECONDS: `data` is ns. NOTE_CRITICAL: opt out of coalescing.
                fflags: libc::NOTE_NSECONDS | libc::NOTE_CRITICAL,
                data: duration_ns as isize,
                udata: std::ptr::null_mut(),
            };
            let zero = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            if libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, &zero) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            owned
        };

        let afd = AsyncFd::new(owned)?;
        loop {
            let mut guard = afd.readable().await?;
            let kq = afd.get_ref().as_raw_fd();
            let res = guard.try_io(|_| {
                let mut ev: libc::kevent = unsafe { std::mem::zeroed() };
                let zero = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, &mut ev, 1, &zero) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else if n == 0 {
                    // Spurious readiness: map to WouldBlock so try_io re-arms.
                    Err(std::io::Error::from_raw_os_error(libc::EWOULDBLOCK))
                } else if ev.flags & libc::EV_ERROR != 0 {
                    Err(std::io::Error::from_raw_os_error(ev.data as i32))
                } else {
                    Ok(())
                }
            });
            match res {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Windows: high-resolution waitable timer
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub async fn sleep_ns(duration_ns: i64) {
    if duration_ns <= 0 {
        tokio::task::yield_now().await;
        return;
    }
    // No reactor-integrated Win32 timer exists; wait on a blocking-pool thread.
    match tokio::task::spawn_blocking(move || windows_timer::high_res_sleep(duration_ns)).await {
        Ok(Ok(())) => {}
        _ => tokio::time::sleep(Duration::from_nanos(duration_ns as u64)).await,
    }
}

#[cfg(windows)]
mod windows_timer {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        CreateWaitableTimerExW, SetWaitableTimer, WaitForSingleObject,
        CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, INFINITE, TIMER_ALL_ACCESS,
    };

    /// Create a one-shot high-resolution waitable timer, arm it for `duration_ns`,
    /// and block until it fires. Returns `Err(())` on any failure so the async
    /// wrapper can fall back to `tokio::time`.
    pub fn high_res_sleep(duration_ns: i64) -> Result<(), ()> {
        unsafe {
            let h = CreateWaitableTimerExW(
                std::ptr::null(),
                std::ptr::null(),
                CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                TIMER_ALL_ACCESS,
            );
            if h.is_null() {
                return Err(());
            }
            // Relative due time in 100 ns units; negative = relative to now.
            let due: i64 = -((duration_ns / 100).max(1));
            if SetWaitableTimer(h, &due, 0, None, std::ptr::null(), 0) == 0 {
                CloseHandle(h);
                return Err(());
            }
            let w = WaitForSingleObject(h, INFINITE);
            CloseHandle(h);
            if w == WAIT_OBJECT_0 {
                Ok(())
            } else {
                Err(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Other platforms: coarse fallback
// ---------------------------------------------------------------------------

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub async fn sleep_ns(duration_ns: i64) {
    if duration_ns <= 0 {
        tokio::task::yield_now().await;
    } else {
        tokio::time::sleep(Duration::from_nanos(duration_ns as u64)).await;
    }
}
