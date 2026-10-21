// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Private controlling terminal for an owned interactive credential process group.

use anyhow::{Context as _, Result};
use std::{
    fs::File,
    io::{Read as _, Write as _},
    os::fd::{AsRawFd as _, FromRawFd as _},
    process::Stdio,
};
use tokio::io::unix::AsyncFd;

/// Preserve the caller's foreground group so Ctrl+C can kill even an ignoring child.
pub(super) struct Terminal {
    caller: AsyncFd<File>,
    master: AsyncFd<File>,
    saved: libc::termios,
}

impl Terminal {
    pub(super) fn attach(command: &mut tokio::process::Command) -> Result<Self> {
        use std::os::unix::{fs::OpenOptionsExt as _, process::CommandExt as _};
        let caller = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NONBLOCK)
            .open("/dev/tty")
            .context("open credential interaction terminal")?;
        // SAFETY: all pointers address initialized, exclusively owned stack storage.
        let mut saved = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(caller.as_raw_fd(), &mut saved) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("read credential terminal settings");
        }
        let mut size = unsafe { std::mem::zeroed::<libc::winsize>() };
        if unsafe { libc::ioctl(caller.as_raw_fd(), libc::TIOCGWINSZ, &mut size) } != 0 {
            return Err(std::io::Error::last_os_error()).context("read credential terminal size");
        }
        let (mut master, mut slave) = (-1, -1);
        // BSD (macOS) openpty takes mutable termios/winsize pointers; *mut
        // coerces to *const under the Linux signature.
        if unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                &raw mut saved,
                &raw mut size,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error()).context("allocate credential terminal");
        }
        // SAFETY: openpty returned two fresh descriptors, each adopted exactly once.
        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        for file in [&master, &slave] {
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
                return Err(std::io::Error::last_os_error())
                    .context("protect credential terminal descriptor");
            }
        }
        if unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } == -1 {
            return Err(std::io::Error::last_os_error()).context("configure credential terminal");
        }
        command.stdin(Stdio::from(slave));
        // SAFETY: only async-signal-safe session/terminal syscalls run after fork.
        unsafe {
            command.as_std_mut().pre_exec(|| {
                // libc's ioctl request type tracks the platform: TIOCSCTTY is
                // c_uint on Apple but c_ulong under glibc.
                if libc::setsid() == -1
                    || libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) == -1
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let terminal = Self {
            caller: AsyncFd::new(caller)?,
            master: AsyncFd::new(master)?,
            saved,
        };
        let mut relay = saved;
        // Keep ISIG: the caller retains Ctrl+C, rather than trusting the provider
        // to honor SIGINT. Echo/canonical handling belongs to the private PTY.
        relay.c_lflag &= !(libc::ICANON | libc::ECHO | libc::IEXTEN);
        relay.c_iflag &= !(libc::IXON | libc::ICRNL);
        relay.c_oflag &= !libc::OPOST;
        relay.c_cc[libc::VMIN] = 1;
        relay.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(terminal.caller.get_ref().as_raw_fd(), libc::TCSANOW, &relay) }
            != 0
        {
            return Err(std::io::Error::last_os_error())
                .context("prepare credential terminal relay");
        }
        Ok(terminal)
    }

    pub(super) async fn write_diagnostics(&self, bytes: &[u8]) -> Result<()> {
        write(&self.caller, bytes).await
    }

    pub(super) async fn pump(&self) -> Result<()> {
        async fn relay(input: &AsyncFd<File>, output: &AsyncFd<File>) -> Result<()> {
            let mut bytes = [0_u8; 4096];
            loop {
                let count = loop {
                    let mut ready = input.readable().await?;
                    match ready.try_io(|file| file.get_ref().read(&mut bytes)) {
                        Ok(Ok(0)) => return std::future::pending().await,
                        Ok(Ok(count)) => break count,
                        Ok(Err(error)) if error.raw_os_error() == Some(libc::EIO) => {
                            return std::future::pending().await;
                        }
                        Ok(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted => {
                            continue;
                        }
                        Ok(Err(error)) => {
                            return Err(error).context("read credential interaction terminal");
                        }
                        Err(_) => continue,
                    }
                };
                write(output, &bytes[..count]).await?;
            }
        }
        tokio::try_join!(
            relay(&self.caller, &self.master),
            relay(&self.master, &self.caller)
        )?;
        Ok(())
    }
}

async fn write(output: &AsyncFd<File>, bytes: &[u8]) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let mut ready = output.writable().await?;
        match ready.try_io(|file| file.get_ref().write(&bytes[offset..])) {
            Ok(Ok(0)) => anyhow::bail!("credential interaction terminal closed"),
            Ok(Ok(written)) => offset += written,
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Ok(Err(error)) => return Err(error).context("write credential interaction terminal"),
            Err(_) => continue,
        }
    }
    Ok(())
}

impl Drop for Terminal {
    fn drop(&mut self) {
        // SAFETY: the descriptor and saved terminal state are owned by this guard.
        unsafe {
            libc::tcsetattr(
                self.caller.get_ref().as_raw_fd(),
                libc::TCSANOW,
                &self.saved,
            );
        }
    }
}
