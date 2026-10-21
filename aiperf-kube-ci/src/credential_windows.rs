// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows credential children enter a kill-on-close job before their first instruction.

use anyhow::{Context as _, Result, ensure};
use std::{
    fs::File,
    os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_NO_MORE_FILES, GetLastError, INVALID_HANDLE_VALUE},
    System::{
        Console::{GetConsoleMode, SetConsoleMode},
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
        },
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject, TerminateJobObject,
        },
        Threading::{
            GetProcessIdOfThread, OpenThread, ResumeThread, THREAD_QUERY_LIMITED_INFORMATION,
            THREAD_SUSPEND_RESUME,
        },
    },
};

/// Windows environment names use case-insensitive ordinal comparison.
pub(super) fn same_env_key(left: &std::ffi::OsStr, right: &std::ffi::OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
    let left: Vec<_> = left.encode_wide().collect();
    let right: Vec<_> = right.encode_wide().collect();
    let (Ok(left_len), Ok(right_len)) = (i32::try_from(left.len()), i32::try_from(right.len()))
    else {
        return false;
    };
    // SAFETY: both buffers stay valid for their explicit lengths.
    unsafe {
        CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) == CSTR_EQUAL
    }
}

fn error() -> anyhow::Error {
    anyhow::anyhow!("Windows credential process ownership could not be established")
}

/// Freeze the same application/system/PATH search tiers as Windows Command.
pub(super) fn resolve_executable(
    command: &std::path::Path,
    directory: &std::path::Path,
    child_path: Option<&std::ffi::OsString>,
    parent_path: Option<&std::ffi::OsString>,
) -> Result<Option<std::path::PathBuf>> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt as _, path::PathBuf};
    use windows_sys::Win32::System::SystemInformation::{
        GetSystemDirectoryW, GetWindowsDirectoryW,
    };
    fn append_exe(path: &std::path::Path) -> PathBuf {
        let mut value = path.as_os_str().to_owned();
        value.push(".exe");
        PathBuf::from(value)
    }
    if command.components().count() > 1 || command.is_absolute() {
        let path = std::path::absolute(directory.join(command))
            .context("resolve explicit Windows credential executable")?;
        if !path
            .extension()
            .is_some_and(|extension| same_env_key(extension, "exe".as_ref()))
        {
            let appended = append_exe(&path);
            if appended.is_file() {
                return Ok(Some(appended));
            }
        }
        return Ok(Some(path));
    }
    fn system_directory(query: unsafe extern "system" fn(*mut u16, u32) -> u32) -> Result<PathBuf> {
        let mut buffer = vec![0_u16; 260];
        loop {
            // SAFETY: the API writes at most the supplied capacity to this owned buffer.
            let length = unsafe { query(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
            ensure!(
                length > 0 && length <= 32768,
                "Windows credential executable search directory is unavailable"
            );
            if length < buffer.len() {
                return Ok(PathBuf::from(OsString::from_wide(&buffer[..length])));
            }
            buffer.resize(length + 1, 0);
        }
    }
    fn extend_path(
        directories: &mut Vec<PathBuf>,
        path: Option<&OsString>,
        directory: &std::path::Path,
    ) {
        if let Some(path) = path {
            directories.extend(
                std::env::split_paths(path)
                    .filter(|entry| !entry.as_os_str().is_empty())
                    .map(|entry| {
                        if entry.is_absolute() {
                            entry
                        } else {
                            directory.join(entry)
                        }
                    }),
            );
        }
    }
    let mut directories = Vec::new();
    extend_path(&mut directories, child_path, directory);
    if let Some(parent) = std::env::current_exe()
        .context("capture Windows credential executable directory")?
        .parent()
    {
        directories.push(parent.to_owned());
    }
    directories.push(system_directory(GetSystemDirectoryW)?);
    directories.push(system_directory(GetWindowsDirectoryW)?);
    extend_path(&mut directories, parent_path, directory);
    use std::os::windows::ffi::OsStrExt as _;
    let filename = if command
        .as_os_str()
        .encode_wide()
        .any(|unit| unit == u16::from(b'.'))
    {
        command.to_owned()
    } else {
        append_exe(command)
    };
    Ok(directories
        .into_iter()
        .map(|entry| entry.join(&filename))
        .find(|path| path.is_file()))
}

/// Own the entire provider process tree; the handle is never inherited.
pub(super) struct Job(OwnedHandle);

impl Job {
    /// The child must have been spawned with CREATE_SUSPENDED.
    pub(super) fn attach(child: &tokio::process::Child) -> Result<Self> {
        let pid = child.id().ok_or_else(error)?;
        let process = child.raw_handle().ok_or_else(error)?;
        // SAFETY: null attributes create a non-inheritable unnamed job.
        let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        ensure!(
            !raw.is_null(),
            "Windows credential job could not be created"
        );
        // SAFETY: this newly created valid handle is adopted exactly once.
        let job = Self(unsafe { OwnedHandle::from_raw_handle(raw) });
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: the owned handle and typed input buffer remain valid throughout each call.
        ensure!(
            unsafe {
                SetInformationJobObject(
                    job.0.as_raw_handle(),
                    JobObjectExtendedLimitInformation,
                    ptr::from_ref(&limits).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            } != 0,
            "Windows credential job policy could not be established"
        );
        ensure!(
            unsafe { AssignProcessToJobObject(job.0.as_raw_handle(), process) } != 0,
            "Windows credential child could not enter its owned job"
        );
        // Tokio exposes the process handle, not the startup thread handle. A
        // suspended process cannot create further threads or children yet.
        let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        ensure!(
            raw != INVALID_HANDLE_VALUE,
            "Windows credential startup threads are unavailable"
        );
        let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let mut available = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) } != 0;
        let mut thread_id = None;
        while available {
            if entry.th32OwnerProcessID == pid {
                ensure!(
                    thread_id.is_none(),
                    "Windows credential startup thread is ambiguous"
                );
                thread_id = Some(entry.th32ThreadID);
            }
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            available = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) } != 0;
        }
        ensure!(
            unsafe { GetLastError() } == ERROR_NO_MORE_FILES,
            "Windows credential startup thread inventory is incomplete"
        );
        let thread_id = thread_id.ok_or_else(error)?;
        let raw = unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                0,
                thread_id,
            )
        };
        ensure!(
            !raw.is_null(),
            "Windows credential startup thread could not be opened"
        );
        let thread = unsafe { OwnedHandle::from_raw_handle(raw) };
        ensure!(
            unsafe { GetProcessIdOfThread(thread.as_raw_handle()) } == pid,
            "Windows credential startup thread changed owner"
        );
        ensure!(
            unsafe { ResumeThread(thread.as_raw_handle()) } == 1,
            "Windows credential startup thread could not be resumed"
        );
        Ok(job)
    }

    pub(super) fn kill(&self) {
        // SAFETY: the job handle is owned and remains valid until its RAII close.
        unsafe {
            TerminateJobObject(self.0.as_raw_handle(), 1);
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Restore console echo/input settings even if the provider is forcibly stopped.
pub(super) struct Console {
    input: File,
    mode: u32,
}

impl Console {
    pub(super) fn capture() -> Result<Self> {
        let input = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("CONIN$")
            .context("open Windows credential interaction console")?;
        let mut mode = 0;
        // SAFETY: the owned console handle and mode output remain valid.
        ensure!(
            unsafe { GetConsoleMode(input.as_raw_handle(), &mut mode) } != 0,
            "Windows credential console mode is unavailable"
        );
        Ok(Self { input, mode })
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        // SAFETY: the guard owns the console handle and its captured mode.
        unsafe {
            SetConsoleMode(self.input.as_raw_handle(), self.mode);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{process::Stdio, time::Duration};
    use tokio::io::AsyncReadExt as _;

    #[test]
    fn environment_names_follow_windows_ordinal_case_rules() {
        assert!(same_env_key("Path".as_ref(), "PATH".as_ref()));
        assert!(same_env_key("Auth_Key".as_ref(), "AUTH_KEY".as_ref()));
        assert!(!same_env_key(
            "Auth_Key".as_ref(),
            "AUTH_KEY_OTHER".as_ref()
        ));
    }

    #[test]
    fn executable_resolution_freezes_windows_search_tiers_and_extensions() {
        use std::path::Path;
        let child = tempfile::tempdir().unwrap();
        let parent = tempfile::tempdir().unwrap();
        let name = format!("aiperf-credential-search-{}", std::process::id());
        let child_path = child.path().as_os_str().to_owned();
        let parent_path = parent.path().as_os_str().to_owned();
        std::fs::write(child.path().join(&name), b"not an exe").unwrap();
        assert!(
            resolve_executable(Path::new(&name), child.path(), Some(&child_path), None)
                .unwrap()
                .is_none()
        );
        let child_exe = child.path().join(format!("{name}.exe"));
        let parent_exe = parent.path().join(format!("{name}.exe"));
        std::fs::write(&child_exe, b"fixture").unwrap();
        std::fs::write(&parent_exe, b"fixture").unwrap();
        assert_eq!(
            resolve_executable(
                Path::new(&name),
                child.path(),
                Some(&child_path),
                Some(&parent_path)
            )
            .unwrap(),
            Some(child_exe)
        );
        assert_eq!(
            resolve_executable(Path::new(&name), child.path(), None, Some(&parent_path)).unwrap(),
            Some(parent_exe)
        );
        let dotted = child.path().join("provider.custom");
        let appended = child.path().join("provider.custom.exe");
        std::fs::write(&dotted, b"fixture").unwrap();
        std::fs::write(&appended, b"fixture").unwrap();
        assert_eq!(
            resolve_executable(
                Path::new("provider.custom"),
                child.path(),
                Some(&child_path),
                None
            )
            .unwrap(),
            Some(dotted)
        );
        assert_eq!(
            resolve_executable(Path::new(".\\provider.custom"), child.path(), None, None).unwrap(),
            Some(appended)
        );
        assert!(
            resolve_executable(Path::new("cmd"), child.path(), None, None)
                .unwrap()
                .unwrap()
                .ends_with("cmd.exe")
        );
    }

    #[tokio::test]
    async fn suspended_provider_job_owns_and_terminates_descendant_pipe_writers() {
        use windows_sys::Win32::System::Threading::CREATE_SUSPENDED;
        let mut child = tokio::process::Command::new("cmd.exe")
            .args(["/D", "/C", "ping -n 60 127.0.0.1"])
            .creation_flags(CREATE_SUSPENDED)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let job = match Job::attach(&child) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.kill().await;
                panic!("{error}");
            }
        };
        let mut stdout = child.stdout.take().unwrap();
        let mut first = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(15), stdout.read(&mut first))
                .await
                .unwrap()
                .unwrap(),
            1
        );
        job.kill();
        let status = tokio::time::timeout(Duration::from_secs(15), child.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(!status.success());
        // A surviving ping descendant would keep the inherited pipe open.
        let mut remainder = Vec::new();
        tokio::time::timeout(Duration::from_secs(15), stdout.read_to_end(&mut remainder))
            .await
            .unwrap()
            .unwrap();
    }
}
