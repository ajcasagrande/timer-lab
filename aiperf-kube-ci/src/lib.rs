// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Isolated native-platform proof for byte-exact AIPerf credential sources.

mod credential_process;
#[cfg(unix)]
mod credential_terminal;
#[cfg(windows)]
mod credential_windows;

// Only process-setup signatures are stubbed. Windows production arms are no-ops;
// Unix parent-death/signal setup is outside this isolated fixture's proof scope.
mod delegate {
    pub(crate) fn unblock_signals_in_child(_: &mut std::process::Command) {}
    pub(crate) fn set_parent_death_signal(_: &mut std::process::Command) {}
}

#[cfg(all(test, unix))]
mod native_executable {
    pub(crate) fn binary(path: &str) -> String {
        path.to_owned()
    }
}

// Compile the actual public PTY fixture on Unix, but do not execute its CLI tests:
// this standalone crate deliberately contains no AIPerf executable.
#[cfg(all(test, unix))]
mod kube_credential_recovery;

fn assert_send(authority: &credential_process::Authority, config: kube::Config) {
    fn require_send(_: impl std::future::Future + Send) {}
    require_send(authority.prepare(config));
}
