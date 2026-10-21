// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Owned credential providers: fixed execution authority and cancellable children.

use anyhow::{Context as _, Result, ensure};
use chrono::{DateTime, Utc};
use kube::{
    Config,
    config::{ExecConfig, ExecInteractiveMode},
};
use std::{collections::BTreeMap, ffi::OsString, path::PathBuf, process::Stdio};
use tokio::io::{AsyncRead, AsyncReadExt as _};

const OUTPUT_BOUND: u64 = 1024 * 1024;

/// Secret-bearing execution authority, captured before client buffering.
#[derive(Clone)]
pub(super) struct Authority {
    executable: Option<PathBuf>,
    arguments: Vec<OsString>,
    environment: BTreeMap<OsString, OsString>,
    directory: PathBuf,
    kind: Kind,
    interactive: bool,
    gate: std::sync::Arc<tokio::sync::Semaphore>,
}

#[derive(Clone)]
enum Kind {
    Exec(Box<ExecConfig>),
    Gcp,
}

fn invalid() -> anyhow::Error {
    anyhow::anyhow!("Kubernetes credential provider failed; credential output was withheld")
}

fn environment_value<'a>(
    environment: &'a BTreeMap<OsString, OsString>,
    name: &std::ffi::OsStr,
) -> Option<&'a OsString> {
    #[cfg(windows)]
    {
        environment.iter().find_map(|(key, value)| {
            super::credential_windows::same_env_key(key, name).then_some(value)
        })
    }
    #[cfg(not(windows))]
    {
        environment.get(name)
    }
}

fn remove_environment(environment: &mut BTreeMap<OsString, OsString>, name: &std::ffi::OsStr) {
    #[cfg(windows)]
    {
        if let Some(key) = environment
            .keys()
            .find(|key| super::credential_windows::same_env_key(key, name))
            .cloned()
        {
            environment.remove(&key);
        }
    }
    #[cfg(not(windows))]
    {
        environment.remove(name);
    }
}

fn set_environment(
    environment: &mut BTreeMap<OsString, OsString>,
    name: OsString,
    value: OsString,
) {
    remove_environment(environment, &name);
    environment.insert(name, value);
}

impl Authority {
    pub(super) fn capture(config: &Config) -> Result<Option<Self>> {
        let auth = &config.auth_info;
        let mut environment = BTreeMap::new();
        for (name, value) in std::env::vars_os() {
            set_environment(&mut environment, name, value);
        }
        #[cfg(windows)]
        let parent_path = environment_value(&environment, std::ffi::OsStr::new("PATH")).cloned();
        let directory = std::env::current_dir().map_err(|_| invalid())?;
        let (command, arguments, kind, interactive) = if let Some(provider) = &auth.auth_provider {
            if provider.name != "gcp" {
                return Ok(None);
            }
            let Some(command) = provider.config.get("cmd-path") else {
                return Ok(None);
            };
            for name in provider
                .config
                .get("cmd-drop-env")
                .map(String::as_str)
                .unwrap_or_default()
                .trim()
                .split(' ')
            {
                remove_environment(&mut environment, std::ffi::OsStr::new(name));
            }
            let arguments = provider
                .config
                .get("cmd-args")
                .map(String::as_str)
                .unwrap_or_default()
                .trim()
                .split(' ')
                .map(OsString::from)
                .collect();
            use std::io::IsTerminal as _;
            (
                command.clone(),
                arguments,
                Kind::Gcp,
                std::io::stdin().is_terminal(),
            )
        } else if auth.token.is_none()
            && auth.token_file.is_none()
            && !(auth.username.is_some() && auth.password.is_some())
        {
            let Some(exec) = &auth.exec else {
                return Ok(None);
            };
            use std::io::IsTerminal as _;
            let interactive = exec.interactive_mode != Some(ExecInteractiveMode::Never)
                && std::io::stdin().is_terminal();
            ensure!(
                exec.interactive_mode != Some(ExecInteractiveMode::Always) || interactive,
                "Kubernetes credential provider requires an interactive terminal"
            );
            for entry in exec.env.iter().flatten() {
                if let (Some(name), Some(value)) = (entry.get("name"), entry.get("value")) {
                    set_environment(&mut environment, name.into(), value.into());
                }
            }
            let mut spec = serde_json::json!({"interactive": interactive});
            if exec.provide_cluster_info {
                spec["cluster"] = serde_json::to_value(
                    exec.cluster
                        .as_ref()
                        .context("credential provider cluster information is unavailable")?,
                )
                .map_err(|_| invalid())?;
            }
            let info = serde_json::json!({"apiVersion":exec.api_version,"kind":"ExecCredential","spec":spec});
            set_environment(
                &mut environment,
                "KUBERNETES_EXEC_INFO".into(),
                serde_json::to_string(&info).map_err(|_| invalid())?.into(),
            );
            for name in exec.drop_env.iter().flatten() {
                remove_environment(&mut environment, std::ffi::OsStr::new(name));
            }
            (
                exec.command
                    .clone()
                    .context("Kubernetes credential provider has no command")?,
                exec.args.iter().flatten().map(OsString::from).collect(),
                Kind::Exec(Box::new(exec.clone())),
                interactive,
            )
        } else {
            return Ok(None);
        };
        let command = PathBuf::from(command);
        #[cfg(windows)]
        let executable = super::credential_windows::resolve_executable(
            &command,
            &directory,
            environment_value(&environment, std::ffi::OsStr::new("PATH")),
            parent_path.as_ref(),
        )
        .unwrap_or_default();
        #[cfg(not(windows))]
        let executable = if command.components().count() > 1 || command.is_absolute() {
            Some(if command.is_absolute() {
                command
            } else {
                directory.join(command)
            })
        } else {
            let search = environment_value(&environment, std::ffi::OsStr::new("PATH"))
                .cloned()
                .unwrap_or_else(|| OsString::from("/bin:/usr/bin"));
            std::env::split_paths(&search)
                .map(|entry| {
                    let entry = if entry.is_absolute() {
                        entry
                    } else {
                        directory.join(entry)
                    };
                    entry.join(&command)
                })
                .find(|path| {
                    let Ok(metadata) = path.metadata() else {
                        return false;
                    };
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt as _;
                        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                    }
                    #[cfg(not(unix))]
                    {
                        metadata.is_file()
                    }
                })
        };
        Ok(Some(Self {
            executable,
            arguments,
            environment,
            directory,
            kind,
            interactive,
            gate: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
        }))
    }

    /// Resolve credentials before a first request, including mutations; no replay.
    pub(super) async fn prepare(
        &self,
        mut config: Config,
    ) -> Result<(Config, Option<DateTime<Utc>>)> {
        let (token, certificate, key, expiration) = match &self.kind {
            Kind::Exec(exec) => {
                let output = self.run().await?;
                let response: serde_json::Value =
                    serde_json::from_slice(&output).map_err(|_| invalid())?;
                ensure!(
                    response["kind"] == "ExecCredential"
                        && response["apiVersion"].as_str() == exec.api_version.as_deref(),
                    "Kubernetes credential provider returned an invalid envelope"
                );
                let status = &response["status"];
                fn field(value: &serde_json::Value, name: &str) -> Result<Option<String>> {
                    value
                        .get(name)
                        .filter(|value| !value.is_null())
                        .map(|value| {
                            value
                                .as_str()
                                .filter(|text| !text.is_empty())
                                .map(str::to_owned)
                                .ok_or_else(invalid)
                        })
                        .transpose()
                }
                let expiration = field(status, "expirationTimestamp")?
                    .map(|value| value.parse::<DateTime<Utc>>().map_err(|_| invalid()))
                    .transpose()?;
                (
                    field(status, "token")?,
                    field(status, "clientCertificateData")?,
                    field(status, "clientKeyData")?,
                    expiration,
                )
            }
            Kind::Gcp => {
                let provider = config
                    .auth_info
                    .auth_provider
                    .as_ref()
                    .ok_or_else(invalid)?;
                if let Some(token) = provider.config.get("id-token") {
                    (Some(token.clone()), None, None, None)
                } else {
                    let expiration = provider
                        .config
                        .get("expiry")
                        .map(|value| value.parse::<DateTime<Utc>>().map_err(|_| invalid()))
                        .transpose()?;
                    if let Some(token) = provider.config.get("access-token").filter(|_| {
                        expiration
                            .is_some_and(|time| time > Utc::now() + chrono::Duration::seconds(60))
                    }) {
                        (Some(token.clone()), None, None, expiration)
                    } else {
                        let output = self.run().await?;
                        if let Some(path) = provider.config.get("token-key") {
                            let json: serde_json::Value =
                                serde_json::from_slice(&output).map_err(|_| invalid())?;
                            let token = extract(&json, path)?;
                            let expiration = provider
                                .config
                                .get("expiry-key")
                                .map(|path| {
                                    extract(&json, path)?
                                        .parse::<DateTime<Utc>>()
                                        .map_err(|_| invalid())
                                })
                                .transpose()?;
                            (Some(token), None, None, expiration)
                        } else {
                            (
                                Some(String::from_utf8(output).map_err(|_| invalid())?),
                                None,
                                None,
                                None,
                            )
                        }
                    }
                }
            }
        };
        ensure!(
            expiration.is_none_or(|time| time > Utc::now()),
            "Kubernetes credential provider returned expired credentials"
        );
        ensure!(
            certificate.is_some() == key.is_some(),
            "Kubernetes credential provider returned an incomplete identity"
        );
        ensure!(
            token.is_some() || certificate.is_some(),
            "Kubernetes credential provider returned no credentials"
        );
        config.auth_info.exec = None;
        config.auth_info.auth_provider = None;
        config.auth_info.token = token.map(Into::into);
        config.auth_info.token_file = None;
        if let (Some(certificate), Some(mut key)) = (certificate, key) {
            use base64::Engine as _;
            // The ordinary SDK identity loader concatenates key and certificate.
            if !key.ends_with('\n') {
                key.push('\n');
            }
            config.auth_info.client_certificate = None;
            config.auth_info.client_key = None;
            config.auth_info.client_certificate_data =
                Some(base64::engine::general_purpose::STANDARD.encode(certificate));
            config.auth_info.client_key_data =
                Some(base64::engine::general_purpose::STANDARD.encode(key).into());
        }
        Ok((config, expiration))
    }

    async fn run(&self) -> Result<Vec<u8>> {
        let _permit = tokio::select! {
            permit = self.gate.clone().acquire_owned() => permit.map_err(|_| invalid())?,
            _ = tokio::signal::ctrl_c() => return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Kubernetes credential provider cancelled").into()),
        };
        let executable = self.executable.as_ref().context(
            "Kubernetes credential provider executable was unavailable at selection time",
        )?;
        let mut command = tokio::process::Command::new(executable);
        command
            .args(&self.arguments)
            .env_clear()
            .envs(&self.environment)
            .current_dir(&self.directory)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        crate::delegate::unblock_signals_in_child(command.as_std_mut());
        crate::delegate::set_parent_death_signal(command.as_std_mut());
        #[cfg(unix)]
        let terminal = if self.interactive {
            Some(super::credential_terminal::Terminal::attach(&mut command)?)
        } else {
            command.process_group(0);
            None
        };
        #[cfg(windows)]
        let _console = if self.interactive {
            command.stdin(Stdio::inherit());
            Some(super::credential_windows::Console::capture()?)
        } else {
            None
        };
        #[cfg(windows)]
        command.creation_flags(windows_sys::Win32::System::Threading::CREATE_SUSPENDED);
        #[cfg(unix)]
        let mut exits = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child())
            .map_err(|_| invalid())?;
        let mut child = command.spawn().map_err(|_| invalid())?;
        drop(command);
        #[cfg(windows)]
        let job = match super::credential_windows::Job::attach(&child) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err(error);
            }
        };
        let group = Group {
            #[cfg(unix)]
            pid: child
                .id()
                .context("credential child has no process identity")?,
            #[cfg(windows)]
            job,
            killed: std::sync::atomic::AtomicBool::new(false),
        };
        let stdout = child.stdout.take().ok_or_else(invalid)?;
        let mut stderr = child.stderr.take().ok_or_else(invalid)?;
        let diagnostics = async {
            let mut total = 0_u64;
            let mut bytes = [0_u8; 4096];
            loop {
                let count = stderr.read(&mut bytes).await.map_err(|_| invalid())?;
                if count == 0 {
                    return Ok::<_, anyhow::Error>(());
                }
                total += count as u64;
                ensure!(
                    total <= OUTPUT_BOUND,
                    "Kubernetes credential provider output exceeded its bound"
                );
                if self.interactive {
                    #[cfg(unix)]
                    terminal
                        .as_ref()
                        .ok_or_else(invalid)?
                        .write_diagnostics(&bytes[..count])
                        .await?;
                    #[cfg(not(unix))]
                    {
                        use tokio::io::AsyncWriteExt as _;
                        tokio::io::stderr()
                            .write_all(&bytes[..count])
                            .await
                            .map_err(|_| invalid())?;
                    }
                }
            }
        };
        let output = {
            let transfer = async {
                tokio::try_join!(
                    async {
                        #[cfg(unix)]
                        {
                            observe_exit(group.pid, &mut exits).await?;
                            // The unreaped child still pins its process-group identity.
                            group.kill();
                        }
                        let status = child.wait().await.map_err(|_| invalid())?;
                        #[cfg(windows)]
                        group.kill();
                        Ok::<_, anyhow::Error>(status)
                    },
                    bounded(stdout),
                    diagnostics
                )
            };
            #[cfg(unix)]
            let terminal_io = async {
                match &terminal {
                    Some(terminal) => terminal.pump().await,
                    None => std::future::pending().await,
                }
            };
            #[cfg(not(unix))]
            let terminal_io = std::future::pending::<Result<()>>();
            tokio::select! {
                result = transfer => result,
                _ = tokio::signal::ctrl_c() => Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Kubernetes credential provider cancelled").into()),
                _ = terminal_io => Err(invalid()),
            }
        };
        group.kill();
        if output.is_err() {
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
        let (status, stdout, _) = output?;
        ensure!(
            status.success(),
            "Kubernetes credential provider failed; credential output was withheld"
        );
        Ok(stdout)
    }
}

#[cfg(unix)]
async fn observe_exit(pid: u32, exits: &mut tokio::signal::unix::Signal) -> Result<()> {
    loop {
        // Apple's siginfo_t holds a raw pointer, so the WNOWAIT probe stays in
        // synchronous scope and never crosses the signal wait below.
        let exited = {
            // SAFETY: waitid initializes this owned siginfo; zero preserves si_pid=0
            // on kernels that leave it untouched when WNOHANG has no exit to report.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result != 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(invalid());
            }
            // SAFETY: successful waitid reports the child identity in siginfo.
            (unsafe { info.si_pid() }) == pid as libc::pid_t
        };
        if exited {
            return Ok(());
        }
        exits.recv().await.ok_or_else(invalid)?;
    }
}

async fn bounded(reader: impl AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(OUTPUT_BOUND + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| invalid())?;
    ensure!(
        bytes.len() as u64 <= OUTPUT_BOUND,
        "Kubernetes credential provider output exceeded its bound"
    );
    Ok(bytes)
}

fn extract(json: &serde_json::Value, path: &str) -> Result<String> {
    let path = path
        .trim_matches(['"', '{', '}'])
        .parse::<jsonpath_rust::JsonPath>()
        .map_err(|_| invalid())?;
    path.find_slice(json)
        .into_iter()
        .next()
        .and_then(|value| value.to_data().as_str().map(str::to_owned))
        .ok_or_else(invalid)
}

struct Group {
    #[cfg(unix)]
    pid: u32,
    #[cfg(windows)]
    job: super::credential_windows::Job,
    killed: std::sync::atomic::AtomicBool,
}
impl Group {
    fn kill(&self) {
        if self.killed.swap(true, std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        #[cfg(unix)]
        // SAFETY: this group was created solely for this owned provider child.
        unsafe {
            libc::kill(-(self.pid as libc::pid_t), libc::SIGKILL);
        }
        #[cfg(windows)]
        self.job.kill();
    }
}
impl Drop for Group {
    fn drop(&mut self) {
        self.kill();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn exec(script: &str) -> (Config, Authority) {
        let mut config = Config::new("http://127.0.0.1:1234".parse().unwrap());
        config.auth_info.exec = Some(serde_json::from_value(serde_json::json!({
            "command":"/bin/sh", "args":["-c", script], "apiVersion":"client.authentication.k8s.io/v1", "interactiveMode":"Never"
        })).unwrap());
        let authority = Authority::capture(&config).unwrap().unwrap();
        (config, authority)
    }

    /// The kube client requires `Send` service futures; Apple's `siginfo_t`
    /// holds a raw pointer, so a `prepare` future that lets one cross an await
    /// only fails to compile on macOS.
    #[test]
    fn prepare_future_is_send() {
        fn assert_send<T: Send>(_: T) {}
        let (config, authority) = exec("true");
        assert_send(authority.prepare(config));
    }

    #[tokio::test]
    async fn exit_observation_keeps_the_child_waitable_until_group_cleanup() {
        let mut exits =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::child()).unwrap();
        let mut child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "exit 7"])
            .process_group(0)
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let group = Group {
            pid: child.id().unwrap(),
            killed: std::sync::atomic::AtomicBool::new(false),
        };
        for _ in 0..2 {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                observe_exit(group.pid, &mut exits),
            )
            .await
            .unwrap()
            .unwrap();
        }
        // A second WNOWAIT observation would fail with ECHILD if the first reaped.
        group.kill();
        assert_eq!(child.wait().await.unwrap().code(), Some(7));
        assert!(observe_exit(group.pid, &mut exits).await.is_err());
    }

    #[tokio::test]
    async fn successful_provider_exit_kills_descendants_holding_output_pipes() {
        let (_, authority) = exec("sleep 60 & printf 'provider-result'");
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(5), authority.run())
                .await
                .unwrap()
                .unwrap(),
            b"provider-result"
        );
    }

    #[tokio::test]
    async fn owned_exec_decodes_credentials_without_retaining_sdk_command() {
        let (config, authority) = exec(
            "printf '%s' '{\"apiVersion\":\"client.authentication.k8s.io/v1\",\"kind\":\"ExecCredential\",\"status\":{\"token\":\"private-token\"}}'",
        );
        let (prepared, expiration) = authority.prepare(config).await.unwrap();
        assert!(prepared.auth_info.exec.is_none());
        assert!(prepared.auth_info.token.is_some());
        assert!(expiration.is_none());
    }

    #[tokio::test]
    async fn nullable_fields_and_identity_pem_separator_match_sdk() {
        use base64::Engine as _;
        let (config, authority) = exec(
            "printf '%s' '{\"apiVersion\":\"client.authentication.k8s.io/v1\",\"kind\":\"ExecCredential\",\"status\":{\"token\":\"private-token\",\"expirationTimestamp\":null,\"clientCertificateData\":null,\"clientKeyData\":null}}'",
        );
        assert!(authority.prepare(config).await.is_ok());
        let (config, authority) = exec(
            "printf '%s' '{\"apiVersion\":\"client.authentication.k8s.io/v1\",\"kind\":\"ExecCredential\",\"status\":{\"token\":null,\"expirationTimestamp\":null,\"clientCertificateData\":\"certificate\",\"clientKeyData\":\"key-without-newline\"}}'",
        );
        let (config, _) = authority.prepare(config).await.unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(
                    serde_json::to_value(config.auth_info).unwrap()["client-key-data"]
                        .as_str()
                        .unwrap()
                )
                .unwrap(),
            b"key-without-newline\n"
        );
    }

    #[tokio::test]
    async fn provider_errors_do_not_reflect_output_and_reject_invalid_identities() {
        for script in [
            "printf 'private-token'; printf 'private-error' >&2; exit 1",
            "printf 'private-invalid-json'",
            "printf '%s' '{\"apiVersion\":\"wrong\",\"kind\":\"ExecCredential\",\"status\":{\"token\":\"private-token\"}}'",
            "printf '%s' '{\"apiVersion\":\"client.authentication.k8s.io/v1\",\"kind\":\"ExecCredential\",\"status\":{\"clientKeyData\":\"private-key\"}}'",
            "printf '%s' '{\"apiVersion\":\"client.authentication.k8s.io/v1\",\"kind\":\"ExecCredential\",\"status\":{\"token\":\"private-token\",\"expirationTimestamp\":\"2000-01-01T00:00:00Z\"}}'",
        ] {
            let (config, authority) = exec(script);
            let error = authority.prepare(config).await.err().unwrap();
            assert!(!format!("{error:#}").contains("private-"));
        }
    }

    #[tokio::test]
    async fn both_provider_pipes_are_drained_and_independently_bounded() {
        let (_, authority) = exec("head -c 1048576 /dev/zero >&2; head -c 1048576 /dev/zero");
        assert_eq!(authority.run().await.unwrap().len(), OUTPUT_BOUND as usize);
        let (_, authority) = exec("head -c 1048577 /dev/zero >&2; sleep 60");
        assert!(authority.run().await.is_err());
    }

    #[test]
    fn gcp_jsonpath_matches_sdk_brace_and_quote_semantics() {
        let value = serde_json::json!({"credential":{"access_token":"private-token"}});
        assert_eq!(
            extract(&value, "{.credential.access_token}").unwrap(),
            "private-token"
        );
        assert!(extract(&value, "{.missing}").is_err());
    }
}
