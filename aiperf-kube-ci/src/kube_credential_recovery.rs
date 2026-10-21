// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Public native credential recovery over real HTTP and controlling terminals.
#![cfg(unix)]

use serde_json::{Value, json};
use std::{
    fs::File,
    io::{Read, Write},
    net::TcpListener,
    os::fd::{AsRawFd, FromRawFd},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

struct Cluster {
    directory: tempfile::TempDir,
    address: std::net::SocketAddr,
    requests: Arc<Mutex<Vec<(String, String)>>>,
    stop: Arc<AtomicBool>,
    server: Option<std::thread::JoinHandle<()>>,
}
impl Cluster {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (recording, stopping) = (requests.clone(), stop.clone());
        let server = std::thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0; 8192];
                let header = loop {
                    let count = stream.read(&mut buffer).unwrap_or(0);
                    if count == 0 {
                        break None;
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                    assert!(bytes.len() < 1024 * 1024);
                    if let Some(end) = bytes.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        break Some(String::from_utf8_lossy(&bytes[..end]).into_owned());
                    }
                };
                let Some(header) = header else {
                    continue;
                };
                let mut words = header.split_whitespace();
                let method = words.next().unwrap().to_owned();
                let path = words.next().unwrap().to_owned();
                let authorized = header.lines().any(|line| {
                    line.eq_ignore_ascii_case("authorization: Bearer fixture-fresh-token")
                });
                recording
                    .lock()
                    .unwrap()
                    .push((method.clone(), path.clone()));
                let (code, body) = if !authorized || method != "GET" {
                    (
                        401,
                        json!({"apiVersion":"v1","kind":"Status","code":401,"status":"Failure","reason":"Unauthorized","message":"private-api-auth-detail"}),
                    )
                } else {
                    (
                        200,
                        json!({"apiVersion":"v1","kind":"List","metadata":{"resourceVersion":"1"},"items":[]}),
                    )
                };
                let body = serde_json::to_vec(&body).unwrap();
                let _ = write!(
                    stream,
                    "HTTP/1.1 {code} Fixture\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(&body);
            }
        });
        let cluster = Self {
            directory: tempfile::tempdir().unwrap(),
            address,
            requests,
            stop,
            server: Some(server),
        };
        cluster.configure(json!({"token":"fixture-old-token"}), address);
        cluster
    }
    fn configure(&self, user: Value, address: std::net::SocketAddr) {
        let document = json!({"apiVersion":"v1","kind":"Config","current-context":"fixture", "clusters":[{"name":"fixture","cluster":{"server":format!("http://{address}")}}], "contexts":[{"name":"fixture","context":{"cluster":"fixture","user":"fixture","namespace":"bench"}}], "users":[{"name":"fixture","user":user}]});
        std::fs::write(self.directory.path().join("config"), document.to_string()).unwrap();
    }
    fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(crate::native_executable::binary(env!(
            "CARGO_BIN_EXE_aiperf"
        )));
        for (name, _) in std::env::vars_os() {
            if name.to_string_lossy().starts_with("AIPERF_") {
                command.env_remove(name);
            }
        }
        command
            .args(arguments)
            .env("KUBECONFIG", self.directory.path().join("config"))
            .env(
                "AIPERF_LAST_KUBE_BENCHMARK_PATH",
                self.directory.path().join("last.json"),
            )
            .env(
                "AIPERF_K8S_CREDENTIAL_RETRY_INITIAL_BACKOFF_SECONDS",
                "0.05",
            )
            .env("AIPERF_K8S_CREDENTIAL_RETRY_MAX_BACKOFF_SECONDS", "0.1")
            .env("NO_PROXY", "*")
            .env_remove("KUBERNETES_SERVICE_HOST")
            .env_remove("KUBERNETES_SERVICE_PORT");
        command
    }
}
impl Drop for Cluster {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.server.take().unwrap().join().unwrap();
    }
}

struct TerminalChild {
    child: Child,
    master: File,
    bytes: Arc<Mutex<Vec<u8>>>,
    reader: Option<std::thread::JoinHandle<()>>,
}
impl TerminalChild {
    fn spawn(mut command: Command) -> Self {
        use std::os::unix::process::CommandExt;
        let (mut master, mut slave) = (-1, -1);
        // SAFETY: both outputs point to valid descriptor storage.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        // SAFETY: each new descriptor is adopted once.
        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        for file in [&master, &slave] {
            assert_ne!(
                unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) },
                -1
            );
        }
        command
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave));
        // SAFETY: session and terminal setup only use async-signal-safe syscalls.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1
                    || libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) == -1
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        drop(command);
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let capture = bytes.clone();
        let mut stream = master.try_clone().unwrap();
        let reader = std::thread::spawn(move || {
            let mut buffer = [0; 8192];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        let mut bytes = capture.lock().unwrap();
                        assert!(bytes.len() + count < 4 * 1024 * 1024);
                        bytes.extend_from_slice(&buffer[..count]);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                    Err(error) => panic!("terminal read: {error}"),
                }
            }
        });
        Self {
            child,
            master,
            bytes,
            reader: Some(reader),
        }
    }
    fn wait_text(&mut self, expected: &str) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let text = String::from_utf8_lossy(&self.bytes.lock().unwrap()).into_owned();
            if text.contains(expected) {
                return;
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "native command exited before {expected}: {text}"
            );
            assert!(
                Instant::now() < deadline,
                "terminal did not show {expected}: {text}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn finish(&mut self) -> (ExitStatus, String) {
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "native credential command did not finish"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        self.reader.take().unwrap().join().unwrap();
        let text = String::from_utf8_lossy(&self.bytes.lock().unwrap()).into_owned();
        for secret in [
            "fixture-old-token",
            "fixture-fresh-token",
            "private-api-auth-detail",
        ] {
            assert!(!text.contains(secret), "credential detail reflected");
        }
        (status, text)
    }
}
impl Drop for TerminalChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn interactive_read_resumes_after_selected_token_rotation() {
    let cluster = Cluster::new();
    let mut child = TerminalChild::spawn(cluster.command(&["kube", "list", "-n", "bench"]));
    child.wait_text("refresh the selected credentials");
    cluster.configure(json!({"token":"fixture-fresh-token"}), cluster.address);
    let (status, text) = child.finish();
    assert!(status.success(), "{text}");
    assert!(text.contains("Kubernetes read resumed"), "{text}");
    let requests = cluster.requests.lock().unwrap();
    assert!(requests.len() >= 2);
    assert!(requests.iter().all(|(method, _)| method == "GET"));
}

#[test]
fn gcp_cached_credentials_do_not_require_an_unused_command() {
    for command in [
        "aiperf-fixture-missing-credential-command",
        "/aiperf-fixture-missing-credential-command",
    ] {
        for cached in [
            json!({"id-token":"fixture-fresh-token"}),
            json!({"access-token":"fixture-fresh-token","expiry":"2099-01-01T00:00:00Z"}),
        ] {
            let cluster = Cluster::new();
            let mut config = cached;
            config["cmd-path"] = json!(command);
            cluster.configure(
                json!({"auth-provider":{"name":"gcp","config":config}}),
                cluster.address,
            );
            let output = cluster
                .command(&["kube", "list", "-n", "bench"])
                .stdin(Stdio::null())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(!cluster.requests.lock().unwrap().is_empty());
        }
        let cluster = Cluster::new();
        cluster.configure(json!({"auth-provider":{"name":"gcp","config":{"cmd-path":command,"access-token":"fixture-old-token","expiry":"2000-01-01T00:00:00Z"}}}), cluster.address);
        let output = cluster
            .command(&["kube", "list", "-n", "bench"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(cluster.requests.lock().unwrap().is_empty());
    }
}

#[test]
fn noninteractive_read_does_not_wait_or_replay() {
    let cluster = Cluster::new();
    let output = cluster
        .command(&["kube", "list", "-n", "bench"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(cluster.requests.lock().unwrap().len(), 1);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-api-auth-detail"));
}

#[test]
fn interactive_mutation_401_is_never_replayed() {
    let cluster = Cluster::new();
    cluster.configure(json!({"token":"fixture-fresh-token"}), cluster.address);
    let mut child = TerminalChild::spawn(cluster.command(&[
        "kube",
        "cancel",
        "--job-id",
        "run",
        "--kind",
        "AIPerfJob",
        "-n",
        "bench",
    ]));
    let (status, text) = child.finish();
    assert!(!status.success(), "{text}");
    let requests = cluster.requests.lock().unwrap();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(requests[0].0, "PATCH");
    assert!(!text.contains("refresh the selected credentials"));
}

#[test]
fn interactive_recovery_cannot_follow_a_changed_server() {
    let cluster = Cluster::new();
    let foreign = Cluster::new();
    let mut child = TerminalChild::spawn(cluster.command(&["kube", "list", "-n", "bench"]));
    child.wait_text("refresh the selected credentials");
    cluster.configure(json!({"token":"fixture-fresh-token"}), foreign.address);
    let (status, text) = child.finish();
    assert!(!status.success(), "{text}");
    assert!(text.contains("authority changed"), "{text}");
    assert!(foreign.requests.lock().unwrap().is_empty());
}

#[test]
fn gcp_provider_can_read_its_controlling_terminal() {
    use std::os::unix::fs::PermissionsExt as _;
    let cluster = Cluster::new();
    let script = cluster.directory.path().join("provider.sh");
    std::fs::write(&script, "#!/bin/sh\nprintf 'gcp-provider-ready\\n' >/dev/tty\nread -r approval </dev/tty\ntest \"$approval\" = approved || exit 1\nprintf '%s' '{\"credential\":{\"access_token\":\"fixture-fresh-token\"}}'\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    cluster.configure(json!({"auth-provider":{"name":"gcp","config":{"cmd-path":script.to_str().unwrap(), "token-key":"{.credential.access_token}"}}}), cluster.address);
    let mut child = TerminalChild::spawn(cluster.command(&["kube", "list", "-n", "bench"]));
    child.wait_text("gcp-provider-ready");
    child.master.write_all(b"approved\n").unwrap();
    let (status, text) = child.finish();
    assert!(status.success(), "{text}");
    assert!(!cluster.requests.lock().unwrap().is_empty());
}

#[test]
fn owned_provider_can_read_its_controlling_terminal() {
    let cluster = Cluster::new();
    let script = "printf 'provider-ready\\n' >/dev/tty; read -r approval </dev/tty; test \"$approval\" = approved || exit 1; printf '%s' '{\"apiVersion\":\"client.authentication.k8s.io/v1\",\"kind\":\"ExecCredential\",\"status\":{\"token\":\"fixture-fresh-token\"}}'";
    cluster.configure(json!({"exec":{"command":"/bin/sh","args":["-c",script],"apiVersion":"client.authentication.k8s.io/v1","interactiveMode":"Always"}}), cluster.address);
    let mut child = TerminalChild::spawn(cluster.command(&["kube", "list", "-n", "bench"]));
    child.wait_text("provider-ready");
    child.master.write_all(b"approved\n").unwrap();
    let (status, text) = child.finish();
    assert!(status.success(), "{text}");
    assert!(!cluster.requests.lock().unwrap().is_empty());
}

#[test]
fn interactive_exec_and_gcp_stderr_challenges_are_visible_before_input() {
    use std::os::unix::fs::PermissionsExt as _;
    for gcp in [false, true] {
        let cluster = Cluster::new();
        let credential = if gcp {
            r#"{"credential":{"access_token":"fixture-fresh-token"}}"#
        } else {
            r#"{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"fixture-fresh-token"}}"#
        };
        let script = cluster.directory.path().join("stderr-provider.sh");
        std::fs::write(&script, format!("#!/bin/sh\nprintf 'stderr-device-code-challenge\\n' >&2\nread -r approval\ntest \"$approval\" = approved || exit 1\nprintf '%s' '{credential}'\n")).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let user = if gcp {
            json!({"auth-provider":{"name":"gcp","config":{"cmd-path":script.to_str().unwrap(),"token-key":"{.credential.access_token}"}}})
        } else {
            json!({"exec":{"command":script.to_str().unwrap(),"apiVersion":"client.authentication.k8s.io/v1","interactiveMode":"Always"}})
        };
        cluster.configure(user, cluster.address);
        let mut child = TerminalChild::spawn(cluster.command(&["kube", "list", "-n", "bench"]));
        child.wait_text("stderr-device-code-challenge");
        assert!(
            cluster.requests.lock().unwrap().is_empty(),
            "prompt must appear before API access/input"
        );
        child.master.write_all(b"approved\n").unwrap();
        let (status, text) = child.finish();
        assert!(status.success(), "{text}");
        assert!(
            !text.contains("fixture-fresh-token"),
            "credential stdout leaked: {text}"
        );
        assert!(!cluster.requests.lock().unwrap().is_empty());
    }
}

#[test]
fn interactive_provider_stderr_remains_bounded_and_cancellable() {
    let cluster = Cluster::new();
    let script = "head -c 1048577 /dev/zero >&2; sleep 60";
    cluster.configure(json!({"exec":{"command":"/bin/sh","args":["-c",script],"apiVersion":"client.authentication.k8s.io/v1","interactiveMode":"Always"}}), cluster.address);
    let mut child = TerminalChild::spawn(cluster.command(&["kube", "list", "-n", "bench"]));
    let (status, text) = child.finish();
    assert!(!status.success());
    assert!(
        text.contains(
            "Kubernetes credential provider failed or was cancelled; credential output was withheld"
        ),
        "missing redacted public provider failure"
    );
    assert!(cluster.requests.lock().unwrap().is_empty());
}

#[test]
fn ctrl_c_reaps_an_interactive_provider_that_ignores_sigint() {
    let cluster = Cluster::new();
    let pid = cluster.directory.path().join("provider.pid");
    let script = format!(
        "trap '' INT; printf '%s' $$ >'{}'; printf 'provider-waiting\\n' >/dev/tty; exec sleep 60",
        pid.display()
    );
    cluster.configure(json!({"exec":{"command":"/bin/sh","args":["-c",script],"apiVersion":"client.authentication.k8s.io/v1","interactiveMode":"Always"}}), cluster.address);
    let mut child = TerminalChild::spawn(cluster.command(&["kube", "list", "-n", "bench"]));
    child.wait_text("provider-waiting");
    let provider: i32 = std::fs::read_to_string(pid).unwrap().parse().unwrap();
    // The caller, not the provider's foreground group, owns cancellation.
    assert_eq!(
        unsafe { libc::kill(child.child.id() as i32, libc::SIGINT) },
        0
    );
    let (status, text) = child.finish();
    assert!(!status.success(), "{text}");
    assert_eq!(
        unsafe { libc::kill(provider, 0) },
        -1,
        "provider survived cancellation"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
    assert!(cluster.requests.lock().unwrap().is_empty());
}
