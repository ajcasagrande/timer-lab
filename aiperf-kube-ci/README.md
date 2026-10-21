# AIP-3141 credential portability proof

Isolated native-platform testing for [AIPerf PR #1133](https://github.com/NVIDIA-dev/aiperf-rs/pull/1133).

The four credential/provider/PTY source files are copied byte-for-byte from the
AIPerf repair revision recorded in `source-manifest.json`. SHA256 checks run before
test selection. The fixture's Git attributes force LF source checkout on Windows
as well as Unix, preserving those byte identities under `core.autocrlf`.
The fixture pins direct dependency versions to the production
lockfile and has its own locked transitive dependency graph.

The matrix compiles the exact production modules and Unix public PTY test source,
requires the provider future to be `Send`, lints test configurations, and executes
a nonempty exact set of existing platform unit tests. Unix tests cover provider
output/identity validation, independent pipe bounds, exit observation without
reaping, and descendant pipe-holder cleanup. Windows tests cover environment and
executable resolution plus suspended-child Job Object ownership/termination.

The public CLI PTY tests are **compile-checked only**, not executed: this fixture
does not contain an AIPerf binary. Its placeholder executable path must never run.
The helper stubs supply only delegate process-setup signatures; Unix parent-death
and child signal-mask setup are not established by this isolated proof. Windows
production delegate arms are already no-ops.

This is not a full CLI/workspace test, real Kubernetes/identity-provider test, or
performance benchmark. Existing timer-lab code and default-branch workflows are
unchanged. The fixture lives on a dedicated CI branch only.
