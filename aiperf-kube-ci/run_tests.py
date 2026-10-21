# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Verify source identity and run a nonempty exact native-platform test set."""

import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "Cargo.toml"
identity = json.loads((ROOT / "source-manifest.json").read_text())
for name, expected in identity["files"].items():
    actual = hashlib.sha256((ROOT / "src" / name).read_bytes()).hexdigest()
    if actual != expected["sha256"]:
        raise SystemExit(f"source identity mismatch: {name}")
print("AIPerf source revision:", identity["source_revision"], flush=True)
print("Native platform:", platform.platform(), flush=True)

env = os.environ.copy()
# Required only for compile-checking the public PTY tests; those are never run.
env["CARGO_BIN_EXE_aiperf"] = "/__not_executed__/aiperf"
command = ["cargo", "test", "--locked", "--manifest-path", str(MANIFEST), "--lib"]
listing = subprocess.check_output(command + ["--", "--list"], cwd=ROOT, env=env, text=True)
windows = platform.system() == "Windows"
prefix = "credential_windows::tests::" if windows else "credential_process::tests::"
names = [line.removesuffix(": test") for line in listing.splitlines() if line.startswith(prefix) and line.endswith(": test")]
expected_names = identity["tests"]["windows" if windows else "unix"]
if not expected_names or sorted(names) != sorted(expected_names):
    raise SystemExit(f"expected exact tests {expected_names}, found {names}: {listing}")
print("Exact tests:", names, flush=True)
subprocess.run(command + ["--", "--exact", "--nocapture", *names], cwd=ROOT, env=env, check=True)
print("NATIVE-CREDENTIAL-RECEIPT-END success", flush=True)
