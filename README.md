# idps-fw-test

Firewall functional-test toolset for **idps-fw**.

Deliverables:

- **[`fw-verify/`](fw-verify/)** — host-side orchestrator (pure Rust; builds on Linux and
  cross-compiles to Windows as `fw-verify.exe`). Runs on a controller PC, drives both Android
  phones over `adb` and the on-device `fw-agent` worker, and asserts both **enforcement**
  (drop/allow) and **detection** (`firewall_event` generation + upload to idps-server). It
  carries a catalog of functional test cases (ingress/egress 5-tuple rules, default policy,
  app/UID policy, CIDR/port matching, port-scan and connection-anomaly detection, traffic
  statistics).
- **[`fw-agent/`](fw-agent/)** — on-device worker, cross-built to `aarch64-linux-android`.
  Writes encrypted rule depot files (reusing `idps-server`'s `RuleDepot` and the same VIN/DSN
  keystore derivation idps-server uses), generates OS-socket traffic (TCP/UDP/ICMP), and reads
  `idps-fw` SQLite state. Driven by `fw-verify` over `adb`.

Build / test / lint / package via the top-level `Makefile` (`make help`).
`make package-android` produces `system.zip` (the `fw-agent` payload), `install.bat`,
`fw-verify.exe`, `fw-verify.conf`, and a distributable zip. The installer pushes the payload
with `adb`, unpacks it on the device, and installs `/system/bin/fw-agent`; `fw-verify.exe`
then runs on the controller PC.

The functional test walkthrough lives in [`docs/fw-verify-testing.md`](docs/fw-verify-testing.md).

## Workspace placement

This repo is part of the `repo`-managed IDPS workspace and **must** sit at the workspace root
next to `idps-base`, `idps-server`, and `idps-fw`. `fw-agent` depends on `idps-core` and
`idps-server` through relative Cargo paths (`../../idps-base/crates/idps-core`,
`../../idps-server`), and the Android cross-build resolves the device-provider shared library
and the workspace-root `Makefile` via `../`. Keep `fw-agent/` and `fw-verify/` as direct
children of this repo root.

## Prerequisites

- **Android cross-build** (`fw-agent`): a working NDK (`ANDROID_NDK_HOME`) plus the
  device-provider Android library. `make` builds the latter on demand via the workspace-root
  `build-device-provider` target.
- **Windows cross-build** (`fw-verify.exe`): `rustup target add --toolchain 1.93.0
  x86_64-pc-windows-gnu` and the `mingw-w64` toolchain (`x86_64-w64-mingw32-gcc`).
- **Two Android phones** on the same WiFi: a TARGET running `idps-fw` and a PEER for traffic.
  Copy [`fw-verify/fw-verify.conf.example`](fw-verify/fw-verify.conf.example) to
  `fw-verify.conf` and fill in the two `adb` serials.
