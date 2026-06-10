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
- **[`fw-agent/`](fw-agent/)** — worker that runs on the device (android) or locally (host).
  Writes encrypted rule depot files (reusing `idps-server`'s `RuleDepot` and the same VIN/DSN
  keystore derivation idps-server uses), generates OS-socket traffic (TCP/UDP/ICMP incl. the
  timestamp probe, bare-FIN scans, connection floods, and ARP-spoof frames), and reads
  `idps-fw` SQLite state (firewall events and side-channel monitor reports).

## Modes

- **android** (default) — two phones over `adb`; rules are written straight into the
  idps-server depot by `fw-agent provision-rule`.
- **host** — everything runs locally: a veth pair with the peer end in a network namespace
  (`fwpeer`) so target↔peer traffic traverses idps-fw's monitored interface, and rules are
  delivered the production way **through the VSOC dashboard API** (`PUT /api/rules/{acd}/{fun}`,
  mutual TLS) so idps-server cloud-syncs them into its depot. Run `fw-verify` as root.

### Host-mode quickstart

```bash
cd vsoc && make deploy                 # mock VSOC (Docker, mTLS :8443)
make clean-dev setup-dev install       # idps-server (+ device-provider libs), from idps/ root
make -C idps-fw setup-dev install      # idps-fw daemon + eBPF object
make -C idps-fw-test install           # fw-verify + fw-agent -> /usr/local/bin
make -C idps-fw-test setup-dev         # veth/netns + host idps-fw.yaml + /etc/idd/fw-verify.conf
# (re)start idps-server and idps-fw, then:
make -C idps-fw-test test-host         # run the whole catalog via the generated config
```

`setup-dev` creates the topology (`fwt0` 10.123.0.1 ↔ netns `fwpeer:fwp0` 10.123.0.2), writes a
host-tuned `/etc/idd/idps-fw.yaml` (monitors `fwt0`, short poll intervals, app-uid override) and
`/etc/idd/fw-verify.conf`; `clean-dev` tears it down.

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
