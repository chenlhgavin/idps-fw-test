# idps-fw-test

Functional-test tool for **idps-fw**.

Deliverable:

- **[`fw-verify/`](fw-verify/)** — a single binary that is both the orchestrator and the
  on-device/in-namespace worker. It **runs locally on the device under test** (host or Android,
  same usage): it stages the topology, provisions firewall rules, generates OS-socket traffic
  (TCP/UDP/ICMP incl. the timestamp probe, bare-FIN scans, connection floods, ARP-spoof frames),
  reads `idps-fw` SQLite state, and asserts both **enforcement** (drop/allow) and **detection**
  (`firewall_event` generation + upload to idps-server). It carries a catalog of functional test
  cases (ingress/egress 5-tuple rules, default policy, app/UID policy, CIDR/port matching,
  port-scan and connection-anomaly detection, traffic statistics, side-channel monitors).

## Single device, single binary

Testing is always single-device: `fw-verify` creates a veth pair with the peer end in a network
namespace (`fwpeer`) so target↔peer traffic traverses idps-fw's monitored interface. The
orchestrator runs as root in the root namespace; work that must run in the peer namespace, in
the background, or under a dropped uid re-executes the same binary as `fw-verify agent <sub>`
(entering the namespace with `nsenter`, falling back to `ip netns exec`).

The **only** difference between modes is how rules are delivered:

- **host** (default, `--mode host`) — rules are delivered the production way **through the VSOC
  dashboard API** (`PUT /api/rules/{acd}/{fun}`, mutual TLS) so idps-server cloud-syncs them into
  its depot.
- **android** (`--mode android`) — rules are written straight into the idps-server depot
  (reusing `idps-server`'s `RuleDepot` and the same VIN/DSN keystore derivation). adb is used
  **only to install the binary**; the tests themselves run on the device after `adb shell`.

### Host-mode quickstart

```bash
cd vsoc && make deploy                 # mock VSOC (Docker, mTLS :8443)
make clean-dev setup-dev install       # idps-server (+ device-provider libs), from idps/ root
make -C idps-fw setup-dev install      # idps-fw daemon + eBPF object
make -C idps-fw-test install           # fw-verify -> /usr/local/bin
make -C idps-fw-test setup-dev         # veth/netns + host idps-fw.yaml + config, restarts idps-fw
make -C idps-fw-test test-host         # run the whole catalog via the generated config
```

`setup-dev` runs `fw-verify setup-env`: it creates the topology (`fwt0` 10.123.0.1 ↔ netns
`fwpeer:fwp0` 10.123.0.2), writes a host-tuned `/etc/idd/idps-fw.yaml` (monitors `fwt0`, short
poll intervals, app-uid override) and `/etc/idd/fw-verify.conf`, then restarts `idps-fw.service`
when systemd is available; `clean-dev` tears it down and restarts the service after restoring the
previous config.

### Android quickstart

```bash
make -C idps-fw-test package-android   # out/idps-fw-test/{system/, install.bat, fw-verify.conf}
# or: make -C idps-fw-test push-fwverify DEVICE=<serial>
adb -s <serial> shell                  # log in to the device, then on the device (root):
fw-verify --mode android setup-env
fw-verify --config /etc/idd/fw-verify.conf run-all
```

Build / test / lint / package via the top-level `Makefile` (`make help`).
`make package-android` produces the `system/` payload (`fw-verify`),
`install.bat`, `fw-verify.conf`, and a distributable zip. The installer pushes the payload with
`adb` and installs `/system/bin/fw-verify`; everything else runs on the device.

The functional test walkthrough lives in [`docs/fw-verify-testing.md`](docs/fw-verify-testing.md).

## Workspace placement

This repo is part of the `repo`-managed IDPS workspace and **must** sit at the workspace root
next to `idps-base`, `idps-server`, and `idps-fw`. `fw-verify` depends on `idps-core` and
`idps-server` through relative Cargo paths (`../../idps-base/crates/idps-core`,
`../../idps-server`), and the Android cross-build resolves the device-provider shared library
and the workspace-root `Makefile` via `../`. Keep `fw-verify/` a direct child of this repo root.

## Prerequisites

- **Host**: Linux with `sudo`, Docker (for the mock VSOC), Rust `1.93.0` + nightly fmt,
  `iproute2` (`ip netns`/veth), loadable eBPF/tc with `/sys/fs/cgroup`, and `/usr/local/bin`
  + `/usr/local/lib` writable for the test binary and the device-provider library.
- **Android cross-build**: a working NDK (`ANDROID_NDK_HOME`, `aarch64-linux-android`) plus the
  device-provider Android library. `make` builds the latter on demand via the workspace-root
  `build-device-provider` target. The target device must be rooted and able to load tc eBPF on
  a veth.
