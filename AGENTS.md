# AGENTS.md

## Scope

- Applies to `idps-fw-test/` and all subdirectories unless a deeper `AGENTS.md` is added later.

## Repo Role

- `idps-fw-test` is the functional-test tool for `idps-fw`. It is a single crate:
  - `fw-verify/` — one binary that is both the orchestrator and the on-device/in-namespace
    worker. It runs locally on the device under test (host or Android), stages a veth/netns
    topology, provisions firewall rules, generates OS-socket traffic, reads `idps-fw` SQLite
    state, and asserts enforcement (drop/allow) and detection (`firewall_event` + upload to
    idps-server). The hidden `fw-verify agent <sub>` subcommand is the worker the binary
    re-executes for namespace/uid-dropped/background work; agent code lives under
    `fw-verify/src/agent/`.
- `fw-verify` reuses `idps-core` + `idps-server` via Cargo path deps
  (`../../idps-base/crates/idps-core`, `../../idps-server`) for byte-exact depot encryption.
  These resolve only when this repo sits at the workspace root next to `idps-base`/`idps-server`
  — **keep `fw-verify/` a direct child of the repo root; do not nest it under a `crates/` dir.**
- The **only** mode difference is rule delivery: `--mode host` upserts through the VSOC API;
  `--mode android` writes the depot directly. Topology and execution are identical.

## Preferred Workflow

- For `idps-fw-test`-only work, prefer the local [Makefile](/home/ubuntu/workspace/idps/idps-fw-test/Makefile).
- Common local entrypoints (same command set as `idps-fw/Makefile`):
  - `make check` — host fmt-check + clippy + test
  - `make build` / `make release` `[platform=host|android]` — host build, or cross-build for
    the device
  - `make push-fwverify DEVICE=<serial>` — install `/system/bin/fw-verify` on a phone
  - `make package-android` — assemble the Android payload (`system.zip`) + `install.bat` +
    `fw-verify.conf` + a distributable zip (adb installs the binary only; tests run on-device)
  - `make install` — host-only: install `fw-verify` to `/usr/local/bin`
  - `make setup-dev` / `make clean-dev` — wrappers over `fw-verify setup-env` / `clean-env`
  - `make clean`
- If you invoke Cargo directly, use the repo toolchain explicitly:
  - `rustup run 1.93.0 cargo test --all-features`
  - `rustup run 1.93.0 cargo clippy --all-features -- -D warnings`
- `fmt` uses nightly: `cargo +nightly fmt`.
- New crates pulled in via the `idps-base` deps require pinning `serde_yml`:
  `cargo update -p serde_yml --precise 0.0.12` (0.0.13 breaks the idps-core build).

## Build Prerequisites

- The Android cross-build needs a working NDK (`ANDROID_NDK_HOME`, currently
  `aarch64-linux-android`) and the device-provider Android shared library. The Makefile's
  `ensure-device-provider-android` target builds the latter on demand by invoking the
  **workspace-root** Makefile (`make -C .. build-device-provider platform=android
  DEVICE_PROVIDER=mock`), so this repo must live inside the `repo` workspace.

## Boundaries

- Do not edit `.repo/` or sibling repos from here.
- Keep test-case specifications in `idps-docs/`; keep firewall test docs under `docs/`.

## Done Criteria

- Run `cd idps-fw-test && make check` before marking work done.
