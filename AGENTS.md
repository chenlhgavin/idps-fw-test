# AGENTS.md

## Scope

- Applies to `idps-fw-test/` and all subdirectories unless a deeper `AGENTS.md` is added later.

## Repo Role

- `idps-fw-test` is the firewall functional-test toolset for `idps-fw`. It holds two crates:
  - `fw-verify/` — host-side orchestrator (pure Rust, runs on Linux and Windows). Drives both
    Android phones over `adb` and the on-device `fw-agent` worker, then asserts both
    enforcement (drop/allow) and detection (`firewall_event` + upload to idps-server).
  - `fw-agent/` — on-device worker, cross-built to `aarch64-linux-android`. Writes encrypted
    rule depot files (reusing `idps-server`'s `RuleDepot` + the same VIN/DSN keystore
    derivation), generates OS-socket traffic, and reads `idps-fw` SQLite state.
- `fw-agent` reuses `idps-core` + `idps-server` via Cargo path deps
  (`../../idps-base/crates/idps-core`, `../../idps-server`). These resolve only when this repo
  sits at the workspace root next to `idps-base`/`idps-server` — **keep `fw-agent/` and
  `fw-verify/` as direct children of the repo root; do not nest them under a `crates/` dir.**

## Preferred Workflow

- For `idps-fw-test`-only work, prefer the local [Makefile](/home/ubuntu/workspace/idps/idps-fw-test/Makefile).
- Common local entrypoints (same command set as `idps-fw/Makefile`):
  - `make check` — host fmt-check + clippy + test for both crates
  - `make build` / `make release` `[platform=host|android]` — host builds both crates;
    `platform=android` cross-builds `fw-agent` only
  - `make release-fwverify-windows` — cross-build `fw-verify.exe` for the controller PC
  - `make push-fwagent DEVICE=<serial>` — install `/system/bin/fw-agent` on a phone
  - `make package-android` — assemble the Android payload (`system.zip`) + `install.bat` +
    `fw-verify.exe` + `fw-verify.conf` + a distributable zip
  - `make install` — host-only: install `fw-verify` + `fw-agent` to `/usr/local/bin`
  - `make clean`
- If you invoke Cargo directly, use the repo toolchain explicitly:
  - `rustup run 1.93.0 cargo test --all-features`
  - `rustup run 1.93.0 cargo clippy --all-features -- -D warnings`
- `fmt` uses nightly: `cargo +nightly fmt`.

## Build Prerequisites

- The `fw-agent` Android cross-build needs a working NDK (`ANDROID_NDK_HOME`, currently
  `aarch64-linux-android`) and the device-provider Android shared library. The Makefile's
  `ensure-device-provider-android` target builds the latter on demand by invoking the
  **workspace-root** Makefile (`make -C .. build-device-provider platform=android
  DEVICE_PROVIDER=mock`), so this repo must live inside the `repo` workspace.
- `make release-fwverify-windows` needs `rustup target add --toolchain 1.93.0
  x86_64-pc-windows-gnu` and the `mingw-w64` toolchain.

## Boundaries

- Do not edit `.repo/` or sibling repos from here.
- Keep test-case specifications in `idps-docs/`; keep firewall test docs under `docs/`.

## Done Criteria

- Run `cd idps-fw-test && make check` before marking work done.
