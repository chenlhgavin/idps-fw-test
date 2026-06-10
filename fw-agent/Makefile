# fw-agent — on-device worker for idps-fw functional tests.
#
# Reuses idps-core + idps-server (depot + keystore), so the Android cross-build
# needs the NDK toolchain env. Use the repo-root targets for cross-builds and
# device install:
#
#   make -C .. release-fwagent-android
#   make -C .. push-fwagent DEVICE=<serial>
#
# The targets below are host-only convenience wrappers.

RUST_CARGO ?= cargo

.PHONY: build release test lint fmt fmt-check check

build:
	$(RUST_CARGO) build

release:
	$(RUST_CARGO) build --release

test:
	$(RUST_CARGO) test

lint:
	$(RUST_CARGO) clippy -- -D warnings

fmt:
	cargo +nightly fmt

fmt-check:
	cargo +nightly fmt --check

check: fmt-check lint test
