# fw-verify — host orchestrator for idps-fw functional tests.
# Pure Rust; builds on any host (incl. Windows). The repo root drives the
# canonical targets — this is a convenience wrapper.

RUST_CARGO ?= cargo

.PHONY: build release test lint fmt fmt-check check

build:
	$(RUST_CARGO) build

release:
	$(RUST_CARGO) build --release

test:
	$(RUST_CARGO) test --all-features

lint:
	$(RUST_CARGO) clippy --all-features -- -D warnings

fmt:
	cargo +nightly fmt

fmt-check:
	cargo +nightly fmt --check

check: fmt-check lint test
