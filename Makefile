export RUST_BACKTRACE ?= full
export RUST_LOG ?= info,rose=info
export MINIMAL_LOG_FORMAT ?= true
export

WASM_DIR := crates/rose-wasm

.PHONY: build build-rust test fmt fmt-check clippy clippy-fix fix check wasm \
	ci fmt-check clippy test wasm \
	publish-crates publish-crates-prerelease npm-pack npm-publish npm-publish-nightly

build: build-rust

build-rust:
	cargo build --release

test:
	cargo test --release

fmt:
	cargo fmt
	$(MAKE) clippy-fix

fmt-check:
	cargo fmt -- --check

clippy:
	cargo clippy --all --all-targets --all-features -- -D warnings

clippy-fix:
	if rustup run nightly rustc -V >/dev/null 2>&1; then \
		rustup run nightly cargo clippy --fix -Z unstable-options --allow-dirty --allow-staged --all --all-targets --all-features; \
	else \
		echo "note: nightly toolchain not installed; skipping clippy auto-fix (run: rustup toolchain install nightly)"; \
	fi

fix: fmt

check: fmt-check clippy

wasm:
	cd "$(WASM_DIR)" && wasm-pack build --target web --out-dir pkg --scope nockchain

publish-crates:
	set -euo pipefail; \
	cargo publish -p rose-ztd-derive --locked; \
	cargo publish -p rose-ztd --locked; \
	cargo publish -p rose-crypto --locked; \
	cargo publish -p rose-nockchain-types --locked; \
	cargo publish -p rose-grpc-proto --locked; \
	cargo publish -p rose-wasm --locked

publish-crates-prerelease:
	set -euo pipefail; \
	cargo publish -p rose-ztd-derive --allow-dirty; \
	cargo publish -p rose-ztd --allow-dirty; \
	cargo publish -p rose-crypto --allow-dirty; \
	cargo publish -p rose-nockchain-types --allow-dirty; \
	cargo publish -p rose-grpc-proto --allow-dirty; \
	cargo publish -p rose-wasm --allow-dirty

npm-pack:
	cd "$(WASM_DIR)/pkg" && npm pack --dry-run

npm-publish:
	cd "$(WASM_DIR)/pkg" && npm publish --access public

npm-publish-nightly:
	cd "$(WASM_DIR)/pkg" && npm publish --access public --tag nightly


