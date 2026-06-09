#!/bin/bash
set -eox pipefail

RUSTC_MINOR_VERSION=$(rustc --version | awk '{ split($2,a,"."); print a[2] }')

export RUST_BACKTRACE=1

cargo check --locked --verbose --color always
cargo check --locked --release --verbose --color always
cargo test --locked --no-default-features
[ "$RUSTC_MINOR_VERSION" -gt 81 ] && cargo test --locked --features http
[ "$RUSTC_MINOR_VERSION" -gt 81 ] && cargo test --locked --features http_proxied
cargo test --locked --features std --release
[ "$RUSTC_MINOR_VERSION" -gt 81 ] && cargo doc --locked --document-private-items --no-default-features
[ "$RUSTC_MINOR_VERSION" -gt 81 ] && cargo doc --locked --document-private-items --features http,std
[ "$RUSTC_MINOR_VERSION" -gt 81 ] && cargo doc --locked --document-private-items --features http_proxied,std
exit 0
