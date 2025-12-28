#!/bin/bash
set -eox pipefail

RUSTC_MINOR_VERSION=$(rustc --version | awk '{ split($2,a,"."); print a[2] }')

# Starting with version 1.39.0, the `tokio` crate has an MSRV of rustc 1.70.0
[ "$RUSTC_MINOR_VERSION" -lt 70 ] && cargo update -p tokio --precise "1.38.1" --verbose

# syn 2.0.107 requires rustc 1.68.0
[ "$RUSTC_MINOR_VERSION" -lt 68 ] && cargo update -p syn --precise "2.0.106" --verbose
# quote 1.0.42 requires rustc 1.68.0
[ "$RUSTC_MINOR_VERSION" -lt 68 ] && cargo update -p quote --precise "1.0.41" --verbose
# Starting with version 1.0.104, the `proc-macro2` crate has an MSRV of rustc 1.68
[ "$RUSTC_MINOR_VERSION" -lt 68 ] && cargo update -p proc-macro2 --precise "1.0.103" --verbose

# Starting with version 2.0.107, the `syn` crate has an MSRV of rustc 1.68
[ "$RUSTC_MINOR_VERSION" -lt 68 ] && cargo update -p syn --precise "2.0.106" --verbose

# Starting with version 1.0.42, the `quote` crate has an MSRV of rustc 1.68
[ "$RUSTC_MINOR_VERSION" -lt 68 ] && cargo update -p quote --precise "1.0.41" --verbose

# Starting with version 1.0.104, the `proc-macro2` crate has an MSRV of rustc 1.68
[ "$RUSTC_MINOR_VERSION" -lt 68 ] && cargo update -p proc-macro2 --precise "1.0.103" --verbose

export RUST_BACKTRACE=1

cargo check --verbose --color always
cargo check --release --verbose --color always
cargo test --no-default-features
[ "$RUSTC_MINOR_VERSION" -gt 81 ] && cargo test --features http
[ "$RUSTC_MINOR_VERSION" -gt 81 ] && cargo test --features http_proxied
cargo test --features std --release
[ "$RUSTC_MINOR_VERSION" -gt 81 ] && cargo doc --document-private-items --no-default-features
[ "$RUSTC_MINOR_VERSION" -gt 81 ] && cargo doc --document-private-items --features http,std
[ "$RUSTC_MINOR_VERSION" -gt 81 ] && cargo doc --document-private-items --features http_proxied,std
exit 0
