#!/bin/sh
set -e
set -x

RUSTC_MINOR_VERSION=$(rustc --version | awk '{ split($2,a,"."); print a[2] }')

# Starting with version 1.39.0, the `tokio` crate has an MSRV of rustc 1.70.0
[ "$RUSTC_MINOR_VERSION" -lt 70 ] && cargo update -p tokio --precise "1.38.1" --verbose

# syn 2.0.107 requires rustc 1.68.0
[ "$RUSTC_MINOR_VERSION" -lt 68 ] && cargo update -p syn --precise "2.0.106" --verbose
# quote 1.0.42 requires rustc 1.68.0
[ "$RUSTC_MINOR_VERSION" -lt 68 ] && cargo update -p quote --precise "1.0.41" --verbose
# Starting with version 1.0.104, the `proc-macro2` crate has an MSRV of rustc 1.68
[ "$RUSTC_MINOR_VERSION" -lt 68 ] && cargo update -p proc-macro2 --precise "1.0.103" --verbose

RUSTFLAGS='-D warnings' cargo clippy -- \
	`# We use this for sat groupings` \
	-A clippy::inconsistent-digit-grouping \
	`# Some stuff we do sometimes when its reasonable` \
	-A clippy::result-unit-err \
	-A clippy::large-enum-variant \
	-A clippy::if-same-then-else \
	-A clippy::needless-lifetimes \
	`# This doesn't actually work sometimes` \
	-A clippy::option-as-ref-deref
