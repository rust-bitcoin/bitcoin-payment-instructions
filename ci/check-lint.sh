#!/bin/sh
set -e
set -x

RUSTFLAGS='-D warnings' cargo clippy --locked -- \
	`# We use this for sat groupings` \
	-A clippy::inconsistent-digit-grouping \
	`# Some stuff we do sometimes when its reasonable` \
	-A clippy::result-unit-err \
	-A clippy::large-enum-variant \
	-A clippy::if-same-then-else \
	-A clippy::needless-lifetimes \
	`# This doesn't actually work sometimes` \
	-A clippy::option-as-ref-deref
