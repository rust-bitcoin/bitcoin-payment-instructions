#!/bin/bash
set -e
set -x

RUSTC_MINOR_VERSION=$(rustc --version | awk '{ split($2,a,"."); print a[2] }')

# Starting with version 0.5.60, the `honggfuzz` crate has an MSRV of rustc 1.70.
# 0.5.59 nominally has an MSRV of 1.63, but its bundled Cargo.lock pulls in
# transitive deps (`unicode-ident` 1.0.24) that require rustc 1.71. The 0.5.58
# bundled lockfile resolves cleanly on 1.63, so use that with `--locked`.
HONGGFUZZ_INSTALL_ARGS=""
[ "$RUSTC_MINOR_VERSION" -lt 70 ] && HONGGFUZZ_INSTALL_ARGS='--locked --version=0.5.58'

pushd src/bin
rm *_target.rs
./gen_target.sh
[ "$(git diff)" != "" ] && exit 1
popd

cargo install --color always --force honggfuzz --no-default-features $HONGGFUZZ_INSTALL_ARGS
sed -i 's/lto = true//' Cargo.toml

export RUSTFLAGS="--cfg=secp256k1_fuzz --cfg=hashes_fuzz"
export HFUZZ_BUILD_ARGS="--features honggfuzz_fuzz"

cargo --color always hfuzz build
for TARGET in src/bin/*.rs; do
	FILENAME=$(basename $TARGET)
	FILE="${FILENAME%.*}"
	HFUZZ_RUN_ARGS="--exit_upon_crash -v -n2 -N10000000"
	export HFUZZ_RUN_ARGS
	cargo --color always hfuzz run $FILE
	if [ -f hfuzz_workspace/$FILE/HONGGFUZZ.REPORT.TXT ]; then
		cat hfuzz_workspace/$FILE/HONGGFUZZ.REPORT.TXT
		for CASE in hfuzz_workspace/$FILE/SIG*; do
			cat $CASE | xxd -p
		done
		exit 1
	fi
done
