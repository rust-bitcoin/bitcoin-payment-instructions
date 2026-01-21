#!/bin/sh

echo "#include <stdint.h>" > ../../targets.h
GEN_TEST() {
	cat target_template.txt | sed s/TARGET_NAME/$1/ | sed s/TARGET_MOD/$2$1/ > $1_target.rs
	echo "void $1_run(const unsigned char* data, size_t data_len);" >> ../../targets.h
}

GEN_TEST cashu
GEN_TEST parse
