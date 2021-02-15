#!/bin/bash -e
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR/secp256k1"
./autogen.sh
./configure --enable-experimental --enable-module-extrakeys --enable-module-schnorrsig --with-bignum=no --with-asm=no --disable-benchmark --disable-tests
make gen_context
./gen_context