#!/bin/bash -e
./depend/configure.sh
emcc -O3 -s WASM=1 -I./depend/secp256k1/src -I./depend/secp256k1 -I./depend/secp256k1/include -DHAVE_CONFIG_H -s EXTRA_EXPORTED_RUNTIME_METHODS='["cwrap"]' ./depend/secp256k1/src/secp256k1.c ./lib/wrapper.c -o ./lib/libsecp256k1.js