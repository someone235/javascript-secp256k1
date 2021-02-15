#!/bin/bash -e
pushd depend
./configure.sh
emcc -O3 -s WASM=1 -I./secp256k1/src -I./secp256k1 -I./secp256k1/include -DHAVE_CONFIG_H -s -s EXPORTED_FUNCTIONS='["_malloc", "_free"]' -s EXTRA_EXPORTED_RUNTIME_METHODS='["cwrap"]' ./secp256k1/src/secp256k1.c ../lib/wrapper.c -o ../lib/libsecp256k1.js -s MODULARIZE=1 -s EXPORT_ES6=1