import Module from "./libsecp256k1.js"

Module.onRuntimeInitialized = async _ => {
    const api = {
        context_create: Module.cwrap('context_create', 'number', []),
        context_destroy: Module.cwrap('context_destroy', '', ['number']),
        seckey_to_pubkey: Module.cwrap('seckey_to_pubkey', 'number', ['number', 'number', 'array']),
        schnorrsig_sign: Module.cwrap('schnorrsig_sign', 'number', ['number', 'array', 'array', 'array', 'array']),
        schnorrsig_verify: Module.cwrap('schnorrsig_verify', 'number', ['number', 'array', 'array', 'array']),
    }
};
// global context variable, initialized once and used for the full duration of the program.
var context = api.context_create();

function seckey_to_pubkey(seckey) {
    if (seckey.length != 32) {
        throw `invalid secret key length(${seckey}), expected 32 bytes`
    }
    const wasmMemoryPublicKey = Module._malloc(32);
    const res = api.seckey_to_pubkey(context, wasmMemoryPublicKey, seckey);
    if (res != 1) {
        throw 'invalid secret key'
    }
    var pubkey = new Uint8Array(32)
    pubkey.set(new Uint8Array(Module.HEAPU8.buffer, wasmMemoryPublicKey, 32))
    Module._free(wasmMemoryPublicKey)
    return pubkey
  }

export {context as default}
export {seckey_to_pubkey};