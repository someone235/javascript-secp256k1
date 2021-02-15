import Module from "./libsecp256k1.browser.js"

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
// should only be created once
var context = api.context_create();

function seckey_to_pubkey(seckey) {
    if (seckey.length != 32) {
        throw `invalid secret key length(${seckey.length}), expected 32 bytes`
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

function schnorrsig_sign(secretKey, messageHash) {
    if (seckey.length != 32) {
        throw `invalid secret key length(${seckey.length}), expected 32 bytes`
    }
    if (messageHash.length != 32) {
        throw `invalid messageHash length(${messageHash.length}), expected 32 bytes`
    }
    const rand32 = crypto.randomBytes(32);
    const wasmMemorySignature = Module._malloc(64);

    const res = api.schnorrsig_sign(context, wasmMemorySignature, messageHash, secretKey, rand32);
    if (res != 1) {
        throw 'invalid secret key'
    }
    var signature = new Uint8Array(64)
    signature.set(new Uint8Array(Module.HEAPU8.buffer, wasmMemorySignature, 64))
    Module._free(wasmMemorySignature)
    return signature
}

function schnorrsig_verify(publicKey, messageHash, signature) {
    if (publicKey.length != 32) {
        throw `invalid public key length(${publicKey.length}), expected 32 bytes`
    }
    if (messageHash.length != 32) {
        throw `invalid messageHash length(${messageHash.length}), expected 32 bytes`
    }
    if (signature.length != 64) {
        throw `invalid signature length(${messageHash.length}), expected 64 bytes`
    }
    const res = api.schnorrsig_verify(context, signature, messageHash, publicKey);
    return res == 1
}


export {context as default}
export {seckey_to_pubkey};