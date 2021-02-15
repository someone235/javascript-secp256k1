const tap = require('tap')
const Module = require("../lib/libsecp256k1.node.js")

tap.test(async t => {
    const loadedModule = await Module();

    const api = {
        context_create: loadedModule.cwrap('context_create', 'number', []),
        context_destroy: loadedModule.cwrap('context_destroy', '', ['number']),
        seckey_to_pubkey: loadedModule.cwrap('seckey_to_pubkey', 'number', ['number', 'number', 'array']),
        schnorrsig_sign: loadedModule.cwrap('schnorrsig_sign', 'number', ['number', 'array', 'array', 'array', 'array']),
        schnorrsig_verify: loadedModule.cwrap('schnorrsig_verify', 'number', ['number', 'array', 'array', 'array']),
    };

    // global context variable, initialized once and used for the full duration of the program.
    var context = api.context_create();

    function seckey_to_pubkey(seckey) {
        if (seckey.length != 32) {
            throw `invalid secret key length(${seckey}), expected 32 bytes`
        }
        const wasmMemoryPublicKey = loadedModule._malloc(32);
        const res = api.seckey_to_pubkey(context, wasmMemoryPublicKey, seckey);
        if (res != 1) {
            throw 'invalid secret key'
        }
        var pubkey = new Uint8Array(32)
        pubkey.set(new Uint8Array(loadedModule.HEAPU8.buffer, wasmMemoryPublicKey, 32))
        loadedModule._free(wasmMemoryPublicKey)
        return pubkey
    }

    var onesSecretKey = new Uint8Array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    var pubkey = seckey_to_pubkey(onesSecretKey);
    var pubkeyHex = Buffer.from(pubkey).toString('hex');
    t.equal(pubkeyHex, "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f")
})