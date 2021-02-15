const tap = require('tap')
const Module = require("../lib/libsecp256k1.node.js")
const crypto = require('crypto');

tap.test(async t => {
    // Should only be loaded once
    const loadedModule = await Module();

    const api = {
        context_create: loadedModule.cwrap('context_create', 'number', []),
        context_destroy: loadedModule.cwrap('context_destroy', '', ['number']),
        seckey_to_pubkey: loadedModule.cwrap('seckey_to_pubkey', 'number', ['number', 'number', 'array']),
        schnorrsig_sign: loadedModule.cwrap('schnorrsig_sign', 'number', ['number', 'number', 'array', 'array', 'array']),
        schnorrsig_verify: loadedModule.cwrap('schnorrsig_verify', 'number', ['number', 'array', 'array', 'array']),
    };

    // global context variable, initialized once and used for the full duration of the program.
    // should only be created once
    var context = api.context_create();

    function seckey_to_pubkey(seckey) {
        if (seckey.length != 32) {
            throw `invalid secret key length(${seckey.length}), expected 32 bytes`
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

    function schnorrsig_sign(secretKey, messageHash) {
        if (seckey.length != 32) {
            throw `invalid secret key length(${seckey.length}), expected 32 bytes`
        }
        if (messageHash.length != 32) {
            throw `invalid messageHash length(${messageHash.length}), expected 32 bytes`
        }
        const rand32 = crypto.randomBytes(32);
        const wasmMemorySignature = loadedModule._malloc(64);

        const res = api.schnorrsig_sign(context, wasmMemorySignature, messageHash, secretKey, rand32);
        if (res != 1) {
            throw 'invalid secret key'
        }
        var signature = new Uint8Array(64)
        signature.set(new Uint8Array(loadedModule.HEAPU8.buffer, wasmMemorySignature, 64))
        loadedModule._free(wasmMemorySignature)
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

    var seckey = Buffer.from('B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF', 'hex')
    var pubkey = seckey_to_pubkey(seckey);
    var pubkeyHex = Buffer.from(pubkey).toString('hex').toUpperCase();
    t.equal(pubkeyHex, 'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659')

    var messageHash = Buffer.from('243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', 'hex')
    var expectedSig = '6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A'
    var auxRand = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex')
    const wasmMemorySignature = loadedModule._malloc(64);
    const res = api.schnorrsig_sign(context, wasmMemorySignature, messageHash, seckey, auxRand);
    if (res != 1) {
        throw 'invalid secret key'
    }
    var sigHex = Buffer.from((new Uint8Array(loadedModule.HEAPU8.buffer, wasmMemorySignature, 64))).toString('hex').toUpperCase()
    t.equal(expectedSig, sigHex)
    loadedModule._free(wasmMemorySignature)

    var sig = schnorrsig_sign(seckey, messageHash)
    t.ok(schnorrsig_verify(pubkey, messageHash, sig))

    sig[30] += 1
    t.notOk(schnorrsig_verify(pubkey, messageHash, sig))
})