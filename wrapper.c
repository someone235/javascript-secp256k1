#include "emscripten.h"
#include <stdint.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>


EMSCRIPTEN_KEEPALIVE
secp256k1_context* context_create() {
    return secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
}

EMSCRIPTEN_KEEPALIVE
void context_destroy(secp256k1_context* ctx) {
    secp256k1_context_destroy(ctx);
}

EMSCRIPTEN_KEEPALIVE
int seckey_to_pubkey(secp256k1_context* ctx, uint8_t *pubkey32, const uint8_t *seckey32) {
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey pubkey;
    int res = secp256k1_keypair_create(ctx, &keypair, seckey32);
    if (!res) {
        return res;
    }
    res = secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &keypair);
    if (!res) {
        return res;
    }
    return secp256k1_xonly_pubkey_serialize(ctx, pubkey32, &pubkey);
}

EMSCRIPTEN_KEEPALIVE
int schnorrsig_sign(secp256k1_context* ctx, uint8_t *sig64, const uint8_t *msg32, const uint8_t *seckey32, const uint8_t *random32) {
    secp256k1_keypair keypair;
    int res = secp256k1_keypair_create(ctx, &keypair, seckey32);
    if (!res) {
        return res;
    }
    return secp256k1_schnorrsig_sign(ctx, sig64, msg32, &keypair, secp256k1_nonce_function_bip340, (void*)random32);
}

EMSCRIPTEN_KEEPALIVE
int schnorrsig_verify(secp256k1_context* ctx, const uint8_t *sig64, const uint8_t *msg32, const uint8_t *pubkey32) {
    secp256k1_xonly_pubkey pubkey;
    int res = secp256k1_xonly_pubkey_parse(ctx, &pubkey, pubkey32);
    if (!res) {
        return res;
    }
    return secp256k1_schnorrsig_verify(ctx, sig64, msg32, &pubkey);
}