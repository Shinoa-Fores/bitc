#include "ecdsa_secp256k1.h"
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <string.h>

// Helper: get a static context (could be improved for thread safety)
static secp256k1_context* get_ctx() {
    static secp256k1_context *ctx = NULL;
    if (!ctx) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    }
    return ctx;
}

int ecdsa_sign_compact_secp256k1(const uint8_t *privkey, const uint8_t *hash32, uint8_t *sig65, int *recid, int is_compressed) {
    secp256k1_ecdsa_recoverable_signature sig;
    int ret;
    secp256k1_context *ctx = get_ctx();
    ret = secp256k1_ecdsa_sign_recoverable(ctx, &sig, hash32, privkey, NULL, NULL);
    if (!ret) return 0;
    ret = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig65+1, recid, &sig);
    if (!ret) return 0;
    // Set header byte (per Bitcoin spec)
    sig65[0] = 27 + (*recid) + (is_compressed ? 4 : 0);
    return 1;
}

int ecdsa_verify_compact_secp256k1(const uint8_t *pubkey, size_t pubkeylen, const uint8_t *hash32, const uint8_t *sig65) {
    secp256k1_ecdsa_signature sig;
    secp256k1_context *ctx = get_ctx();
    // Remove header byte
    if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, sig65+1)) return 0;
    if (!secp256k1_ec_pubkey_parse(ctx, (secp256k1_pubkey *)pubkey, pubkey, pubkeylen)) return 0;
    secp256k1_pubkey pubkey_struct;
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey_struct, pubkey, pubkeylen)) return 0;
    return secp256k1_ecdsa_verify(ctx, &sig, hash32, &pubkey_struct);
} 