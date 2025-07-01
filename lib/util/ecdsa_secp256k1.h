#ifndef ECDSA_SECP256K1_H
#define ECDSA_SECP256K1_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
// Signs a 32-byte hash with a secp256k1 private key, producing a 65-byte compact signature.
// privkey: 32-byte private key
// hash32:  32-byte message hash
// sig65:   output buffer for 65-byte signature (header + r + s)
// recid:   output recovery id (0-3)
// is_compressed: 1 if compressed pubkey, 0 otherwise
// Returns 1 on success, 0 on failure.
int ecdsa_sign_compact_secp256k1(const uint8_t *privkey, const uint8_t *hash32, uint8_t *sig65, int *recid, int is_compressed);
// Verifies a 65-byte compact signature against a 32-byte message hash and public key.
// pubkey: 33 or 65 bytes
// hash32: 32-byte message hash
// sig65:  65-byte signature
// Returns 1 on success, 0 on failure.
int ecdsa_verify_compact_secp256k1(const uint8_t *pubkey, size_t pubkeylen, const uint8_t *hash32, const uint8_t *sig65);
#ifdef __cplusplus
}
#endif
#endif // ECDSA_SECP256K1_H 