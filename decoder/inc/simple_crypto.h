/**
 * @file "simple_crypto.h"
 * @author Ben Janis
 * @brief Simplified Crypto API Header 
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#ifndef ECTF_CRYPTO_H
#define ECTF_CRYPTO_H
// #define HAVE_ED25519
// #define WOLFSSL_SHA512

#include "wolfssl/options.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/hash.h"
#include "wolfssl/wolfcrypt/ed25519.h"

/******************************** MACRO DEFINITIONS ********************************/
#define BLOCK_SIZE AES_BLOCK_SIZE
#define HASH_SIZE MD5_DIGEST_SIZE

// Yi: word32 pubkey is 32 bytes and sig is 64 bytes， in wolfssl it defines as word32 format
#define SIG_SIZE 64 // Ed25519 signature size in bytes
#define PUB_KEY_SIZE 32 // Ed25519 public key size in bytes
#define MESSAGE_SIZE 74 // Size of the message in bytes, need to change 

// Zhong: AES_GCM
#define IV_SIZE 12 
#define AUTH_TAG_SIZE 16
#define KEY_SIZE 32

// Zhong: Secure wipe
// Add secure memset zero macro (place near top after includes)
#define secure_wipe(buf, len) do { \
    volatile uint8_t *p = (volatile uint8_t *)(buf); \
    size_t _len = (len); \
    while (_len--) *p++ = 0; \
} while(0)

// Yi: reference https://github.com/wolfSSL/wolfssl/blob/master/doc/dox_comments/header_files/ed25519.h#L345
/** @brief Verifies a digital signature using Ed25519
 *
 * @param sig A pointer to a buffer of length sigSz containing the signature
 * @param sigSz The length of the signature buffer
 * @param msg A pointer to a buffer of length msgSz containing the original message
 * @param msgSz The length of the message buffer
 * @param pubKey A pointer to a buffer of length pubKeySz containing the public key
 * @param pubKeySz The length of the public key buffer
 *
 * @return 0 Returned upon successfully performing the signature verification and authentication.
 * @return BAD_FUNC_ARG Returned if any of the input parameters evaluate to NULL, or if the siglen does not match the actual length of a signature.
 * @return SIG_VERIFY_E Returned if verification completes, but the signature generated does not match the signature provided.
 */
int ed25519_authenticate(const byte* sig, word32 sigSz, const byte* msg, word32 msgSz,
                 const byte* pubKey, word32 pubKeySz);

/** @brief Decrypts ciphertext using AES-GCM
 * 
 * @author Gavin Zhong
 * 
 * @param ciphertext A pointer to a buffer of length len containing the
 *          ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for decryption
 * @param iv A pointer to a buffer of length IV_SIZE (12 bytes) containing
 *          the initialization vector to use for decryption
 * @param tag A pointer to a buffer of length AUTH_TAG_SIZE (16 bytes) containing
 *          the authentication tag to use for decryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *          plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */

int aes_gcm_decrypt(uint8_t *ciphertext, size_t ciphertext_len,
                     uint8_t *key, uint8_t *iv, uint8_t *tag, uint8_t *plaintext);

#endif // ECTF_CRYPTO_H
