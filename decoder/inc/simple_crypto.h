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

#ifdef CRYPTO_EXAMPLE
#ifndef ECTF_CRYPTO_H
#define ECTF_CRYPTO_H

#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/hash.h"

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/signature.h>

/******************************** MACRO DEFINITIONS ********************************/
#define BLOCK_SIZE AES_BLOCK_SIZE
#define KEY_SIZE 16
#define HASH_SIZE MD5_DIGEST_SIZE

/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using a symmetric cipher
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for encryption
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext);

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *           ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *           BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *           the key to use for decryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *           plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext);

/** @brief Hashes arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *           to be hashed
 * @param len The length of the plaintext to hash
 * @param hash_out A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
 *           hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int hash(void *data, size_t len, uint8_t *hash_out);

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
                 const byte* pubKey, word32 pubKeySz)
#endif // ECTF_CRYPTO_H
#endif // CRYPTO_EXAMPLE