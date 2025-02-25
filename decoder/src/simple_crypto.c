/**
 * @file "simple_crypto.c"
 * @author Ben Janis
 * @brief Simplified Crypto API Implementation
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>


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
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    Aes ctx; // Context for encryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for encryption
    result = wc_AesSetKey(&ctx, key, 16, NULL, AES_ENCRYPTION);
    if (result != 0)
        return result; // Report error


    // Encrypt each block
    for (int i = 0; i < len - 1; i += BLOCK_SIZE) {
        result = wc_AesEncryptDirect(&ctx, ciphertext + i, plaintext + i);
        if (result != 0)
            return result; // Report error
    }
    return 0;
}

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *          ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for decryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *          plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    Aes ctx; // Context for decryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for decryption
    result = wc_AesSetKey(&ctx, key, 16, NULL, AES_DECRYPTION);
    if (result != 0)
        return result; // Report error

    // Decrypt each block
    for (int i = 0; i < len - 1; i += BLOCK_SIZE) {
        result = wc_AesDecryptDirect(&ctx, plaintext + i, ciphertext + i);
        if (result != 0)
            return result; // Report error
    }
    return 0;
}

/** @brief Hashes arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *          to be hashed
 * @param len The length of the plaintext to hash
 * @param hash_out A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
 *          hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int hash(void *data, size_t len, uint8_t *hash_out) {
    // Pass values to hash
    return wc_Md5Hash((uint8_t *)data, len, hash_out);
}

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
                 const byte* pubKey, word32 pubKeySz) {
    int ret;
    int result = 0;
    ed25519_key myKey;

    ret = wc_ed25519_init(&myKey);
    if (ret == 0) {
        ret = wc_ed25519_import_public(pubKey, pubKeySz, &myKey);
        if (ret == 0) {
            ret = wc_ed25519_verify_msg(sig, sigSz, msg, msgSz, &result, &myKey);
        }
        wc_ed25519_free(&myKey);
    }
    return ret;
}

int aes_gcm_decrypt(uint8_t *ciphertext, size_t ciphertext_len,
                     uint8_t *key, uint8_t *iv, uint8_t *tag, uint8_t *plaintext) {
    Aes aes; //can use the same struct as was passed to wc_AesGcmEncrypt
    // initialize aes structure by calling wc_AesInit and wc_AesGcmSetKey
    // if not already done
    int ret;

    // Initialize AES-GCM context
    if (ret = wc_AesInit(&aes, NULL, INVALID_DEVID) != 0) {
        return -1;
    }
    // Set AES-GCM key for decryption
    if (ret = wc_AesGcmSetKey(&aes, key, KEY_SIZE) != 0) {
        return -1;
    }
    if (ret = wc_AesGcmDecrypt(&aes, plaintext, ciphertext, ciphertext_len,
                              iv, IV_SIZE, tag, AUTH_TAG_SIZE, NULL, 0) != 0) {
        return -1;
    }
    return 0;
}
