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
#include "utils.h"
#include <stdint.h>
#include <string.h>


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
int ed25519_authenticate(const byte* sig, const byte* msg, word32 msgSz, const byte* pubKey) {
    volatile int ret_init = -1;
    volatile int ret_import = -1;
    volatile int ret_verify = -1;
    int result = 0;
    ed25519_key myKey = {0};

    ret_init = wc_ed25519_init(&myKey);
    if (ret_init != 0 || ret_init != 0 || ret_init != 0) {
        // The caller has violated the function's contract,
        // this can only be caused by a hardware fault.
        HALT_AND_CATCH_FIRE();
        return -1;
    }
    ret_import = wc_ed25519_import_public(pubKey, KEY_SIZE, &myKey);
    if (ret_import != 0 || ret_import != 0 || ret_import != 0) {
        // The caller has violated the function's contract,
        // this can only be caused by a hardware fault.
        HALT_AND_CATCH_FIRE();
        return -1;
    }
    ret_verify = wc_ed25519_verify_msg(sig, SIG_SIZE, msg, msgSz, &result, &myKey);
    if ((volatile int) result != 1 || ret_verify != 0 || ret_verify != 0 || (volatile int) result != 1 || (volatile int) result != 1) {
        return -1;
    }
    wc_ed25519_free(&myKey);
    return ret_verify;
}

// Zhong: AES_GCM
#define IV_SIZE 12 
#define AUTH_TAG_SIZE 16

int aes_gcm_decrypt(uint8_t *ciphertext, size_t ciphertext_len,
                     uint8_t *key, uint8_t *iv, uint8_t *tag, uint8_t *plaintext) {
    Aes aes = {0}; // AES-GCM context
    volatile int ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    // Initialize AES-GCM context
    if (ret != 0 || ret != 0 || ret != 0) {
        // The caller has violated the function's contract,
        // this can only be caused by a hardware fault.
        HALT_AND_CATCH_FIRE();
        return -1;
    }
    volatile int ret_set_key = wc_AesGcmSetKey(&aes, key, KEY_SIZE);
    // Set AES-GCM key for decryption
    if (ret_set_key != 0 || ret_set_key != 0 || ret_set_key != 0) {
        // The caller has violated the function's contract,
        // this can only be caused by a hardware fault.
        HALT_AND_CATCH_FIRE();
        return -1;
    }
    volatile int ret_decrypt = wc_AesGcmDecrypt(&aes, plaintext, ciphertext, ciphertext_len,
                              iv, IV_SIZE, tag, AUTH_TAG_SIZE, NULL, 0);
    if (ret_decrypt != 0 || ret_decrypt != 0 || ret_decrypt != 0) {
        // The caller has violated the function's contract,
        // the decryption failure after authentication can only be caused by a hardware fault.
        HALT_AND_CATCH_FIRE();
        return -1;
    }

    if (ret | ret_set_key | ret_decrypt) { 
        // The caller has violated the function's contract,
        // this can only be caused by a hardware fault.
        HALT_AND_CATCH_FIRE();
        return -1;
    }
    return 0;
}
