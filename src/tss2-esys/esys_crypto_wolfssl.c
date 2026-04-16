/* SPDX-FileCopyrightText: 2026, wolfSSL Inc. */
/* SPDX-License-Identifier: BSD-2-Clause */

#ifdef HAVE_CONFIG_H
#include "config.h" // IWYU pragma: keep
#endif

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

/*
 * options.h must be included before any other wolfSSL header.  It defines
 * the build-time feature flags compiled into this wolfSSL installation,
 * including WOLFSSL_AES_CFB (required for CFB mode) and HAVE_ECC (required
 * for ECDH).  Without this include first, those defines are absent and the
 * subsequent headers silently omit the declarations we depend on.
 */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/wc_port.h>  /* wolfSSL_Mutex, wc_LockMutex, wc_UnLockMutex */
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/types.h>

#include "tss2_esys.h"
#include "tss2_mu.h"
#include "util/aux_util.h"

#define LOGMODULE esys_crypto
#include "util/log.h"

/*
 * Module-level RNG handle.  wolfCrypt_Init() is reference-counted so
 * calling it from multiple threads is safe.
 *
 * g_rng_mutex (a wolfSSL_Mutex, portable across wolfSSL-supported platforms
 * including embedded RTOS targets that lack pthreads) serves two roles:
 *   1. One-time initialization: g_rng_state gates a single wc_InitRng()
 *      call.  A mutex-protected enum is used because wolfSSL provides no
 *      pthread_once equivalent; always locking before checking the state
 *      avoids double-checked-locking races.
 *   2. Ongoing RNG serialization: WC_RNG is not documented as thread-safe for
 *      concurrent wc_RNG_GenerateBlock calls.  wc_ecc_make_key_ex and
 *      wc_RsaPublicEncrypt* also consume the RNG internally, so all callers
 *      must hold g_rng_mutex for the duration of the operation.
 */
typedef enum {
    RNG_STATE_UNINITIALIZED = 0, /* wc_InitRng not yet attempted */
    RNG_STATE_FAILED,            /* wc_InitRng was attempted and failed */
    RNG_STATE_READY,             /* wc_InitRng succeeded; g_rng is usable */
} rng_state_t;
static WC_RNG        g_rng;
static rng_state_t   g_rng_state = RNG_STATE_UNINITIALIZED;
static wolfSSL_Mutex g_rng_mutex = WOLFSSL_MUTEX_INITIALIZER(g_rng_mutex);
static int           g_wolf_init_count = 0;  /* tracks wolfCrypt_Init() calls */

/*
 * Best-effort cleanup at library unload.  The ESYS_CRYPTO_CALLBACKS
 * interface has no finalize hook, so a GCC/Clang destructor is the only
 * available mechanism.  Toolchains that do not support __attribute__((destructor))
 * (e.g. MSVC, IAR) will see a wolfCrypt reference-count and RNG memory leak;
 * adding a finalize callback to ESYS_CRYPTO_CALLBACKS would be the proper fix.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((destructor))
static void wolfssl_backend_fini(void) {
    /* Hold the mutex while accessing all shared state so we cannot race with
     * a concurrent iesys_cryptwolfssl_init() or random2b() call. */
    wc_LockMutex(&g_rng_mutex);
    if (g_rng_state == RNG_STATE_READY) {
        wc_FreeRng(&g_rng);
        g_rng_state = RNG_STATE_UNINITIALIZED;
    }
    /* Drain the wolfCrypt reference count: one Cleanup() per Init() call. */
    int n = g_wolf_init_count;
    g_wolf_init_count = 0;
    wc_UnLockMutex(&g_rng_mutex);
    for (int i = 0; i < n; i++)
        wolfCrypt_Cleanup();
    /* Destroy the mutex last; no other thread may acquire it afterward. */
    wc_FreeMutex(&g_rng_mutex);
}
#endif /* __GNUC__ || __clang__ */

/** Internal context for hash and HMAC streaming operations. */
typedef struct ESYS_CRYPTO_CONTEXT_BLOB {
    enum {
        IESYS_CRYPTWOLF_TYPE_HASH = 1,
        IESYS_CRYPTWOLF_TYPE_HMAC,
    } type;
    union {
        struct {
            wc_HashAlg       ctx;
            enum wc_HashType hash_type;
            size_t           hash_len;
        } hash;
        struct {
            Hmac   ctx;
            int    hmac_type; /* WC_SHA, WC_SHA256, etc. */
            size_t hmac_len;
        } hmac;
    };
} IESYS_CRYPTWOLF_CONTEXT;

/** Map a TPM2 hash algorithm ID to a wolfSSL wc_HashType (used for hash and HMAC). */
static enum wc_HashType
tpm2_to_wc_hash_type(TPM2_ALG_ID hashAlg) {
    switch (hashAlg) {
    case TPM2_ALG_SHA1:
        return WC_HASH_TYPE_SHA;
    case TPM2_ALG_SHA256:
        return WC_HASH_TYPE_SHA256;
    case TPM2_ALG_SHA384:
        return WC_HASH_TYPE_SHA384;
    case TPM2_ALG_SHA512:
        return WC_HASH_TYPE_SHA512;
    default:
        return WC_HASH_TYPE_NONE;
    }
}


/** Initialize a hash context.
 *
 * @param[out] context Callee-allocated context.
 * @param[in]  hashAlg TPM2 hash algorithm ID.
 * @retval TSS2_RC_SUCCESS on success.
 * @retval TSS2_ESYS_RC_BAD_REFERENCE for invalid parameters.
 * @retval TSS2_ESYS_RC_MEMORY on allocation failure.
 * @retval TSS2_ESYS_RC_NOT_IMPLEMENTED for unsupported algorithms.
 * @retval TSS2_ESYS_RC_GENERAL_FAILURE for wolfSSL errors.
 */
TSS2_RC
iesys_cryptwolfssl_hash_start(ESYS_CRYPTO_CONTEXT_BLOB **context,
                           TPM2_ALG_ID                hashAlg,
                           void                      *userdata) {
    UNUSED(userdata);

    if (context == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed in for context");
    }

    IESYS_CRYPTWOLF_CONTEXT *mycontext = calloc(1, sizeof(IESYS_CRYPTWOLF_CONTEXT));
    return_if_null(mycontext, "Out of Memory", TSS2_ESYS_RC_MEMORY);

    enum wc_HashType hash_type = tpm2_to_wc_hash_type(hashAlg);
    if (hash_type == WC_HASH_TYPE_NONE) {
        LOG_ERROR("Unsupported hash algorithm (%" PRIu16 ")", hashAlg);
        SAFE_FREE(mycontext);
        return TSS2_ESYS_RC_NOT_IMPLEMENTED;
    }

    int digest_size = wc_HashGetDigestSize(hash_type);
    if (digest_size < 0) {
        SAFE_FREE(mycontext);
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "wc_HashGetDigestSize failed");
    }
    mycontext->hash.hash_len = (size_t)digest_size;
    mycontext->hash.hash_type = hash_type;

    if (wc_HashInit(&mycontext->hash.ctx, hash_type) != 0) {
        SAFE_FREE(mycontext);
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "wc_HashInit failed");
    }

    mycontext->type = IESYS_CRYPTWOLF_TYPE_HASH;
    *context = (ESYS_CRYPTO_CONTEXT_BLOB *)mycontext;
    return TSS2_RC_SUCCESS;
}

/** Update a hash context with new data.
 *
 * @param[in,out] context The hash context.
 * @param[in]     buffer  Data to hash.
 * @param[in]     size    Length of data.
 */
TSS2_RC
iesys_cryptwolfssl_hash_update(ESYS_CRYPTO_CONTEXT_BLOB *context,
                            const uint8_t            *buffer,
                            size_t                    size,
                            void                     *userdata) {
    UNUSED(userdata);

    if (context == NULL || buffer == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }
    IESYS_CRYPTWOLF_CONTEXT *mycontext = (IESYS_CRYPTWOLF_CONTEXT *)context;
    if (mycontext->type != IESYS_CRYPTWOLF_TYPE_HASH) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "bad context");
    }

    if (size > (size_t)UINT32_MAX) {
        return_error(TSS2_ESYS_RC_BAD_SIZE, "hash_update: buffer too large for wolfCrypt (>4 GiB)");
    }
    if (wc_HashUpdate(&mycontext->hash.ctx, mycontext->hash.hash_type,
                      buffer, (word32)size) != 0) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "wc_HashUpdate failed");
    }

    return TSS2_RC_SUCCESS;
}

/** Finalize a hash context, writing the digest and freeing the context.
 *
 * @param[in,out] context The hash context (freed and set to NULL).
 * @param[out]    buffer  Caller-allocated buffer to receive the digest.
 * @param[in,out] size    On input, buffer capacity; on output, digest length.
 */
TSS2_RC
iesys_cryptwolfssl_hash_finish(ESYS_CRYPTO_CONTEXT_BLOB **context,
                            uint8_t                   *buffer,
                            size_t                    *size,
                            void                      *userdata) {
    UNUSED(userdata);

    TSS2_RC r = TSS2_RC_SUCCESS;

    if (context == NULL || *context == NULL || buffer == NULL || size == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }
    IESYS_CRYPTWOLF_CONTEXT *mycontext = (IESYS_CRYPTWOLF_CONTEXT *)*context;
    if (mycontext->type != IESYS_CRYPTWOLF_TYPE_HASH) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "bad context");
    }
    if (*size < mycontext->hash.hash_len) {
        return_error(TSS2_ESYS_RC_BAD_SIZE, "Buffer too small");
    }

    if (wc_HashFinal(&mycontext->hash.ctx, mycontext->hash.hash_type, buffer) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "wc_HashFinal failed", cleanup);
    }
    *size = mycontext->hash.hash_len;

cleanup:
    wc_HashFree(&mycontext->hash.ctx, mycontext->hash.hash_type);
    SAFE_FREE(mycontext);
    *context = NULL;
    return r;
}

/** Abort a hash context, releasing resources without producing a digest. */
void
iesys_cryptwolfssl_hash_abort(ESYS_CRYPTO_CONTEXT_BLOB **context, void *userdata) {
    UNUSED(userdata);

    if (context == NULL || *context == NULL) {
        return;
    }
    IESYS_CRYPTWOLF_CONTEXT *mycontext = (IESYS_CRYPTWOLF_CONTEXT *)*context;
    if (mycontext->type != IESYS_CRYPTWOLF_TYPE_HASH) {
        return;
    }

    wc_HashFree(&mycontext->hash.ctx, mycontext->hash.hash_type);
    SAFE_FREE(mycontext);
    *context = NULL;
}

/* HMAC */

/** Initialize an HMAC context with the given key.
 *
 * @param[out] context  Callee-allocated context.
 * @param[in]  hmacAlg  TPM2 hash algorithm for the HMAC.
 * @param[in]  key      HMAC key bytes.
 * @param[in]  size     Length of key in bytes.
 */
TSS2_RC
iesys_cryptwolfssl_hmac_start(ESYS_CRYPTO_CONTEXT_BLOB **context,
                           TPM2_ALG_ID                hmacAlg,
                           const uint8_t             *key,
                           size_t                     size,
                           void                      *userdata) {
    UNUSED(userdata);

    TSS2_RC r = TSS2_RC_SUCCESS;

    if (context == NULL || key == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed in for context");
    }

    IESYS_CRYPTWOLF_CONTEXT *mycontext = calloc(1, sizeof(IESYS_CRYPTWOLF_CONTEXT));
    return_if_null(mycontext, "Out of Memory", TSS2_ESYS_RC_MEMORY);

    /* WC_SHA == WC_HASH_TYPE_SHA etc.; cast int for wc_Hmac* APIs. */
    enum wc_HashType hmac_hash_type = tpm2_to_wc_hash_type(hmacAlg);
    if (hmac_hash_type == WC_HASH_TYPE_NONE) {
        LOG_ERROR("Unsupported hash algorithm (%" PRIu16 ")", hmacAlg);
        SAFE_FREE(mycontext);
        return TSS2_ESYS_RC_NOT_IMPLEMENTED;
    }

    int hmac_len = wc_HmacSizeByType((int)hmac_hash_type);
    if (hmac_len < 0) {
        LOG_ERROR("wc_HmacSizeByType failed for hash type %d", (int)hmac_hash_type);
        SAFE_FREE(mycontext);
        return TSS2_ESYS_RC_GENERAL_FAILURE;
    }
    mycontext->hmac.hmac_len = (size_t)hmac_len;
    mycontext->hmac.hmac_type = (int)hmac_hash_type;

    if (wc_HmacInit(&mycontext->hmac.ctx, NULL, INVALID_DEVID) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "wc_HmacInit failed", cleanup);
    }

    if (size > (size_t)UINT32_MAX) {
        wc_HmacFree(&mycontext->hmac.ctx);
        goto_error(r, TSS2_ESYS_RC_BAD_SIZE, "hmac_start: key too large for wolfCrypt (>4 GiB)", cleanup);
    }
    if (wc_HmacSetKey(&mycontext->hmac.ctx, (int)hmac_hash_type, key, (word32)size) != 0) {
        wc_HmacFree(&mycontext->hmac.ctx);
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "wc_HmacSetKey failed", cleanup);
    }

    mycontext->type = IESYS_CRYPTWOLF_TYPE_HMAC;
    *context = (ESYS_CRYPTO_CONTEXT_BLOB *)mycontext;
    return TSS2_RC_SUCCESS;

cleanup:
    SAFE_FREE(mycontext);
    return r;
}

/** Update an HMAC context with new data. */
TSS2_RC
iesys_cryptwolfssl_hmac_update(ESYS_CRYPTO_CONTEXT_BLOB *context,
                            const uint8_t            *buffer,
                            size_t                    size,
                            void                     *userdata) {
    UNUSED(userdata);

    if (context == NULL || buffer == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }
    IESYS_CRYPTWOLF_CONTEXT *mycontext = (IESYS_CRYPTWOLF_CONTEXT *)context;
    if (mycontext->type != IESYS_CRYPTWOLF_TYPE_HMAC) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "bad context");
    }

    if (size > (size_t)UINT32_MAX) {
        return_error(TSS2_ESYS_RC_BAD_SIZE, "hmac_update: buffer too large for wolfCrypt (>4 GiB)");
    }
    if (wc_HmacUpdate(&mycontext->hmac.ctx, buffer, (word32)size) != 0) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "wc_HmacUpdate failed");
    }

    return TSS2_RC_SUCCESS;
}

/** Finalize an HMAC context, writing the MAC and freeing the context. */
TSS2_RC
iesys_cryptwolfssl_hmac_finish(ESYS_CRYPTO_CONTEXT_BLOB **context,
                            uint8_t                   *buffer,
                            size_t                    *size,
                            void                      *userdata) {
    UNUSED(userdata);

    TSS2_RC r = TSS2_RC_SUCCESS;

    if (context == NULL || *context == NULL || buffer == NULL || size == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed");
    }
    IESYS_CRYPTWOLF_CONTEXT *mycontext = (IESYS_CRYPTWOLF_CONTEXT *)*context;
    if (mycontext->type != IESYS_CRYPTWOLF_TYPE_HMAC) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "bad context");
    }
    if (*size < mycontext->hmac.hmac_len) {
        return_error(TSS2_ESYS_RC_BAD_SIZE, "Buffer too small");
    }

    if (wc_HmacFinal(&mycontext->hmac.ctx, buffer) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "wc_HmacFinal failed", cleanup);
    }
    *size = mycontext->hmac.hmac_len;

cleanup:
    wc_HmacFree(&mycontext->hmac.ctx);
    SAFE_FREE(mycontext);
    *context = NULL;
    return r;
}

/** Abort an HMAC context without producing a MAC. */
void
iesys_cryptwolfssl_hmac_abort(ESYS_CRYPTO_CONTEXT_BLOB **context, void *userdata) {
    UNUSED(userdata);

    if (context == NULL || *context == NULL) {
        return;
    }
    IESYS_CRYPTWOLF_CONTEXT *mycontext = (IESYS_CRYPTWOLF_CONTEXT *)*context;
    if (mycontext->type != IESYS_CRYPTWOLF_TYPE_HMAC) {
        return;
    }

    wc_HmacFree(&mycontext->hmac.ctx);
    SAFE_FREE(mycontext);
    *context = NULL;
}

/** Generate random bytes into a TPM2B_NONCE.
 *
 * @param[out] nonce     Destination (caller-allocated).
 * @param[in]  num_bytes Number of bytes to generate; 0 fills the full buffer.
 */
TSS2_RC
iesys_cryptwolfssl_random2b(TPM2B_NONCE *nonce, size_t num_bytes, void *userdata) {
    UNUSED(userdata);

    if (nonce == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Null-Pointer passed in for nonce");
    }

    size_t out_size = (num_bytes == 0) ? sizeof(nonce->buffer) : num_bytes;
    if (out_size > sizeof(nonce->buffer)) {
        return_error(TSS2_ESYS_RC_BAD_SIZE, "num_bytes exceeds nonce buffer capacity");
    }
    nonce->size = (UINT16)out_size;

    wc_LockMutex(&g_rng_mutex);
    if (g_rng_state != RNG_STATE_READY) {
        wc_UnLockMutex(&g_rng_mutex);
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "RNG not initialized");
    }
    int rc = wc_RNG_GenerateBlock(&g_rng, nonce->buffer, nonce->size);
    wc_UnLockMutex(&g_rng_mutex);
    if (rc != 0) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "wc_RNG_GenerateBlock failed");
    }

    return TSS2_RC_SUCCESS;
}

/** Encrypt a buffer with a TPM RSA public key (OAEP or PKCS#1 v1.5).
 *
 * Used during Esys_StartAuthSession to encrypt the session salt.
 *
 * @param[in]  pub_tpm_key   TPM2B_PUBLIC containing the RSA key.
 * @param[in]  in_size       Plaintext length.
 * @param[in]  in_buffer     Plaintext.
 * @param[in]  max_out_size  Output buffer capacity.
 * @param[out] out_buffer    Ciphertext output.
 * @param[out] out_size      Ciphertext length.
 * @param[in]  label         OAEP label (may be NULL for PKCS#1).
 */
TSS2_RC
iesys_cryptwolfssl_pk_encrypt(TPM2B_PUBLIC *pub_tpm_key,
                           size_t        in_size,
                           BYTE         *in_buffer,
                           size_t        max_out_size,
                           BYTE         *out_buffer,
                           size_t       *out_size,
                           const char   *label,
                           void         *userdata) {
    UNUSED(userdata);

    TSS2_RC r = TSS2_RC_SUCCESS;
    RsaKey  rsa_key;
    bool    key_inited = false;

    if (pub_tpm_key->publicArea.unique.rsa.size == 0) {
        return_error(TSS2_ESYS_RC_BAD_VALUE, "Public key size may not be 0");
    }

    if (wc_InitRsaKey(&rsa_key, NULL) != 0) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "wc_InitRsaKey failed");
    }
    key_inited = true;

    /* Build the public exponent.
     * TPM 2.0 Part 2, §12.2.3.5 (TPMT_RSA_PARMS): when the exponent field
     * is 0, the value 65537 (0x00010001) is used. */
    UINT8  exp_buf[4] = { 0x00, 0x01, 0x00, 0x01 }; /* 65537 big-endian */
    UINT32 exponent   = pub_tpm_key->publicArea.parameters.rsaDetail.exponent;
    if (exponent != 0) {
        exp_buf[0] = (UINT8)((exponent >> 24) & 0xff);
        exp_buf[1] = (UINT8)((exponent >> 16) & 0xff);
        exp_buf[2] = (UINT8)((exponent >> 8) & 0xff);
        exp_buf[3] = (UINT8)((exponent >> 0) & 0xff);
    }

    if (wc_RsaPublicKeyDecodeRaw(pub_tpm_key->publicArea.unique.rsa.buffer,
                                 pub_tpm_key->publicArea.unique.rsa.size,
                                 exp_buf, sizeof(exp_buf),
                                 &rsa_key) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "wc_RsaPublicKeyDecodeRaw failed", cleanup);
    }

    if (in_size > (size_t)UINT32_MAX || max_out_size > (size_t)UINT32_MAX) {
        goto_error(r, TSS2_ESYS_RC_BAD_SIZE,
                   "pk_encrypt: buffer too large for wolfCrypt (>4 GiB)", cleanup);
    }

    /* Initialize to error sentinel; set by each case below. */
    int enc_ret = -1;
    switch (pub_tpm_key->publicArea.parameters.rsaDetail.scheme.scheme) {
    case TPM2_ALG_OAEP: {
        /* hash_type and mgf are only needed for OAEP padding. */
        enum wc_HashType hash_type;
        int              mgf;
        switch (pub_tpm_key->publicArea.nameAlg) {
        case TPM2_ALG_SHA1:
            hash_type = WC_HASH_TYPE_SHA;   mgf = WC_MGF1SHA1;   break;
        case TPM2_ALG_SHA256:
            hash_type = WC_HASH_TYPE_SHA256; mgf = WC_MGF1SHA256; break;
        case TPM2_ALG_SHA384:
            hash_type = WC_HASH_TYPE_SHA384; mgf = WC_MGF1SHA384; break;
        case TPM2_ALG_SHA512:
            hash_type = WC_HASH_TYPE_SHA512; mgf = WC_MGF1SHA512; break;
        default:
            LOG_ERROR("Unsupported nameAlg for OAEP (%" PRIu16 ")",
                      pub_tpm_key->publicArea.nameAlg);
            r = TSS2_ESYS_RC_NOT_IMPLEMENTED;
            goto cleanup;
        }
        wc_LockMutex(&g_rng_mutex);
        if (g_rng_state != RNG_STATE_READY) {
            wc_UnLockMutex(&g_rng_mutex);
            goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "RNG not initialized", cleanup);
        }
        enc_ret = wc_RsaPublicEncrypt_ex(
            in_buffer, (word32)in_size,
            out_buffer, (word32)max_out_size,
            &rsa_key, &g_rng,
            WC_RSA_OAEP_PAD, hash_type, mgf,
            (byte *)label,
            /* +1: ESYS OAEP labels include the NUL terminator by convention;
             * see iesys_crypto_rsa_pk_encrypt() in esys_crypto.c. */
            (label != NULL) ? (word32)(strlen(label) + 1) : 0);
        wc_UnLockMutex(&g_rng_mutex);
        break;
    }
    case TPM2_ALG_RSAES:
        wc_LockMutex(&g_rng_mutex);
        if (g_rng_state != RNG_STATE_READY) {
            wc_UnLockMutex(&g_rng_mutex);
            goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "RNG not initialized", cleanup);
        }
        enc_ret = wc_RsaPublicEncrypt(
            in_buffer, (word32)in_size,
            out_buffer, (word32)max_out_size,
            &rsa_key, &g_rng);
        wc_UnLockMutex(&g_rng_mutex);
        break;
    default:
        goto_error(r, TSS2_ESYS_RC_BAD_VALUE, "Illegal RSA scheme", cleanup);
    }

    if (enc_ret < 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "RSA encrypt failed", cleanup);
    }
    *out_size = (size_t)enc_ret;

cleanup:
    if (key_inited) wc_FreeRsaKey(&rsa_key);
    return r;
}

/** Compute an ephemeral ECDH key pair and the shared secret Z.
 *
 * Implements TPM spec part 1 section C.6.1: generates an ephemeral ECC key,
 * performs ECDH with the TPM's static public key, and outputs both the
 * ephemeral public key Q and the shared secret Z.
 *
 * @param[in]  key          TPM2B_PUBLIC containing the peer ECC public key.
 * @param[in]  max_out_size Capacity of out_buffer.
 * @param[out] Z            Shared secret (x-coordinate of ECDH result).
 * @param[out] Q            Ephemeral public key in TPM format.
 * @param[out] out_buffer   Q marshaled to bytes.
 * @param[out] out_size     Length of marshaled Q.
 */
TSS2_RC
iesys_cryptwolfssl_get_ecdh_point(TPM2B_PUBLIC        *key,
                               size_t               max_out_size,
                               TPM2B_ECC_PARAMETER *Z,
                               TPMS_ECC_POINT      *Q,
                               BYTE                *out_buffer,
                               size_t              *out_size,
                               void                *userdata) {
    UNUSED(userdata);

    TSS2_RC r           = TSS2_RC_SUCCESS;
    bool    eph_inited  = false;
    bool    peer_inited = false;
    ecc_key ephemeral;
    ecc_key peer;

    int curve_id;
    int keysize;
    switch (key->publicArea.parameters.eccDetail.curveID) {
    case TPM2_ECC_NIST_P192:
        curve_id = ECC_SECP192R1;
        keysize = 24;
        break;
    case TPM2_ECC_NIST_P224:
        curve_id = ECC_SECP224R1;
        keysize = 28;
        break;
    case TPM2_ECC_NIST_P256:
        curve_id = ECC_SECP256R1;
        keysize = 32;
        break;
    case TPM2_ECC_NIST_P384:
        curve_id = ECC_SECP384R1;
        keysize = 48;
        break;
    case TPM2_ECC_NIST_P521:
        curve_id = ECC_SECP521R1;
        keysize = 66;
        break;
    default:
        LOG_ERROR("ECC curve not implemented (%" PRIu16 ")",
                  key->publicArea.parameters.eccDetail.curveID);
        return TSS2_ESYS_RC_NOT_IMPLEMENTED;
    }

    /* Generate the ephemeral key pair. */
    if (wc_ecc_init(&ephemeral) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "wc_ecc_init ephemeral failed", cleanup);
    }
    eph_inited = true;

    wc_LockMutex(&g_rng_mutex);
    if (g_rng_state != RNG_STATE_READY) {
        wc_UnLockMutex(&g_rng_mutex);
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "RNG not initialized", cleanup);
    }
    int make_key_rc = wc_ecc_make_key_ex(&g_rng, keysize, &ephemeral, curve_id);
    wc_UnLockMutex(&g_rng_mutex);
    if (make_key_rc != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "wc_ecc_make_key_ex failed", cleanup);
    }

    /* Export ephemeral public key coordinates to TPM format. */
    word32 qx_len = TPM2_MAX_ECC_KEY_BYTES;
    word32 qy_len = TPM2_MAX_ECC_KEY_BYTES;
    if (wc_ecc_export_public_raw(&ephemeral,
                                 Q->x.buffer, &qx_len,
                                 Q->y.buffer, &qy_len) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "wc_ecc_export_public_raw failed", cleanup);
    }
    Q->x.size = (UINT16)qx_len;
    Q->y.size = (UINT16)qy_len;

    /* Import the TPM's static public key. */
    if (wc_ecc_init(&peer) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "wc_ecc_init peer failed", cleanup);
    }
    peer_inited = true;

    /* Validate coordinate sizes before passing raw pointers to wolfSSL.
     * wc_ecc_import_raw_private (called internally) reads exactly dp->size bytes
     * from qx/qy unconditionally, with no caller-supplied length; a short
     * coordinate would cause a buffer over-read. */
    if (key->publicArea.unique.ecc.x.size != (UINT16)keysize ||
        key->publicArea.unique.ecc.y.size != (UINT16)keysize) {
        goto_error(r, TSS2_ESYS_RC_BAD_VALUE,
                   "ECC public key coordinate size mismatch", cleanup);
    }

    if (wc_ecc_import_unsigned(&peer,
                               key->publicArea.unique.ecc.x.buffer,
                               key->publicArea.unique.ecc.y.buffer,
                               NULL, /* public key only */
                               curve_id) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "wc_ecc_import_unsigned failed", cleanup);
    }

    /*
     * Explicitly validate that the imported point lies on the curve.
     * wolfSSL's ECC_POINT_CHECK build option controls whether
     * wc_ecc_import_unsigned does this internally; calling wc_ecc_check_key
     * here is unconditional and guards against invalid-curve attacks from
     * a malicious TPM response.
     */
    if (wc_ecc_check_key(&peer) != 0) {
        goto_error(r, TSS2_ESYS_RC_BAD_VALUE,
                   "Peer ECC public key failed on-curve validation", cleanup);
    }

    /* Compute the shared secret Z = ephemeral_priv * peer_pub.
     * wc_ecc_shared_secret requires private_key->rng != NULL when
     * ECC_TIMING_RESISTANT is defined (present in this wolfSSL build).
     * wc_ecc_make_key_ex does not set key->rng, so we must call
     * wc_ecc_set_rng explicitly.  Hold g_rng_mutex across both calls so
     * g_rng is not accessed concurrently from another thread. */
    word32 z_len = (word32)keysize;
    wc_LockMutex(&g_rng_mutex);
    if (g_rng_state != RNG_STATE_READY) {
        wc_UnLockMutex(&g_rng_mutex);
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "RNG not initialized", cleanup);
    }
    if (wc_ecc_set_rng(&ephemeral, &g_rng) != 0) {
        wc_UnLockMutex(&g_rng_mutex);
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "wc_ecc_set_rng failed", cleanup);
    }
    int ss_rc = wc_ecc_shared_secret(&ephemeral, &peer, Z->buffer, &z_len);
    wc_UnLockMutex(&g_rng_mutex);
    if (ss_rc != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE,
                   "wc_ecc_shared_secret failed", cleanup);
    }
    /*
     * wc_ecc_shared_secret strips leading zeros from the x-coordinate.
     * TPM Part 1 §C.6.1 requires Z to be the full curve-coordinate width
     * (keysize bytes for this curve). Zero-pad from the front when short.
     */
    if ((int)z_len < keysize) {
        int pad = keysize - (int)z_len;
        memmove(Z->buffer + pad, Z->buffer, z_len);
        memset(Z->buffer, 0, (size_t)pad);
    }
    Z->size = (UINT16)keysize;

    /* Marshal Q for the caller. */
    size_t offset = 0;
    r = Tss2_MU_TPMS_ECC_POINT_Marshal(Q, out_buffer, max_out_size, &offset);
    goto_if_error(r, "Error marshaling Q", cleanup);
    *out_size = offset;

cleanup:
    if (peer_inited) wc_ecc_free(&peer);
    if (eph_inited) wc_ecc_free(&ephemeral);
    return r;
}

/** Encrypt a buffer in-place with AES in CFB mode.
 *
 * @param[in]     key          AES key bytes.
 * @param[in]     tpm_sym_alg  Must be TPM2_ALG_AES.
 * @param[in]     key_bits     Key size in bits (128, 192, or 256).
 * @param[in]     tpm_mode     Must be TPM2_ALG_CFB.
 * @param[in,out] buffer       Data buffer; encrypted in-place.
 * @param[in]     buffer_size  Length of buffer.
 * @param[in]     iv           Initialization vector (16 bytes).
 */
TSS2_RC
iesys_cryptwolfssl_sym_aes_encrypt(uint8_t          *key,
                                TPM2_ALG_ID       tpm_sym_alg,
                                TPMI_AES_KEY_BITS key_bits,
                                TPM2_ALG_ID       tpm_mode,
                                uint8_t          *buffer,
                                size_t            buffer_size,
                                uint8_t          *iv,
                                void             *userdata) {
    UNUSED(userdata);

    TSS2_RC r = TSS2_RC_SUCCESS;
    Aes     aes_ctx;

    if (key == NULL || buffer == NULL || iv == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Bad reference");
    }
    if (tpm_sym_alg != TPM2_ALG_AES) {
        return_error(TSS2_ESYS_RC_BAD_VALUE, "sym_aes_encrypt: unexpected symmetric algorithm");
    }
    if (tpm_mode != TPM2_ALG_CFB) {
        return_error(TSS2_ESYS_RC_BAD_VALUE, "sym_aes_encrypt: unexpected cipher mode");
    }

    if (wc_AesInit(&aes_ctx, NULL, INVALID_DEVID) != 0) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "wc_AesInit failed");
    }

    /* CFB uses the encrypt key schedule for both directions.
     * key_bits is always 128, 192, or 256 per TPM spec; division is exact. */
    if (wc_AesSetKey(&aes_ctx, key, key_bits / 8, iv, AES_ENCRYPTION) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "wc_AesSetKey failed", cleanup);
    }

    if (buffer_size > (size_t)UINT32_MAX) {
        goto_error(r, TSS2_ESYS_RC_BAD_SIZE, "sym_aes_encrypt: buffer too large for wolfCrypt (>4 GiB)", cleanup);
    }
    if (wc_AesCfbEncrypt(&aes_ctx, buffer, buffer, (word32)buffer_size) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "wc_AesCfbEncrypt failed", cleanup);
    }

cleanup:
    wc_AesFree(&aes_ctx);
    return r;
}

/** Decrypt a buffer in-place with AES in CFB mode.
 *
 * @param[in]     key          AES key bytes.
 * @param[in]     tpm_sym_alg  Must be TPM2_ALG_AES.
 * @param[in]     key_bits     Key size in bits (128, 192, or 256).
 * @param[in]     tpm_mode     Must be TPM2_ALG_CFB.
 * @param[in,out] buffer       Data buffer; decrypted in-place.
 * @param[in]     buffer_size  Length of buffer.
 * @param[in]     iv           Initialization vector (16 bytes).
 */
TSS2_RC
iesys_cryptwolfssl_sym_aes_decrypt(uint8_t          *key,
                                TPM2_ALG_ID       tpm_sym_alg,
                                TPMI_AES_KEY_BITS key_bits,
                                TPM2_ALG_ID       tpm_mode,
                                uint8_t          *buffer,
                                size_t            buffer_size,
                                uint8_t          *iv,
                                void             *userdata) {
    UNUSED(userdata);

    TSS2_RC r = TSS2_RC_SUCCESS;
    Aes     aes_ctx;

    if (key == NULL || buffer == NULL || iv == NULL) {
        return_error(TSS2_ESYS_RC_BAD_REFERENCE, "Bad reference");
    }
    if (tpm_sym_alg != TPM2_ALG_AES) {
        return_error(TSS2_ESYS_RC_BAD_VALUE, "sym_aes_decrypt: unexpected symmetric algorithm");
    }
    if (tpm_mode != TPM2_ALG_CFB) {
        return_error(TSS2_ESYS_RC_BAD_VALUE, "sym_aes_decrypt: unexpected cipher mode");
    }

    if (wc_AesInit(&aes_ctx, NULL, INVALID_DEVID) != 0) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "wc_AesInit failed");
    }

    /* CFB decryption uses the same AES_ENCRYPTION key schedule, because
     * CFB mode encrypts the keystream then XORs it with the ciphertext.
     * key_bits is always 128, 192, or 256 per TPM spec; division is exact. */
    if (wc_AesSetKey(&aes_ctx, key, key_bits / 8, iv, AES_ENCRYPTION) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "wc_AesSetKey failed", cleanup);
    }

    if (buffer_size > (size_t)UINT32_MAX) {
        goto_error(r, TSS2_ESYS_RC_BAD_SIZE, "sym_aes_decrypt: buffer too large for wolfCrypt (>4 GiB)", cleanup);
    }
    if (wc_AesCfbDecrypt(&aes_ctx, buffer, buffer, (word32)buffer_size) != 0) {
        goto_error(r, TSS2_ESYS_RC_GENERAL_FAILURE, "wc_AesCfbDecrypt failed", cleanup);
    }

cleanup:
    wc_AesFree(&aes_ctx);
    return r;
}

/** Backend initialization: bring up wolfCrypt and seed the shared RNG. */
TSS2_RC
iesys_cryptwolfssl_init(void *userdata) {
    UNUSED(userdata);
    if (wolfCrypt_Init() != 0) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "wolfCrypt_Init failed");
    }
    /*
     * Track each successful wolfCrypt_Init() and, on the very first call,
     * initialize the shared RNG.  All updates are under g_rng_mutex.
     * The mutex-protected g_rng_state enum is used in place of pthread_once
     * because wolfSSL has no equivalent primitive; always locking before
     * checking avoids double-checked-locking races.
     */
    wc_LockMutex(&g_rng_mutex);
    g_wolf_init_count++;
    if (g_rng_state == RNG_STATE_UNINITIALIZED) {
        int rc = wc_InitRng(&g_rng);
        g_rng_state = (rc == 0) ? RNG_STATE_READY : RNG_STATE_FAILED;
    }
    /* Capture before releasing: g_rng_state is not atomic, so reading it
     * after the mutex is released would be a C11 data race. */
    int failed = (g_rng_state == RNG_STATE_FAILED);
    wc_UnLockMutex(&g_rng_mutex);
    if (failed) {
        return_error(TSS2_ESYS_RC_GENERAL_FAILURE, "wc_InitRng failed");
    }
    return TSS2_RC_SUCCESS;
}
