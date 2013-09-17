#include <linux/crypto.h>
#include <crypto/hash.h>
#include <crypto/internal/hash.h>

#ifndef _TRANSCRYPT_HASH_H
#define _TRANSCRYPT_HASH_H

#define POLARSSL_ERR_MD_FEATURE_UNAVAILABLE                -0x5080  /**< The selected feature is not available. */
#define POLARSSL_ERR_MD_BAD_INPUT_DATA                     -0x5100  /**< Bad input parameters to function. */
#define POLARSSL_ERR_MD_ALLOC_FAILED                       -0x5180  /**< Failed to allocate memory. */
#define POLARSSL_ERR_MD_FILE_IO_ERROR                      -0x5200  /**< Opening or reading of file failed. */

typedef enum {
    POLARSSL_MD_NONE=0,
    POLARSSL_MD_MD2,
    POLARSSL_MD_MD4,
    POLARSSL_MD_MD5,
    POLARSSL_MD_SHA1,
    POLARSSL_MD_SHA224,
    POLARSSL_MD_SHA256,
    POLARSSL_MD_SHA384,
    POLARSSL_MD_SHA512,
} md_type_t;

typedef enum {
    POLARSSL_CIPHER_NONE = 0,
    POLARSSL_CIPHER_AES_128_CBC,
    POLARSSL_CIPHER_AES_192_CBC,
    POLARSSL_CIPHER_AES_256_CBC,
    POLARSSL_CIPHER_AES_128_CFB128,
    POLARSSL_CIPHER_AES_192_CFB128,
    POLARSSL_CIPHER_AES_256_CFB128,
    POLARSSL_CIPHER_AES_128_CTR,
    POLARSSL_CIPHER_AES_192_CTR,
    POLARSSL_CIPHER_AES_256_CTR,
    POLARSSL_CIPHER_CAMELLIA_128_CBC,
    POLARSSL_CIPHER_CAMELLIA_192_CBC,
    POLARSSL_CIPHER_CAMELLIA_256_CBC,
    POLARSSL_CIPHER_CAMELLIA_128_CFB128,
    POLARSSL_CIPHER_CAMELLIA_192_CFB128,
    POLARSSL_CIPHER_CAMELLIA_256_CFB128,
    POLARSSL_CIPHER_CAMELLIA_128_CTR,
    POLARSSL_CIPHER_CAMELLIA_192_CTR,
    POLARSSL_CIPHER_CAMELLIA_256_CTR,
    POLARSSL_CIPHER_DES_CBC,
    POLARSSL_CIPHER_DES_EDE_CBC,
    POLARSSL_CIPHER_DES_EDE3_CBC
} cipher_type_t;


#define POLARSSL_MD_MAX_SIZE         64

struct transcryptfs_sdesc {
                struct shash_desc *desc;
                void *ctx[];
    };

typedef struct {
	struct crypto_shash *shash;
	unsigned int size;
	struct transcryptfs_sdesc sdesc;
} md_info_t;

typedef struct {
	md_info_t *md_info;
} md_context_t;

typedef struct {
	struct crypto_blkcipher *tfm;
   	struct blkcipher_desc desc;
} des_context;

typedef struct {
	struct crypto_blkcipher *tfm;
   	struct blkcipher_desc desc;
} des3_context;

typedef struct {
	struct crypto_blkcipher *tfm;
   	struct blkcipher_desc desc;
} aes_context;

md_info_t * md_info_from_type( md_type_t hash_id );	

unsigned int md_get_size(const md_info_t *md_info );

int md_init_ctx( md_context_t *ctx, const md_info_t *md_info);

int md_starts( md_context_t *ctx );

int md_update( md_context_t *ctx, const unsigned char *buf, unsigned int buflen);

int md_finish( md_context_t *ctx, unsigned char *buf);

int md_info_free(const md_info_t *md_info);

int md(const md_info_t *md_info, const unsigned char *buf, int buflen, unsigned char *out);

int md2(const unsigned char *buf, int buflen, unsigned char *out);

int md4(const unsigned char *buf, int buflen, unsigned char *out);

int md5(const unsigned char *buf, int buflen, unsigned char *out);

int sha1(const unsigned char *buf, int buflen, unsigned char *out);

int sha2(const unsigned char *buf, int buflen, unsigned char *out, int flag);

int sha4(const unsigned char *buf, int buflen, unsigned char *out, int flag);

int des_setkey_dec( des_context *des_ctx, unsigned char *key);

int des_init_ctx(des_context *des_ctx);

int des_free_ctx(des_context *des_ctx);

int des_crypt_cbc( des_context *des_ctx, int flag, int buflen, unsigned char *iv,
                  const unsigned char *buf, unsigned char *out);

int des3_set3key_dec( des3_context *des_ctx, unsigned char *key);

int des3_init_ctx(des3_context *des_ctx);

int des3_free_ctx(des3_context *des_ctx);

int des3_crypt_cbc( des3_context *des_ctx, int flag, int buflen, unsigned char *iv,
                  const unsigned char *buf, unsigned char *out);

int aes_setkey_dec( aes_context *aes_ctx, unsigned char *key, int keylen);

int aes_init_ctx(aes_context *aes_ctx);

int aes_free_ctx(aes_context *aes_ctx);

int aes_crypt_cbc( aes_context *aes_ctx, int flag, int buflen, unsigned char *iv,
                  const unsigned char *buf, unsigned char *out);

struct hmac_sha1_result {
        struct completion completion;
        int err;
};

int hmac_sha1(u8 *data_in, size_t dlen, // key and key length
                        const char *key, size_t klen,     // data in and length
                        u8 *hash_out, size_t outlen);
#endif

