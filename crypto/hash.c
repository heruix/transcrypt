#include "hash.h"
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/internal/hash.h>
#include <crypto/hash.h>
#include <linux/slab.h>

char *hash_name[]={"raw", "md2", "md4", "md5", "sha1", "sha224", "sha256", "sha384", "sha512"};

md_info_t * md_info_from_type( md_type_t hash_id)
{
	md_info_t *p = NULL;
	p = kmalloc( sizeof(md_info_t), GFP_KERNEL);
	p->shash = crypto_alloc_shash( hash_name[hash_id], 0, 0);
	p->size = crypto_shash_digestsize(p->shash);
	p->sdesc.desc = kmalloc( sizeof(struct shash_desc) + crypto_shash_descsize(p->shash), GFP_KERNEL);
	p->sdesc.desc->tfm = p->shash;
	p->sdesc.desc->flags = 0x0;
	return p;
}

unsigned int md_get_size( const md_info_t *md_info)
{
	return md_info->size;
}

int md_init_ctx( md_context_t *ctx, const md_info_t *md_info)
{
	int ret = 0;
	if( md_info == NULL || ctx == NULL )
	        return POLARSSL_ERR_MD_BAD_INPUT_DATA;

	memset( ctx, 0, sizeof( md_context_t ) );

	ctx->md_info = md_info;
	ret = crypto_shash_init(md_info->sdesc.desc);
	return ret;
}

int md_starts ( md_context_t *ctx ) 
{
	if( ctx == NULL || ctx->md_info == NULL )
		return POLARSSL_ERR_MD_BAD_INPUT_DATA;

	return crypto_shash_init(ctx->md_info->sdesc.desc);
}

int md_update( md_context_t *ctx, const unsigned char *buf, unsigned int buflen ) 
{
	if( ctx == NULL || ctx->md_info == NULL )
		return POLARSSL_ERR_MD_BAD_INPUT_DATA;
	
	return crypto_shash_update(ctx->md_info->sdesc.desc, buf, buflen);
}

int md_finish( md_context_t *ctx, unsigned char *buf)
{
	if( ctx == NULL || ctx->md_info == NULL )
		return POLARSSL_ERR_MD_BAD_INPUT_DATA;

	return crypto_shash_final( ctx->md_info->sdesc.desc, buf );
}

int md_info_free ( const md_info_t *md_info ) 
{
	if( md_info == NULL )
		return POLARSSL_ERR_MD_BAD_INPUT_DATA;

	crypto_free_shash(md_info->shash);
	kfree(md_info->sdesc.desc);
	kfree(md_info);
	return 0;
}

int md( const md_info_t *md_info, const unsigned char *buf, int buflen, unsigned char *hash)
{
	return crypto_shash_digest(md_info->sdesc.desc, buf, buflen, hash);	
}

int md2(const unsigned char *buf, int buflen, unsigned char *out)
{
	md_info_t *md_info;
	md_context_t md_ctx;
	md_info = md_info_from_type( POLARSSL_MD_MD2);
	if( md_info == NULL )
		return POLARSSL_ERR_MD_BAD_INPUT_DATA;
	md_init_ctx( &md_ctx, md_info);
	md(md_info, buf, buflen, out);
	md_info_free(md_info);
	return 0;
}
int md4(const unsigned char *buf, int buflen, unsigned char *out)
{
	md_info_t *md_info;
	md_context_t md_ctx;
	md_info = md_info_from_type( POLARSSL_MD_MD4);
	if( md_info == NULL )
		return POLARSSL_ERR_MD_BAD_INPUT_DATA;
	md_init_ctx( &md_ctx, md_info);
	md(md_info, buf, buflen, out);
	md_info_free(md_info);
	return 0;
}
int md5(const unsigned char *buf, int buflen, unsigned char *out)
{
	md_info_t *md_info;
	md_context_t md_ctx;
	md_info = md_info_from_type( POLARSSL_MD_MD5);
	if( md_info == NULL )
		return POLARSSL_ERR_MD_BAD_INPUT_DATA;
	md_init_ctx( &md_ctx, md_info);
	md(md_info, buf, buflen, out);
	md_info_free(md_info);
	return 0;
}
int sha1(const unsigned char *buf, int buflen, unsigned char *out)
{
	md_info_t *md_info;
	md_context_t md_ctx;
	md_info = md_info_from_type( POLARSSL_MD_SHA1);
	if( md_info == NULL )
		return POLARSSL_ERR_MD_BAD_INPUT_DATA;
	md_init_ctx( &md_ctx, md_info);
	md(md_info, buf, buflen, out);
	md_info_free(md_info);
	return 0;
}
int sha2(const unsigned char *buf, int buflen, unsigned char *out, int flag)
{
	md_info_t *md_info;
	md_context_t md_ctx;
	if(flag)
		md_info = md_info_from_type( POLARSSL_MD_SHA224);
	else
		md_info = md_info_from_type( POLARSSL_MD_SHA256);
	if( md_info == NULL )
		return POLARSSL_ERR_MD_BAD_INPUT_DATA;
	md_init_ctx( &md_ctx, md_info);
	md(md_info, buf, buflen, out);
	md_info_free(md_info);
	return 0;
}
int sha4(const unsigned char *buf, int buflen, unsigned char *out, int flag)
{
	md_info_t *md_info;
	md_context_t md_ctx;
	if(flag)
		md_info = md_info_from_type( POLARSSL_MD_SHA384);
	else
		md_info = md_info_from_type( POLARSSL_MD_SHA512);
	if( md_info == NULL )
		return POLARSSL_ERR_MD_BAD_INPUT_DATA;
	md_init_ctx( &md_ctx, md_info);
	md(md_info, buf, buflen, out);
	md_info_free(md_info);
	return 0;
}

int des_setkey_dec( des_context *des_ctx, unsigned char *key)
{
	return crypto_blkcipher_setkey(des_ctx->tfm, key, 8);
}

int des_init_ctx(des_context *des_ctx)
{
	des_ctx->tfm = crypto_alloc_blkcipher("cbc(des)", 0, CRYPTO_ALG_ASYNC);
	des_ctx->desc.tfm = des_ctx->tfm;
	des_ctx->desc.flags = 0;
	return 0;
}

int des_free_ctx(des_context *des_ctx)
{
	crypto_free_blkcipher(des_ctx->tfm);
	return 0;
}

int des_crypt_cbc( des_context *des_ctx, int flag, int buflen, unsigned char *iv, 
		  const unsigned char *buf, unsigned char *out)
{
	unsigned int nents = buflen/PAGE_SIZE + (buflen%PAGE_SIZE != 0);
	struct scatterlist sg[nents];
	unsigned int minlen = min_t(unsigned int, PAGE_SIZE, buflen);
	unsigned int tbuflen = buflen;
	int j;
	
	// sg = kzalloc( sizeof(struct scatterlist)*nents , GFP_KERNEL);

	sg_init_table( sg, nents );
	sg_set_buf(sg, buf, minlen);
	tbuflen -= minlen;
	for( j=1; j<nents; j++) {
	    if(tbuflen >= PAGE_SIZE) {
	        sg_set_buf(sg+j, buf+minlen, PAGE_SIZE);
	        minlen += PAGE_SIZE;
	        tbuflen -= PAGE_SIZE;
	    } else {
	        sg_set_buf(sg+j, buf+minlen, tbuflen);
	        tbuflen -= tbuflen;
	    }
	}
	
	BUG_ON(tbuflen != 0);
	crypto_blkcipher_set_iv(des_ctx->tfm, iv, 8);
	crypto_blkcipher_decrypt(&des_ctx->desc, sg, sg, buflen);
	// sg_kfree(sg, nents);
	return 0;
}

int des3_set3key_dec( des3_context *des_ctx, unsigned char *key)
{
	return crypto_blkcipher_setkey(des_ctx->tfm, key, 24);
}

int des3_init_ctx(des3_context *des_ctx)
{
	des_ctx->tfm = crypto_alloc_blkcipher("cbc(des3_ede)", 0, CRYPTO_ALG_ASYNC);
	des_ctx->desc.tfm = des_ctx->tfm;
	des_ctx->desc.flags = 0;
	return 0;
}

int des3_free_ctx(des3_context *des_ctx)
{
	crypto_free_blkcipher(des_ctx->tfm);
	return 0;
}

int des3_crypt_cbc( des3_context *des_ctx, int flag, int buflen, unsigned char *iv, 
		  const unsigned char *buf, unsigned char *out)
{
	unsigned int nents = buflen/PAGE_SIZE + (buflen%PAGE_SIZE != 0);
	struct scatterlist sg[nents];
	unsigned int minlen = min_t(unsigned int, PAGE_SIZE, buflen);
	unsigned int tbuflen = buflen;
	int j;
	
	// sg = kzalloc( sizeof(struct scatterlist)*nents , GFP_KERNEL);

	sg_init_table( sg, nents );
	sg_set_buf(sg, buf, minlen);
	tbuflen -= minlen;
	for( j=1; j<nents; j++) {
	    if(tbuflen >= PAGE_SIZE) {
	        sg_set_buf(sg+j, buf+minlen, PAGE_SIZE);
	        minlen += PAGE_SIZE;
	        tbuflen -= PAGE_SIZE;
	    } else {
	        sg_set_buf(sg+j, buf+minlen, tbuflen);
	        tbuflen -= tbuflen;
	    }
	}
	
	BUG_ON(tbuflen != 0);
	crypto_blkcipher_set_iv(des_ctx->tfm, iv, 8);
	crypto_blkcipher_decrypt(&des_ctx->desc, sg, sg, buflen);
	// sg_kfree(sg, nents);
	return 0;
}

int aes_setkey_dec( aes_context *aes_ctx, unsigned char *key, int keylen)
{
	return crypto_blkcipher_setkey(aes_ctx->tfm, key, keylen/8);
}

int aes_init_ctx(aes_context *aes_ctx)
{
	aes_ctx->tfm = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
	aes_ctx->desc.tfm = aes_ctx->tfm;
	aes_ctx->desc.flags = 0;
	return 0;
}

int aes_free_ctx(aes_context *aes_ctx)
{
	crypto_free_blkcipher(aes_ctx->tfm);
	return 0;
}

int aes_crypt_cbc( aes_context *aes_ctx, int flag, int buflen, unsigned char *iv, 
		  const unsigned char *buf, unsigned char *out)
{
	unsigned int nents = buflen/PAGE_SIZE + (buflen%PAGE_SIZE != 0);
	struct scatterlist sg[nents];
	unsigned int minlen = min_t(unsigned int, PAGE_SIZE, buflen);
	unsigned int tbuflen = buflen;
	int j;
	
	// sg = kzalloc( sizeof(struct scatterlist)*nents , GFP_KERNEL);

	sg_init_table( sg, nents );
	sg_set_buf(sg, buf, minlen);
	tbuflen -= minlen;
	for( j=1; j<nents; j++) {
	    if(tbuflen >= PAGE_SIZE) {
	        sg_set_buf(sg+j, buf+minlen, PAGE_SIZE);
	        minlen += PAGE_SIZE;
	        tbuflen -= PAGE_SIZE;
	    } else {
	        sg_set_buf(sg+j, buf+minlen, tbuflen);
	        tbuflen -= tbuflen;
	    }
	}
	
	BUG_ON(tbuflen != 0);
	crypto_blkcipher_set_iv(aes_ctx->tfm, iv, 16);
	crypto_blkcipher_decrypt(&aes_ctx->desc, sg, sg, buflen);
	// sg_kfree(sg, nents);
	return 0;
}
static void hmac_sha1_complete(struct crypto_async_request *req, int err) {
        struct hmac_sha1_result *r=req->data;
        if(err==-EINPROGRESS)
                return;
        r->err=err;
        complete(&r->completion);
}

int hmac_sha1(u8 *data_in, size_t dlen, // key and key length
                        const char *key, size_t klen,     // data in and length
                        u8 *hash_out, size_t outlen) {  // hash buffer and length
        int rc=0;
        struct crypto_ahash *tfm;
        struct scatterlist sg;
        struct ahash_request *req;
        struct hmac_sha1_result tresult;
        void *hash_buf;

        int len = 20;
        // char hash_tmp[20];
        // char *hash_res = hash_tmp;

        /* Set hash output to 0 initially */
        memset(hash_out, 0, outlen);

        init_completion(&tresult.completion);
        tfm=crypto_alloc_ahash("hmac(sha1)",0,0);
        if(IS_ERR(tfm)) {
                printk(KERN_ERR "hmac_sha1: crypto_alloc_ahash failed.n");
                rc=PTR_ERR(tfm);
                goto err_tfm;
        }
        if(!(req=ahash_request_alloc(tfm,GFP_KERNEL))) {
                printk(KERN_ERR "hmac_sha1: failed to allocate request for hmac(sha1)n");
                rc=-ENOMEM;
                goto err_req;
        }
        if(crypto_ahash_digestsize(tfm)>len) {
                printk(KERN_ERR "hmac_sha1: tfm size > result buffer.n");
                rc=-EINVAL;
                goto err_req;
        }
        ahash_request_set_callback(req,CRYPTO_TFM_REQ_MAY_BACKLOG,
                                        hmac_sha1_complete,&tresult);

        if(!(hash_buf=kzalloc(dlen,GFP_KERNEL))) {
                printk(KERN_ERR "hmac_sha1: failed to kzalloc hash_buf");
                rc=-ENOMEM;
                goto err_hash_buf;
        }
        memcpy(hash_buf,data_in,dlen);
        sg_init_one(&sg,hash_buf,dlen);

        crypto_ahash_clear_flags(tfm,-0);
        if((rc=crypto_ahash_setkey(tfm,key,klen))){
                printk(KERN_ERR "hmac_sha1: crypto_ahash_setkey failedn");
                goto err_setkey;
        }
        ahash_request_set_crypt(req,&sg,hash_out,dlen);
        rc=crypto_ahash_digest(req);
        switch(rc) {
                // case 0:
                //         while (len--) {
                //                 snprintf(hash_out, outlen, "%02x", (*hash_res++ & 0x0FF));
                //                 hash_out += 2;
                //         }

                //         break;
                case -EINPROGRESS:
                case -EBUSY:
                        rc=wait_for_completion_interruptible(&tresult.completion);
                        if(!rc && !(rc=tresult.err)) {
                                INIT_COMPLETION(tresult.completion);
                                break;
                        } else {
                                printk(KERN_ERR "hmac_sha1: wait_for_completion_interruptible failedn");
                                goto out;
                        }
                default:
                        goto out;
        }

        out:
        err_setkey:
                kfree(hash_buf);
        err_hash_buf:
                ahash_request_free(req);
        err_req:
                crypto_free_ahash(tfm);
        err_tfm:
                return rc;
}

