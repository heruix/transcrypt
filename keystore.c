#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/key.h>
#include <linux/random.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include "transcryptfs.h"
#include "crypto/include/rsa.h"
#include "crypto/include/x509.h"
#include "crypto/include/certs.h"


int transcryptfs_generate_tokens(char *dest_base,
				struct transcryptfs_crypt_stat *crypt_stat,
				struct dentry *transcryptfs_dentry, 
				size_t *len, size_t max)
{
	unsigned char blinded_key[crypt_stat->key_size];	
	struct scatterlist dst_sg[2];
	struct scatterlist src_sg[2];
	struct crypto_blkcipher *tfm;
	struct blkcipher_desc desc = {
		.tfm = NULL,
		.flags = CRYPTO_TFM_REQ_MAY_SLEEP
	};
	struct transcryptfs_mount_crypt_stat *mount_crypt_stat;
	x509_cert *cacert;
	x509_cert *clicert;
	unsigned char *token;
	size_t token_size;
	int flags;
	int err = 0;

	cacert = kmalloc(sizeof(x509_cert),  GFP_KERNEL);
	clicert = kmalloc(sizeof(x509_cert),  GFP_KERNEL);


	mount_crypt_stat = crypt_stat->mount_crypt_stat;
	
	memset(blinded_key, 0, crypt_stat->key_size);
	
	err = virt_to_scatterlist(crypt_stat->key, crypt_stat->key_size, src_sg, 2);

	if (err < 1 || err > 2) {
                printk(KERN_ERR "Error generating scatterlist "
                                "for crypt_stat session key; expected err = 1; "
                                "got err = [%d].\n", err);
                err = -ENOMEM;
                goto out;
        }

	err = virt_to_scatterlist(blinded_key, crypt_stat->key_size, dst_sg, 2);

	if (err < 1 || err > 2) {
                printk(KERN_ERR "Error generating scatterlist "
                                "for crypt_stat session key; expected err = 1; "
                                "got err = [%d].\n", err);
                err = -ENOMEM;
                goto out;
        }

	tfm = crypto_alloc_blkcipher(mount_crypt_stat->global_blinding_cipher, 
				     0, CRYPTO_ALG_ASYNC);
	desc.tfm = tfm;

	err = crypto_blkcipher_setkey(desc.tfm, mount_crypt_stat->fsk,
				      mount_crypt_stat->fsk_size);

	if (err < 0) {
		printk(KERN_ERR "Error setting key for crypto "
                                "context; err = [%d]\n", err);
                goto out_free_blkcipher;
        }

	err = 0;

	err = crypto_blkcipher_encrypt(&desc, dst_sg, src_sg, crypt_stat->key_size);

	if (err) {
		printk(KERN_ERR "Error generating tag 3 packet header; cannot "
                       "generate packet length. err = [%d]\n", err);
		*len = 0;
		goto out_free_blkcipher;
	}

	/* Certificate Parsing */
	memset(clicert, 0, sizeof(x509_cert));

	err = x509parse_crt( clicert, (unsigned char *) test_cli_crt,
                         strlen( test_cli_crt ) );

	if( err != 0 )       
    	{
           	printk( KERN_ERR "X.509 certificate load: failed \n" );

        	goto out_free_blkcipher;
    	}

	memset( cacert, 0, sizeof( x509_cert ) );

	err = x509parse_crt( cacert, (unsigned char *) test_ca_crt,
			 strlen( test_ca_crt ) );
	if( err != 0 )
	{
	    	printk( KERN_ERR "X.509 certificate load: failed\n" );

		goto out_clicert;
	}

	err = x509parse_verify( clicert, cacert, NULL, "PolarSSL Client 2", &flags, NULL, NULL );
    	if( err != 0 )
    	{
		printk("%02x", flags);
            	printk( "Certificate verification: failed\n" );

	        goto out_cacert;
    	}
	
	token_size = clicert->rsa.len;
	token = kmalloc(token_size, GFP_KERNEL);

	err = rsa_pkcs1_encrypt( &clicert->rsa, &myrand, NULL, RSA_PUBLIC, 
			crypt_stat->key_size, blinded_key, token);

	memcpy(dest_base, token, token_size);
	*len = token_size;

out_cacert:
	x509_free(cacert);
out_clicert:
	x509_free(clicert);
out_free_blkcipher:
	crypto_free_blkcipher(tfm);
out:
	kfree(cacert);
	kfree(clicert);
	return err;
}

int transcryptfs_read_tokens(struct transcryptfs_crypt_stat *crypt_stat, 
			     char *dest_base, 
			     struct dentry *transcryptfs_dentry)
{
	int err = 0;
	int cipher_name_len;
	struct scatterlist dst_sg[2];
	struct scatterlist src_sg[2];
	struct crypto_blkcipher *tfm;
	struct blkcipher_desc desc = {
		.tfm = NULL,
		.flags = CRYPTO_TFM_REQ_MAY_SLEEP
	};
	char blinded_key[TRANSCRYPTFS_DEFAULT_KEY_BYTES];
	struct transcryptfs_mount_crypt_stat *mount_crypt_stat;
	rsa_context rsa;
	unsigned char *token;
	size_t token_size;
	size_t len;
	size_t i;

	i = strlen( test_cli_key );

	rsa_init(&rsa, RSA_PKCS_V15, 0);

	mount_crypt_stat = crypt_stat->mount_crypt_stat;
	cipher_name_len =  strlen(TRANSCRYPTFS_DEFAULT_CIPHER);
	memcpy(crypt_stat->cipher, TRANSCRYPTFS_DEFAULT_CIPHER, cipher_name_len);

	if( ( err = x509parse_key( &rsa,
                    (unsigned char *) test_cli_key, i,
                    NULL, 0 ) ) != 0 )
    	{
            	printk( "X509 private key load: failed\n" );

        	goto out;
    	}

	token_size = rsa.len;
	token = kmalloc(token_size, GFP_KERNEL); 

	memcpy(token, dest_base, token_size);

	err =  rsa_pkcs1_decrypt( &rsa, RSA_PRIVATE, &len,
                           token, blinded_key,
                           sizeof(blinded_key) );

	if ( err != 0 ){
		printk(KERN_ERR "Decryption of Token: failed \n");
		goto out_token;
	}

	err = transcryptfs_init_crypt_ctx(crypt_stat);
        if (err) {       
                printk(KERN_ERR "Error initializing crypto "
                                "context for cipher [%s]; err = [%d]\n",
                                crypt_stat->cipher, err);
        }
	crypt_stat->key_size = TRANSCRYPTFS_DEFAULT_KEY_BYTES;

	err = virt_to_scatterlist(blinded_key, crypt_stat->key_size, src_sg, 2);

	if (err < 1 || err > 2) {
                printk(KERN_ERR "Error generating scatterlist "
                                "for crypt_stat session key; expected err = 1; "
                                "got err = [%d].\n", err);
                err = -ENOMEM;
                goto out;
        }

	err = virt_to_scatterlist(crypt_stat->key, crypt_stat->key_size, dst_sg, 2);

	if (err < 1 || err > 2) {
                printk(KERN_ERR "Error generating scatterlist "
                                "for crypt_stat session key; expected err = 1; "
                                "got err = [%d].\n", err);
                err = -ENOMEM;
                goto out;
        }

	tfm = crypto_alloc_blkcipher(mount_crypt_stat->global_blinding_cipher, 
				     0, CRYPTO_ALG_ASYNC);
	desc.tfm = tfm;

	err = crypto_blkcipher_setkey(desc.tfm, mount_crypt_stat->fsk,
				      mount_crypt_stat->fsk_size);

	if (err < 0) {
		printk(KERN_ERR "Error setting key for crypto "
                                "context; err = [%d]\n", err);
                goto out_free_blkcipher;
        }

	err = 0;

	err = crypto_blkcipher_decrypt(&desc, dst_sg, src_sg, crypt_stat->key_size);

	if (err) {
		printk(KERN_ERR "Error generating tag 3 packet header; cannot "
                       "generate packet length. err = [%d]\n", err);
		goto out_free_blkcipher;
	}
	// dst_sg already points to crypt_stat->key, its wrong to copy blinded key :s
	// memcpy(crypt_stat->key, blinded_key, crypt_stat->key_size);

out_free_blkcipher:
	crypto_free_blkcipher(tfm);
out_token:
	kfree(token);
out:
	rsa_free(&rsa);
	return err;
}
