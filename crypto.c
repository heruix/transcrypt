/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 1997-2004 Erez Zadok
 * Copyright (C) 2001-2004 Stony Brook University
 * Copyright (C) 2004-2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *              Michael C. Thompson <mcthomps@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/random.h>
#include <linux/compiler.h>
#include <linux/key.h>
#include <linux/namei.h>
#include <linux/crypto.h>
#include <linux/file.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <asm/unaligned.h>
#include "transcryptfs.h"


struct kmem_cache *transcryptfs_header_cache;


static int
transcryptfs_decrypt_page_offset(struct transcryptfs_crypt_stat *crypt_stat,
				struct page *dst_page, int dst_offset,
				struct page *src_page, int src_offset, int size,
				unsigned char *iv);
static int
transcryptfs_encrypt_page_offset(struct transcryptfs_crypt_stat *crypt_stat,
				struct page *dst_page, int dst_offset,
				struct page *src_page, int src_offset, int size,
				unsigned char *iv);

static void transcryptfs_lower_offset_for_extent(loff_t *offset, loff_t extent_num,
                                             struct transcryptfs_crypt_stat *crypt_stat)
{
        (*offset) = crypt_stat->metadata_size + (crypt_stat->extent_size * extent_num);
}

static int transcryptfs_copy_filename(char **copied_name, size_t *copied_name_size,
				      const char *name, size_t name_size)
{
	int err = 0;
	
	(*copied_name) = kzalloc((name_size + 1), GFP_KERNEL);
	if(!(*copied_name)) {
		err = -ENOMEM;
		goto out;
	}
	memcpy((void *)(*copied_name), (void *)name, name_size);
	(*copied_name)[name_size] = '\0';
	
	(*copied_name_size) = name_size;
out:
	return err;
}

int transcryptfs_encrypt_and_encode_filename(
	char **encoded_name,
	size_t *encoded_name_size,
	const char *name, size_t name_size)
{
	int err = 0;
	(*encoded_name) = NULL;
	(*encoded_name_size) = 0;
	err = transcryptfs_copy_filename(encoded_name,
                                         encoded_name_size,
                                         name, name_size);
	return err;
}

int transcryptfs_decode_and_decrypt_filename(char **plaintext_name,
                                         size_t *plaintext_name_size,
                                         const char *name, size_t name_size)
{
	int err = 0;
	(*plaintext_name) =  NULL;
	(*plaintext_name_size) = 0;
	err = transcryptfs_copy_filename(plaintext_name,
					 plaintext_name_size,
					 name, name_size);
	return err;
}

struct transcryptfs_result{
	struct completion completion;
	int err;
};

static void transcryptfs_complete(struct crypto_async_request *req, int err)
{
	struct transcryptfs_result *res = req->data;

	if (err == -EINPROGRESS)
		return;
	
	res->err = err;
	complete(&res->completion);
}

void transcryptfs_dump_hex(char *data, int bytes)
{       
        int i = 0;
        int add_newline = 1;
                                             
        if (bytes != 0) {
                printk(KERN_DEBUG "0x%.2x.", (unsigned char)data[i]);
                i++;            
        }       
        while (i < bytes) {
                printk("0x%.2x.", (unsigned char)data[i]);
                i++;
                if (i % 16 == 0) {
                        printk("\n");
                        add_newline = 0;
                } else
                        add_newline = 1;
        }
        if (add_newline)
                printk("\n");
}

int virt_to_scatterlist(const void *addr, int size, struct scatterlist *sg,
                        int sg_size)
{
        int i = 0;
        struct page *pg;
        int offset;
        int remainder_of_page;

        sg_init_table(sg, sg_size);

        while (size > 0 && i < sg_size) {
                pg = virt_to_page(addr);
                offset = offset_in_page(addr);
                if (sg)
                        sg_set_page(&sg[i], pg, 0, offset);
                remainder_of_page = PAGE_CACHE_SIZE - offset;
                if (size >= remainder_of_page) {
                        if (sg)
                                sg[i].length = remainder_of_page;
                        addr += remainder_of_page;
                        size -= remainder_of_page;
                } else { 
                        if (sg) 
                                sg[i].length = size;
                        addr += size;
                        size = 0;
                }
                i++;
        }
        if (size > 0)
                return -ENOMEM;
        return i;
}

static int encrypt_scatterlist(struct transcryptfs_crypt_stat *crypt_stat,
			       struct scatterlist *dest_sg, 
			       struct scatterlist *src_sg, int size,
			       unsigned char *iv)
{
	int err = 0;
	// struct blkcipher_desc desc = {
	// 	.info = iv,
	// 	.flags = CRYPTO_TFM_REQ_MAY_SLEEP
	// };
	struct crypto_ablkcipher *tfm;
	struct ablkcipher_request *req;	
	struct transcryptfs_result tresult;
	init_completion(&tresult.completion);
	//crypto_blkcipher_set_flags(tfm, CRYPTO_TFM_REQ_WEAK_KEY);
	tfm = crypt_stat->tfm;
	if (IS_ERR(tfm)) {
                pr_err("failed to load transform for xts: %ld\n", 
                       PTR_ERR(tfm));
                goto out;
        }

	BUG_ON(!crypt_stat || !crypt_stat->tfm
               || !(crypt_stat->flags & TRANSCRYPTFS_STRUCT_INITIALIZED));

// 	printk(KERN_DEBUG "Key size [%zd]; key: \n", crypt_stat->key_size);
// 	transcryptfs_dump_hex(crypt_stat->key, crypt_stat->key_size);

	crypto_ablkcipher_clear_flags(tfm, ~0);
	err = crypto_ablkcipher_setkey(tfm, crypt_stat->key, crypt_stat->key_size);
	if (err) {
		printk(KERN_ERR "Error setting key; err = [%d]\n",
                                err);
		err = -EINVAL;
		goto out_free_ablkcipher;
	}
	// desc.tfm = tfm;
	req = ablkcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
                pr_err("skcipher: Failed to allocate request for xts\n");
                goto out_free_ablkcipher;
        }
	ablkcipher_request_set_tfm(req, tfm);
	ablkcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
					transcryptfs_complete, &tresult);

	ablkcipher_request_set_crypt(req, src_sg, dest_sg, size, iv);
	// crypto_blkcipher_encrypt_iv(&desc, dest_sg, src_sg, size);
	printk(KERN_DEBUG "Encrypting [%d] bytes.\n", size);
	err = crypto_ablkcipher_encrypt(req);
        if (err == -EINPROGRESS || err == -EBUSY) {
                err = wait_for_completion_interruptible
                        (&tresult.completion);
                if (!err)
                        err = tresult.err;
        }
        ablkcipher_request_free(req);
out_free_ablkcipher:
        // crypto_free_ablkcipher(tfm);
out:
	return err;
}

static int transcryptfs_encrypt_extent(struct page *enc_extent_page,
				       struct transcryptfs_crypt_stat *crypt_stat,
				       struct page *page, 
				       unsigned long extent_offset)
{
// 	char *src_byte;
// 	char *dst_byte;
 	int err = 0;
	loff_t extent_base;
	char extent_iv[TRANSCRYPTFS_MAX_IV_BYTES];

	extent_base =(loff_t)page->index;
	memset(extent_iv, 0, TRANSCRYPTFS_MAX_IV_BYTES);

	err = transcryptfs_encrypt_page_offset(crypt_stat, enc_extent_page, 0, page, 
					       (extent_offset 
						* crypt_stat->extent_size),
					       crypt_stat->extent_size, extent_iv);
	if (err < 0) {
		printk(KERN_ERR "%s: Error attempting to encrypt page with "
                       "page->index = [%ld], extent_offset = [%ld]; "
                       "err = [%d]\n", __func__, page->index, extent_offset,
                       err);
                goto out;
        }
        err = 0;
out:
        return err;

// 	int size = 0;
// 	src_byte = kmap(page);
// 	dst_byte = kmap(enc_extent_page);
// 	for(size = 0; size < PAGE_CACHE_SIZE; size++)
// 		dst_byte[size] = src_byte[size]++;
// 	kunmap(enc_extent_page);
// 	kunmap(page);
// 	return err;
}

int transcryptfs_encrypt_page(struct page *page)
{
	int err = 0;
	char *enc_extent_virt;
	struct page *enc_extent_page = NULL;
	struct inode *transcryptfs_inode;
	struct transcryptfs_crypt_stat *crypt_stat;
	loff_t extent_offset;
//	unsigned int extent_size = PAGE_CACHE_SIZE;

	transcryptfs_inode = page->mapping->host;
	crypt_stat = &TRANSCRYPTFS_I(transcryptfs_inode)->crypt_stat;
	enc_extent_page = alloc_page(GFP_USER);
	if(!enc_extent_page) {
                err = -ENOMEM;
                printk(KERN_ERR "Error allocating memory for "
                                "encrypted extent\n");
                goto out;
        }
	enc_extent_virt = kmap(enc_extent_page);
	for (extent_offset = 0;
	     extent_offset < (PAGE_CACHE_SIZE / crypt_stat->extent_size);
	     extent_offset++) {
		loff_t offset;
		
		err = transcryptfs_encrypt_extent(enc_extent_page, crypt_stat, page,
						  extent_offset);
		if (err) {
			 printk(KERN_ERR "%s: Error encrypting extent; "
                               "err = [%d]\n", __func__, err);
                        goto out;
                }
		
//		offset = (page->index + extent_offset) * PAGE_CACHE_SIZE;
// 		err = transcryptfs_encrypt(enc_extent_page, page);
		transcryptfs_lower_offset_for_extent(
                        &offset, ((((loff_t)page->index)
                                   * (PAGE_CACHE_SIZE
                                      / crypt_stat->extent_size))
                                  + extent_offset), crypt_stat);
		err = transcryptfs_write_lower(transcryptfs_inode, enc_extent_virt,
                	                       offset, crypt_stat->extent_size);
		if (err < 0) {
                	printk(KERN_ERR "Error attempting "
                        	        "to write lower page; err = [%d]"
                                	"\n", err);
	                goto out;
        	}
	}
        err = 0;
out:
        if (enc_extent_page) {
                kunmap(enc_extent_page);
                __free_page(enc_extent_page);
        }
	return err;
}

static int
transcryptfs_encrypt_page_offset(struct transcryptfs_crypt_stat *crypt_stat,
				 struct page *dst_page, int dst_offset,
				 struct page *src_page, int src_offset,
				 int size, unsigned char *iv)
{
	struct scatterlist src_sg, dst_sg;
	
	sg_init_table(&src_sg, 1);
	sg_init_table(&dst_sg, 1);

	sg_set_page(&src_sg, src_page, size, src_offset);
	sg_set_page(&dst_sg, dst_page, size, dst_offset);

	return encrypt_scatterlist(crypt_stat, &dst_sg, &src_sg, size, iv);
}

static int transcryptfs_decrypt_extent(struct page *page, 
				       struct transcryptfs_crypt_stat *crypt_stat,
				       struct page *enc_extent_page,
				       unsigned long extent_offset)
{
//         char *src_byte;
//         char *dst_byte;
        int err = 0;
	loff_t extent_base;
	char extent_iv[TRANSCRYPTFS_MAX_IV_BYTES];


	// XXX : FIX THIS.
	extent_base = (loff_t)page->index;
	memset(extent_iv, 0, TRANSCRYPTFS_MAX_IV_BYTES);

	err = transcryptfs_decrypt_page_offset(crypt_stat, page, (extent_offset
						      * PAGE_CACHE_SIZE),
						     enc_extent_page, 0,
						     PAGE_CACHE_SIZE, extent_iv);

	if (err < 0) {
		 printk(KERN_ERR "%s: Error attempting to decrypt to page with "
                       "page->index = [%ld], extent_offset = [%ld]; "
                       "err = [%d]\n", __func__, page->index, extent_offset,
                       err);
                goto out;
        }
        err = 0;
out:

//         int size = 0;
//         src_byte = kmap(enc_extent_page);
//         dst_byte = kmap(page);
//         for(size = 0; size < PAGE_CACHE_SIZE; size++)
//                 dst_byte[size] = src_byte[size]--;
//         kunmap(enc_extent_page);
//         kunmap(page);
       return err;
}


int transcryptfs_decrypt_page(struct page *page)
{
        struct inode *transcryptfs_inode;
        char *enc_extent_virt;
	struct transcryptfs_crypt_stat *crypt_stat;
        struct page *enc_extent_page = NULL;
	unsigned long extent_offset;
//	unsigned long extent_size = PAGE_CACHE_SIZE;
        int err = 0;

        transcryptfs_inode = page->mapping->host;
	crypt_stat = &TRANSCRYPTFS_I(transcryptfs_inode)->crypt_stat;

        enc_extent_page = alloc_page(GFP_USER);
        if (!enc_extent_page) {
                err = -ENOMEM;
                printk(KERN_ERR "Error allocating memory for "
                                "encrypted extent\n");
                goto out;
        }
        enc_extent_virt = kmap(enc_extent_page);
	for (extent_offset = 0;
	     extent_offset < (PAGE_CACHE_SIZE / crypt_stat->extent_size);
	     extent_offset++) {
		loff_t offset;
		
//		offset = (page->index + extent_offset) * PAGE_CACHE_SIZE;
		transcryptfs_lower_offset_for_extent(
			&offset, ((page->index * (PAGE_CACHE_SIZE
                                                  / crypt_stat->extent_size))
                                  + extent_offset), crypt_stat);
 
		err = transcryptfs_read_lower(enc_extent_virt, offset, 
					      crypt_stat->extent_size, transcryptfs_inode);
	        if (err < 0) {
        	        printk(KERN_ERR "%s: Error reading from lowerfs "
                	       "err = [%d]\n", __func__, err);
        	        goto out;
	        }
	        err = transcryptfs_decrypt_extent(page, crypt_stat, enc_extent_page, 
						  extent_offset);
        	if (err) {
                	printk(KERN_ERR "%s: Error decrypting extent; "
    	                       "err = [%d]\n", __func__, err);
	                goto out;
	        }
	}
out:
        if (enc_extent_page) {
                kunmap(enc_extent_page);
                __free_page(enc_extent_page);
        }
        return err;
}

static int decrypt_scatterlist(struct transcryptfs_crypt_stat *crypt_stat, 
			       struct scatterlist *dest_sg,
			       struct scatterlist *src_sg, int size,
			       unsigned char *iv)
{	int err = 0;
	// struct blkcipher_desc desc = {
	// 	.info = iv,
	// 	.flags = CRYPTO_TFM_REQ_MAY_SLEEP
	// };
	struct crypto_ablkcipher *tfm;
	struct ablkcipher_request *req;	
	struct transcryptfs_result tresult;
	init_completion(&tresult.completion);
	//crypto_blkcipher_set_flags(tfm, CRYPTO_TFM_REQ_WEAK_KEY);
	tfm = crypt_stat->tfm;
	crypto_ablkcipher_clear_flags(tfm, ~0);
	err = crypto_ablkcipher_setkey(tfm, crypt_stat->key, crypt_stat->key_size);
	if (err) {
		printk(KERN_ERR "Error setting key; err = [%d]\n",
                                err);
		err = -EINVAL;
		goto out;
	}
	// desc.tfm = tfm;
	req = ablkcipher_request_alloc(tfm, GFP_KERNEL);
	ablkcipher_request_set_tfm(req, tfm);
	ablkcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
					transcryptfs_complete, &tresult);

	ablkcipher_request_set_crypt(req, src_sg, dest_sg, size, iv);
	// crypto_blkcipher_encrypt_iv(&desc, dest_sg, src_sg, size);
	printk(KERN_DEBUG "Decrypting [%d] bytes.\n", size);
	err = crypto_ablkcipher_decrypt(req);
        if (err == -EINPROGRESS || err == -EBUSY) {
                err = wait_for_completion_interruptible
                        (&tresult.completion);
                if (!err)
                        err = tresult.err;
        }
        ablkcipher_request_free(req);
out:
        // crypto_free_ablkcipher(tfm);
	return err;

// 	struct crypto_blkcipher *tfm = crypto_alloc_blkcipher("cbc(aes)", 0,
// 							      CRYPTO_ALG_ASYNC);
// 	crypto_blkcipher_set_flags(tfm, CRYPTO_TFM_REQ_WEAK_KEY);
// 	desc.tfm = tfm;
// 
// 	err = crypto_blkcipher_setkey(tfm, "TRANSCRYPT_SAMPL", 16);
// 	if (err) {
// 		printk(KERN_ERR "Error setting key; err = [%d]\n",
//                                 err);
// 		err = -EINVAL;
// 		goto out;
// 	}
// 	err = crypto_blkcipher_decrypt_iv(&desc, dest_sg, src_sg, size);
// 	if (err) {
//                 printk(KERN_ERR "Error decrypting; err = [%d]\n",
//                                 err);
//                 goto out;
//         }
//         err = size;
// out:
// 	return err;
}

static int 
transcryptfs_decrypt_page_offset(struct transcryptfs_crypt_stat *crypt_stat, 
				 struct page *dst_page, int dst_offset,
				 struct page *src_page, int src_offset, int size,
				 unsigned char *iv)
{
	struct scatterlist src_sg, dst_sg;
	
	sg_init_table(&src_sg, 1);
	sg_set_page(&src_sg, src_page, size, src_offset);
	
	sg_init_table(&dst_sg, 1);
	sg_set_page(&dst_sg, dst_page, size, dst_offset);
	
	return decrypt_scatterlist(crypt_stat, &dst_sg, &src_sg, size, iv);
}

int transcryptfs_init_crypt_ctx(struct transcryptfs_crypt_stat *crypt_stat)
{
	int err = -EINVAL;

	if (!crypt_stat->cipher) {
		printk(KERN_ERR "No cipher specified\n");
		goto out;
	}
	
	if (crypt_stat->tfm) {
		err = 0;
		goto out;
	}
	mutex_lock(&crypt_stat->cs_tfm_mutex);
	crypt_stat->tfm = crypto_alloc_ablkcipher(crypt_stat->cipher, 0,
						  CRYPTO_ALG_ASYNC);
	if (IS_ERR(crypt_stat->tfm)) {
		err = PTR_ERR(crypt_stat->tfm);
		crypt_stat->tfm = NULL;
		printk(KERN_ERR "transcryptfs: init_crypt_ctx():"
		       "Error initializing cipher[%s]\n",
		       crypt_stat->cipher);
		goto out_unlock;
	}
	crypto_ablkcipher_clear_flags(crypt_stat->tfm, ~0);
	err = 0;
out_unlock:
	mutex_unlock(&crypt_stat->cs_tfm_mutex);
out:
	return err;
}

static void set_default_header_data(struct transcryptfs_crypt_stat *crypt_stat)
{
	crypt_stat->metadata_size = TRANSCRYPTFS_MINIMUM_HEADER_EXTENT_SIZE;
}

void transcryptfs_i_size_init(const char *page_virt, struct inode *inode)
{
	struct transcryptfs_mount_crypt_stat *mount_crypt_stat;
	struct transcryptfs_crypt_stat *crypt_stat;
	u64 file_size;

	crypt_stat = &TRANSCRYPTFS_I(inode)->crypt_stat;
	mount_crypt_stat =
                &TRANSCRYPTFS_SB(inode->i_sb)->mount_crypt_stat;
	if (mount_crypt_stat->flags & TRANSCRYPTFS_ENCRYPTED_VIEW_ENABLED) 
		file_size = i_size_read(transcryptfs_lower_inode(inode));
	else
		file_size = get_unaligned_be64(page_virt);
	i_size_write(inode, (loff_t)file_size);
	crypt_stat->flags |= TRANSCRYPTFS_I_SIZE_INITIALIZED;
}

static int parse_header_metadata(struct transcryptfs_crypt_stat *crypt_stat,
				 char *virt, int *bytes_read)
{
	int err = 0;
	u32 header_extent_size;
	u16 num_header_extents_at_front;

	header_extent_size = get_unaligned_be32(virt);
	virt += sizeof(__be32);
	num_header_extents_at_front = get_unaligned_be16(virt);
	crypt_stat->metadata_size = (((size_t)num_header_extents_at_front
				     * (size_t)header_extent_size));
	(*bytes_read) = (sizeof(__be32) + sizeof(__be16));
	return err;
} 


static int transcryptfs_read_headers_virt(char *page_virt,
				struct transcryptfs_crypt_stat *crypt_stat,
				struct dentry *transcryptfs_dentry)
{
	int err = 0;
	int offset;
	int bytes_read;
	
	transcryptfs_set_default_sizes(crypt_stat);
	crypt_stat->mount_crypt_stat = &TRANSCRYPTFS_SB(transcryptfs_dentry->d_sb)->mount_crypt_stat;
	offset = TRANSCRYPTFS_FILE_SIZE_BYTES;
	if (!(crypt_stat->flags & TRANSCRYPTFS_I_SIZE_INITIALIZED))
		transcryptfs_i_size_init(page_virt, transcryptfs_dentry->d_inode);
	crypt_stat->file_version = TRANSCRYPTFS_SUPPORTED_FILE_VERSION;
	if (crypt_stat->file_version > TRANSCRYPTFS_SUPPORTED_FILE_VERSION) {
		printk(KERN_ERR "File version is [%d]; only "
                                "file version [%d] is supported by this "
                                "version of eCryptfs\n",
                                crypt_stat->file_version,
                                TRANSCRYPTFS_SUPPORTED_FILE_VERSION);
                err = -EINVAL;
                goto out;
        }
	if (crypt_stat->file_version >= 1) {
                err = parse_header_metadata(crypt_stat, (page_virt + offset),
                                           &bytes_read);
                if (err) {
			printk(KERN_ERR "Error Reading header metadata;err=%d", err);
		}
		offset += bytes_read;
	} else
		set_default_header_data(crypt_stat);
	err = transcryptfs_read_tokens(crypt_stat, (page_virt + offset),
					transcryptfs_dentry);

out:
	return err;
}

static void transcryptfs_copy_mount_wide_flags_to_inode_flags(
        struct transcryptfs_crypt_stat *crypt_stat,
        struct transcryptfs_mount_crypt_stat *mount_crypt_stat)
{
        if (mount_crypt_stat->flags & TRANSCRYPTFS_ENCRYPTED_VIEW_ENABLED)
                crypt_stat->flags |= TRANSCRYPTFS_VIEW_AS_ENCRYPTED;
	if (mount_crypt_stat->flags & TRANSCRYPTFS_GLOBAL_ENCRYPT_FILENAMES) {
                crypt_stat->flags |= TRANSCRYPTFS_ENCRYPT_FILENAMES;
                if (mount_crypt_stat->flags
                    & TRANSCRYPTFS_GLOBAL_ENCFN_USE_MOUNT_FNEK)
                        crypt_stat->flags |= TRANSCRYPTFS_ENCFN_USE_MOUNT_FNEK;
                else if (mount_crypt_stat->flags
                         & TRANSCRYPTFS_GLOBAL_ENCFN_USE_FEK)
                        crypt_stat->flags |= TRANSCRYPTFS_ENCFN_USE_FEK;
        }
}


int transcryptfs_read_metadata(struct dentry *transcryptfs_dentry)
{
	int err;
	char *page_virt;
	struct inode *transcryptfs_inode = transcryptfs_dentry->d_inode;
	struct transcryptfs_crypt_stat *crypt_stat =
            &TRANSCRYPTFS_I(transcryptfs_inode)->crypt_stat;
	struct transcryptfs_mount_crypt_stat *mount_crypt_stat =
                &TRANSCRYPTFS_SB(transcryptfs_dentry->d_sb)->mount_crypt_stat;
	
	transcryptfs_copy_mount_wide_flags_to_inode_flags(crypt_stat,
                                                      mount_crypt_stat);
	page_virt = kmem_cache_alloc(transcryptfs_header_cache, GFP_USER);
	if (!page_virt) {
		err = -ENOMEM;
		printk(KERN_ERR "%s: Unable to allocate page_virt\n", 
		       __func__);
		goto out;	
	}
	err = transcryptfs_read_lower(page_virt, 0, crypt_stat->extent_size,
				      transcryptfs_inode);

	if (err >= 0)
		err = transcryptfs_read_headers_virt(page_virt, crypt_stat,
						transcryptfs_dentry);
out:
	if (page_virt) {
		memset(page_virt, 0, PAGE_CACHE_SIZE);
		kmem_cache_free(transcryptfs_header_cache, page_virt);
	}
	return err;
}

int transcryptfs_read_and_validate_header_region(struct inode *inode)
{
	u8 file_size[TRANSCRYPTFS_FILE_SIZE_BYTES];
	int err;
	
	err = transcryptfs_read_lower(file_size, 0, 
				      TRANSCRYPTFS_FILE_SIZE_BYTES, inode);

	if (err < TRANSCRYPTFS_FILE_SIZE_BYTES)
		return err >= 0 ? -EINVAL : err;
	
	
	transcryptfs_i_size_init(file_size, inode);
	return err;
}

void transcryptfs_write_header_metadata(char *virt,
				    struct transcryptfs_crypt_stat *crypt_stat,
				    size_t *written)
{
	u32 header_extent_size;
	u16 num_header_extents_at_front;
	
	header_extent_size = (u32)crypt_stat->extent_size;
	num_header_extents_at_front = 
		(u16)(crypt_stat->metadata_size / crypt_stat->extent_size);
	put_unaligned_be32(header_extent_size, virt);
	virt += 4;
	put_unaligned_be16(num_header_extents_at_front, virt);
	(*written) = 6;
}


static int transcryptfs_write_headers_virt(char *page_virt, size_t max,
				size_t *size,
				struct transcryptfs_crypt_stat *crypt_stat,
				struct dentry *transcryptfs_dentry)
{
	int err;
	size_t written;
	size_t offset;
	
	offset = TRANSCRYPTFS_FILE_SIZE_BYTES;
	transcryptfs_write_header_metadata((page_virt + offset), crypt_stat,
					   &written);
	offset += written;
	err = transcryptfs_generate_tokens((page_virt + offset), crypt_stat,
					   transcryptfs_dentry, &written,
					   max - offset);
	if (err)
		printk(KERN_ERR "Error generating tokens; err = [%d]\n", err);
	if (size) {
		offset += written;
		*size = offset;
	}
	return err;
}

static int
transcryptfs_write_metadata_to_contents(struct inode *transcryptfs_inode,
					char *virt, size_t virt_len)
{
	int err;
	
	err = transcryptfs_write_lower(transcryptfs_inode, virt, 0, virt_len);

	if (err < 0)
		printk(KERN_ERR "%s: Error attempting to write header "
		"information to lower file; err = [%d]\n", __func__, err);
	else
		err = 0;
	return err;
}

static void transcryptfs_generate_new_key(
	struct transcryptfs_crypt_stat *crypt_stat)
{
	get_random_bytes(crypt_stat->key, crypt_stat->key_size);
	crypt_stat->flags |= TRANSCRYPTFS_KEY_VALID;
}



static void set_extent_mask_and_shift(struct transcryptfs_crypt_stat *crypt_stat)
{
        int extent_size_tmp;

        crypt_stat->extent_mask = 0xFFFFFFFF;
        crypt_stat->extent_shift = 0;
        if (crypt_stat->extent_size == 0)
                return;
        extent_size_tmp = crypt_stat->extent_size;
        while ((extent_size_tmp & 0x01) == 0) {
                extent_size_tmp >>= 1;
                crypt_stat->extent_mask <<= 1;
                crypt_stat->extent_shift++;
        }
}

void transcryptfs_set_default_sizes(struct transcryptfs_crypt_stat *crypt_stat)
{
	crypt_stat->extent_size = TRANSCRYPTFS_DEFAULT_EXTENT_SIZE;
	set_extent_mask_and_shift(crypt_stat);
	if (PAGE_CACHE_SIZE <= TRANSCRYPTFS_MINIMUM_HEADER_EXTENT_SIZE)
        	crypt_stat->metadata_size =
                	TRANSCRYPTFS_MINIMUM_HEADER_EXTENT_SIZE;
        else
                crypt_stat->metadata_size = PAGE_CACHE_SIZE;
}

static void transcryptfs_set_default_crypt_stat_vals(
	struct transcryptfs_crypt_stat *crypt_stat,
	struct transcryptfs_mount_crypt_stat *mount_crypt_stat) 
{
	transcryptfs_copy_mount_wide_flags_to_inode_flags(crypt_stat,
							mount_crypt_stat);
	transcryptfs_set_default_sizes(crypt_stat);
	strcpy(crypt_stat->cipher, TRANSCRYPTFS_DEFAULT_CIPHER);
	crypt_stat->key_size = TRANSCRYPTFS_DEFAULT_KEY_BYTES;
        crypt_stat->flags &= ~(TRANSCRYPTFS_KEY_VALID);
        crypt_stat->file_version = TRANSCRYPTFS_FILE_VERSION;
        crypt_stat->mount_crypt_stat = mount_crypt_stat;
}


int transcryptfs_new_file_context(struct inode *transcryptfs_inode)
{
	struct transcryptfs_crypt_stat *crypt_stat =
	    &TRANSCRYPTFS_I(transcryptfs_inode)->crypt_stat;
	struct transcryptfs_mount_crypt_stat *mount_crypt_stat =
	    &TRANSCRYPTFS_SB(transcryptfs_inode->i_sb)->mount_crypt_stat;
	int cipher_name_len;
	int err = 0;

	transcryptfs_set_default_crypt_stat_vals(crypt_stat, mount_crypt_stat);
	crypt_stat->flags |= (TRANSCRYPTFS_ENCRYPTED|TRANSCRYPTFS_KEY_VALID);
	transcryptfs_copy_mount_wide_flags_to_inode_flags(crypt_stat,
                                                      mount_crypt_stat);
//	if(mount_crypt_stat->flags & TRANSCRYPTFS_ENCRYPTED_VIEW_ENABLED)
//		crypt_stat->flags |= TRANSCRYPTFS_VIEW_AS_ENCRYPTED;
	cipher_name_len =  strlen(TRANSCRYPTFS_DEFAULT_CIPHER);
	memcpy(crypt_stat->cipher,
               TRANSCRYPTFS_DEFAULT_CIPHER,
               cipher_name_len);
        crypt_stat->cipher[cipher_name_len] = '\0';
        crypt_stat->key_size = TRANSCRYPTFS_DEFAULT_KEY_BYTES;
	transcryptfs_generate_new_key(crypt_stat);	
	
	err = transcryptfs_init_crypt_ctx(crypt_stat);
	if (err)
                printk(KERN_ERR "Error initializing cryptographic "
                                "context for cipher [%s]: err = [%d]\n",
                                crypt_stat->cipher, err);
        return err;
}

static unsigned long transcryptfs_get_zeroed_pages(gfp_t gfp_mask,
						unsigned int order)
{
	struct page *page;
	
	page = alloc_pages(gfp_mask | __GFP_ZERO, order);
	if(page)
		return (unsigned long) page_address(page);
	return 0;
}

int transcryptfs_write_metadata(struct dentry *transcryptfs_dentry,
				struct inode *transcryptfs_inode)
{
	struct transcryptfs_crypt_stat *crypt_stat = 
		&TRANSCRYPTFS_I(transcryptfs_inode)->crypt_stat;
	unsigned int order;
	char *virt;
	size_t virt_len;
	size_t size=0;
	int err = 0;
	
	if (likely(crypt_stat->flags & TRANSCRYPTFS_ENCRYPTED)) {
		if (!(crypt_stat->flags & TRANSCRYPTFS_KEY_VALID)) {
			printk(KERN_ERR "Key is invalid; bailing out\n");
                        err = -EINVAL;
                        goto out;
                }
        } else {
                printk(KERN_WARNING "%s: Encrypted flag not set\n",
                       __func__);
                err = -EINVAL;
                goto out;
        }
	virt_len = crypt_stat->metadata_size;
	order = get_order(virt_len);

	virt = (char *)transcryptfs_get_zeroed_pages(GFP_KERNEL, order);
	if (!virt) {
		printk(KERN_ERR "%s: Out of memory\n", __func__);
                err = -ENOMEM;
                goto out;
        }
        /* Zeroed page ensures the in-header unencrypted i_size is set to 0 */
        err = transcryptfs_write_headers_virt(virt, virt_len, &size, crypt_stat,
                                         transcryptfs_dentry);
        if (unlikely(err)) {
                printk(KERN_ERR "%s: Error whilst writing headers; rc = [%d]\n",
                       __func__, err);
                goto out_free;
        }

	err = transcryptfs_write_metadata_to_contents(transcryptfs_inode, virt,
                                                         virt_len);
	if (err) {
                printk(KERN_ERR "%s: Error writing metadata out to lower file; "
                       "err = [%d]\n", __func__, err);
                goto out_free;
        }
out_free:
        free_pages((unsigned long)virt, order);
out:
        return err;
}

void transcryptfs_init_crypt_stat(struct transcryptfs_crypt_stat *crypt_stat)
{
        memset((void *)crypt_stat, 0, sizeof(struct transcryptfs_crypt_stat));
        INIT_LIST_HEAD(&crypt_stat->keysig_list);
        mutex_init(&crypt_stat->keysig_list_mutex);
        mutex_init(&crypt_stat->cs_mutex);
        mutex_init(&crypt_stat->cs_tfm_mutex);
        crypt_stat->flags |= TRANSCRYPTFS_STRUCT_INITIALIZED;
}

void transcryptfs_destroy_crypt_stat(struct transcryptfs_crypt_stat *crypt_stat)
{
        // struct transcryptfs_key_sig *key_sig, *key_sig_tmp;
        
        if (crypt_stat->tfm)
                crypto_free_ablkcipher(crypt_stat->tfm);
        // if (crypt_stat->hash_tfm)
        //         crypto_free_hash(crypt_stat->hash_tfm);
       //  list_for_each_entry_safe(key_sig, key_sig_tmp,
       //                           &crypt_stat->keysig_list, crypt_stat_list) {
       //          list_del(&key_sig->crypt_stat_list);
       //          kmem_cache_free(myecryptfs_key_sig_cache, key_sig);
       //  }
        memset(crypt_stat, 0, sizeof(struct transcryptfs_crypt_stat));
}                                    

void transcryptfs_destroy_mount_crypt_stat(
        struct transcryptfs_mount_crypt_stat *mount_crypt_stat)
{
        // struct myecryptfs_global_auth_tok *auth_tok, *auth_tok_tmp;

        if (!(mount_crypt_stat->flags & TRANSCRYPTFS_MOUNT_CRYPT_STAT_INITIALIZED))
                return;              
       //  mutex_lock(&mount_crypt_stat->global_auth_tok_list_mutex);
       //  list_for_each_entry_safe(auth_tok, auth_tok_tmp, 
       //                           &mount_crypt_stat->global_auth_tok_list,
       //                           mount_crypt_stat_list) {
       //          list_del(&auth_tok->mount_crypt_stat_list);
       //          if (auth_tok->global_auth_tok_key
       //              && !(auth_tok->flags & MYECRYPTFS_AUTH_TOK_INVALID))
       //                  key_put(auth_tok->global_auth_tok_key);
       //          kmem_cache_free(myecryptfs_global_auth_tok_cache, auth_tok);
       //  }
       //  mutex_unlock(&mount_crypt_stat->global_auth_tok_list_mutex);
        memset(mount_crypt_stat, 0, sizeof(struct transcryptfs_mount_crypt_stat));
}



