/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/page-flags.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <asm/unaligned.h>
#include "transcryptfs.h"

// static int transcryptfs_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
// {
// 	int err;
// 	struct file *file, *lower_file;
// 	const struct vm_operations_struct *lower_vm_ops;
// 	struct vm_area_struct lower_vma;
// 
// 	memcpy(&lower_vma, vma, sizeof(struct vm_area_struct));
// 	file = lower_vma.vm_file;
// 	lower_vm_ops = TRANSCRYPTFS_F(file)->lower_vm_ops;
// 	BUG_ON(!lower_vm_ops);
// 
// 	lower_file = transcryptfs_file_to_lower(file);
// 	/*
// 	 * XXX: vm_ops->fault may be called in parallel.  Because we have to
// 	 * resort to temporarily changing the vma->vm_file to point to the
// 	 * lower file, a concurrent invocation of transcryptfs_fault could see a
// 	 * different value.  In this workaround, we keep a different copy of
// 	 * the vma structure in our stack, so we never expose a different
// 	 * value of the vma->vm_file called to us, even temporarily.  A
// 	 * better fix would be to change the calling semantics of ->fault to
// 	 * take an explicit file pointer.
// 	 */
// 	lower_vma.vm_file = lower_file;
// 	err = lower_vm_ops->fault(&lower_vma, vmf);
// 	return err;
// }

struct page *transcryptfs_get_locked_page(struct inode *inode, loff_t index)
{
        struct page *page = read_mapping_page(inode->i_mapping, index, NULL);
        if (!IS_ERR(page))
                lock_page(page);
        return page;
}

static int transcryptfs_write_inode_size_to_header(struct inode *transcryptfs_inode)
{
        char *file_size_virt;
        int err;

        file_size_virt = kmalloc(sizeof(u64), GFP_KERNEL);
        if (!file_size_virt) {
                err = -ENOMEM;
                goto out;
        }
        put_unaligned_be64(i_size_read(transcryptfs_inode), file_size_virt);
        err = transcryptfs_write_lower(transcryptfs_inode, file_size_virt, 0,
                                  sizeof(u64));
        kfree(file_size_virt);
        if (err < 0)
                printk(KERN_ERR "%s: Error writing file size to header; "
                       "err = [%d]\n", __func__, err);
        else
                err = 0;
out:
        return err;
}

int transcryptfs_write_inode_size_to_metadata(struct inode *transcryptfs_inode)
{               
        struct transcryptfs_crypt_stat *crypt_stat;
        
        crypt_stat = &TRANSCRYPTFS_I(transcryptfs_inode)->crypt_stat;
        BUG_ON(!(crypt_stat->flags & TRANSCRYPTFS_ENCRYPTED));
	return transcryptfs_write_inode_size_to_header(transcryptfs_inode);
} 

static int transcryptfs_write_begin(struct file *file,
                        struct address_space *mapping,
                        loff_t pos, unsigned len, unsigned flags,
                        struct page **pagep, void **fsdata)
{
        pgoff_t index = pos >> PAGE_CACHE_SHIFT;
        struct page *page;
        loff_t prev_page_end_size;
        int err = 0;

        page = grab_cache_page_write_begin(mapping, index, flags);
        if (!page)
                return -ENOMEM;
        *pagep = page;

        prev_page_end_size = ((loff_t)index << PAGE_CACHE_SHIFT);
        if (!PageUptodate(page)) {
		 struct transcryptfs_crypt_stat *crypt_stat =
			  &TRANSCRYPTFS_I(mapping->host)->crypt_stat;

		 if (!(crypt_stat->flags & TRANSCRYPTFS_ENCRYPTED)) {
			err = transcryptfs_read_lower_page_segment(
			 page, index, 0, PAGE_CACHE_SIZE, mapping->host);
			if (err) {
				printk(KERN_ERR "%s: Error attemping to read "
                                       "lower page segment; err = [%d]\n",
                                       __func__, err);
                                ClearPageUptodate(page);
                                goto out;
                        } else
                                SetPageUptodate(page);
                } else if (crypt_stat->flags & TRANSCRYPTFS_VIEW_AS_ENCRYPTED) {
		// 	if (crypt_stat->flags & TRANSCRYPTFS_METADATA_IN_XATTR) {
                //                 rc = myecryptfs_copy_up_encrypted_with_header(
                //                         page, crypt_stat);
                //                 if (rc) {
                //                         printk(KERN_ERR "%s: Error attempting "
                //                                "to copy the encrypted content "
                //                                "from the lower file whilst "
                //                                "inserting the metadata from "
                //                                "the xattr into the header; rc "
                //                                "= [%d]\n", __func__, rc);
                //                         ClearPageUptodate(page);
                //                         goto out;
                //                 }
                //                 SetPageUptodate(page);
                //         } else {
                                err = transcryptfs_read_lower_page_segment(
                                        page, index, 0, PAGE_CACHE_SIZE,
                                        mapping->host);
                                if (err) {
                                        printk(KERN_ERR "%s: Error reading "
                                               "page; err = [%d]\n",
                                               __func__, err);
                                        ClearPageUptodate(page);
                                        goto out;
                                }
                                SetPageUptodate(page);
                        // }
                } else {
		 	if (prev_page_end_size
                 	    >= i_size_read(page->mapping->host)) {
                 	        zero_user(page, 0, PAGE_CACHE_SIZE);
                 	} else {
                 	        err = transcryptfs_decrypt_page(page);
                 	        if (err) {
                 	                printk(KERN_ERR "%s: Error decrypting "
                 	                       "page at index [%ld]; "
                 	                       "err = [%d]\n",
                 	                       __func__, page->index, err);
                 	                ClearPageUptodate(page);
                 	                goto out;
                 	        }
                 	}
                 	SetPageUptodate(page);
		}
	}
	/* If creating a page or more of holes, zero them out via truncate.
         * Note, this will increase i_size. */
        if (index != 0) {
                if (prev_page_end_size > i_size_read(page->mapping->host)) {
                        err = transcryptfs_truncate(file->f_path.dentry,
                                               prev_page_end_size);
                        if (err) {
                                printk(KERN_ERR "%s: Error on attempt to "
                                       "truncate to (higher) offset [%lld];"
                                       " err = [%d]\n", __func__,
                                       prev_page_end_size, err);
                                goto out;
                        }
                }
        }
        /* Writing to a new page, and creating a small hole from start
         * of page?  Zero it out. */
        if ((i_size_read(mapping->host) == prev_page_end_size)
            && (pos != 0))
                zero_user(page, 0, PAGE_CACHE_SIZE);
out:    
        if (unlikely(err)) {
                unlock_page(page);
                page_cache_release(page);
                *pagep = NULL;
        }
        return err;
}

/**
 * Called with lower inode mutex held.
 */
static int fill_zeros_to_end_of_page(struct page *page, unsigned int to)
{
        struct inode *inode = page->mapping->host;
        int end_byte_in_page;

        if ((i_size_read(inode) / PAGE_CACHE_SIZE) != page->index)
                goto out;
        end_byte_in_page = i_size_read(inode) % PAGE_CACHE_SIZE;
        if (to > end_byte_in_page)
                end_byte_in_page = to;
        zero_user_segment(page, end_byte_in_page, PAGE_CACHE_SIZE);
out:
        return 0;
}

static int transcryptfs_write_end(struct file *file,
                        struct address_space *mapping,
                        loff_t pos, unsigned len, unsigned copied,
                        struct page *page, void *fsdata)
{
        pgoff_t index = pos >> PAGE_CACHE_SHIFT;
        unsigned from = pos & (PAGE_CACHE_SIZE - 1);
        unsigned to = from + copied;
        struct inode *transcryptfs_inode = mapping->host;
        int err;
        int need_unlock_page = 1;

        printk(KERN_DEBUG "Calling fill_zeros_to_end_of_page"
                        "(page w/ index = [0x%.16lx], to = [%d])\n", index, to);
        /* Fills in zeros if 'to' goes beyond inode size */
        err = fill_zeros_to_end_of_page(page, to);
        if (err) {
                printk(KERN_WARNING "Error attempting to fill "
                        "zeros in page with index = [0x%.16lx]\n", index);
                goto out;
        }
        set_page_dirty(page);
        unlock_page(page);
        need_unlock_page = 0;
        if (pos + copied > i_size_read(transcryptfs_inode)) {
                i_size_write(transcryptfs_inode, pos + copied);
                printk(KERN_DEBUG "Expanded file size to "
                        "[0x%.16llx]\n",
                        (unsigned long long)i_size_read(transcryptfs_inode));
                balance_dirty_pages_ratelimited(mapping);
		err = transcryptfs_write_inode_size_to_metadata(transcryptfs_inode);
		if (err) {
			printk(KERN_ERR "Error writing inode size to metadata; "
				"err = [%d]\n", err);
			goto out;
		}
        }
        err = copied;
out:
        if (need_unlock_page)
                unlock_page(page);
        page_cache_release(page);
        return err;
}

static int transcryptfs_writepage(struct page *page, struct writeback_control *wbc)
{
        int err;

        /*
         * Refuse to write the page out if we are called from reclaim context
         * since our writepage() path may potentially allocate memory when
         * calling into the lower fs vfs_write() which may in turn invoke
         * us again.
         */
        if (current->flags & PF_MEMALLOC) {
                redirty_page_for_writepage(wbc, page);
                err = 0;
                goto out;
        }

        err = transcryptfs_encrypt_page(page);
        if (err) {
                printk(KERN_WARNING "Error encrypting "
                                "page (upper index [0x%.16lx])\n", page->index);
                ClearPageUptodate(page);
                goto out;
        }
        SetPageUptodate(page);
out:
        unlock_page(page);
        return err;
}

static int transcryptfs_readpage(struct file *file, struct page *page)
{
        int err = 0;
	// char *page_virt;
//
//	err = transcryptfs_read_lower_page_segment(
//		 page, page->index, 0, PAGE_CACHE_SIZE,
//		 page->mapping->host);
//        if (err) {
//                printk(KERN_ERR "Error reading page; "
//                                "err = [%d]\n", err);
//                goto out;
//        }
//
        err = transcryptfs_decrypt_page(page);
        if (err) {
                printk(KERN_ERR "Error decrypting page; "
                                "err = [%d]\n", err);
                goto out;
        }
// 	page_virt = kmap(page);
// 	printk(KERN_ERR "Data read: [%s]",page_virt);
// 	kunmap(page);
out:
        if (err)
                ClearPageUptodate(page);
        else
                SetPageUptodate(page);
        printk(KERN_DEBUG "Unlocking page with index = [0x%.16lx]\n",
                        page->index);
        unlock_page(page);
        return err;
}

static sector_t transcryptfs_bmap(struct address_space *mapping, sector_t block)
{
        int err = 0;
        struct inode *inode;
        struct inode *lower_inode;

        inode = (struct inode *)mapping->host;
        lower_inode = transcryptfs_lower_inode(inode);
        if (lower_inode->i_mapping->a_ops->bmap)
                err = lower_inode->i_mapping->a_ops->bmap(lower_inode->i_mapping,
                                                         block);
        return err;
}

const struct address_space_operations transcryptfs_aops = {
        .writepage = transcryptfs_writepage,
        .readpage = transcryptfs_readpage,
        .write_begin = transcryptfs_write_begin,
        .write_end = transcryptfs_write_end,
        .bmap = transcryptfs_bmap,
};

// NOTE: Already set this structure in file.c
// const struct vm_operations_struct transcryptfs_vm_ops = {
// 	.fault		= transcryptfs_fault,
// };
