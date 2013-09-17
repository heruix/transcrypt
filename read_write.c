/**
 * eCryptfs: Linux filesystem encryption layer
 *
 * Copyright (C) 2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
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
#include <linux/pagemap.h>         
#include "transcryptfs.h"          

int transcryptfs_write_lower(struct inode *transcryptfs_inode, char *data,
                         loff_t offset, size_t size)
{       
        struct file *lower_file;
        mm_segment_t fs_save;
        ssize_t err;

        lower_file = TRANSCRYPTFS_I(transcryptfs_inode)->lower_file;
        if (!lower_file)           
                return -EIO;       
        fs_save = get_fs();
        set_fs(get_ds());
        err = vfs_write(lower_file, data, size, &offset);
        set_fs(fs_save);
        mark_inode_dirty_sync(transcryptfs_inode);
        return err;
}

int transcryptfs_write_lower_page_segment(struct inode *transcryptfs_inode,
                                      struct page *page_for_lower,
                                      size_t offset_in_page, size_t size)
{
        char *virt;
        loff_t offset;
        int err;

        offset = ((((loff_t)page_for_lower->index) << PAGE_CACHE_SHIFT)
                  + offset_in_page);
        virt = kmap(page_for_lower);
        err = transcryptfs_write_lower(transcryptfs_inode, virt, offset, size);
        if (err > 0)
                err = 0;
        kunmap(page_for_lower);
        return err;
}


int transcryptfs_write(struct inode *transcryptfs_inode, char *data, loff_t offset,
		       size_t size)
{
	struct page *transcryptfs_page;
        struct transcryptfs_crypt_stat *crypt_stat;
        char *transcryptfs_page_virt;
        loff_t transcryptfs_file_size = i_size_read(transcryptfs_inode);
        loff_t data_offset = 0;
        loff_t pos;            
        int err = 0;     
                
        crypt_stat = &TRANSCRYPTFS_I(transcryptfs_inode)->crypt_stat;
        /*
         * if we are writing beyond current size, then start pos
         * at the current size - we'll fill in zeros from there.
         */     
        if (offset > transcryptfs_file_size)
                pos = transcryptfs_file_size;
        else            
                pos = offset;
        while (pos < (offset + size)) {
                pgoff_t transcryptfs_page_idx = (pos >> PAGE_CACHE_SHIFT);
                size_t start_offset_in_page = (pos & ~PAGE_CACHE_MASK);
                size_t num_bytes = (PAGE_CACHE_SIZE - start_offset_in_page);
                loff_t total_remaining_bytes = ((offset + size) - pos);
        
                if (fatal_signal_pending(current)) {
                        err = -EINTR;
                        break;
                }

                if (num_bytes > total_remaining_bytes)
                        num_bytes = total_remaining_bytes;
                if (pos < offset) {
                        /* remaining zeros to write, up to destination offset */
                        loff_t total_remaining_zeros = (offset - pos);

                        if (num_bytes > total_remaining_zeros)
                                num_bytes = total_remaining_zeros;
                }
                transcryptfs_page = transcryptfs_get_locked_page(transcryptfs_inode,
                                                         transcryptfs_page_idx);
                if (IS_ERR(transcryptfs_page)) {
                        err = PTR_ERR(transcryptfs_page);
                        printk(KERN_ERR "%s: Error getting page at "
                               "index [%ld] from eCryptfs inode "
                               "mapping; err = [%d]\n", __func__,
                               transcryptfs_page_idx, err);
                        goto out;
                }
                transcryptfs_page_virt = kmap_atomic(transcryptfs_page);
		                /*
                 * pos: where we're now writing, offset: where the request was
                 * If current pos is before request, we are filling zeros
                 * If we are at or beyond request, we are writing the *data*
                 * If we're in a fresh page beyond eof, zero it in either case
                 */
                if (pos < offset || !start_offset_in_page) {
                        /* We are extending past the previous end of the file.
                         * Fill in zero values to the end of the page */
                        memset(((char *)transcryptfs_page_virt
                                + start_offset_in_page), 0,
                                PAGE_CACHE_SIZE - start_offset_in_page);
                }

                /* pos >= offset, we are now writing the data request */
                if (pos >= offset) {
                        memcpy(((char *)transcryptfs_page_virt
                                + start_offset_in_page),
                               (data + data_offset), num_bytes);
                        data_offset += num_bytes;
                }
                kunmap_atomic(transcryptfs_page_virt);
                flush_dcache_page(transcryptfs_page);
                SetPageUptodate(transcryptfs_page);
                unlock_page(transcryptfs_page);
                if (crypt_stat->flags & TRANSCRYPTFS_ENCRYPTED)
                        err = transcryptfs_encrypt_page(transcryptfs_page);
                else
                        err = transcryptfs_write_lower_page_segment(transcryptfs_inode,
                                                transcryptfs_page,
                                                start_offset_in_page,
                                                data_offset);
                page_cache_release(transcryptfs_page);
                if (err) {
                        printk(KERN_ERR "%s: Error encrypting "
                               "page; err = [%d]\n", __func__, err);
                        goto out;
                }
                pos += num_bytes;
        }
        if (pos > transcryptfs_file_size) {
                i_size_write(transcryptfs_inode, pos);
                if (crypt_stat->flags & TRANSCRYPTFS_ENCRYPTED) {
                        int err2;

                        err2 = transcryptfs_write_inode_size_to_metadata(
                                                                transcryptfs_inode);
                        if (err2) {
                                printk(KERN_ERR "Problem with "
                                       "transcryptfs_write_inode_size_to_metadata; "
                                       "err = [%d]\n", err2);
				if (!err)
                                        err = err2;
                                goto out;
                        }
                }
        }
out:
        return err;
}


int transcryptfs_read_lower(char *data, loff_t offset, size_t size,
                            struct inode *transcryptfs_inode)
{
        struct file *lower_file;
        mm_segment_t fs_save;
        ssize_t err;
        
        lower_file = TRANSCRYPTFS_I(transcryptfs_inode)->lower_file;
        if (!lower_file)
                return -EIO;
        fs_save = get_fs();                           
        set_fs(get_ds());                             
        err = vfs_read(lower_file, data, size, &offset);
        set_fs(fs_save);
        return err;      
} 

int transcryptfs_read_lower_page_segment(struct page *page_for_transcryptfs,
                                         pgoff_t page_index,
                                         size_t offset_in_page, size_t size,
                                         struct inode *transcryptfs_inode)
{                                       
        char *virt;     
        loff_t offset;
        int err;

        offset = ((((loff_t)page_index) << PAGE_CACHE_SHIFT) + offset_in_page);
        virt = kmap(page_for_transcryptfs);
        err = transcryptfs_read_lower(virt, offset, size, transcryptfs_inode);
        if (err > 0)
                err = 0;
        kunmap(page_for_transcryptfs);
        flush_dcache_page(page_for_transcryptfs);
        return err;
}
