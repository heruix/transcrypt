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

#include "transcryptfs.h"

struct kmem_cache *transcryptfs_inode_info_cache;
/*
 * The inode cache is used with alloc_inode for both our inode info and the
 * vfs inode.
 */

/* final actions when unmounting a file system */
// static void transcryptfs_put_super(struct super_block *sb)
// {
// 	struct transcryptfs_sb_info *spd;
// 	struct super_block *s;
// 
// 	spd = TRANSCRYPTFS_SB(sb);
// 	if (!spd)
// 		return;
// 
// 	/* decrement lower super references */
// 	s = transcryptfs_lower_super(sb);
// 	transcryptfs_set_lower_super(sb, NULL);
// 	atomic_dec(&s->s_active);
// 
// 	kfree(spd);
// 	sb->s_fs_info = NULL;
// }

static int transcryptfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	int err;
	struct dentry *lower_dentry = transcryptfs_dentry_to_lower(dentry);
// 	struct path lower_path;

	if (!lower_dentry->d_sb->s_op->statfs)
		return -ENOSYS;

// 	transcryptfs_get_lower_path(dentry, &lower_path);
	err = lower_dentry->d_sb->s_op->statfs(lower_dentry, buf);
	if (err)
		return err;
// 	err = vfs_statfs(&lower_path, buf);
// 	transcryptfs_put_lower_path(dentry, &lower_path);

	/* set return buf to our f/s to avoid confusing user-level utils */
	buf->f_type = TRANSCRYPTFS_SUPER_MAGIC;

	return err;
}

/*
 * @flags: numeric mount options
 * @options: mount options string
 */
// static int transcryptfs_remount_fs(struct super_block *sb, int *flags, char *options)
// {
// 	int err = 0;
// 
// 	/*
// 	 * The VFS will take care of "ro" and "rw" flags among others.  We
// 	 * can safely accept a few flags (RDONLY, MANDLOCK), and honor
// 	 * SILENT, but anything else left over is an error.
// 	 */
// 	if ((*flags & ~(MS_RDONLY | MS_MANDLOCK | MS_SILENT)) != 0) {
// 		printk(KERN_ERR
// 		       "transcryptfs: remount flags 0x%x unsupported\n", *flags);
// 		err = -EINVAL;
// 	}
// 
// 	return err;
// }

/*
 * Called by iput() when the inode reference count reached zero
 * and the inode is not hashed anywhere.  Used to clear anything
 * that needs to be, before the inode is completely destroyed and put
 * on the inode free list.
 */
static void transcryptfs_evict_inode(struct inode *inode)
{
	struct inode *lower_inode;

	truncate_inode_pages(&inode->i_data, 0);
	end_writeback(inode);
	/*
	 * Decrement a reference to a lower_inode, which was incremented
	 * by our read_inode when it was created initially.
	 */
	lower_inode = transcryptfs_lower_inode(inode);
// 	transcryptfs_set_lower_inode(inode, NULL);
	iput(lower_inode);
}

static struct inode *transcryptfs_alloc_inode(struct super_block *sb)
{
	struct transcryptfs_inode_info *i;
	struct inode *inode = NULL;

	i = kmem_cache_alloc(transcryptfs_inode_info_cache, GFP_KERNEL);
	if (!i)
		goto out;
// 		return NULL;

	/* memset everything up to the inode to 0 */
// 	memset(i, 0, offsetof(struct transcryptfs_inode_info, vfs_inode));
	transcryptfs_init_crypt_stat(&i->crypt_stat);
	mutex_init(&i->lower_file_mutex);
        atomic_set(&i->lower_file_count, 0);
        i->lower_file = NULL;
	inode = &i->vfs_inode;

// 	i->vfs_inode.i_version = 1;
out:
	return inode;
}

static void transcryptfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct transcryptfs_inode_info *inode_info;
	inode_info = TRANSCRYPTFS_I(inode);
	
	kmem_cache_free(transcryptfs_inode_info_cache, inode_info);
}

static void transcryptfs_destroy_inode(struct inode *inode)
{
	struct transcryptfs_inode_info *inode_info;
	
	inode_info = TRANSCRYPTFS_I(inode);
	BUG_ON(inode_info->lower_file);
	transcryptfs_destroy_crypt_stat(&inode_info->crypt_stat);
	call_rcu(&inode->i_rcu, transcryptfs_i_callback);
// 	kmem_cache_free(transcryptfs_inode_info_cache, TRANSCRYPTFS_I(inode));
}


// int transcryptfs_init_inode_cache(void)
// {
// 	int err = 0;
// 
// 	transcryptfs_inode_info_cache =
// 		kmem_cache_create("transcryptfs_inode_cache",
// 				  sizeof(struct transcryptfs_inode_info), 0,
// 				  SLAB_RECLAIM_ACCOUNT, init_once);
// 	if (!transcryptfs_inode_info_cache)
// 		err = -ENOMEM;
// 	return err;
// }
//  
// /* transcryptfs inode cache destructor */
// void transcryptfs_destroy_inode_cache(void)
// {
// 	if (transcryptfs_inode_info_cache)
// 		kmem_cache_destroy(transcryptfs_inode_info_cache);
// }

/*
 * Used only in nfs, to kill any pending RPC tasks, so that subsequent
 * code can actually succeed and won't leave tasks that need handling.
 */
// static void transcryptfs_umount_begin(struct super_block *sb)
// {
// 	struct super_block *lower_sb;
// 
// 	lower_sb = transcryptfs_lower_super(sb);
// 	if (lower_sb && lower_sb->s_op && lower_sb->s_op->umount_begin)
// 		lower_sb->s_op->umount_begin(lower_sb);
// }

const struct super_operations transcryptfs_sops = {
// 	.put_super	= transcryptfs_put_super,
	.statfs		= transcryptfs_statfs,
	.remount_fs	= NULL,
	.evict_inode	= transcryptfs_evict_inode,
// 	.umount_begin	= transcryptfs_umount_begin,
	.show_options	= generic_show_options,
	.alloc_inode	= transcryptfs_alloc_inode,
	.destroy_inode	= transcryptfs_destroy_inode,
	.drop_inode	= generic_drop_inode,
};
