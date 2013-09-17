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

/*
 * returns: -ERRNO if error (returned to user)
 *          0: tell VFS to invalidate dentry
 *          1: dentry is valid
 */
static int transcryptfs_d_revalidate(struct dentry *dentry, struct nameidata *nd)
{
//	struct path lower_path;//,  saved_path;
	struct dentry *lower_dentry;
	struct vfsmount *lower_mnt;
	struct dentry *dentry_save = NULL;
	struct vfsmount *vfsmount_save = NULL;
	int err = 1;

	if (nd && nd->flags & LOOKUP_RCU)
		return -ECHILD;

// 	transcryptfs_get_lower_path(dentry, &lower_path);
	lower_dentry = transcryptfs_dentry_to_lower(dentry);
	lower_mnt = transcryptfs_dentry_to_lower_mnt(dentry);
	if (!lower_dentry->d_op || !lower_dentry->d_op->d_revalidate)
		goto out;
	if (nd) {
		dentry_save = nd->path.dentry;
		vfsmount_save = nd->path.mnt;
		nd->path.dentry = lower_dentry;
		nd->path.mnt = lower_mnt;
	}
// 	pathcpy(&saved_path, &nd->path);
// 	pathcpy(&nd->path, &lower_path);
	err = lower_dentry->d_op->d_revalidate(lower_dentry, nd);
	if (err) {
		nd->path.dentry = dentry_save;
		nd->path.mnt = vfsmount_save;
	}
	if (dentry->d_inode) {
		struct inode *lower_inode =
			transcryptfs_lower_inode(dentry->d_inode);

		fsstack_copy_attr_all(dentry->d_inode, lower_inode);
	}
// 	pathcpy(&nd->path, &saved_path);
out:
//	transcryptfs_put_lower_path(dentry, &lower_path);
	return err;
}

struct kmem_cache *transcryptfs_dentry_info_cache;

static void transcryptfs_d_release(struct dentry *dentry)
{
	/* release and reset the lower paths */
	if (TRANSCRYPTFS_D(dentry)) {
		if (transcryptfs_dentry_to_lower(dentry)) {
			dput(transcryptfs_dentry_to_lower(dentry));
			mntput(transcryptfs_dentry_to_lower_mnt(dentry));
		}
		kmem_cache_free(transcryptfs_dentry_info_cache, 
				TRANSCRYPTFS_D(dentry));
	}
// 	transcryptfs_put_reset_lower_path(dentry);
// 	free_dentry_private_data(dentry);
	return;
}

const struct dentry_operations transcryptfs_dops = {
	.d_revalidate	= transcryptfs_d_revalidate,
	.d_release	= transcryptfs_d_release,
};
