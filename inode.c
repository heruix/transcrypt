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
#include <linux/pagemap.h>

static int transcryptfs_inode_test(struct inode *inode, void *candidate_lower_inode)
{
	struct inode *current_lower_inode = transcryptfs_lower_inode(inode);
	if (current_lower_inode == (struct inode *)candidate_lower_inode)
		return 1; /* found a match */
	else
		return 0; /* no match */
}

static int transcryptfs_inode_set(struct inode *inode, void *opaque)
{
	/* we do actual inode initialization in transcryptfs_iget */
	struct inode *lower_inode = opaque;

	transcryptfs_set_lower_inode(inode, lower_inode);
	fsstack_copy_attr_all(inode, lower_inode);

	fsstack_copy_inode_size(inode, lower_inode);
	inode->i_ino = lower_inode->i_ino;
	inode->i_version++;
	inode->i_mapping->a_ops = &transcryptfs_aops;
	inode->i_mapping->backing_dev_info = inode->i_sb->s_bdi;

	if (S_ISLNK(inode->i_mode))
		inode->i_op = &transcryptfs_symlink_iops;
	else if (S_ISDIR(inode->i_mode))
		inode->i_op = &transcryptfs_dir_iops;
	else
		inode->i_op = &transcryptfs_main_iops;

	if (S_ISDIR(inode->i_mode))
		inode->i_fop = &transcryptfs_dir_fops;
	else if (special_file(inode->i_mode))
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
	else
		inode->i_fop = &transcryptfs_main_fops;

	return 0;
}


static struct inode *__transcryptfs_get_inode(struct inode *lower_inode,
					      struct super_block *sb)
{
	struct inode *inode;
	
	if (lower_inode->i_sb != ((struct transcryptfs_sb_info *)sb->s_fs_info)->lower_sb)
		return ERR_PTR(-EXDEV);
	if(!igrab(lower_inode))
		return ERR_PTR(-ESTALE);
	inode = iget5_locked(sb, (unsigned long)lower_inode,
			     transcryptfs_inode_test, transcryptfs_inode_set,
			     lower_inode);
	if (!inode) {
		iput(lower_inode);
		return ERR_PTR(-EACCES);
	}
	if (!(inode->i_state & I_NEW))
		iput(lower_inode);
	
	return inode;
}

struct inode *transcryptfs_get_inode(struct inode *lower_inode,
				     struct super_block *sb)
{
	struct inode *inode = __transcryptfs_get_inode(lower_inode, sb);

	if(!IS_ERR(inode) && (inode->i_state & I_NEW))
		unlock_new_inode(inode);

	return inode;
}
static int transcryptfs_interpose(struct dentry *lower_dentry, 
				  struct dentry *dentry, 
				  struct super_block *sb)
{
	int err = 0;
	struct inode *inode = transcryptfs_get_inode(lower_dentry->d_inode, sb);
// 	struct inode *lower_inode;
// 	struct super_block *lower_sb;
// 
// 	lower_inode = lower_path->dentry->d_inode;
// 	lower_sb = transcryptfs_lower_super(sb);
// 
// 	/* check that the lower file system didn't cross a mount point */
// 	if (lower_inode->i_sb != lower_sb) {
// 		err = -EXDEV;
// 		goto out;
// 	}
// 
// 	/*
// 	 * We allocate our new inode below by calling transcryptfs_iget,
// 	 * which will initialize some of the new inode's fields
// 	 */
// 
// 	/* inherit lower inode number for transcryptfs's inode */
// 	inode = transcryptfs_get_inode(lower_inode, sb);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out;
	}

	d_instantiate(dentry, inode);

out:
	return err;
}
static struct inode *
transcryptfs_do_create(struct inode *directory_inode,
		       struct dentry *transcryptfs_dentry, umode_t mode)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	struct inode *inode = NULL;
	
	lower_dentry = transcryptfs_dentry_to_lower(transcryptfs_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);
	if (IS_ERR(lower_dir_dentry)) {
		printk(KERN_ERR "Error locking directory of dentry\n");
		inode = ERR_CAST(lower_dir_dentry);
		goto out;
	}
	err = vfs_create(lower_dir_dentry->d_inode, lower_dentry, mode, NULL);
	if (err) {
		printk(KERN_ERR "%s: Failed to create dentry in lower fs; "
		       "err = [%d]\n", __func__, err);
		goto out_lock;
	}
	inode = __transcryptfs_get_inode(lower_dentry->d_inode,
					 directory_inode->i_sb);
	if (IS_ERR(inode))
		goto out_lock;
	fsstack_copy_attr_times(directory_inode, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(directory_inode, lower_dir_dentry->d_inode);
out_lock:
	unlock_dir(lower_dir_dentry);
out:
	return inode;
}

static int transcryptfs_initialize_file(struct dentry *transcryptfs_dentry,
					struct inode *transcryptfs_inode)
{
	struct transcryptfs_crypt_stat *crypt_stat = 
		&TRANSCRYPTFS_I(transcryptfs_inode)->crypt_stat;
	int err = 0;
	
	if (S_ISDIR(transcryptfs_inode->i_mode)) {
		crypt_stat->flags &= ~(TRANSCRYPTFS_ENCRYPTED);
		goto out;
	}
	
	err = transcryptfs_new_file_context(transcryptfs_inode);

	if (err) {
		printk(KERN_ERR "Error creating new file context;"
		       " err = [%d]\n",err);
		goto out;
	}
	
	err = transcryptfs_get_lower_file(transcryptfs_dentry, 
					  transcryptfs_inode);
	if (err) {
		printk(KERN_ERR "%s: Error attempting to initialize "
                        "the lower file for the dentry with name "
                        "[%s]; err = [%d]\n", __func__,
                        transcryptfs_dentry->d_name.name, err);
                goto out;
        }
	err = transcryptfs_write_metadata(transcryptfs_dentry, 
					  transcryptfs_inode);
	if (err) 
		printk(KERN_ERR "Error writing headers; err = [%d]\n", err);
	transcryptfs_put_lower_file(transcryptfs_inode);
out:
	return err;
}
	
static int transcryptfs_create(struct inode *directory_inode, 
			       struct dentry *transcryptfs_dentry,
			       umode_t mode, struct nameidata *nd)
{
	int err = 0;
	struct inode *transcryptfs_inode;

// 	struct dentry *lower_dentry;
// 	struct dentry *lower_parent_dentry = NULL;
// 	struct path lower_path, saved_path;

	transcryptfs_inode = transcryptfs_do_create(directory_inode, 
						    transcryptfs_dentry, mode);

	if (unlikely(IS_ERR(transcryptfs_inode))) {
		printk(KERN_WARNING "Failed to create lower filesystem\n");
		err = PTR_ERR(transcryptfs_inode);
		goto out;
	}

	// dump_stack();
	err = transcryptfs_initialize_file(transcryptfs_dentry, 
					   transcryptfs_inode);
	if (err) {
		drop_nlink(transcryptfs_inode);
		unlock_new_inode(transcryptfs_inode);
		iput(transcryptfs_inode);
		goto out;
	}
	d_instantiate(transcryptfs_dentry, transcryptfs_inode);
	unlock_new_inode(transcryptfs_inode);
// 	transcryptfs_get_lower_path(dentry, &lower_path);
// 	lower_dentry = lower_path.dentry;
// 	lower_parent_dentry = lock_parent(lower_dentry);
// 
// 	err = mnt_want_write(lower_path.mnt);
// 	if (err)
// 		goto out_unlock;
// 
// 	pathcpy(&saved_path, &nd->path);
// 	pathcpy(&nd->path, &lower_path);
// 	err = vfs_create(lower_parent_dentry->d_inode, lower_dentry, mode, nd);
// 	pathcpy(&nd->path, &saved_path);
// 	if (err)
// 		goto out;
// 
// 	err = transcryptfs_interpose(dentry, dir->i_sb, &lower_path);
// 	if (err)
// 		goto out;
// 	fsstack_copy_attr_times(dir, transcryptfs_lower_inode(dir));
// 	fsstack_copy_inode_size(dir, lower_parent_dentry->d_inode);
// 
// out:
// 	mnt_drop_write(lower_path.mnt);
// out_unlock:
// 	unlock_dir(lower_parent_dentry);
// 	transcryptfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int transcryptfs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;
// 	struct path lower_old_path, lower_new_path;

	file_size_save = i_size_read(old_dentry->d_inode);
// 	transcryptfs_get_lower_path(old_dentry, &lower_old_path);
// 	transcryptfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = transcryptfs_dentry_to_lower(old_dentry);// lower_old_path.dentry;
	lower_new_dentry = transcryptfs_dentry_to_lower(new_dentry);// lower_new_path.dentry;
	dget(lower_old_dentry);
	dget(lower_new_dentry);
	lower_dir_dentry = lock_parent(lower_new_dentry);

//	err = mnt_want_write(lower_new_path.mnt);
//	if (err)
//		goto out_unlock;

	err = vfs_link(lower_old_dentry, lower_dir_dentry->d_inode,
		       lower_new_dentry);
	if (err || !lower_new_dentry->d_inode)
		goto out;

	err = transcryptfs_interpose(lower_new_dentry, new_dentry, dir->i_sb);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_new_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_new_dentry->d_inode);
	set_nlink(old_dentry->d_inode,
		transcryptfs_lower_inode(old_dentry->d_inode)->i_nlink);
	i_size_write(new_dentry->d_inode, file_size_save);
out:
//	mnt_drop_write(lower_new_path.mnt);
// out_unlock:
	unlock_dir(lower_dir_dentry);
	dput(lower_new_dentry);
	dput(lower_old_dentry);
//	transcryptfs_put_lower_path(old_dentry, &lower_old_path);
//	transcryptfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static int transcryptfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode = transcryptfs_lower_inode(dir);
	struct dentry *lower_dir_dentry;
	struct path lower_path;

	transcryptfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	dget(lower_dentry);
	lower_dir_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_unlink(lower_dir_inode, lower_dentry);

	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS
	 * below.  Silly-renamed files will get deleted by NFS later on, so
	 * we just need to detect them here and treat such EBUSY errors as
	 * if the upper file was successfully deleted.
	 */
	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
		err = 0;
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	fsstack_copy_inode_size(dir, lower_dir_inode);
	set_nlink(dentry->d_inode,
		transcryptfs_lower_inode(dentry->d_inode)->i_nlink);
	dentry->d_inode->i_ctime = dir->i_ctime;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	transcryptfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int transcryptfs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry = NULL;
	char *encoded_symname;
	size_t encoded_symlen;
 	struct path lower_path;

	transcryptfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

	err = transcryptfs_encrypt_and_encode_filename(&encoded_symname,
						       &encoded_symlen, 
						       symname,
						       strlen(symname));
	if (err)
		goto out;

// 	err = mnt_want_write(lower_path.mnt);
// 	if (err)
// 		goto out_unlock;
	err = vfs_symlink(lower_dir_dentry->d_inode, lower_dentry, encoded_symname);
	kfree(encoded_symname);
	if (err || !lower_dentry->d_inode)
		goto out;
	err = transcryptfs_interpose(lower_dentry, dentry, dir->i_sb);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);

out:
// 	mnt_drop_write(lower_path.mnt);
// out_lock:
	unlock_dir(lower_dir_dentry);
	// transcryptfs_put_lower_path(dentry, &lower_path);
	dput(lower_dentry);
	if(!dentry->d_inode)
		d_drop(dentry);
	return err;
}

static int transcryptfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry = NULL;
 	struct path lower_path;

	transcryptfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

// 	err = mnt_want_write(lower_path.mnt);
// 	if (err)
// 		goto out_unlock;
	err = vfs_mkdir(lower_dir_dentry->d_inode, lower_dentry, mode);
	if (err || !lower_dentry->d_inode)
		goto out;

	err = transcryptfs_interpose(lower_dentry, dentry, dir->i_sb);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
	/* update number of links on parent directory */
	set_nlink(dir, lower_dir_dentry->d_inode->i_nlink);

out:
// 	mnt_drop_write(lower_path.mnt);
// out_unlock:
	unlock_dir(lower_dir_dentry);
	if (!dentry->d_inode)
		d_drop(dentry);
// 	transcryptfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int transcryptfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path lower_path;

	transcryptfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

	err = mnt_want_write(lower_path.mnt);
	if (err)
		goto out_unlock;
	err = vfs_rmdir(lower_dir_dentry->d_inode, lower_dentry);
	if (err)
		goto out;

	d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */
	if (dentry->d_inode)
		clear_nlink(dentry->d_inode);
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);
	set_nlink(dir, lower_dir_dentry->d_inode->i_nlink);

out:
	mnt_drop_write(lower_path.mnt);
out_unlock:
	unlock_dir(lower_dir_dentry);
	transcryptfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int transcryptfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
			dev_t dev)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry = NULL;
	struct path lower_path;

	transcryptfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

// 	err = mnt_want_write(lower_path.mnt);
// 	if (err)
// 		goto out_unlock;
	err = vfs_mknod(lower_dir_dentry->d_inode, lower_dentry, mode, dev);
	if (err || !lower_dentry->d_inode)
		goto out;

	err = transcryptfs_interpose(lower_dentry, dentry, dir->i_sb);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, lower_dir_dentry->d_inode);
	fsstack_copy_inode_size(dir, lower_dir_dentry->d_inode);

out:
// 	mnt_drop_write(lower_path.mnt);
// out_unlock:
	unlock_dir(lower_dir_dentry);
	if (!dentry->d_inode)
		d_drop(dentry);
//	transcryptfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * The locking rules in transcryptfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int transcryptfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;

	transcryptfs_get_lower_path(old_dentry, &lower_old_path);
	transcryptfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = mnt_want_write(lower_old_path.mnt);
	if (err)
		goto out;
	err = mnt_want_write(lower_new_path.mnt);
	if (err)
		goto out_drop_old_write;

	err = vfs_rename(lower_old_dir_dentry->d_inode, lower_old_dentry,
			 lower_new_dir_dentry->d_inode, lower_new_dentry);
	if (err)
		goto out_err;

	fsstack_copy_attr_all(new_dir, lower_new_dir_dentry->d_inode);
	fsstack_copy_inode_size(new_dir, lower_new_dir_dentry->d_inode);
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				      lower_old_dir_dentry->d_inode);
		fsstack_copy_inode_size(old_dir,
					lower_old_dir_dentry->d_inode);
	}

out_err:
	mnt_drop_write(lower_new_path.mnt);
out_drop_old_write:
	mnt_drop_write(lower_old_path.mnt);
out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	transcryptfs_put_lower_path(old_dentry, &lower_old_path);
	transcryptfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static int transcryptfs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	transcryptfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!lower_dentry->d_inode->i_op ||
	    !lower_dentry->d_inode->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = lower_dentry->d_inode->i_op->readlink(lower_dentry,
						    buf, bufsiz);
	if (err < 0)
		goto out;
	fsstack_copy_attr_atime(dentry->d_inode, lower_dentry->d_inode);

out:
	transcryptfs_put_lower_path(dentry, &lower_path);
	return err;
}

static void *transcryptfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	/* This is freed by the put_link method assuming a successful call. */
	buf = kzalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		goto out;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = transcryptfs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = ERR_PTR(err);
	} else {
		buf[err] = '\0';
	}
out:
	nd_set_link(nd, buf);
	return NULL;
}

/* this @nd *IS* still used */
static void transcryptfs_put_link(struct dentry *dentry, struct nameidata *nd,
			    void *cookie)
{
	char *buf = nd_get_link(nd);
	if (!IS_ERR(buf))	/* free the char* */
		kfree(buf);
}

static loff_t
upper_size_to_lower_size(struct transcryptfs_crypt_stat *crypt_stat,
                         loff_t upper_size)
{
        loff_t lower_size;

        lower_size = crypt_stat->metadata_size;
        if (upper_size != 0) {
                loff_t num_extents;

                num_extents = upper_size >> crypt_stat->extent_shift;
                if (upper_size & ~crypt_stat->extent_mask)
                        num_extents++;
                lower_size += (num_extents * crypt_stat->extent_size);
        }
        return lower_size;
}

static int truncate_upper(struct dentry *dentry, struct iattr *ia,
			  struct iattr *lower_ia)
{
	int err = 0;
	struct inode *inode = dentry->d_inode;
	struct transcryptfs_crypt_stat *crypt_stat;
	loff_t i_size = i_size_read(inode);
	loff_t lower_size_before_truncate;
	loff_t lower_size_after_truncate;

	if (unlikely((ia->ia_size == i_size))) {
		lower_ia->ia_valid &= ~ATTR_SIZE;
		return 0;
	}
	err = transcryptfs_get_lower_file(dentry, inode);
	if (err)
		return err;
	crypt_stat = &TRANSCRYPTFS_I(dentry->d_inode)->crypt_stat;
	if (ia->ia_size > i_size) {
                char zero[] = { 0x00 };

                lower_ia->ia_valid &= ~ATTR_SIZE;
                /* Write a single 0 at the last position of the file;
                 * this triggers code that will fill in 0's throughout
                 * the intermediate portion of the previous end of the
                 * file and the new and of the file */
                err = transcryptfs_write(inode, zero,
                                    (ia->ia_size - 1), 1);
        } else { /* ia->ia_size < i_size_read(inode) */
                /* We're chopping off all the pages down to the page
                 * in which ia->ia_size is located. Fill in the end of
                 * that page from (ia->ia_size & ~PAGE_CACHE_MASK) to
                 * PAGE_CACHE_SIZE with zeros. */
                size_t num_zeros = (PAGE_CACHE_SIZE
                                    - (ia->ia_size & ~PAGE_CACHE_MASK));

                if (!(crypt_stat->flags & TRANSCRYPTFS_ENCRYPTED)) {
                        truncate_setsize(inode, ia->ia_size);
                        lower_ia->ia_size = ia->ia_size;
                        lower_ia->ia_valid |= ATTR_SIZE;
                        goto out;
                }
                if (num_zeros) {
                        char *zeros_virt;

                        zeros_virt = kzalloc(num_zeros, GFP_KERNEL);
                        if (!zeros_virt) {
                                err = -ENOMEM;
                                goto out;
                        }
                        err = transcryptfs_write(inode, zeros_virt,
                                            ia->ia_size, num_zeros);
                        kfree(zeros_virt);
			if (err) {
                                printk(KERN_ERR "Error attempting to zero out "
                                       "the remainder of the end page on "
                                       "reducing truncate; err = [%d]\n", err);
                                goto out;
                        }
                }
                truncate_setsize(inode, ia->ia_size);
                err = transcryptfs_write_inode_size_to_metadata(inode);
                if (err) {
                        printk(KERN_ERR "Problem with "
                               "myecryptfs_write_inode_size_to_metadata; "
                               "err = [%d]\n", err);
                        goto out;
                }
                /* We are reducing the size of the myecryptfs file, and need to
                 * know if we need to reduce the size of the lower file. */
                lower_size_before_truncate =
                    upper_size_to_lower_size(crypt_stat, i_size);
                lower_size_after_truncate =
                    upper_size_to_lower_size(crypt_stat, ia->ia_size);
                if (lower_size_after_truncate < lower_size_before_truncate) {
                        lower_ia->ia_size = lower_size_after_truncate;
                        lower_ia->ia_valid |= ATTR_SIZE;
                } else
                        lower_ia->ia_valid &= ~ATTR_SIZE;
        }
out:
        transcryptfs_put_lower_file(inode);
        return err;
}

static int transcryptfs_inode_newsize_ok(struct inode *inode, loff_t offset)
{
	struct transcryptfs_crypt_stat *crypt_stat;
	loff_t lower_oldsize, lower_newsize;
	
	crypt_stat = &TRANSCRYPTFS_I(inode)->crypt_stat;
	lower_oldsize = upper_size_to_lower_size(crypt_stat,
						 i_size_read(inode));
	lower_newsize = upper_size_to_lower_size(crypt_stat, offset);
	if (lower_newsize > lower_oldsize) {
		return inode_newsize_ok(inode, lower_newsize);
	}
	
	return 0;
}

int transcryptfs_truncate(struct dentry *dentry, loff_t new_length)
{
	struct iattr ia = { .ia_valid = ATTR_SIZE, .ia_size = new_length };
	struct iattr lower_ia = { .ia_valid = 0 };
	int err;
	
	err = transcryptfs_inode_newsize_ok(dentry->d_inode, new_length);
	if (err)
		return err;

	err = truncate_upper(dentry, &ia, &lower_ia);
	if (!err && lower_ia.ia_valid & ATTR_SIZE) {
		struct dentry * lower_dentry = transcryptfs_dentry_to_lower(dentry);

		mutex_lock(&lower_dentry->d_inode->i_mutex);
		err = notify_change(lower_dentry, &lower_ia);
		mutex_unlock(&lower_dentry->d_inode->i_mutex);
	}
	return err;
}

static int transcryptfs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err;

	lower_inode = transcryptfs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);
	return err;
}

static int transcryptfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err = 0;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;

	inode = dentry->d_inode;

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = inode_change_ok(inode, ia);
	if (err)
		goto out_err;

	transcryptfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = transcryptfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = transcryptfs_file_to_lower(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use lower_dentry->d_inode, because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	mutex_lock(&lower_dentry->d_inode->i_mutex);
	err = notify_change(lower_dentry, &lower_ia); /* note: lower_ia */
	mutex_unlock(&lower_dentry->d_inode->i_mutex);
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	transcryptfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

const struct inode_operations transcryptfs_symlink_iops = {
	.readlink	= transcryptfs_readlink,
	.permission	= transcryptfs_permission,
	.follow_link	= transcryptfs_follow_link,
	.setattr	= transcryptfs_setattr,
	.put_link	= transcryptfs_put_link,
};

const struct inode_operations transcryptfs_dir_iops = {
	.create		= transcryptfs_create,
	.lookup		= transcryptfs_lookup,
	.link		= transcryptfs_link,
	.unlink		= transcryptfs_unlink,
	.symlink	= transcryptfs_symlink,
	.mkdir		= transcryptfs_mkdir,
	.rmdir		= transcryptfs_rmdir,
	.mknod		= transcryptfs_mknod,
	.rename		= transcryptfs_rename,
	.permission	= transcryptfs_permission,
	.setattr	= transcryptfs_setattr,
};

const struct inode_operations transcryptfs_main_iops = {
	.permission	= transcryptfs_permission,
	.setattr	= transcryptfs_setattr,
};
// Lookup.c  Appended
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

// #include "transcryptfs.h"

/* The dentry cache is just so we have properly sized dentries */
// struct kmem_cache *transcryptfs_dentry_info_cache;

// int transcryptfs_init_dentry_cache(void)
// {
// 	transcryptfs_dentry_info_cache =
// 		kmem_cache_create("transcryptfs_dentry",
// 				  sizeof(struct transcryptfs_dentry_info),
// 				  0, SLAB_RECLAIM_ACCOUNT, NULL);
// 
// 	return transcryptfs_dentry_info_cache ? 0 : -ENOMEM;
// }
// 
// void transcryptfs_destroy_dentry_cache(void)
// {
// 	if (transcryptfs_dentry_info_cache)
// 		kmem_cache_destroy(transcryptfs_dentry_info_cache);
// }

void free_dentry_private_data(struct dentry *dentry)
{
	if (!dentry || !dentry->d_fsdata)
		return;
	kmem_cache_free(transcryptfs_dentry_info_cache, dentry->d_fsdata);
	dentry->d_fsdata = NULL;
}

/* allocate new dentry private data */
int new_dentry_private_data(struct dentry *dentry)
{
	struct transcryptfs_dentry_info *info = TRANSCRYPTFS_D(dentry);

	/* use zalloc to init dentry_info.lower_path */
	info = kmem_cache_zalloc(transcryptfs_dentry_info_cache, GFP_ATOMIC);
	if (!info)
		return -ENOMEM;

	spin_lock_init(&info->lock);
	dentry->d_fsdata = info;

	return 0;
}

// struct inode *transcryptfs_iget(struct super_block *sb, struct inode *lower_inode)
// {
// 	struct transcryptfs_inode_info *info;
// 	struct inode *inode; /* the new inode to return */
// 	int err;
// 
// 	inode = iget5_locked(sb, /* our superblock */
// 			     /*
// 			      * hashval: we use inode number, but we can
// 			      * also use "(unsigned long)lower_inode"
// 			      * instead.
// 			      */
// 			     lower_inode->i_ino, /* hashval */
// 			     transcryptfs_inode_test,	/* inode comparison function */
// 			     transcryptfs_inode_set, /* inode init function */
// 			     lower_inode); /* data passed to test+set fxns */
// 	if (!inode) {
// 		err = -EACCES;
// 		iput(lower_inode);
// 		return ERR_PTR(err);
// 	}
// 	/* if found a cached inode, then just return it */
// 	if (!(inode->i_state & I_NEW))
// 		return inode;
// 
// 	/* initialize new inode */
// 	info = TRANSCRYPTFS_I(inode);
// 
// 	inode->i_ino = lower_inode->i_ino;
// 	if (!igrab(lower_inode)) {
// 		err = -ESTALE;
// 		return ERR_PTR(err);
// 	}
// 	transcryptfs_set_lower_inode(inode, lower_inode);
// 
// 	inode->i_version++;
// 
// 	/* use different set of inode ops for symlinks & directories */
// 	if (S_ISDIR(lower_inode->i_mode))
// 		inode->i_op = &transcryptfs_dir_iops;
// 	else if (S_ISLNK(lower_inode->i_mode))
// 		inode->i_op = &transcryptfs_symlink_iops;
// 	else
// 		inode->i_op = &transcryptfs_main_iops;
// 
// 	/* use different set of file ops for directories */
// 	if (S_ISDIR(lower_inode->i_mode))
// 		inode->i_fop = &transcryptfs_dir_fops;
// 	else
// 		inode->i_fop = &transcryptfs_main_fops;
// 
// 	inode->i_mapping->a_ops = &transcryptfs_aops;
// 
// 	inode->i_atime.tv_sec = 0;
// 	inode->i_atime.tv_nsec = 0;
// 	inode->i_mtime.tv_sec = 0;
// 	inode->i_mtime.tv_nsec = 0;
// 	inode->i_ctime.tv_sec = 0;
// 	inode->i_ctime.tv_nsec = 0;
// 
// 	/* properly initialize special inodes */
// 	if (S_ISBLK(lower_inode->i_mode) || S_ISCHR(lower_inode->i_mode) ||
// 	    S_ISFIFO(lower_inode->i_mode) || S_ISSOCK(lower_inode->i_mode))
// 		init_special_inode(inode, lower_inode->i_mode,
// 				   lower_inode->i_rdev);
// 
// 	/* all well, copy inode attributes */
// 	fsstack_copy_attr_all(inode, lower_inode);
// 	fsstack_copy_inode_size(inode, lower_inode);
// 
// 	unlock_new_inode(inode);
// 	return inode;
// }

/*
 * Connect a transcryptfs inode dentry/inode with several lower ones.  This is
 * the classic stackable file system "vnode interposition" action.
 *
 * @dentry: transcryptfs's dentry which interposes on lower one
 * @sb: transcryptfs's super_block
 * @lower_path: the lower path (caller does path_get/put)
 */


/*
 * Main driver function for transcryptfs's lookup.
 *
 * Returns: NULL (ok), ERR_PTR if an error occurred.
 * Fills in lower_parent_path with <dentry,mnt> on success.
 */
// static struct dentry *__transcryptfs_lookup(struct dentry *dentry, int flags,
// 				      struct path *lower_parent_path)
// {
// 	int err = 0;
// 	struct vfsmount *lower_dir_mnt;
// 	struct dentry *lower_dir_dentry = NULL;
// 	struct dentry *lower_dentry;
// 	const char *name;
// 	struct path lower_path;
// 	struct qstr this;
// 
// 	/* must initialize dentry operations */
// 	d_set_d_op(dentry, &transcryptfs_dops);
// 
// 	if (IS_ROOT(dentry))
// 		goto out;
// 
// 	name = dentry->d_name.name;
// 
// 	/* now start the actual lookup procedure */
// 	lower_dir_dentry = lower_parent_path->dentry;
// 	lower_dir_mnt = lower_parent_path->mnt;
// 
// 	/* Use vfs_path_lookup to check if the dentry exists or not */
// 	err = vfs_path_lookup(lower_dir_dentry, lower_dir_mnt, name, 0,
// 			      &lower_path);
// 
// 	/* no error: handle positive dentries */
// 	if (!err) {
// 		transcryptfs_set_lower_path(dentry, &lower_path);
// 		err = transcryptfs_interpose(dentry, dentry->d_sb, &lower_path);
// 		if (err) /* path_put underlying path on error */
// 			transcryptfs_put_reset_lower_path(dentry);
// 		goto out;
// 	}
// 
// 	/*
// 	 * We don't consider ENOENT an error, and we want to return a
// 	 * negative dentry.
// 	 */
// 	if (err && err != -ENOENT)
// 		goto out;
// 
// 	/* instatiate a new negative dentry */
// 	this.name = name;
// 	this.len = strlen(name);
// 	this.hash = full_name_hash(this.name, this.len);
// 	lower_dentry = d_lookup(lower_dir_dentry, &this);
// 	if (lower_dentry)
// 		goto setup_lower;
// 
// 	lower_dentry = d_alloc(lower_dir_dentry, &this);
// 	if (!lower_dentry) {
// 		err = -ENOMEM;
// 		goto out;
// 	}
// 	d_add(lower_dentry, NULL); /* instantiate and hash */
// 
// setup_lower:
// 	lower_path.dentry = lower_dentry;
// 	lower_path.mnt = mntget(lower_dir_mnt);
// 	transcryptfs_set_lower_path(dentry, &lower_path);
// 
// 	/*
// 	 * If the intent is to create a file, then don't return an error, so
// 	 * the VFS will continue the process of making this negative dentry
// 	 * into a positive one.
// 	 */
// 	if (flags & (LOOKUP_CREATE|LOOKUP_RENAME_TARGET))
// 		err = 0;
// 
// out:
// 	return ERR_PTR(err);
// }

static int transcryptfs_i_size_read(struct dentry *dentry, struct inode *inode)
{
	int err;
	struct transcryptfs_crypt_stat *crypt_stat;	

	err = transcryptfs_get_lower_file(dentry, inode);
	if (err) {
		printk(KERN_ERR "%s: Error attempting to initialize "
                        "the lower file for the dentry with name "
                        "[%s]; rc = [%d]\n", __func__,
                        dentry->d_name.name, err);
		return err;
	}

	crypt_stat = &TRANSCRYPTFS_I(inode)->crypt_stat;

	if (!(crypt_stat->flags & TRANSCRYPTFS_POLICY_APPLIED))
		transcryptfs_set_default_sizes(crypt_stat);

	err = transcryptfs_read_and_validate_header_region(inode);
	transcryptfs_put_lower_file(inode);
	return 0;
}

static int transcryptfs_lookup_interpose(struct dentry *dentry,
					 struct dentry *lower_dentry,
					 struct inode *dir_inode)
{
	struct inode *inode, *lower_inode = lower_dentry->d_inode;
	struct transcryptfs_dentry_info *dentry_info;
	struct vfsmount *lower_mnt;
	int err = 0;

	lower_mnt = mntget(transcryptfs_dentry_to_lower_mnt(dentry->d_parent));
	fsstack_copy_attr_atime(dir_inode, lower_dentry->d_parent->d_inode);
	BUG_ON(!lower_dentry->d_count);

	dentry_info = kmem_cache_alloc(transcryptfs_dentry_info_cache, GFP_KERNEL);
	dentry->d_fsdata = dentry_info;
	if (!dentry_info) {
		printk(KERN_ERR "%s: Out of memory whilst attempting "
                       "to allocate transcryptfs_dentry_info struct\n",
                        __func__);
                dput(lower_dentry);
                mntput(lower_mnt);
                d_drop(dentry); 
                return -ENOMEM;
        }

	TRANSCRYPTFS_D(dentry)->lower_path.dentry = lower_dentry;
	TRANSCRYPTFS_D(dentry)->lower_path.mnt = lower_mnt;

	if( !lower_dentry->d_inode) {
		d_add(dentry, NULL);
		return 0;
	}
	inode = __transcryptfs_get_inode(lower_inode, dir_inode->i_sb);
	if (IS_ERR(inode)) {
		printk(KERN_ERR "%s: Error interposing; rc = [%ld]\n",
                       __func__, PTR_ERR(inode));
                return PTR_ERR(inode);
        }
        if (S_ISREG(inode->i_mode)) {
		err = transcryptfs_i_size_read(dentry, inode);
		if (err) {
			make_bad_inode(inode);
			return err;
		}
	}
	
	if (inode->i_state & I_NEW)
		unlock_new_inode(inode);
	d_add(dentry, inode);

	return err;
}
	
	
	

struct dentry *transcryptfs_lookup(struct inode *transcryptfs_dir_inode, 
				   struct dentry *transcryptfs_dentry,
			           struct nameidata *transcryptfs_nd)
{
	char *encrypted_and_encoded_name = NULL;
	size_t encrypted_and_encoded_name_size;
	struct dentry *lower_dir_dentry, *lower_dentry;
	
	//struct path lower_parent_path;
	int err = 0;

	BUG_ON(!transcryptfs_nd);
	if ((transcryptfs_dentry->d_name.len == 1
	     && !strcmp(transcryptfs_dentry->d_name.name, "."))
	    || (transcryptfs_dentry->d_name.len == 2
		&& !strcmp(transcryptfs_dentry->d_name.name, ".."))) {
		goto out_d_drop;
	}
	lower_dir_dentry = transcryptfs_dentry_to_lower(transcryptfs_dentry->d_parent);
	mutex_lock(&lower_dir_dentry->d_inode->i_mutex);
	lower_dentry = lookup_one_len(transcryptfs_dentry->d_name.name,
				      lower_dir_dentry,
				      transcryptfs_dentry->d_name.len);
	mutex_unlock(&lower_dir_dentry->d_inode->i_mutex);
	if (IS_ERR(lower_dentry)) {
		err = PTR_ERR(lower_dentry);
		printk(KERN_DEBUG "%s: lookup_one_len() returned "
                                "[%d] on lower_dentry = [%s]\n", __func__, err,
				transcryptfs_dentry->d_name.name);
		goto out_d_drop;
	}
	if (lower_dentry->d_inode)
		goto interpose;
	dput(lower_dentry);
	err = transcryptfs_encrypt_and_encode_filename(
		&encrypted_and_encoded_name, &encrypted_and_encoded_name_size,
		transcryptfs_dentry->d_name.name, transcryptfs_dentry->d_name.len); 
	if (err) {
		printk(KERN_ERR "%s: Error attempting to encrypt and encode "
                       "filename; err = [%d]\n", __func__, err);
                goto out_d_drop;
        }
	mutex_lock(&lower_dir_dentry->d_inode->i_mutex);
	lower_dentry = lookup_one_len(encrypted_and_encoded_name,
				      lower_dir_dentry,
				      encrypted_and_encoded_name_size);
	mutex_unlock(&lower_dir_dentry->d_inode->i_mutex);
	if (IS_ERR(lower_dentry)) {
                err = PTR_ERR(lower_dentry);
		printk(KERN_DEBUG "%s: lookup_one_len() returned "
                                "[%d] on lower_dentry = [%s]\n", __func__, err,
                                encrypted_and_encoded_name);
                goto out_d_drop;
        }
interpose:
	err = transcryptfs_lookup_interpose(transcryptfs_dentry, lower_dentry,
					    transcryptfs_dir_inode);
	goto out;
out_d_drop:
	d_drop(transcryptfs_dentry);
out:
	kfree(encrypted_and_encoded_name);
	return ERR_PTR(err);
// 	parent = dget_parent(dentry);
// 
// 	transcryptfs_get_lower_path(parent, &lower_parent_path);
// 
// 	/* allocate dentry private data.  We free it in ->d_release */
// 	err = new_dentry_private_data(dentry);
// 	if (err) {
// 		ret = ERR_PTR(err);
// 		goto out;
// 	}
// 	ret = __transcryptfs_lookup(dentry, nd->flags, &lower_parent_path);
// 	if (IS_ERR(ret))
// 		goto out;
// 	if (ret)
// 		dentry = ret;
// 	if (dentry->d_inode)
// 		fsstack_copy_attr_times(dentry->d_inode,
// 					transcryptfs_lower_inode(dentry->d_inode));
// 	/* update parent directory's atime */
// 	fsstack_copy_attr_atime(parent->d_inode,
// 				transcryptfs_lower_inode(parent->d_inode));
// 
// out:
// 	transcryptfs_put_lower_path(parent, &lower_parent_path);
// 	dput(parent);
// 	return ret;
}
