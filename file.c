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
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/security.h>
#include <linux/compat.h>
#include <linux/fs_stack.h>
#include "transcryptfs.h"

// static ssize_t transcryptfs_read(struct file *file, char __user *buf,
// 			   size_t count, loff_t *ppos)
// {
// 	int err,i;
// 	struct file *lower_file;
// 	struct dentry *dentry = file->f_path.dentry;
// 
// 	lower_file = transcryptfs_file_to_lower(file);
// 	err = vfs_read(lower_file, buf, count, ppos);
// 	printk(KERN_INFO
//                        "transcryptfs:  Read from lower layer: %s", buf);
// 	for(i=0;i<count;i++)
// 		buf[i]--;
// 	/* update our inode atime upon a successful lower read */
// 	if (err >= 0)
// 		fsstack_copy_attr_atime(dentry->d_inode,
// 					lower_file->f_path.dentry->d_inode);
// 
// 	return err;
// }
// 
// static ssize_t transcryptfs_write(struct file *file, char __user *buf,
// 			    size_t count, loff_t *ppos)
// {
// 	int err = 0,i;
// 	struct file *lower_file;
// 	struct dentry *dentry = file->f_path.dentry;
// 
// 	printk(KERN_INFO
//                        "transcryptfs:  Writing to file");
// 	lower_file = transcryptfs_file_to_lower(file);
// 	for(i=0;i<count;i++)
// 		buf[i]++;
// 	err = vfs_write(lower_file, buf, count, ppos);
// 	/* update our inode times+sizes upon a successful lower write */
// 	if (err >= 0) {
// 		fsstack_copy_inode_size(dentry->d_inode,
// 					lower_file->f_path.dentry->d_inode);
// 		fsstack_copy_attr_times(dentry->d_inode,
// 					lower_file->f_path.dentry->d_inode);
// 	}
// 
// 	return err;
// }

static ssize_t transcryptfs_read_update_atime(struct kiocb *iocb,
                                const struct iovec *iov,
                                unsigned long nr_segs, loff_t pos)
{
        ssize_t err;
        // struct dentry *lower_dentry;
        // struct vfsmount *lower_vfsmount;
	struct path lower;
        struct file *file = iocb->ki_filp;

        err = generic_file_aio_read(iocb, iov, nr_segs, pos);
        /*
         * Even though this is a async interface, we need to wait
         * for IO to finish to update atime
         */
        if (-EIOCBQUEUED == err)
                err = wait_on_sync_kiocb(iocb);
        if (err >= 0) {
                lower.dentry = transcryptfs_dentry_to_lower(file->f_path.dentry);
                lower.mnt = transcryptfs_dentry_to_lower_mnt(file->f_path.dentry);
                touch_atime(&lower);
        }
        return err;
}

struct transcryptfs_getdents_callback {
        void *dirent;
        struct dentry *dentry;
        filldir_t filldir;
        int filldir_called;
        int entries_written;
};

static int
transcryptfs_filldir(void *dirent, const char *lower_name, int lower_namelen,
		     loff_t offset, u64 ino, unsigned int d_type)
{
	struct transcryptfs_getdents_callback *buf =
	     (struct transcryptfs_getdents_callback *)dirent;
	size_t name_size;
	char *name;
	int err;

	buf->filldir_called++;
	// TODO: Complete the dummy function before actual use.
	err = transcryptfs_decode_and_decrypt_filename(&name, &name_size,
						       lower_name,
						       lower_namelen);
	if (err) {
		printk(KERN_ERR "%s: Error attempting to decode and decrypt "
                       "filename [%s]; err = [%d]\n", __func__, lower_name,
			err);
		goto out;
	}
	err = buf->filldir(buf->dirent, name, name_size, offset, ino, d_type);
	kfree(name);
	if (err >=0)
		buf->entries_written++;
out:
	return err;
}

static int transcryptfs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct transcryptfs_getdents_callback buf;

	lower_file = transcryptfs_file_to_lower(file);
	lower_file->f_pos = file->f_pos;
	memset(&buf, 0, sizeof(buf));
	buf.dirent = dirent;
	buf.dentry = dentry;
	buf.filldir = filldir;
	buf.filldir_called = 0;
	buf.entries_written = 0;
	err = vfs_readdir(lower_file, transcryptfs_filldir, (void *)&buf);
	file->f_pos = lower_file->f_pos;
	if (err < 0)
		goto out;
	if(buf.filldir_called && !buf.entries_written)
		goto out;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
out:
	return err;
}

static long transcryptfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = transcryptfs_file_to_lower(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

out:
	return err;
}

#ifdef CONFIG_COMPAT
static long transcryptfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = transcryptfs_file_to_lower(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static void transcryptfs_vma_close(struct vm_area_struct *vma)
{
        filemap_write_and_wait(vma->vm_file->f_mapping);
}

static const struct vm_operations_struct transcryptfs_file_vm_ops = {
        .close          = transcryptfs_vma_close,
        .fault          = filemap_fault,
};

static int transcryptfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;

	err = generic_file_mmap(file, vma);
	if(!err)
		vma->vm_ops = &transcryptfs_file_vm_ops;

	return err;
// 	bool willwrite;
// 	struct file *lower_file;
// 	const struct vm_operations_struct *saved_vm_ops = NULL;
// 
// 	/* this might be deferred to mmap's writepage */
// 	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);
// 
// 	/*
// 	 * File systems which do not implement ->writepage may use
// 	 * generic_file_readonly_mmap as their ->mmap op.  If you call
// 	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
// 	 * But we cannot call the lower ->mmap op, so we can't tell that
// 	 * writeable mappings won't work.  Therefore, our only choice is to
// 	 * check if the lower file system supports the ->writepage, and if
// 	 * not, return EINVAL (the same error that
// 	 * generic_file_readonly_mmap returns in that case).
// 	 */
// 	lower_file = transcryptfs_file_to_lower(file);
// 	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
// 		err = -EINVAL;
// 		printk(KERN_ERR "transcryptfs: lower file system does not "
// 		       "support writeable mmap\n");
// 		goto out;
// 	}
// 
// 	/*
// 	 * find and save lower vm_ops.
// 	 *
// 	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
// 	 */
// 	if (!TRANSCRYPTFS_F(file)->lower_vm_ops) {
// 		err = lower_file->f_op->mmap(lower_file, vma);
// 		if (err) {
// 			printk(KERN_ERR "transcryptfs: lower mmap failed %d\n", err);
// 			goto out;
// 		}
// 		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
// 		err = do_munmap(current->mm, vma->vm_start,
// 				vma->vm_end - vma->vm_start);
// 		if (err) {
// 			printk(KERN_ERR "transcryptfs: do_munmap failed %d\n", err);
// 			goto out;
// 		}
// 	}
// 
// 	/*
// 	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
// 	 * don't want its test for ->readpage which returns -ENOEXEC.
// 	 */
// 	file_accessed(file);
// 	vma->vm_ops = &transcryptfs_vm_ops;
// 	vma->vm_flags |= VM_CAN_NONLINEAR;
// 
// 	file->f_mapping->a_ops = &transcryptfs_aops; /* set our aops */
// 	if (!TRANSCRYPTFS_F(file)->lower_vm_ops) /* save for our ->fault */
// 		TRANSCRYPTFS_F(file)->lower_vm_ops = saved_vm_ops;
// 
// out:
// 	return err;
}

struct kmem_cache *transcryptfs_file_info_cache;

static int transcryptfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct dentry *transcryptfs_dentry = file->f_path.dentry;
	struct dentry *lower_dentry;
	struct transcryptfs_file_info *file_info;
	struct transcryptfs_crypt_stat *crypt_stat = NULL;
	struct transcryptfs_mount_crypt_stat *mount_crypt_stat;


	/* don't open unhashed/deleted files */
// 	if (d_unhashed(file->f_path.dentry)) {
// 		err = -ENOENT;
// 		goto out;
// 	}

	file_info = kmem_cache_zalloc(transcryptfs_file_info_cache, GFP_KERNEL);	
	file->private_data = file_info;
//		kzalloc(sizeof(struct transcryptfs_file_info), GFP_KERNEL);
	if (!file_info) {
		err = -ENOMEM;
		goto out;
	}

	/* open lower object and link transcryptfs's file struct to lower's */
	// transcryptfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_dentry = transcryptfs_dentry_to_lower(transcryptfs_dentry);
	mount_crypt_stat = &TRANSCRYPTFS_SB(
			transcryptfs_dentry->d_sb)->mount_crypt_stat;
	crypt_stat = &TRANSCRYPTFS_I(inode)->crypt_stat;
	mutex_lock(&crypt_stat->cs_mutex);
	if(!(crypt_stat->flags & TRANSCRYPTFS_POLICY_APPLIED)) {
		crypt_stat->flags |= (TRANSCRYPTFS_POLICY_APPLIED
				      | TRANSCRYPTFS_ENCRYPTED);
	}
	mutex_unlock(&crypt_stat->cs_mutex);
	err = transcryptfs_get_lower_file(transcryptfs_dentry, inode);
	if (err) {
		printk(KERN_ERR "%s: Error attempting to initialize "
                        "the lower file for the dentry with name "
                        "[%s]; err = [%d]\n", __func__,
                        transcryptfs_dentry->d_name.name, err);
                goto out_free;
        }
	// lower_file = dentry_open(lower_path.dentry, lower_path.mnt,
	//			 file->f_flags, current_cred());
	// if (IS_ERR(lower_file)) {
	// 	err = PTR_ERR(lower_file);
	// 	lower_file = transcryptfs_file_to_lower(file);
	// 	if (lower_file) {
	// 		transcryptfs_set_lower_file(file, NULL);
	// 		fput(lower_file); /* fput calls dput for lower_dentry */
	// 	}
	// } else {
	transcryptfs_set_lower_file(file, TRANSCRYPTFS_I(inode)->lower_file);
	if (S_ISDIR(transcryptfs_dentry->d_inode->i_mode)) {
		// printk(KERN_ERR "This is a directory\n");
		mutex_lock(&crypt_stat->cs_mutex);
		crypt_stat->flags &= ~(TRANSCRYPTFS_ENCRYPTED);
		mutex_unlock(&crypt_stat->cs_mutex);
		err = 0;
		goto out;
	}
	mutex_lock(&crypt_stat->cs_mutex);
	if (!(crypt_stat->flags & TRANSCRYPTFS_POLICY_APPLIED)
            || !(crypt_stat->flags & TRANSCRYPTFS_KEY_VALID)) {
                err = transcryptfs_read_metadata(transcryptfs_dentry);
                if (err) {
                        printk(KERN_DEBUG "Valid headers not found\n");
                        if (!(mount_crypt_stat->flags
                              & TRANSCRYPTFS_PLAINTEXT_PASSTHROUGH_ENABLED)) {
                                err = -EIO;
                                printk(KERN_WARNING "Either the lower file "
                                       "is not in a valid eCryptfs format, "
                                       "or the key could not be retrieved. "
                                       "Plaintext passthrough mode is not "
                                       "enabled; returning -EIO\n");
                                mutex_unlock(&crypt_stat->cs_mutex);
                                goto out_put;
                        }
                        err = 0;
                        crypt_stat->flags &= ~(TRANSCRYPTFS_I_SIZE_INITIALIZED
                                               | TRANSCRYPTFS_ENCRYPTED);
                        mutex_unlock(&crypt_stat->cs_mutex);
                        goto out;
                }
        }
        mutex_unlock(&crypt_stat->cs_mutex);
	goto out;
	// }
out_put:                      
        transcryptfs_put_lower_file(inode);
out_free:
        kmem_cache_free(transcryptfs_file_info_cache,
                        file->private_data);
out:    
        return err;

// 	if (err)
// 		kfree(TRANSCRYPTFS_F(file));
// 	else
// 		fsstack_copy_attr_all(inode, transcryptfs_lower_inode(inode));
// out_err:
// 	return err;
}

static int transcryptfs_flush(struct file *file, fl_owner_t id)
{
	return file->f_mode & FMODE_WRITE
               ? filemap_write_and_wait(file->f_mapping) : 0;

//	int err = 0;
//	struct file *lower_file = NULL;
//
//	lower_file = transcryptfs_file_to_lower(file);
//	if (lower_file && lower_file->f_op && lower_file->f_op->flush)
//		err = lower_file->f_op->flush(lower_file, id);
//
//	return err;
}

/* release all lower object references & free the file info structure */
static int transcryptfs_file_release(struct inode *inode, struct file *file)
{
	transcryptfs_put_lower_file(inode);
	kmem_cache_free(transcryptfs_file_info_cache,
			TRANSCRYPTFS_F(file));
// 	struct file *lower_file;
// 
// 	lower_file = transcryptfs_file_to_lower(file);
// 	if (lower_file) {
// 		transcryptfs_set_lower_file(file, NULL);
// 		fput(lower_file);
// 	}
// 
// 	kfree(TRANSCRYPTFS_F(file));
	return 0;
}

static int transcryptfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
// 	struct path lower_path;
// 	struct dentry *dentry = file->f_path.dentry;

	err = generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = transcryptfs_file_to_lower(file);
//	transcryptfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
//	transcryptfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int transcryptfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = transcryptfs_file_to_lower(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

const struct file_operations transcryptfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= do_sync_read,
	.aio_read	= transcryptfs_read_update_atime,
	.write		= do_sync_write,
	.aio_write	= generic_file_aio_write,
	.readdir	= transcryptfs_readdir,
	.unlocked_ioctl	= transcryptfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= transcryptfs_compat_ioctl,
#endif
	.mmap		= transcryptfs_mmap,
	.open		= transcryptfs_open,
	.flush		= transcryptfs_flush,
	.release	= transcryptfs_file_release,
	.fsync		= transcryptfs_fsync,
	.fasync		= transcryptfs_fasync,
	.splice_read	= generic_file_splice_read,
};

/* trimmed directory options */
const struct file_operations transcryptfs_dir_fops = {
	.llseek		= default_llseek,
	.read		= generic_read_dir,
	.readdir	= transcryptfs_readdir,
	.unlocked_ioctl	= transcryptfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= transcryptfs_compat_ioctl,
#endif
	.open		= transcryptfs_open,
	.release	= transcryptfs_file_release,
	.flush		= transcryptfs_flush,
	.fsync		= transcryptfs_fsync,
	.fasync		= transcryptfs_fasync,
	.splice_read	= generic_file_splice_read,
};
