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

#ifndef _TRANSCRYPTFS_H_
#define _TRANSCRYPTFS_H_

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/backing-dev.h>
#include <linux/scatterlist.h>

#define TRANSCRYPTFS_SUPER_MAGIC	0x0513
/* the file system name */
#define TRANSCRYPTFS_NAME "transcryptfs"

/* transcryptfs root inode number */
#define TRANSCRYPTFS_ROOT_INO     1
#define TRANSCRYPTFS_FSK_BYTES	16
#define TRANSCRYPTFS_DEFAULT_BLINDING_CIPHER	"ecb(aes)"
#define TRANSCRYPTFS_MAX_IV_BYTES	16
#define TRANSCRYPTFS_DEFAULT_EXTENT_SIZE 4096
#define TRANSCRYPTFS_MINIMUM_HEADER_EXTENT_SIZE 4096
#define TRANSCRYPTFS_FILE_SIZE_BYTES (sizeof(u64))
#define TRANSCRYPTFS_SUPPORTED_FILE_VERSION 0x03

#define TRANSCRYPTFS_MAX_CIPHER_NAME_SIZE 32
#define TRANSCRYPTFS_MAX_KEY_BYTES 64
#define TRANSCRYPTFS_MAX_TWEAK_BYTES 32
#define TRANSCRYPTFS_DEFAULT_CIPHER "xts(aes)"
#define TRANSCRYPTFS_DEFAULT_KEY_BYTES 32
#define TRANSCRYPTFS_FILE_VERSION 0x03


/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

/* operations vectors defined in specific files */
extern const struct file_operations transcryptfs_main_fops;
extern const struct file_operations transcryptfs_dir_fops;
extern const struct inode_operations transcryptfs_main_iops;
extern const struct inode_operations transcryptfs_dir_iops;
extern const struct inode_operations transcryptfs_symlink_iops;
extern const struct super_operations transcryptfs_sops;
extern const struct dentry_operations transcryptfs_dops;
extern const struct address_space_operations transcryptfs_aops, transcryptfs_dummy_aops;
extern const struct vm_operations_struct transcryptfs_vm_ops;
extern struct kmem_cache *transcryptfs_open_req_cache;
extern struct kmem_cache *transcryptfs_inode_info_cache;
extern struct kmem_cache *transcryptfs_file_info_cache;
extern struct kmem_cache *transcryptfs_dentry_info_cache;
extern struct kmem_cache *transcryptfs_sb_info_cache;
extern struct kmem_cache *transcryptfs_header_cache;


/* kthread.c required structures: */
struct transcryptfs_open_req {
#define TRANSCRYPTFS_REQ_PROCESSED 0x00000001
#define TRANSCRYPTFS_REQ_DROPPED   0x00000002
#define TRANSCRYPTFS_REQ_ZOMBIE    0x00000004
        u32 flags;      
        struct file **lower_file;
        struct dentry *lower_dentry;
        struct vfsmount *lower_mnt;
        wait_queue_head_t wait;                
        struct mutex mux;                      
        struct list_head kthread_ctl_list;
};        

int transcryptfs_init_kthread(void);
void transcryptfs_destroy_kthread(void);
int transcryptfs_privileged_open(struct file **lower_file,
				 struct dentry *lower_dentry,
				 struct vfsmount *lower_mnt,
				 const struct cred *cred);

// struct transcryptfs_crypt_stat;
// struct transcryptfs_mount_crypt_stat;
struct transcryptfs_crypt_stat {
#define TRANSCRYPTFS_STRUCT_INITIALIZED   0x00000001
#define TRANSCRYPTFS_POLICY_APPLIED       0x00000002
#define TRANSCRYPTFS_ENCRYPTED            0x00000004
#define TRANSCRYPTFS_SECURITY_WARNING     0x00000008
#define TRANSCRYPTFS_ENABLE_HMAC          0x00000010
#define TRANSCRYPTFS_ENCRYPT_IV_PAGES     0x00000020
#define TRANSCRYPTFS_KEY_VALID            0x00000040
#define TRANSCRYPTFS_VIEW_AS_ENCRYPTED    0x00000100 
#define TRANSCRYPTFS_KEY_SET              0x00000200
#define TRANSCRYPTFS_ENCRYPT_FILENAMES    0x00000400    
#define TRANSCRYPTFS_ENCFN_USE_MOUNT_FNEK 0x00000800
#define TRANSCRYPTFS_ENCFN_USE_FEK        0x00001000       
#define TRANSCRYPTFS_UNLINK_SIGS          0x00002000
#define TRANSCRYPTFS_I_SIZE_INITIALIZED   0x00004000
        u32 flags;     
        unsigned int file_version;
        size_t metadata_size;
        size_t extent_size; /* Data extent size; default is 4096 */
        size_t key_size;
        size_t extent_shift;
        unsigned int extent_mask;
	struct transcryptfs_mount_crypt_stat *mount_crypt_stat;
        struct crypto_ablkcipher *tfm;
        unsigned char cipher[TRANSCRYPTFS_MAX_CIPHER_NAME_SIZE];
        unsigned char key[TRANSCRYPTFS_MAX_KEY_BYTES];
        unsigned char tweak[TRANSCRYPTFS_MAX_TWEAK_BYTES];
        struct list_head keysig_list;
        struct mutex keysig_list_mutex;
        struct mutex cs_tfm_mutex;
        struct mutex cs_mutex;
};

struct transcryptfs_mount_crypt_stat {
        /* Pointers to memory we do not own, do not free these */
#define TRANSCRYPTFS_PLAINTEXT_PASSTHROUGH_ENABLED 0x00000001
#define TRANSCRYPTFS_ENCRYPTED_VIEW_ENABLED        0x00000004
#define TRANSCRYPTFS_MOUNT_CRYPT_STAT_INITIALIZED  0x00000008
#define TRANSCRYPTFS_GLOBAL_ENCRYPT_FILENAMES      0x00000010
#define TRANSCRYPTFS_GLOBAL_ENCFN_USE_MOUNT_FNEK   0x00000020
#define TRANSCRYPTFS_GLOBAL_ENCFN_USE_FEK          0x00000040
        u32 flags;
//        struct list_head global_auth_tok_list;
//        struct mutex global_auth_tok_list_mutex;
//        size_t global_default_cipher_key_size;
//        size_t global_default_fn_cipher_key_bytes;
//        unsigned char global_default_cipher_name[MYECRYPTFS_MAX_CIPHER_NAME_SIZE
//                                                 + 1];
//        unsigned char global_default_fn_cipher_name[
//                MYECRYPTFS_MAX_CIPHER_NAME_SIZE + 1];
//        char global_default_fnek_sig[MYECRYPTFS_SIG_SIZE_HEX + 1];
	unsigned char fsk[TRANSCRYPTFS_FSK_BYTES + 1];
	unsigned char global_blinding_cipher[TRANSCRYPTFS_MAX_CIPHER_NAME_SIZE
						+ 1];
	size_t fsk_size;
};


// extern int transcryptfs_init_inode_cache(void);
// extern void transcryptfs_destroy_inode_cache(void);
// extern int transcryptfs_init_dentry_cache(void);
// extern void transcryptfs_destroy_dentry_cache(void);
int new_dentry_private_data(struct dentry *dentry);
void free_dentry_private_data(struct dentry *dentry);
struct dentry *transcryptfs_lookup(struct inode *dir, struct dentry *dentry,
 			    struct nameidata *nd);
struct inode *transcryptfs_get_inode(struct inode *lower_inode,
					    struct super_block *sb);
void transcryptfs_i_size_init(const char *page_virt, struct inode *inode);
int transcryptfs_decode_and_decrypt_filename(char **decrypted_name,
					     size_t *decrypted_name_size,
					     const char *name, size_t name_size);
int transcryptfs_encrypt_and_encode_filename(
	char **encoded_name,
	size_t *encoded_name_size,
	const char *name, size_t name_size);
void transcryptfs_dump_hex(char *data, int bytes);
int transcryptfs_truncate(struct dentry *dentry, loff_t new_length);

// extern int transcryptfs_interpose(struct dentry *dentry, struct super_block *sb,
// 			    struct path *lower_path);

/* crypto.c functions: */
void transcryptfs_init_crypt_stat(struct transcryptfs_crypt_stat *crypt_stat);
void transcryptfs_destroy_crypt_stat(struct transcryptfs_crypt_stat *crypt_stat);
void transcryptfs_destroy_mount_crypt_stat(
        struct transcryptfs_mount_crypt_stat *mount_crypt_stat);
int transcryptfs_init_crypt_ctx(struct transcryptfs_crypt_stat *crypt_stat);
int transcryptfs_encrypt_page(struct page *page);
int transcryptfs_decrypt_page(struct page *page);
int transcryptfs_write_metadata(struct dentry *transcryptfs_dentry,
                                struct inode *transcryptfs_inode);
int transcryptfs_read_metadata(struct dentry *transcryptfs_dentry);
int transcryptfs_new_file_context(struct inode *transcryptfs_inode);
void transcryptfs_set_default_sizes(struct transcryptfs_crypt_stat *crypt_stat);
void transcryptfs_write_header_metadata(char *virt,
                                    struct transcryptfs_crypt_stat *crypt_stat,
                                    size_t *written);
int transcryptfs_read_and_validate_header_region(struct inode *inode);
int virt_to_scatterlist(const void *addr, int size, struct scatterlist *sg,
                        int sg_size);

/* keystore.c functions */
int transcryptfs_generate_tokens(char *dest_base,
                                struct transcryptfs_crypt_stat *crypt_stat,
                                struct dentry *transcryptfs_dentry,
                                size_t *len, size_t max);
int transcryptfs_read_tokens(struct transcryptfs_crypt_stat *crypt_stat,
                             char *dest_base,
                             struct dentry *transcryptfs_dentry);

/* mmap.c  functions: */
int transcryptfs_write_lower(struct inode *transcryptfs_inode, char *data,
			     loff_t offset, size_t size);
int transcryptfs_write_lower_page_segment(struct inode *transcryptfs_inode,
					  struct page *page_for_lower,
					  size_t offset_in_page, size_t size);
int transcryptfs_read_lower(char *data, loff_t offset, size_t size,
			    struct inode *transcryptfs_inode);
int transcryptfs_read_lower_page_segment(struct page *page_for_transcryptfs,
					 pgoff_t page_index,
					 size_t offset_in_page, size_t size,
					 struct inode *transcryptfs_inode);
struct page *transcryptfs_get_locked_page(struct inode *inode, loff_t index);
int transcryptfs_write_inode_size_to_metadata(struct inode *transcryptfs_inode);
int transcryptfs_write_lower_page_segment(struct inode *transcryptfs_inode,
                                      struct page *page_for_lower,
                                      size_t offset_in_page, size_t size);
int transcryptfs_write(struct inode *transcryptfs_inode, char *data, loff_t offset,
                       size_t size);

/* main.c functions: */
int transcryptfs_get_lower_file(struct dentry *dentry, struct inode *inode);
void transcryptfs_put_lower_file(struct inode *inode);

/* file private data */
struct transcryptfs_file_info {
	struct file *lower_file;
//	const struct vm_operations_struct *lower_vm_ops;
	struct transcryptfs_crypt_stat *crypt_stat;
};

/* transcryptfs inode data in memory */
struct transcryptfs_inode_info {
	struct inode *lower_inode;
	struct inode vfs_inode;
	struct mutex lower_file_mutex;
	atomic_t lower_file_count;
	struct file *lower_file;
	struct transcryptfs_crypt_stat crypt_stat;
};

/* transcryptfs dentry data in memory */
struct transcryptfs_dentry_info {
	spinlock_t lock;	/* protects lower_path */
	struct path lower_path;
	struct transcryptfs_crypt_stat *crypt_stat;
};

/* transcryptfs super-block data in memory */
struct transcryptfs_sb_info {
	struct super_block *lower_sb;
	struct backing_dev_info bdi;
	struct transcryptfs_mount_crypt_stat mount_crypt_stat;
};


/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * transcryptfs_inode_info structure, TRANSCRYPTFS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct transcryptfs_inode_info *TRANSCRYPTFS_I(const struct inode *inode)
{
	return container_of(inode, struct transcryptfs_inode_info, vfs_inode);
}

/* dentry to private data */
#define TRANSCRYPTFS_D(dent) ((struct transcryptfs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define TRANSCRYPTFS_SB(super) ((struct transcryptfs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define TRANSCRYPTFS_F(file) ((struct transcryptfs_file_info *)((file)->private_data))

/* file to lower file */
static inline struct file *transcryptfs_file_to_lower(const struct file *f)
{
	return TRANSCRYPTFS_F(f)->lower_file;
}

static inline void transcryptfs_set_lower_file(struct file *f, struct file *val)
{
	TRANSCRYPTFS_F(f)->lower_file = val;
}

/* inode to lower inode. */
static inline struct inode *transcryptfs_lower_inode(const struct inode *i)
{
	return TRANSCRYPTFS_I(i)->lower_inode;
}

static inline void transcryptfs_set_lower_inode(struct inode *i, struct inode *val)
{
	TRANSCRYPTFS_I(i)->lower_inode = val;
}

/* superblock to lower superblock */
static inline struct super_block *transcryptfs_lower_super(
	const struct super_block *sb)
{
	return TRANSCRYPTFS_SB(sb)->lower_sb;
}

static inline void transcryptfs_set_lower_super(struct super_block *sb,
					  struct super_block *val)
{
	TRANSCRYPTFS_SB(sb)->lower_sb = val;
}

/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline void transcryptfs_get_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&TRANSCRYPTFS_D(dent)->lock);
	pathcpy(lower_path, &TRANSCRYPTFS_D(dent)->lower_path);
	path_get(lower_path);
	spin_unlock(&TRANSCRYPTFS_D(dent)->lock);
	return;
}
static inline void transcryptfs_put_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	path_put(lower_path);
	return;
}
static inline void transcryptfs_set_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&TRANSCRYPTFS_D(dent)->lock);
	pathcpy(&TRANSCRYPTFS_D(dent)->lower_path, lower_path);
	spin_unlock(&TRANSCRYPTFS_D(dent)->lock);
	return;
}
static inline void transcryptfs_reset_lower_path(const struct dentry *dent)
{
	spin_lock(&TRANSCRYPTFS_D(dent)->lock);
	TRANSCRYPTFS_D(dent)->lower_path.dentry = NULL;
	TRANSCRYPTFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&TRANSCRYPTFS_D(dent)->lock);
	return;
}
static inline void transcryptfs_put_reset_lower_path(const struct dentry *dent)
{
	struct path lower_path;
	spin_lock(&TRANSCRYPTFS_D(dent)->lock);
	pathcpy(&lower_path, &TRANSCRYPTFS_D(dent)->lower_path);
	TRANSCRYPTFS_D(dent)->lower_path.dentry = NULL;
	TRANSCRYPTFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&TRANSCRYPTFS_D(dent)->lock);
	path_put(&lower_path);
	return;
}

static inline void
transcryptfs_set_dentry_private(struct dentry *dentry,
				struct transcryptfs_dentry_info *dentry_info)
{
	dentry->d_fsdata = dentry_info;
}

static inline void
transcryptfs_set_dentry_lower(struct dentry *dentry, struct dentry *lower_dentry)
{
	((struct transcryptfs_dentry_info *)dentry->d_fsdata)
		->lower_path.dentry = lower_dentry;
}

static inline void
transcryptfs_set_dentry_lower_mnt(struct dentry *dentry, struct vfsmount *lower_mnt)
{
	((struct transcryptfs_dentry_info *)dentry->d_fsdata)->lower_path.mnt =
		lower_mnt;
}

static inline struct dentry *
transcryptfs_dentry_to_lower(struct dentry *dentry)
{
	return TRANSCRYPTFS_D(dentry)->lower_path.dentry; 
}

static inline struct vfsmount * 
transcryptfs_dentry_to_lower_mnt(struct dentry *dentry)
{
	return TRANSCRYPTFS_D(dentry)->lower_path.mnt;
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	mutex_lock_nested(&dir->d_inode->i_mutex, I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(dir);
}
#endif	/* not _TRANSCRYPTFS_H_ */
