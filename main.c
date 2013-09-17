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
#include "crypto/hash.h"
#include "crypto/pbkdf2.h"
#include <linux/pagemap.h>
#include <linux/parser.h>
#include <linux/fs_stack.h>
#include <linux/module.h>

/* transcryptfs inode cache constructor */
static void inode_info_init_once(void *obj)
{
	struct transcryptfs_inode_info *i = (struct transcryptfs_inode_info *)obj;

	inode_init_once(&i->vfs_inode);
}

struct kmem_cache *transcryptfs_sb_info_cache;
// struct kmem_cache *transcryptfs_header_cache;
static struct file_system_type transcryptfs_fs_type;

static struct transcryptfs_cache_info {
	struct kmem_cache **cache;
	const char *name;
	size_t size;
	void (*ctor)(void *obj);
} transcryptfs_cache_infos[] = {
	{
		.cache = &transcryptfs_inode_info_cache,
		.name = "transcryptfs_inode_cache",
		.size = sizeof(struct transcryptfs_inode_info),
		.ctor = inode_info_init_once,
	},
	{
		.cache = &transcryptfs_dentry_info_cache,
		.name = "transcryptfs_dentry_cache",
		.size = sizeof(struct transcryptfs_dentry_info),
	},
	{
		.cache = &transcryptfs_file_info_cache,
		.name = "transcryptfs_file_cache",
		.size = sizeof(struct transcryptfs_file_info),
	},
	{
		.cache = &transcryptfs_open_req_cache,
		.name = "transcryptfs_open_req_cache",
		.size = sizeof(struct transcryptfs_open_req),
	},
	{
                .cache = &transcryptfs_sb_info_cache,
                .name = "transcryptfs_sb_cache",
                .size = sizeof(struct transcryptfs_sb_info),
        },
	{
                .cache = &transcryptfs_header_cache,
                .name = "transcryptfs_headers",
                .size = PAGE_CACHE_SIZE,
        },
};


static int transcryptfs_init_lower_file(struct dentry *dentry,
					struct file **lower_file)
{
	const struct cred *cred = current_cred();
	struct dentry *lower_dentry = transcryptfs_dentry_to_lower(dentry);
	struct vfsmount *lower_mnt = transcryptfs_dentry_to_lower_mnt(dentry);
	int err;
	
	err = transcryptfs_privileged_open(lower_file, lower_dentry, lower_mnt,
					   cred);
	if (err) {
		 printk(KERN_ERR "Error opening lower file "
                       "for lower_dentry [0x%p] and lower_mnt [0x%p]; "
                       "err = [%d]\n", lower_dentry, lower_mnt, err);
                (*lower_file) = NULL;
        }
        return err;
}


int transcryptfs_get_lower_file(struct dentry *dentry, struct inode *inode)
{
	struct transcryptfs_inode_info *inode_info;
	int count, err = 0;

	inode_info = TRANSCRYPTFS_I(inode);
	mutex_lock(&inode_info->lower_file_mutex);
	count = atomic_inc_return(&inode_info->lower_file_count);
	if (WARN_ON_ONCE(count < 1))
		err = -EINVAL;
	else if (count == 1) {
		err = transcryptfs_init_lower_file(dentry,
						   &inode_info->lower_file);
		if (err)
			atomic_set(&inode_info->lower_file_count, 0);
	}
	mutex_unlock(&inode_info->lower_file_mutex);
	return err;
}

void transcryptfs_put_lower_file(struct inode *inode)
{
	struct transcryptfs_inode_info *inode_info;
	
	inode_info = TRANSCRYPTFS_I(inode);
	if (atomic_dec_and_mutex_lock(&inode_info->lower_file_count,
                                      &inode_info->lower_file_mutex)) {
                fput(inode_info->lower_file);
                inode_info->lower_file = NULL;
                mutex_unlock(&inode_info->lower_file_mutex);
        }                             
}       


/*
 * There is no need to lock the transcryptfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
// static int transcryptfs_read_super(struct super_block *sb, void *raw_data, int silent)
// {
// 	int err = 0;
// 	struct super_block *lower_sb;
// 	struct path lower_path;
// 	char *dev_name = (char *) raw_data;
// 	struct inode *inode;
// 	printk(KERN_INFO
// 		       "transcryptfs:  Entered transcryptfs_read_super");
// 
// 	if (!dev_name) {
// 		printk(KERN_ERR
// 		       "transcryptfs: read_super: missing dev_name argument\n");
// 		err = -EINVAL;
// 		goto out;
// 	}
// 
// 	/* parse lower path */
// 	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
// 			&lower_path);
// 	if (err) {
// 		printk(KERN_ERR	"transcryptfs: error accessing "
// 		       "lower directory '%s'\n", dev_name);
// 		goto out;
// 	}
// 
// 	/* allocate superblock private data */
// 	sb->s_fs_info = kzalloc(sizeof(struct transcryptfs_sb_info), GFP_KERNEL);
// 	if (!TRANSCRYPTFS_SB(sb)) {
// 		printk(KERN_CRIT "transcryptfs: read_super: out of memory\n");
// 		err = -ENOMEM;
// 		goto out_free;
// 	}
// 
// 	/* set the lower superblock field of upper superblock */
// 	lower_sb = lower_path.dentry->d_sb;
// 	atomic_inc(&lower_sb->s_active);
// 	transcryptfs_set_lower_super(sb, lower_sb);
// 
// 	/* inherit maxbytes from lower file system */
// 	sb->s_maxbytes = lower_sb->s_maxbytes;
// 
// 	/*
// 	 * Our c/m/atime granularity is 1 ns because we may stack on file
// 	 * systems whose granularity is as good.
// 	 */
// 	sb->s_time_gran = 1;
// 
// 	sb->s_op = &transcryptfs_sops;
// 
// 	/* get a new inode and allocate our root dentry */
// 	inode = transcryptfs_get_inode(lower_path.dentry->d_inode, sb);
// 	if (IS_ERR(inode)) {
// 		err = PTR_ERR(inode);
// 		goto out_sput;
// 	}
// 	sb->s_root = d_alloc_root(inode);
// 	if (!sb->s_root) {
// 		err = -ENOMEM;
// 		goto out_iput;
// 	}
// 	d_set_d_op(sb->s_root, &transcryptfs_dops);
// 
// 	/* link the upper and lower dentries */
// 	sb->s_root->d_fsdata = NULL;
// 	err = new_dentry_private_data(sb->s_root);
// 	if (err)
// 		goto out_freeroot;
// 
// 	/* if get here: cannot have error */
// 
// 	/* set the lower dentries for s_root */
// 	transcryptfs_set_lower_path(sb->s_root, &lower_path);
// 
// 	/*
// 	 * No need to call interpose because we already have a positive
// 	 * dentry, which was instantiated by d_alloc_root.  Just need to
// 	 * d_rehash it.
// 	 */
// 	d_rehash(sb->s_root);
// 	if (!silent)
// 		printk(KERN_INFO
// 		       "transcryptfs: mounted on top of %s type %s\n",
// 		       dev_name, lower_sb->s_type->name);
// 	goto out; /* all is well */
// 
// 	/* no longer needed: free_dentry_private_data(sb->s_root); */
// out_freeroot:
// 	dput(sb->s_root);
// out_iput:
// 	iput(inode);
// out_sput:
// 	/* drop refs we took earlier */
// 	atomic_dec(&lower_sb->s_active);
// 	kfree(TRANSCRYPTFS_SB(sb));
// 	sb->s_fs_info = NULL;
// out_free:
// 	path_put(&lower_path);
// 
// out:
// 	return err;
// }

enum { transcryptfs_opt_mount_pass, transcryptfs_opt_err };

static const match_table_t tokens = {
	{transcryptfs_opt_mount_pass, "pass=%s"},
	{transcryptfs_opt_err, NULL}
};

static void transcryptfs_init_mount_crypt_stat(
	struct transcryptfs_mount_crypt_stat *mount_crypt_stat)
{
	memset((void *)mount_crypt_stat, 0,
		sizeof(struct transcryptfs_mount_crypt_stat));
	mount_crypt_stat->fsk_size = TRANSCRYPTFS_FSK_BYTES;
	memcpy(mount_crypt_stat->global_blinding_cipher,
		TRANSCRYPTFS_DEFAULT_BLINDING_CIPHER, 8);
	mount_crypt_stat->global_blinding_cipher[8]='\0';
	mount_crypt_stat->flags |= TRANSCRYPTFS_MOUNT_CRYPT_STAT_INITIALIZED;
}

static int transcryptfs_parse_options(struct transcryptfs_sb_info *sbi, char *options,
				      uid_t *check_ruid)
{
	int err = 0;
	substring_t args[MAX_OPT_ARGS];
	int token;
	char *p, *passphrase, salt[SHA1_DIGEST_LENGTH];
	int passlen;
	struct transcryptfs_mount_crypt_stat *mount_crypt_stat =
		&sbi->mount_crypt_stat;
	
	*check_ruid = 0;
	
	memset(salt, 0, SHA1_DIGEST_LENGTH);
	if (!options) {
		err = -EINVAL;
		goto out;
	}
	transcryptfs_init_mount_crypt_stat(mount_crypt_stat);
	// printk(KERN_ERR "raw_data= [%s]", options);
	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;
		token = match_token(p, tokens, args);
		switch (token) {
		case transcryptfs_opt_mount_pass:
			passphrase = args[0].from;
			passlen = strlen(passphrase);
			err = pkcs5_pbkdf2(passphrase, passlen, salt, 
			SHA1_DIGEST_LENGTH, mount_crypt_stat->fsk, 16, 10000);
			break;
		case transcryptfs_opt_err:
		default:
			printk(KERN_ERR "%s: Transcryptfs: unrecognized option!"
				,__func__);
		}
	}
	// memcpy(mount_crypt_stat->fsk, "TRANSCRYPTTRANSC", 16);
out:
	return err;
}

struct dentry *transcryptfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	struct super_block *s;
	// void *lower_path_name = (void *) dev_name;
	struct transcryptfs_sb_info *sbi;
	struct transcryptfs_dentry_info *root_info;
	struct inode *inode;
	struct path path;
	uid_t check_ruid;
	int err;

	sbi = kmem_cache_zalloc(transcryptfs_sb_info_cache, GFP_KERNEL);
	
	if (!sbi) {
		err = -ENOMEM;
		goto out;
	}

	err = transcryptfs_parse_options(sbi, raw_data, &check_ruid);
	if (err) {
		printk( KERN_ERR "Error parsing options." );
		goto out;
	}
	
	s = sget(fs_type, NULL, set_anon_super, NULL);
	if (IS_ERR(s)) {
		err = PTR_ERR(s);
		goto out;
	}

	s->s_flags = flags;
	err = bdi_setup_and_register(&sbi->bdi, "transcryptfs",  BDI_CAP_MAP_COPY);
	if (err)
		goto out_deact_super;

	s->s_fs_info = sbi;
	s->s_bdi = &sbi->bdi;

	sbi = NULL;
	s->s_op = &transcryptfs_sops;
	s->s_d_op = &transcryptfs_dops;

	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &path);
	if (err) {
		printk(KERN_WARNING "kern_path() failed\n");
		goto out;
	}
	if (path.dentry->d_sb->s_type == &transcryptfs_fs_type) {
		err = -EINVAL;
		printk(KERN_ERR "Can't mount on transcryptfs filesystem");
		goto out_free;
	}

	transcryptfs_set_lower_super(s, path.dentry->d_sb);
	s->s_maxbytes = path.dentry->d_sb->s_maxbytes;
	s->s_blocksize = path.dentry->d_sb->s_blocksize;
	s->s_magic = TRANSCRYPTFS_SUPER_MAGIC;	
	
	inode = transcryptfs_get_inode(path.dentry->d_inode, s);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_free;

	s->s_root = d_make_root(inode);
	if (!s->s_root) {
		iput(inode);
		err = -ENOMEM;
		goto out_free;
	}
	
	err = -ENOMEM;
	root_info = kmem_cache_zalloc(transcryptfs_dentry_info_cache, GFP_KERNEL);
	if(!root_info)
		goto out_free;
	
	transcryptfs_set_dentry_private(s->s_root, root_info);
	transcryptfs_set_dentry_lower(s->s_root, path.dentry);
	transcryptfs_set_dentry_lower_mnt(s->s_root, path.mnt);

	s->s_flags |= MS_ACTIVE;
	
	return dget(s->s_root);
	
out_free:
	path_put(&path);
out_deact_super:
	deactivate_locked_super(s);
out:
	if (sbi) 
		kmem_cache_free(transcryptfs_sb_info_cache, sbi);
	printk(KERN_ERR "Error while mounting!; err = [%d]\n", err);
	return ERR_PTR(err);
// 	return mount_nodev(fs_type, flags, lower_path_name,
// 			   transcryptfs_read_super);
}

static void transcryptfs_kill_block_super(struct super_block *sb)
{
	struct transcryptfs_sb_info *sb_info = TRANSCRYPTFS_SB(sb);
	kill_anon_super(sb);
	if (!sb_info)
		return;
	transcryptfs_destroy_mount_crypt_stat(&sb_info->mount_crypt_stat);
	bdi_destroy(&sb_info->bdi);
	kmem_cache_free(transcryptfs_sb_info_cache, sb_info);
}

static struct file_system_type transcryptfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= TRANSCRYPTFS_NAME,
	.mount		= transcryptfs_mount,
	.kill_sb	= transcryptfs_kill_block_super,
	.fs_flags	= 0,
};

static void transcryptfs_free_kmem_caches(void)
{
	int i;
	
	for (i = 0; i < ARRAY_SIZE(transcryptfs_cache_infos); i++) {
		struct transcryptfs_cache_info *info;

		info = &transcryptfs_cache_infos[i];
		if(*(info->cache))
			kmem_cache_destroy(*(info->cache));
	}
}

static int transcryptfs_init_kmem_caches(void)
{
	int i;
	
// 	asm("int $3");
	for (i = 0; i < ARRAY_SIZE(transcryptfs_cache_infos); i++) {
		struct transcryptfs_cache_info *info;

		info = &transcryptfs_cache_infos[i];
		*(info->cache) = kmem_cache_create(info->name, info->size,
				0, SLAB_HWCACHE_ALIGN, info->ctor);
		// pr_info("The new address for %s is %p",info->name, info->cache);
		if (!*(info->cache)) {
			transcryptfs_free_kmem_caches();
			printk(KERN_WARNING  "%s: "
                                        "kmem_cache_create failed\n",
                                        info->name);
                        return -ENOMEM;
                }
        }
	return 0;
}

static int __init transcryptfs_init(void)
{
	int err = 0;

	pr_info("Registering transcryptfs " TRANSCRYPTFS_VERSION "\n");
	pr_info("inside init_transcryptfs_fs " TRANSCRYPTFS_VERSION "\n");

	err = transcryptfs_init_kmem_caches();
	if (err) {
                printk(KERN_ERR
                       "Failed to allocate one or more kmem_cache objects\n");
                goto out;
        }

// 	err = transcryptfs_init_inode_cache();
// 	if (err) {
//                 printk(KERN_ERR
//                        "Failed to allocate inode cache objects\n");
// 		goto out;
// 	}
// 	err = transcryptfs_init_dentry_cache();
// 	if (err) {
//                 printk(KERN_ERR
//                        "Failed to allocate dentry cache objects\n");
// 		goto out_free_inode_cache;
// 	}
	err = register_filesystem(&transcryptfs_fs_type);
	if (err) {
                printk(KERN_ERR
                       "Failed to register filesystem\n");
		goto out_free_kmem_caches;
	}
	err = transcryptfs_init_kthread();
	if (err) {
                printk(KERN_ERR
                       "Failed to initialize kthread\n");
		goto out_unregister_filesystem;
	}
	goto out;
out_unregister_filesystem:
	unregister_filesystem(&transcryptfs_fs_type);
out_free_kmem_caches:
	transcryptfs_free_kmem_caches();
out:
	return err;
}

static void __exit transcryptfs_exit(void)
{
// 	transcryptfs_destroy_inode_cache();
// 	transcryptfs_destroy_dentry_cache();
//	int err;

	transcryptfs_destroy_kthread();
	unregister_filesystem(&transcryptfs_fs_type);
	transcryptfs_free_kmem_caches();
	pr_info("Completed transcryptfs module unload\n");
}

MODULE_AUTHOR("Sourav, Adarsh");
MODULE_DESCRIPTION("Transcryptfs " TRANSCRYPTFS_VERSION);
MODULE_LICENSE("GPL");

module_init(transcryptfs_init);
module_exit(transcryptfs_exit);
