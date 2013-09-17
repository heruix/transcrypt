TRANSCRYPTFS_VERSION="0.1"
EXTRA_CFLAGS += -DTRANSCRYPTFS_VERSION=\"$(TRANSCRYPTFS_VERSION)\" -g
#mpi.o :


transcryptfs-y := dentry.o file.o inode.o main.o super.o mmap.o \
		crypto.o keystore.o read_write.o kthread.o	\
		crypto/base64.o                         \
	        crypto/hash.o                           \
        	crypto/asn1parse.o                      \
        	crypto/certs.o                          \
        	crypto/pem.o                            \
        	crypto/x509parse.o                      \
        	crypto/pbkdf2.o                      \
        	crypto/bignum.o                         \
        	crypto/rsa.o

#transcryptfs-y := dentry.o file.o inode.o main.o super.o mmap.o crypto.o read_write.o kthread.o base64.o x509.o rsa1024.o rsa_mpi.o \
#	mpi/generic_mpih-lshift.o		\
#	mpi/generic_mpih-mul1.o		\
#	mpi/generic_mpih-mul2.o		\
#	mpi/generic_mpih-mul3.o		\
#	mpi/generic_mpih-rshift.o		\
#	mpi/generic_mpih-sub1.o		\
#	mpi/generic_mpih-add1.o		\
#	mpi/mpicoder.o			\
#	mpi/mpi-bit.o			\
#	mpi/mpih-cmp.o			\
#	mpi/mpih-div.o			\
#	mpi/mpih-mul.o			\
#	mpi/mpi-pow.o			\
#	mpi/mpiutil.o			\
#	mpi/mpi-add.o			\
#	mpi/mpi-div.o			\
#	mpi/mpi-cmp.o			\
#	mpi/mpi-gcd.o			\
#	mpi/mpi-inline.o			\
#	mpi/mpi-inv.o			\
#	mpi/mpi-mpow.o			\
#	mpi/mpi-mul.o			\
#	mpi/mpi-scan.o			\
#	clz_tab.o

# rsa_demo-y := 					\
	crypto/base64.o 			\
	crypto/hash.o				\
	crypto/asn1parse.o			\
	crypto/certs.o				\
        crypto/pem.o				\
        crypto/x509parse.o			\
	crypto/bignum.o				\
	crypto/pbkdf2.o				\
	crypto/rsa.o				
        


# obj-m := rsa_demo.o
obj-m := transcryptfs.o

all:
	make -C $(KERN_DIR) M=$(PWD) modules
clean:
	make -C $(KERN_DIR) M=$(PWD) clean


#
# MPI multiprecision maths library (from gpg)
#

