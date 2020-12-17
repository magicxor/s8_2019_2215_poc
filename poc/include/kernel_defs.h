#ifndef _KERNEL_DEFS__H_
#define _KERNEL_DEFS__H_

// These definitions can vary across kernel versions/builds. 
// If you wish to adapt the POC for your device, modify them accordingly. 

// Offset of task_struct (task) field in binder_thread structure // offsetof(struct binder_thread, task) = 0x190
#define TASK_BINDER_THREAD_OFFSET      0x190

// Offset of wait_queue_head_t (wait) field in binder_thread structure // offsetof(struct binder_thread, wait) = 0xA0
#define WAITQUEUE_BINDER_THREAD_OFFSET 0xA0

// Size of binder_thread structure in bytes // sizeof(struct binder_thread) = 0x198
#define BINDER_THREAD_SZ               0x198

// Offset of thread_info structure in task_struct (if not in kstack) // always 0x0
#define THREAD_INFO_TASK_OFFSET        0x0

// Offset of stack pointer field in task_struct // offsetof(struct task_struct, stack) = 0x28
#define KSTACK_TASK_OFFSET             0x28 // not 0x8

// Offset of addr_limit in thread_info structure // 0x8
#define ADDR_LIMIT_THREAD_INFO_OFFSET  0x8

// Size of a thread's kernel stack // in arm64(AArch64) kernel stack has 16384/16k/0x4000 bytes,in arm32 ,it’s 8k bytes. Every process use the same kernel stack.
#define THREAD_KSTACK_SIZE             0x4000

// Offset of files_struct pointer in task_struct // offsetof(struct task_struct, files) = 0x860
#define FILES_STRUCT_TASK_OFFSET       0x860

// Offset of fdtable pointer in files_struct // offsetof(struct files_struct, fdt) = 0x20
#define FDTABLE_FILES_STRUCT_OFFSET    0x20

// Offset of files/fd array in fdtable // offsetof(struct fdtable, fd) = 0x8
#define FD_ARRAY_FDTABLE_OFFSET        0x8

// Offset of file_operations pointer in file // offsetof(struct file, f_op) = 0x28
#define FILE_OPS_FILE_OFFSET           0x28

// Offset of check_flags pointer in file_operations // offsetof(struct file_operations, check_flags) = 0xA0
#define CHECK_FLAGS_FILE_OPS_OFFSET    0xA0 // not 0xB0

// Offset of vfsmount pointer in file (part of path structure) // offsetof(struct file, f_path.mnt) = 0x10
#define MNT_FILE_OFFSET                0x10

// Offset of mnt_flags in vfsmont // offsetof(struct vfsmount, mnt_flags) = 0x18
#define MNT_FLAGS_MNT_OFFSET           0x18

// Offset of dentry pointer in file (part of path structure) // offsetof(struct file, f_path.mnt) = 0x18
#define DENTRY_FILE_OFFSET             0x18

// Offset of inode pointer in dentry // offsetof(struct dentry, d_inode) = 0x30
#define INODE_DENTRY_OFFSET            0x30

// Offset of inoide_operations pointer in inode // offsetof(struct inode, i_op) = 0x20
#define INODE_OPS_INODE_OFFSET         0x20

// Offset of get_attr in inode_operations // offsetof(struct inode_operations, getattr) = 0x80
#define GET_ATTR_INODE_OPS_OFFSET      0x80 // not 0x90

// Offset of security_capable list head in security_hook_heads // offsetof(struct security_hook_heads, capable) = 0x80
#define SECURITY_CAPABLE_OFFSET        0x80

// Number of decision slots stored in the avc cache // 512 = 0x200
#define AVC_CACHE_SLOTS                0x200

// Offset of the decision field in an avc_cache slot // ??
#define DECISION_AVC_CACHE_OFFSET      0x1C

// Address to start memory searches in the kernel
#define KERNEL_BASE                    0xffffff8008080000 // ??

// Kernel/Userspace memory address separation
#define USER_DS                        0x8000000000 // ??
#define KERNEL_DS                      0xFFFFFFFFFFFFFFFF // -1UL in "arch\arm64\include\asm\uaccess.h"
#define IS_KERNEL_POINTER(x)           (((x > KERNEL_BASE) && (x < KERNEL_DS))?1:0)

#endif