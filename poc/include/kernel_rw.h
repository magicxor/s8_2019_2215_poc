#ifndef _KERNEL_RW__H_
#define _KERNEL_RW__H_

int32_t check_kernel_memory_valid(uint64_t pAddr, uint64_t ulSz);

uint8_t kernel_read_uchar(uint64_t pAddr);

#endif