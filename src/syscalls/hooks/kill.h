#pragma once

#include <linux/kallsyms.h>

#include "../syscalls.h"

#ifdef PTREGS_SYSCALL_STUBS
asmlinkage int hook_kill(const struct pt_regs* regs);
#else
asmlinkage int hook_kill(pid_t pid, int sig);
#endif
