#include "sys_recvmsg.h"

#include <linux/syscalls.h>

extern asmlinkage ssize_t (*orig_sys_recvmsg)(const struct pt_regs* regs);
