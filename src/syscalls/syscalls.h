#pragma once

#include <linux/kallsyms.h>
#include <linux/version.h>

#define KALLSYMS_LOOKUP_NAME_EXPORT (LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0))

// Prevent recursive loops when hooking to avoid panic/hang
#define USE_FENTRY_OFFSET 0
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0))
#define PTREGS_SYSCALL_STUBS 1
#endif

void hook_syscalls(void);
void unhook_syscalls(void);
