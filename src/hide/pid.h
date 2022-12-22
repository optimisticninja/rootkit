#pragma once

#include <linux/pid.h>

void hide_pid(pid_t pid);
int pid_match(const char* d_name);
