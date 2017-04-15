#include "synproxy.h"
#include <stdio.h>

int main(int argc, char **argv)
{
  printf("%zu\n", sizeof(struct synproxy_hash_entry));
  return 0;
}
