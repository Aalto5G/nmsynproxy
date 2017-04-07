#include "conf.h"
#include "yyutils.h"
#include <stdio.h>

int main(int argc, char **argv)
{
  FILE *f = fopen("conf.txt", "r");
  struct conf conf = CONF_INITIALIZER;
  confyydoparse(f, &conf);
  fclose(f);
  printf("mode %u\n", conf.sackmode);
  return 0;
}
