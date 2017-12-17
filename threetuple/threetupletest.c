#include <stdint.h>
#include <errno.h>
#include "siphash.h"
#include "hashseed.h"
#include "hashtable.h"
#include "containerof.h"
#include "threetuple.h"

int main(int argc, char **argv)
{
  struct threetuplectx ctx = {};
  hash_seed_init();
  threetuplectx_init(&ctx);
  if (threetuplectx_find(&ctx, (10<<24) | 1, 12345, 17) != NULL)
  {
    abort();
  }
  if (threetuplectx_delete(&ctx, (10<<24) | 1, 12345, 17, 1, 1) != -ENOENT)
  {
    abort();
  }
  if (threetuplectx_add(&ctx, (10<<24) | 1, 12345, 17, 1, 1, 1460, 1, 6) != 0)
  {
    abort();
  }
  if (threetuplectx_find(&ctx, (10<<24) | 1, 12345, 17) == NULL)
  {
    abort();
  }
  if (threetuplectx_add(&ctx, (10<<24) | 1, 12345, 17, 1, 1, 1460, 1, 6)
      != -EEXIST)
  {
    abort();
  }
  if (threetuplectx_delete(&ctx, (10<<24) | 1, 12345, 17, 1, 1) != 0)
  {
    abort();
  }
  if (threetuplectx_find(&ctx, (10<<24) | 1, 12345, 17) != NULL)
  {
    abort();
  }
  return 0;
}
