#include "dynarr.h"

int main(int argc, char **argv)
{
  DYNARR(int) ar = DYNARR_INITER;
  int i;
  for (i = 0; i < 32; i++)
  {
    if (!DYNARR_PUSH_BACK(&ar, i))
    {
      abort();
    }
  }
  for (i = 0; i < DYNARR_SIZE(&ar); i++)
  {
    printf("%d\n", DYNARR_GET(&ar, i));
  }
  return 0;
}
