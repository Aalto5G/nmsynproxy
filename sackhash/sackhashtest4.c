#include "hashtable.h"
#include "siphash.h"
#include "linkedlist.h"
#include "containerof.h"
#include <pthread.h>
#include "sackhash.h"
#include "hashseed.h"

int main(int argc, char **argv)
{
  struct sack_ip_port_hash hash;
  size_t i;
  struct sack_hash_data data;
  struct sack_hash_data data2;
  data.mss = 1460;
  data.sack_supported = 1;
  hash_seed_init();
  if (sack_ip_port_hash_init(&hash, 128*1024) != 0)
  {
    abort();
  }
  if (sack_ip_port_hash_get4(&hash, 0, 0, &data2))
  {
    abort();
  }
  for (i = 0; i < 10*1000*1000; i++)
  {
    uint32_t randval = (uint32_t)rand();
    uint32_t ip = randval&0xFFF;
    uint16_t port = 128 | ((randval>>16)&0xF);
    if (sack_ip_port_hash_add4(&hash, ip, port, &data) != 0)
    {
      abort();
    }
    if (sack_ip_port_hash_get4(&hash, ip, port, &data) == 0)
    {
      abort();
    }
  }
  sack_ip_port_hash_free(&hash);
  return 0;
}
