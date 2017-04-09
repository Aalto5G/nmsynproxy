#define _GNU_SOURCE
#include <pthread.h>
#include "llalloc.h"
#include "synproxy.h"
#include "iphdr.h"
#include "ipcksum.h"
#include "packet.h"
#include "hashseed.h"
#include "mypcapng.h"

static inline uint64_t gettime64(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec*1000UL*1000UL + tv.tv_usec;
}

#define POOL_SIZE 300
#define CACHE_SIZE 100
#define QUEUE_SIZE 512
#define BLOCK_SIZE 1800

struct rx_args {
  struct synproxy *synproxy;
  struct worker_local *local;
  const char *file;
};

static void *rx_func(void *userdata)
{
  struct rx_args *args = userdata;
  struct ll_alloc_st st;
  struct port outport;
  struct allocifdiscardfunc_userdata ud;
  struct timeval tv1;
  void *buf;
  size_t bufcapacity;
  size_t len, snap;
  const char *ifname;
  struct pcapng_in_ctx ctx;
  size_t cnt = 0;
  struct allocif intf = {.ops = &ll_allocif_ops_st, .userdata = &st};

  if (pcapng_in_ctx_init(&ctx, args->file, 1) != 0)
  {
    printf("can't open input file\n");
    exit(1);
  }

  gettimeofday(&tv1, NULL);

  ud.intf = &intf;
  outport.portfunc = allocifdiscardfunc;
  outport.userdata = &ud;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  for (;;)
  {
    struct packet *pktstruct;
    uint64_t time64 = gettime64();
    int result;
    enum packet_direction direction;

    result = pcapng_in_ctx_read(
      &ctx, &buf, &bufcapacity, &len, &snap, NULL, &ifname);

    if (result < 0)
    {
      printf("can't read from .pcapng\n");
      exit(1);
    }
    else if (result == 0)
    {
      free(buf);
      buf = NULL;
      bufcapacity = 0;
      break;
    }
    printf("pkt %zu\n", ++cnt);
    if (snap != len)
    {
      printf("packet truncated\n");
      exit(1);
    }
    if (ifname == NULL)
    {
      printf("missing ifname\n");
      exit(1);
    }
    if (strcmp(ifname, "in") == 0)
    {
      direction = PACKET_DIRECTION_DOWNLINK;
    }
    else if (strcmp(ifname, "out") == 0)
    {
      direction = PACKET_DIRECTION_UPLINK;
    }
    else
    {
      printf("unsupported ifname: %s\n", ifname);
      exit(1);
    }

    pktstruct = ll_alloc_st(&st, packet_size(snap));
    pktstruct->direction = direction;
    pktstruct->sz = snap;
    memcpy(packet_data(pktstruct), buf, snap);
    if (direction == PACKET_DIRECTION_UPLINK)
    {
      if (uplink(args->synproxy, args->local, pktstruct, &outport, time64))
      {
        ll_free_st(&st, pktstruct);
      }
    }
    else
    {
      if (downlink(args->synproxy, args->local, pktstruct, &outport, time64))
      {
        ll_free_st(&st, pktstruct);
      }
    }
  }
  ll_alloc_st_free(&st);
  return NULL;
}


int main(int argc, char **argv)
{
  pthread_t rx;
  struct rx_args rx_args;
  struct synproxy synproxy;
  struct worker_local local;
  cpu_set_t cpuset;

  hash_seed_init();
  setlinebuf(stdout);

  if (argc != 2)
  {
    printf("usage: %s in.pcapng\n", argv[0]);
    exit(1);
  }

  hash_table_init(&local.hash, 8, synproxy_hash_fn, NULL);
  timer_linkheap_init(&local.timers);
  synproxy_hash_put_connected(&local, (10<<24)|2, 12345, (11<<24)|1, 54321);

  rx_args.synproxy = &synproxy;
  rx_args.local = &local;
  rx_args.file = argv[1];

  pthread_create(&rx, NULL, rx_func, &rx_args);
  CPU_ZERO(&cpuset);
  CPU_SET(0, &cpuset);
  pthread_setaffinity_np(rx, sizeof(cpuset), &cpuset);
  pthread_join(rx, NULL);

  return 0;
}