#define _GNU_SOURCE
#include <pthread.h>
#include "synproxy.h"
#include "iphdr.h"
#include "ipcksum.h"
#include "packet.h"

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

static void periodic(uint64_t count, struct timeval *tv1ptr)
{
  struct timeval tv2;
  if ((count & (16*1024*1024-1)) == 0)
  {
    double diff;
    gettimeofday(&tv2, NULL);
    diff = tv2.tv_sec - tv1ptr->tv_sec + (tv2.tv_usec - tv1ptr->tv_usec)/1000.0/1000.0;
    printf("%g Mpps\n", 16*1024*1024/diff/1000.0/1000.0);
    *tv1ptr = tv2;
    exit(0);
  }
}

struct rx_args {
  struct queue *workerq;
  struct synproxy *synproxy;
  struct worker_local *local;
};

static void *rx_func(void *userdata)
{
  struct rx_args *args = userdata;
  char pkt[1514] = {0};
  char pktsmall[64] = {0};
  void *ether;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  void *ip;
  void *tcp;
  struct ll_alloc_st st;
  struct queue_cache cache;
  struct port outport;
  struct asdiscardfunc_userdata ud;
  struct timeval tv1;
  uint64_t count = 0;

  gettimeofday(&tv1, NULL);

  ud.loc = &loc;
  outport.portfunc = asdiscardfunc;
  outport.userdata = &ud;

  if (queue_cache_init(&cache, args->workerq, CACHE_SIZE) != 0)
  {
    abort();
  }
  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }
  
  ether = pkt;
  memcpy(ether_dst(ether), lan_mac, 6);
  memcpy(ether_src(ether), cli_mac, 6);
  ether_set_type(ether, ETHER_TYPE_IP);
  ip = ether_payload(ether);
  ip_set_version(ip, 4);
  ip_set_hdr_len(ip, 20);
  ip_set_total_len(ip, sizeof(pkt) - 14);
  ip_set_dont_frag(ip, 1);
  ip_set_id(ip, 123);
  ip_set_ttl(ip, 64);
  ip_set_proto(ip, 6);
  ip_set_src(ip, (10<<24)|2);
  ip_set_dst(ip, (11<<24)|1);
  ip_set_hdr_cksum_calc(ip, 20);
  tcp = ip_payload(ip);
  tcp_set_src_port(tcp, 12345);
  tcp_set_dst_port(tcp, 54321);
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);

  ether = pktsmall;
  memcpy(ether_dst(ether), lan_mac, 6);
  memcpy(ether_src(ether), cli_mac, 6);
  ether_set_type(ether, ETHER_TYPE_IP);
  ip = ether_payload(ether);
  ip_set_version(ip, 4);
  ip_set_hdr_len(ip, 20);
  ip_set_total_len(ip, sizeof(pktsmall) - 14);
  ip_set_dont_frag(ip, 1);
  ip_set_id(ip, 123);
  ip_set_ttl(ip, 64);
  ip_set_proto(ip, 6);
  ip_set_src(ip, (10<<24)|2);
  ip_set_dst(ip, (11<<24)|1);
  ip_set_hdr_cksum_calc(ip, 20);
  tcp = ip_payload(ip);
  tcp_set_src_port(tcp, 12345);
  tcp_set_dst_port(tcp, 54321);
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(pktsmall) - 14 - 20);

  for (;;)
  {
    struct packet *pktstruct;
    uint64_t time64 = gettime64();

    pktstruct = ll_alloc_st(&st, packet_size(sizeof(pkt)));
    pktstruct->direction = PACKET_DIRECTION_UPLINK;
    pktstruct->sz = sizeof(pkt);
    memcpy(packet_data(pktstruct), pkt, sizeof(pkt));
    if (uplink(args->synproxy, args->local, pktstruct, &outport, time64))
    {
      as_free_mt(&loc, pktstruct);
    }
    count++;
    periodic(count, &tv1);


    pktstruct = ll_alloc_st(&st, packet_size(sizeof(pkt)));
    pktstruct->direction = PACKET_DIRECTION_UPLINK;
    pktstruct->sz = sizeof(pkt);
    memcpy(packet_data(pktstruct), pkt, sizeof(pkt));
    if (uplink(args->synproxy, args->local, pktstruct, &outport, time64))
    {
      as_free_mt(&loc, pktstruct);
    }
    count++;
    periodic(count, &tv1);

    pktstruct = ll_alloc_st(&st, packet_size(sizeof(pktsmall)));
    pktstruct->direction = PACKET_DIRECTION_UPLINK;
    pktstruct->sz = sizeof(pktsmall);
    memcpy(packet_data(pktstruct), pktsmall, sizeof(pktsmall));
    if (uplink(args->synproxy, args->local, pktstruct, &outport, time64))
    {
      as_free_mt(&loc, pktstruct);
    }
    count++;
    periodic(count, &tv1);
  }
}


int main(int argc, char **argv)
{
  pthread_t rx;
  struct rx_args rx_args;
  struct synproxy synproxy;
  struct queue workerq;
  struct queue txq;
  struct worker_local local;
  cpu_set_t cpuset;

  setlinebuf(stdout);

  if (queue_init(&workerq, QUEUE_SIZE) != 0)
  {
    abort();
  }
  if (queue_init(&txq, QUEUE_SIZE) != 0)
  {
    abort();
  }

  hash_table_init(&local.hash, 8, synproxy_hash_fn, NULL);
  timer_linkheap_init(&local.timers);
  synproxy_hash_put_connected(&local, (10<<24)|2, 12345, (11<<24)|1, 54321);

  rx_args.workerq = &workerq;
  rx_args.synproxy = &synproxy;
  rx_args.local = &local;

  pthread_create(&rx, NULL, rx_func, &rx_args);
  CPU_ZERO(&cpuset);
  CPU_SET(0, &cpuset);
  pthread_setaffinity_np(rx, sizeof(cpuset), &cpuset);
  pthread_join(rx, NULL);

  return 0;
}
