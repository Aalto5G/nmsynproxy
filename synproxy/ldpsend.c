#include <pthread.h>
#include "synproxy.h"
#include "iphdr.h"
#include "ipcksum.h"
#include "packet.h"
#include "ldp.h"
#include <sys/poll.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>

#define POOL_SIZE 300
#define CACHE_SIZE 100
#define QUEUE_SIZE 512
#define BLOCK_SIZE 1800

#define NUM_THR 2

atomic_int exit_threads = 0;

static void *signal_handler_thr(void *arg)
{
  sigset_t set;
  int sig;
  sigemptyset(&set);
  sigaddset(&set, SIGINT);
  sigaddset(&set, SIGPIPE);
  sigaddset(&set, SIGHUP);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGUSR1);
  sigaddset(&set, SIGUSR2);
  sigaddset(&set, SIGALRM);
  sigwait(&set, &sig);
  atomic_store(&exit_threads, 1);
  return NULL;
}

struct thr_arg {
  size_t idx;
};

struct ldp_interface *nmd;

struct pktctx {
  char pkt[1514];
  char pktsmall[64];
};

static inline void maybe_clear(struct ldp_out_queue *outq,
                               struct ldp_packet *pkt_tbl, int *cnt, int sz)
{
  if (*cnt < sz)
  {
    return;
  }
  ldp_out_inject(outq, pkt_tbl, *cnt);
  ldp_out_txsync(outq);
  *cnt = 0;
}

static void *thr(void *arg)
{
  struct thr_arg *args = arg;
  struct pktctx ctx[90] = {};
  void *ether;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  //char lan_mac[6] = {0x02,0,0,0,0,0x01};
  char lan_mac[6] = {0x3c,(char)0xfd,(char)0xfe,(char)0xa5,0x41,0x49};
  void *ip;
  void *tcp;
  size_t i;
  struct ldp_packet pkt_tbl[1024];
  size_t cnt = (int)(sizeof(ctx)/sizeof(*ctx));
  int x = 0;

  for (i = 0; i < (sizeof(ctx)/sizeof(*ctx)); i++)
  {
    ether = ctx[i].pkt;
    memcpy(ether_dst(ether), lan_mac, 6);
    memcpy(ether_src(ether), cli_mac, 6);
    ether_set_type(ether, ETHER_TYPE_IP);
    ip = ether_payload(ether);
    ip_set_version(ip, 4);
    ip_set_hdr_len(ip, 20);
    ip_set_total_len(ip, sizeof(ctx[i].pkt) - 14);
    ip_set_dont_frag(ip, 1);
    ip_set_id(ip, 123);
    ip_set_ttl(ip, 64);
    ip_set_proto(ip, 6);
    ip_set_src(ip, (10<<24)|(2*(i+cnt*args->idx)+2));
    ip_set_dst(ip, (11<<24)|(2*(i+cnt*args->idx)+1));
    ip_set_hdr_cksum_calc(ip, 20);
    tcp = ip_payload(ip);
    tcp_set_src_port(tcp, 12345);
    tcp_set_dst_port(tcp, 54321);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_cksum_calc(ip, 20, tcp, sizeof(ctx[i].pkt) - 14 - 20);
  
    ether = ctx[i].pktsmall;
    memcpy(ether_dst(ether), lan_mac, 6);
    memcpy(ether_src(ether), cli_mac, 6);
    ether_set_type(ether, ETHER_TYPE_IP);
    ip = ether_payload(ether);
    ip_set_version(ip, 4);
    ip_set_hdr_len(ip, 20);
    ip_set_total_len(ip, sizeof(ctx[i].pktsmall) - 14);
    ip_set_dont_frag(ip, 1);
    ip_set_id(ip, 123);
    ip_set_ttl(ip, 64);
    ip_set_proto(ip, 6);
    ip_set_src(ip, (10<<24)|(2*(i+cnt*args->idx)+2));
    ip_set_dst(ip, (11<<24)|(2*(i+cnt*args->idx)+1));
    ip_set_hdr_cksum_calc(ip, 20);
    tcp = ip_payload(ip);
    tcp_set_src_port(tcp, 12345);
    tcp_set_dst_port(tcp, 54321);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_cksum_calc(ip, 20, tcp, sizeof(ctx[i].pktsmall) - 14 - 20);
  }

  while (!atomic_load(&exit_threads))
  {
    for (i = 0; i < (int)(sizeof(ctx)/sizeof(*ctx)); i++)
    {
      pkt_tbl[x].data = ctx[i].pkt;
      pkt_tbl[x].sz = sizeof(ctx[i].pkt);
      x++;
      maybe_clear(nmd->outq[args->idx], pkt_tbl, &x, sizeof(pkt_tbl)/sizeof(*pkt_tbl));

      pkt_tbl[x].data = ctx[i].pkt;
      pkt_tbl[x].sz = sizeof(ctx[i].pkt);
      x++;
      maybe_clear(nmd->outq[args->idx], pkt_tbl, &x, sizeof(pkt_tbl)/sizeof(*pkt_tbl));

      pkt_tbl[x].data = ctx[i].pktsmall;
      pkt_tbl[x].sz = sizeof(ctx[i].pktsmall);
      x++;
      maybe_clear(nmd->outq[args->idx], pkt_tbl, &x, sizeof(pkt_tbl)/sizeof(*pkt_tbl));
    }
  }

  return NULL;
}

int main(int argc, char **argv)
{
  struct thr_arg args[NUM_THR];
  pthread_t thrs[NUM_THR];
  pthread_t sigthr;
  size_t i;
  sigset_t set;

  sigemptyset(&set);
  sigaddset(&set, SIGINT);
  sigaddset(&set, SIGPIPE);
  sigaddset(&set, SIGHUP);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGUSR1);
  sigaddset(&set, SIGUSR2);
  sigaddset(&set, SIGALRM);
  pthread_sigmask(SIG_BLOCK, &set, NULL);

  setlinebuf(stdout);

  if (argc != 2)
  {
    printf("usage: ldpsend vale0:0\n");
    exit(1);
  }
  nmd = ldp_interface_open(argv[1], NUM_THR, NUM_THR);
  if (nmd == NULL)
  {
    printf("cannot open %s\n", argv[1]);
    exit(1);
  }

  for (i = 0; i < NUM_THR; i++)
  {
    args[i].idx = i;
    pthread_create(&thrs[i], NULL, thr, &args[i]);
  }
  pthread_create(&sigthr, NULL, signal_handler_thr, NULL);

  for (i = 0; i < NUM_THR; i++)
  {
    pthread_join(thrs[i], NULL);
  }
  pthread_join(sigthr, NULL);

  ldp_interface_close(nmd);

  return 0;
}
