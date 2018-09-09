#define NETMAP_WITH_LIBS
#define _GNU_SOURCE
#include <pthread.h>
#include "synproxy.h"
#include "iphdr.h"
#include "ipcksum.h"
#include "packet.h"
#include "net/netmap_user.h"
#include "netmapcommon.h"
#include "mypcapng.h"
#include "time64.h"
#include <sys/poll.h>
#include <stdatomic.h>

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

struct nm_desc *ulnmds[NUM_THR];
struct nm_desc *dlnmds[NUM_THR];

char cli_mac[6] = {0x3c,0xfd,0xfe,0xa5,0x41,0x48};
char lan_mac[6] = {0x3c,0xfd,0xfe,0xa5,0x41,0x49};

struct tcp_ctx {
  uint32_t seq;
  uint32_t seq1;
  uint32_t seq2;
  uint32_t ip1;
  uint32_t ip2;
  uint16_t port1;
  uint16_t port2;
  char pkt[1514];
  char pktsmall[60];
};

static void init_uplink(struct tcp_ctx *ctx)
{
  void *ether, *ip, *tcp;
  ether = ctx->pkt;
  memset(ctx->pkt, 0, sizeof(ctx->pkt));
  memcpy(ether_dst(ether), lan_mac, 6);
  memcpy(ether_src(ether), cli_mac, 6);
  ether_set_type(ether, ETHER_TYPE_IP);
  ip = ether_payload(ether);
  ip_set_version(ip, 4);
  ip_set_hdr_len(ip, 20);
  ip_set_total_len(ip, sizeof(ctx->pkt) - 14);
  ip_set_dont_frag(ip, 1);
  ip_set_id(ip, 123);
  ip_set_ttl(ip, 64);
  ip_set_proto(ip, 6);
  ip_set_src(ip, ctx->ip1);
  ip_set_dst(ip, ctx->ip2);
  ip_set_hdr_cksum_calc(ip, 20);
  tcp = ip_payload(ip);
  tcp_set_src_port(tcp, ctx->port1);
  tcp_set_dst_port(tcp, ctx->port2);
  tcp_set_ack_on(tcp);
  tcp_set_window(tcp, 65535);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, ctx->seq1);
  tcp_set_ack_number(tcp, ctx->seq2);
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(ctx->pkt) - 14 - 20);

  ether = ctx->pktsmall;
  memset(ctx->pktsmall, 0, sizeof(ctx->pktsmall));
  memcpy(ether_dst(ether), cli_mac, 6);
  memcpy(ether_src(ether), lan_mac, 6);
  ether_set_type(ether, ETHER_TYPE_IP);
  ip = ether_payload(ether);
  ip_set_version(ip, 4);
  ip_set_hdr_len(ip, 20);
  ip_set_total_len(ip, 14+20+20 - 14);
  ip_set_dont_frag(ip, 1);
  ip_set_id(ip, 123);
  ip_set_ttl(ip, 64);
  ip_set_proto(ip, 6);
  ip_set_src(ip, ctx->ip2);
  ip_set_dst(ip, ctx->ip1);
  ip_set_hdr_cksum_calc(ip, 20);
  tcp = ip_payload(ip);
  tcp_set_src_port(tcp, ctx->port2);
  tcp_set_dst_port(tcp, ctx->port1);
  tcp_set_ack_on(tcp);
  tcp_set_window(tcp, 65535);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, ctx->seq2);
  tcp_set_ack_number(tcp, ctx->seq);
  tcp_set_cksum_calc(ip, 20, tcp, 14+20+20 - 14 - 20);
}

static void run_uplink(int thr, struct tcp_ctx *ctx, unsigned pkts, struct pcapng_out_ctx *pcapctx)
{
  void *ether, *ip, *tcp;
  uint16_t tcp_len;
  unsigned pkt;
  for (pkt = 0; pkt < pkts; pkt++)
  {
    ether = ctx->pkt;
    ip = ether_payload(ether);
    tcp = ip_payload(ip);
    tcp_len = ip_total_len(ip) - ip_hdr_len(ip);
    tcp_set_seq_number_cksum_update(tcp, tcp_len, ctx->seq1);
    nm_my_inject(ulnmds[thr], ctx->pkt, sizeof(ctx->pkt));
    //pcapng_out_ctx_write(pcapctx, ctx->pkt, sizeof(ctx->pkt), gettime64(), "ul");
    ctx->seq1 += sizeof(ctx->pkt) - 14 - 20 - 20;
    ctx->seq += sizeof(ctx->pkt) - 14 - 20 - 20;
    tcp_set_seq_number_cksum_update(tcp, tcp_len, ctx->seq1);
    nm_my_inject(ulnmds[thr], ctx->pkt, sizeof(ctx->pkt));
    //pcapng_out_ctx_write(pcapctx, ctx->pkt, sizeof(ctx->pkt), gettime64(), "ul");
    ioctl(ulnmds[thr]->fd, NIOCTXSYNC);
    usleep(100);
    ctx->seq1 += sizeof(ctx->pkt) - 14 - 20 - 20;
    ctx->seq += sizeof(ctx->pkt) - 14 - 20 - 20;
    ether = ctx->pktsmall;
    ip = ether_payload(ether);
    tcp = ip_payload(ip);
    tcp_len = ip_total_len(ip) - ip_hdr_len(ip);
    tcp_set_ack_number_cksum_update(tcp, tcp_len, ctx->seq);
    nm_my_inject(dlnmds[thr], ctx->pktsmall, sizeof(ctx->pktsmall));
    //pcapng_out_ctx_write(pcapctx, ctx->pktsmall, sizeof(ctx->pktsmall), gettime64(), "dl");
    ioctl(dlnmds[thr]->fd, NIOCTXSYNC);
    usleep(100);
  }
}

static void *thr(void *arg)
{
  struct thr_arg *args = arg;
  struct tcp_ctx ctx[1] = {};
  void *ether;
  void *ip;
  void *tcp;
  size_t i;
  char pkt[14+20+20] = {0};
  size_t cnt = (sizeof(ctx)/sizeof(*ctx));
  struct pcapng_out_ctx pcapctx;
  char filebuf[256] = {0};
  
  snprintf(filebuf, sizeof(filebuf), "tcpsendrecv-%zu.pcapng", args->idx);

  //if (pcapng_out_ctx_init(&pcapctx, filebuf) != 0)
  //{
  //  abort();
  //}


  for (i = 0; i < (sizeof(ctx)/sizeof(*ctx)); i++)
  {
    ctx[i].ip1 = (10U<<24)|(100U<<16)|(2*(i+cnt*args->idx)+2);
    ctx[i].ip2 = (11U<<24)|(100U<<16)|(2*(i+cnt*args->idx)+1);
    ctx[i].port1 = 12121;
    ctx[i].port2 = 21212;
    ctx[i].seq1 = 0x12345678;
    ctx[i].seq2 = 0x12345678;
    ctx[i].seq = 0x12345678;
    init_uplink(&ctx[i]);
    ether = pkt;
    memset(pkt, 0, sizeof(pkt));
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
    ip_set_src(ip, ctx[i].ip1);
    ip_set_dst(ip, ctx[i].ip2);
    ip_set_hdr_cksum_calc(ip, 20);
    tcp = ip_payload(ip);
    tcp_set_src_port(tcp, ctx[i].port1);
    tcp_set_dst_port(tcp, ctx[i].port2);
    tcp_set_syn_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_window(tcp, 65535);
    tcp_set_seq_number(tcp, ctx[i].seq1 - 1);
    tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);
    //pcapng_out_ctx_write(&pcapctx, pkt, sizeof(pkt), gettime64(), "ul");
    nm_my_inject(ulnmds[args->idx], pkt, sizeof(pkt));
    ioctl(ulnmds[args->idx]->fd, NIOCTXSYNC);
    usleep(1000);

    memset(pkt, 0, sizeof(pkt));
    memcpy(ether_dst(ether), cli_mac, 6);
    memcpy(ether_src(ether), lan_mac, 6);
    ether_set_type(ether, ETHER_TYPE_IP);
    ip = ether_payload(ether);
    ip_set_version(ip, 4);
    ip_set_hdr_len(ip, 20);
    ip_set_total_len(ip, sizeof(pkt) - 14);
    ip_set_dont_frag(ip, 1);
    ip_set_id(ip, 123);
    ip_set_ttl(ip, 64);
    ip_set_proto(ip, 6);
    ip_set_src(ip, ctx[i].ip2);
    ip_set_dst(ip, ctx[i].ip1);
    ip_set_hdr_cksum_calc(ip, 20);
    tcp = ip_payload(ip);
    tcp_set_src_port(tcp, ctx[i].port2);
    tcp_set_dst_port(tcp, ctx[i].port1);
    tcp_set_syn_on(tcp);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_window(tcp, 65535);
    tcp_set_seq_number(tcp, ctx[i].seq2 - 1);
    tcp_set_ack_number(tcp, ctx[i].seq1);
    tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);
    //pcapng_out_ctx_write(&pcapctx, pkt, sizeof(pkt), gettime64(), "dl");
    nm_my_inject(dlnmds[args->idx], pkt, sizeof(pkt));
    ioctl(dlnmds[args->idx]->fd, NIOCTXSYNC);
    usleep(1000);

    memset(pkt, 0, sizeof(pkt));
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
    ip_set_src(ip, ctx[i].ip1);
    ip_set_dst(ip, ctx[i].ip2);
    ip_set_hdr_cksum_calc(ip, 20);
    tcp = ip_payload(ip);
    tcp_set_src_port(tcp, ctx[i].port1);
    tcp_set_dst_port(tcp, ctx[i].port2);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_window(tcp, 65535);
    tcp_set_seq_number(tcp, ctx[i].seq1);
    tcp_set_ack_number(tcp, ctx[i].seq2);
    tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);
    //pcapng_out_ctx_write(&pcapctx, pkt, sizeof(pkt), gettime64(), "ul");
    nm_my_inject(ulnmds[args->idx], pkt, sizeof(pkt));
    ioctl(ulnmds[args->idx]->fd, NIOCTXSYNC);
    usleep(1000);
  }
  printf("generatic traffic\n");

  while (!atomic_load(&exit_threads))
  {
    for (i = 0; i < (int)(sizeof(ctx)/sizeof(*ctx)); i++)
    {
      run_uplink(args->idx, &ctx[i], 32, &pcapctx);
    }
  }

  return NULL;
}

int main(int argc, char **argv)
{
  struct thr_arg args[NUM_THR];
  pthread_t thrs[NUM_THR];
  pthread_t sigthr;
  struct nmreq nmr;
  size_t i;
  char nmifnamebuf[64];
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

  if (argc != 3)
  {
    printf("usage: tcpsendrecv netmap:eth0 netmap:eth1\n");
    exit(1);
  }
  for (i = 0; i < NUM_THR; i++)
  {
    snprintf(nmifnamebuf, sizeof(nmifnamebuf), "%s-%zu", argv[1], i);
    memset(&nmr, 0, sizeof(nmr));
    nmr.nr_tx_slots = 64;
    nmr.nr_tx_rings = NUM_THR;
    nmr.nr_rx_rings = NUM_THR;
    nmr.nr_flags = NR_REG_ONE_NIC;
    nmr.nr_ringid = i;
    ulnmds[i] = nm_open(nmifnamebuf, &nmr, 0, NULL);
    if (ulnmds[i] == NULL)
    {
      printf("cannot open %s\n", argv[1]);
      exit(1);
    }
  }
  for (i = 0; i < NUM_THR; i++)
  {
    snprintf(nmifnamebuf, sizeof(nmifnamebuf), "%s-%zu", argv[2], i);
    memset(&nmr, 0, sizeof(nmr));
    nmr.nr_tx_slots = 64;
    nmr.nr_tx_rings = NUM_THR;
    nmr.nr_rx_rings = NUM_THR;
    nmr.nr_flags = NR_REG_ONE_NIC;
    nmr.nr_ringid = i;
    dlnmds[i] = nm_open(nmifnamebuf, &nmr, 0, NULL);
    if (dlnmds[i] == NULL)
    {
      printf("cannot open %s\n", argv[2]);
      exit(1);
    }
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

  for (i = 0; i < NUM_THR; i++)
  {
    nm_close(ulnmds[i]);
    nm_close(dlnmds[i]);
  }

  return 0;
}
