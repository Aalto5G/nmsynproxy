#define NETMAP_WITH_LIBS
#define _GNU_SOURCE
#include <pthread.h>
#include "synproxy.h"
#include "iphdr.h"
#include "ipcksum.h"
#include "packet.h"
#include "net/netmap_user.h"
#include <sys/poll.h>

#define POOL_SIZE 300
#define CACHE_SIZE 100
#define QUEUE_SIZE 512
#define BLOCK_SIZE 1800

#define NUM_THR 2

static inline void nm_my_inject(struct nm_desc *nmd, void *data, size_t sz)
{
  int i, j;
  for (i = 0; i < 2; i++)
  {
    for (j = 0; j < 2; j++)
    {
      if (nm_inject(nmd, data, sz) == 0)
      {
        struct pollfd pollfd;
        pollfd.fd = nmd->fd;
        pollfd.events = POLLOUT;
        poll(&pollfd, 1, 0);
      }
      else
      {
        return;
      }
    }
    ioctl(nmd->fd, NIOCTXSYNC, NULL);
  }
}

struct thr_arg {
  int idx;
};

struct nm_desc *nmds[NUM_THR];

struct pktctx {
  char pkt[1514];
  char pktsmall[64];
};

static void *thr(void *arg)
{
  struct thr_arg *args = arg;
  struct pktctx ctx[90];
  void *ether;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  void *ip;
  void *tcp;
  int i;
  int cnt = (int)(sizeof(ctx)/sizeof(*ctx));

  for (i = 0; i < (int)(sizeof(ctx)/sizeof(*ctx)); i++)
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
    tcp_set_cksum_calc(ip, 20, tcp, sizeof(ctx[i].pktsmall) - 14 - 20);
  }

  for (;;)
  {
    for (i = 0; i < (int)(sizeof(ctx)/sizeof(*ctx)); i++)
    {
      nm_my_inject(nmds[args->idx], ctx[i].pkt, sizeof(ctx[i].pkt));
      nm_my_inject(nmds[args->idx], ctx[i].pkt, sizeof(ctx[i].pkt));
      nm_my_inject(nmds[args->idx], ctx[i].pktsmall, sizeof(ctx[i].pktsmall));
    }
  }

  return NULL;
}

int main(int argc, char **argv)
{
  struct thr_arg args[NUM_THR];
  pthread_t thrs[NUM_THR];
  struct nmreq nmr;
  int i;
  char nmifnamebuf[64];

  setlinebuf(stdout);

  if (argc != 2)
  {
    printf("usage: netmapsend vale0:0\n");
    exit(1);
  }
  for (i = 0; i < NUM_THR; i++)
  {
    snprintf(nmifnamebuf, sizeof(nmifnamebuf), "%s-%d", argv[1], i);
    memset(&nmr, 0, sizeof(nmr));
    nmr.nr_tx_slots = 64;
    nmr.nr_tx_rings = NUM_THR;
    nmr.nr_rx_rings = NUM_THR;
    nmr.nr_flags = NR_REG_ONE_NIC;
    nmds[i] = nm_open(nmifnamebuf, &nmr, 0, NULL);
    if (nmds[i] == NULL)
    {
      printf("cannot open %s\n", argv[1]);
      exit(1);
    }
  }

  for (i = 0; i < NUM_THR; i++)
  {
    args[i].idx = i;
    pthread_create(&thrs[i], NULL, thr, &args[i]);
  }

  for (i = 0; i < NUM_THR; i++)
  {
    pthread_join(thrs[i], NULL);
  }

  return 0;
}
