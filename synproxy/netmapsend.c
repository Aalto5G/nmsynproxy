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

int main(int argc, char **argv)
{
  struct nm_desc *nmd;
  char pkt[1514] = {0};
  char pktsmall[64] = {0};
  void *ether;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  void *ip;
  void *tcp;
  struct nmreq nmr;

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

  setlinebuf(stdout);

  if (argc != 2)
  {
    printf("usage: netmapsend vale0:0\n");
    exit(1);
  }
  memset(&nmr, 0, sizeof(nmr));
  nmr.nr_tx_slots = 64;
  nmd = nm_open(argv[1], &nmr, 0, NULL);
  if (nmd == NULL)
  {
    printf("cannot open %s\n", argv[1]);
    exit(1);
  }

  for (;;)
  {
    nm_my_inject(nmd, pkt, sizeof(pkt));
    nm_my_inject(nmd, pkt, sizeof(pkt));
    nm_my_inject(nmd, pktsmall, sizeof(pktsmall));
  }

  return 0;
}
