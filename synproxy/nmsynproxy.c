#define _GNU_SOURCE
#define NETMAP_WITH_LIBS
#include <pthread.h>
#include "llalloc.h"
#include "synproxy.h"
#include "iphdr.h"
#include "ipcksum.h"
#include "packet.h"
#include "net/netmap_user.h"
#include "hashseed.h"
#include "yyutils.h"
#include "mypcapng.h"
#include "netmapports.h"
#include <unistd.h>
#include <sys/poll.h>
#include <sys/time.h>
#include "time64.h"
#include "databuf.h"
#include "read.h"
#include "ctrl.h"
#include "netmapcommon.h"

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

struct rx_args {
  struct synproxy *synproxy;
  struct worker_local *local;
  int idx;
};


struct periodic_userdata {
  struct rx_args *args;
  uint64_t dlbytes, ulbytes;
  uint64_t dlpkts, ulpkts;
  uint64_t last_dlbytes, last_ulbytes;
  uint64_t last_dlpkts, last_ulpkts;
  uint64_t last_time64;
  uint64_t next_time64;
};

static void periodic_fn(
  struct periodic_userdata *ud)
{
  uint64_t time64 = gettime64();
  double diff = (time64 - ud->last_time64)/1000.0/1000.0;
  uint64_t ulbdiff = ud->ulbytes - ud->last_ulbytes;
  uint64_t dlbdiff = ud->dlbytes - ud->last_dlbytes;
  uint64_t ulpdiff = ud->ulpkts - ud->last_ulpkts;
  uint64_t dlpdiff = ud->dlpkts - ud->last_dlpkts;
  ud->last_ulbytes = ud->ulbytes;
  ud->last_dlbytes = ud->dlbytes;
  ud->last_ulpkts = ud->ulpkts;
  ud->last_dlpkts = ud->dlpkts;
  worker_local_rdlock(ud->args->local);
  printf("worker/%d %g MPPS %g Gbps ul %g MPPS %g Gbps dl"
         " %u conns synproxied %u conns not\n",
         ud->args->idx,
         ulpdiff/diff/1e6, 8*ulbdiff/diff/1e9,
         dlpdiff/diff/1e6, 8*dlbdiff/diff/1e9,
         ud->args->local->synproxied_connections,
         ud->args->local->direct_connections);
  fflush(stdout);
  worker_local_rdunlock(ud->args->local);
  ud->last_time64 = time64;
  ud->next_time64 += 2*1000*1000;
}

#define MAX_WORKERS 64
#define MAX_RX_TX 64
#define MAX_TX 64
#define MAX_RX 64

struct nm_desc *dlnmds[MAX_RX_TX], *ulnmds[MAX_RX_TX];

int in = 0;
struct pcapng_out_ctx inctx;
int out = 0;
struct pcapng_out_ctx outctx;
int lan = 0;
struct pcapng_out_ctx lanctx;
int wan = 0;
struct pcapng_out_ctx wanctx;

#define POOL_SIZE 300
#define CACHE_SIZE 100
#define QUEUE_SIZE 512
#define BLOCK_SIZE 1800

struct tx_args {
  struct queue *txq;
  int idx;
};

static void *rx_func(void *userdata)
{
  struct rx_args *args = userdata;
  struct ll_alloc_st st;
  int i;
  struct port outport;
  struct netmapfunc2_userdata ud;
  struct timeval tv1;
  struct periodic_userdata periodic = {};
  struct allocif intf = {.ops = &ll_allocif_ops_st, .userdata = &st};

  gettimeofday(&tv1, NULL);

  ud.intf = &intf;
  ud.dlnmd = dlnmds[args->idx];
  ud.ulnmd = ulnmds[args->idx];
  outport.portfunc = netmapfunc2;
  outport.userdata = &ud;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  periodic.last_time64 = gettime64();
  periodic.next_time64 = periodic.last_time64 + 2*1000*1000;
  periodic.args = args;

  while (!atomic_load(&exit_threads))
  {
    uint64_t time64;
    uint64_t expiry;
    int try;
    uint32_t timeout;
    struct pollfd pfds[2];

    pfds[0].fd = dlnmds[args->idx]->fd;
    pfds[0].events = POLLIN;
    pfds[1].fd = ulnmds[args->idx]->fd;
    pfds[1].events = POLLIN;

    worker_local_rdlock(args->local);
    expiry = timer_linkheap_next_expiry_time(&args->local->timers);
    time64 = gettime64();
    if (expiry > time64 + 1000*1000)
    {
      expiry = time64 + 1000*1000;
    }
    worker_local_rdunlock(args->local);

    timeout = (expiry > time64 ? (999 + expiry - time64)/1000 : 0);
    if (timeout > 0)
    {
      poll(pfds, 2, timeout);
    }

    time64 = gettime64();
    worker_local_rdlock(args->local);
    try = (timer_linkheap_next_expiry_time(&args->local->timers) < time64);
    worker_local_rdunlock(args->local);

    if (time64 >= periodic.next_time64)
    {
      periodic_fn(&periodic);
    }

    if (try)
    {
      worker_local_wrlock(args->local);
      while (timer_linkheap_next_expiry_time(&args->local->timers) < time64)
      {
        struct timer_link *timer = timer_linkheap_next_expiry_timer(&args->local->timers);
        timer_linkheap_remove(&args->local->timers, timer);
        worker_local_wrunlock(args->local);
        timer->fn(timer, &args->local->timers, timer->userdata);
        worker_local_wrlock(args->local);
      }
      worker_local_wrunlock(args->local);
    }
    for (i = 0; i < 1000; i++)
    {
      struct packet *pktstruct;
      struct nm_pkthdr hdr;
      unsigned char *pkt;
      pkt = nm_nextpkt(dlnmds[args->idx], &hdr);
      if (pkt == NULL)
      {
        break;
      }

      pktstruct = ll_alloc_st(&st, packet_size(hdr.len));
      pktstruct->direction = PACKET_DIRECTION_UPLINK;
      pktstruct->sz = hdr.len;
      memcpy(packet_data(pktstruct), pkt, hdr.len);

      if (uplink(args->synproxy, args->local, pktstruct, &outport, time64, &st))
      {
        ll_free_st(&st, pktstruct);
      }
      periodic.ulpkts++;
      periodic.ulbytes += hdr.len;
      if (in)
      {
        if (pcapng_out_ctx_write(&inctx, pkt, hdr.len, gettime64(), "out"))
        {
          printf("can't record packet\n");
          exit(1);
        }
      }
      if (lan)
      {
        if (pcapng_out_ctx_write(&lanctx, pkt, hdr.len, gettime64(), "in"))
        {
          printf("can't record packet\n");
          exit(1);
        }
      }
    }
    for (i = 0; i < 1000; i++)
    {
      struct packet *pktstruct;
      struct nm_pkthdr hdr;
      unsigned char *pkt;
      pkt = nm_nextpkt(ulnmds[args->idx], &hdr);
      if (pkt == NULL)
      {
        break;
      }

      pktstruct = ll_alloc_st(&st, packet_size(hdr.len));
      pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
      pktstruct->sz = hdr.len;
      memcpy(packet_data(pktstruct), pkt, hdr.len);

      if (downlink(args->synproxy, args->local, pktstruct, &outport, time64, &st))
      {
        ll_free_st(&st, pktstruct);
      }
      periodic.dlpkts++;
      periodic.dlbytes += hdr.len;
      if (in)
      {
        if (pcapng_out_ctx_write(&inctx, pkt, hdr.len, gettime64(), "in"))
        {
          printf("can't record packet\n");
          exit(1);
        }
      }
      if (wan)
      {
        if (pcapng_out_ctx_write(&wanctx, pkt, hdr.len, gettime64(), "in"))
        {
          printf("can't record packet\n");
          exit(1);
        }
      }
    }
  }
  ll_alloc_st_free(&st);
  log_log(LOG_LEVEL_NOTICE, "RX", "exiting RX thread");
  return NULL;
}

int main(int argc, char **argv)
{
  pthread_t rx[MAX_RX], ctrl, sigthr;
  struct rx_args rx_args[MAX_RX];
  struct ctrl_args ctrl_args;
  struct synproxy synproxy;
  struct worker_local local;
  struct nmreq nmr;
  cpu_set_t cpuset;
  struct conf conf = CONF_INITIALIZER;
  int opt;
  char *inname = NULL;
  char *outname = NULL;
  char *lanname = NULL;
  char *wanname = NULL;
  int i;
  char nmifnamebuf[64];
  sigset_t set;
  int pipefd[2];
  int sockfd;
  struct timer_link timer;

  log_open("NMSYNPROXY", LOG_LEVEL_DEBUG, LOG_LEVEL_INFO);

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0)
  {
    abort();
  }

  sigemptyset(&set);
  sigaddset(&set, SIGINT);
  sigaddset(&set, SIGPIPE);
  sigaddset(&set, SIGHUP);
  sigaddset(&set, SIGTERM);
  sigaddset(&set, SIGUSR1);
  sigaddset(&set, SIGUSR2);
  sigaddset(&set, SIGALRM);
  pthread_sigmask(SIG_BLOCK, &set, NULL);

  confyydirparse(argv[0], "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  hash_seed_init();
  setlinebuf(stdout);

  while ((opt = getopt(argc, argv, "i:o:l:w:")) != -1)
  {
    switch (opt)
    {
      case 'i':
        inname = optarg;
        break;
      case 'o':
        outname = optarg;
        break;
      case 'l':
        lanname = optarg;
        break;
      case 'w':
        wanname = optarg;
        break;
      default:
        printf("usage: %s [-i in.pcapng] [-o out.pcapng] [-l lan.pcapng] [-w wan.pcapng] vale0:1 vale1:1\n", argv[0]);
        exit(1);
        break;
    }
  }

  if (argc != optind + 2)
  {
    printf("usage: %s [-i in.pcapng] [-o out.pcapng] [-l lan.pcapng] [-w wan.pcapng] vale0:1 vale1:1\n", argv[0]);
    exit(1);
  }
  if (inname != NULL)
  {
    if (pcapng_out_ctx_init(&inctx, inname) != 0)
    {
      printf("can't open file for storing input\n");
      exit(1);
    }
    in = 1;
  }
  if (outname != NULL)
  {
    if (pcapng_out_ctx_init(&outctx, outname) != 0)
    {
      printf("can't open file for storing output\n");
      exit(1);
    }
    out = 1;
  }
  if (lanname != NULL)
  {
    if (pcapng_out_ctx_init(&lanctx, lanname) != 0)
    {
      printf("can't open file for storing LAN traffic\n");
      exit(1);
    }
    lan = 1;
  }
  if (wanname != NULL)
  {
    if (pcapng_out_ctx_init(&wanctx, wanname) != 0)
    {
      printf("can't open file for storing WAN traffic\n");
      exit(1);
    }
    wan = 1;
  }

  int num_rx;
  int max;
  num_rx = conf.threadcount;
  if (num_rx <= 0 || num_rx > MAX_RX)
  {
    printf("too many threads: %d\n", num_rx);
    exit(1);
  }
  max = num_rx;

  for (i = 0; i < max; i++)
  {
    memset(&nmr, 0, sizeof(nmr));
    nmr.nr_tx_rings = max;
    nmr.nr_rx_rings = max;
    nmr.nr_flags = NR_REG_ONE_NIC;
    nmr.nr_ringid = i | NETMAP_NO_TX_POLL;
#if 1
    nmr.nr_rx_slots = 256;
    nmr.nr_tx_slots = 64;
#endif
    snprintf(nmifnamebuf, sizeof(nmifnamebuf), "%s-%d", argv[optind+0], i);
    dlnmds[i] = nm_open(nmifnamebuf, &nmr, 0, NULL);
    if (dlnmds[i] == NULL)
    {
      printf("cannot open %s\n", argv[optind+0]);
      exit(1);
    }
    printf("Downlink interface:\n");
    printf("RX rings: %u %u\n", dlnmds[i]->last_rx_ring, dlnmds[i]->first_rx_ring + 1);
    printf("TX rings: %u %u\n", dlnmds[i]->last_tx_ring, dlnmds[i]->first_tx_ring + 1);
    printf("RX rings: %u\n", dlnmds[i]->last_rx_ring - dlnmds[i]->first_rx_ring + 1);
    printf("TX rings: %u\n", dlnmds[i]->last_tx_ring - dlnmds[i]->first_tx_ring + 1);
  }
  for (i = 0; i < max; i++)
  {
    memset(&nmr, 0, sizeof(nmr));
    nmr.nr_tx_rings = max;
    nmr.nr_rx_rings = max;
    nmr.nr_flags = NR_REG_ONE_NIC;
    nmr.nr_ringid = i | NETMAP_NO_TX_POLL;
#if 1
    nmr.nr_rx_slots = 256;
    nmr.nr_tx_slots = 64;
#endif
    snprintf(nmifnamebuf, sizeof(nmifnamebuf), "%s-%d", argv[optind+1], i);
    ulnmds[i] = nm_open(nmifnamebuf, &nmr, 0, NULL);
    if (ulnmds[i] == NULL)
    {
      printf("cannot open %s\n", argv[optind+1]);
      exit(1);
    }
    printf("Uplink interface:\n");
    printf("RX rings: %u %u\n", ulnmds[i]->last_rx_ring, ulnmds[i]->first_rx_ring + 1);
    printf("TX rings: %u %u\n", ulnmds[i]->last_tx_ring, ulnmds[i]->first_tx_ring + 1);
    printf("RX rings: %u\n", ulnmds[i]->last_rx_ring - ulnmds[i]->first_rx_ring + 1);
    printf("TX rings: %u\n", ulnmds[i]->last_tx_ring - ulnmds[i]->first_tx_ring + 1);
  }
  link_wait(sockfd, argv[optind + 0]);
  link_wait(sockfd, argv[optind + 1]);

  {
    int j;
    worker_local_init(&local, &synproxy, 0, 1);
    for (j = 0; j < 90*6; j++)
    {
      synproxy_hash_put_connected(
        &local, (10<<24)|(2*j+2), 12345, (11<<24)|(2*j+1), 54321,
        gettime64());
    }
  }

  for (i = 0; i < num_rx; i++)
  {
    rx_args[i].idx = i;
    rx_args[i].synproxy = &synproxy;
    rx_args[i].local = &local;
  }

  char pktdl[14] = {0x02,0,0,0,0,0x04, 0x02,0,0,0,0,0x01, 0, 0};
  char pktul[14] = {0x02,0,0,0,0,0x01, 0x02,0,0,0,0,0x04, 0, 0};

  if (strncmp(argv[optind+0], "vale", 4) == 0)
  {
    nm_my_inject(dlnmds[0], pktdl, sizeof(pktdl));
    ioctl(dlnmds[0]->fd, NIOCTXSYNC, NULL);
  }
  if (strncmp(argv[optind+1], "vale", 4) == 0)
  {
    nm_my_inject(ulnmds[0], pktul, sizeof(pktul));
    ioctl(ulnmds[0]->fd, NIOCTXSYNC, NULL);
  }

  timer.time64 = gettime64() + 32*1000*1000;
  timer.fn = revolve_secret;
  timer.userdata = &local.info;
  timer_linkheap_add(&local.timers, &timer);

  for (i = 0; i < num_rx; i++)
  {
    pthread_create(&rx[i], NULL, rx_func, &rx_args[i]);
  }
  int cpu = 0;
  if (num_rx <= sysconf(_SC_NPROCESSORS_ONLN))
  {
    for (i = 0; i < num_rx; i++)
    {
      CPU_ZERO(&cpuset);
      CPU_SET(cpu, &cpuset);
      cpu++;
      pthread_setaffinity_np(rx[i], sizeof(cpuset), &cpuset);
    }
  }
  sleep(1);
  set_promisc_mode(sockfd, argv[optind + 0], 1);
  set_promisc_mode(sockfd, argv[optind + 1], 1);
  if (getuid() == 0 && conf.gid != 0)
  {
    if (setgid(conf.gid) != 0)
    {
      printf("setgid failed\n");
    }
    log_log(LOG_LEVEL_NOTICE, "NMPROXY", "dropped group privileges");
  }
  if (getuid() == 0 && conf.uid != 0)
  {
    if (setuid(conf.uid) != 0)
    {
      printf("setuid failed\n");
    }
    log_log(LOG_LEVEL_NOTICE, "NMPROXY", "dropped user privileges");
  }
  if (pipe(pipefd) != 0)
  {
    abort();
  }
  ctrl_args.piperd = pipefd[0];
  ctrl_args.synproxy = &synproxy;
  if (   conf.mssmode == HASHMODE_COMMANDED
      || conf.sackmode == HASHMODE_COMMANDED
      || conf.wscalemode == HASHMODE_COMMANDED)
  {
    pthread_create(&ctrl, NULL, ctrl_func, &ctrl_args);
  }

  pthread_create(&sigthr, NULL, signal_handler_thr, NULL);
  log_log(LOG_LEVEL_NOTICE, "NMPROXY", "fully running");
  for (i = 0; i < num_rx; i++)
  {
    pthread_join(rx[i], NULL);
  }
  pthread_join(sigthr, NULL);
  if (write(pipefd[1], "X", 1) != 1)
  {
    printf("pipe write failed\n");
  }
  if (   conf.mssmode == HASHMODE_COMMANDED
      || conf.sackmode == HASHMODE_COMMANDED
      || conf.wscalemode == HASHMODE_COMMANDED)
  {
    pthread_join(ctrl, NULL);
  }

  for (i = 0; i < num_rx; i++)
  {
    nm_close(ulnmds[i]);
    nm_close(dlnmds[i]);
  }
  close(pipefd[0]);
  close(pipefd[1]);
  set_promisc_mode(sockfd, argv[optind + 0], 0);
  set_promisc_mode(sockfd, argv[optind + 1], 0);
  close(sockfd);

  worker_local_free(&local);
  synproxy_free(&synproxy);
  conf_free(&conf);
  log_close();

  return 0;
}
