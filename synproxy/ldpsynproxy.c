#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
#include "llalloc.h"
#include "synproxy.h"
#include "iphdr.h"
#include "ipcksum.h"
#include "packet.h"
#include "hashseed.h"
#include "yyutils.h"
#include "mypcapng.h"
#include "ldpports.h"
#include <unistd.h>
#include <sys/poll.h>
#include <sys/time.h>
#include "time64.h"
#include "databuf.h"
#include "read.h"
#include "ctrl.h"
#include "ldp.h"
#include "linkcommon.h"

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
  log_log(LOG_LEVEL_INFO, "LDPPROXY",
         "worker/%d %g MPPS %g Gbps ul %g MPPS %g Gbps dl"
         " %u conns synproxied %u conns not",
         ud->args->idx,
         ulpdiff/diff/1e6, 8*ulbdiff/diff/1e9,
         dlpdiff/diff/1e6, 8*dlbdiff/diff/1e9,
         ud->args->local->synproxied_connections,
         ud->args->local->direct_connections);
  worker_local_rdunlock(ud->args->local);
  ud->last_time64 = time64;
  ud->next_time64 += 2*1000*1000;
}

#define MAX_WORKERS 64
#define MAX_RX_TX 64
#define MAX_TX 64
#define MAX_RX 64

struct ldp_interface *dlintf, *ulintf;
struct ldp_in_queue *dlinq[MAX_RX_TX];
struct ldp_in_queue *ulinq[MAX_RX_TX];
struct ldp_out_queue *dloutq[MAX_RX_TX];
struct ldp_out_queue *uloutq[MAX_RX_TX];


int in = 0;
struct pcapng_out_ctx inctx;
int out = 0;
struct pcapng_out_ctx outctx;
int lan = 0;
struct pcapng_out_ctx lanctx;
int wan = 0;
struct pcapng_out_ctx wanctx;

#define POOL_SIZE 48
#define CACHE_SIZE 100
#define QUEUE_SIZE 512
#define BLOCK_SIZE 65664

struct tx_args {
  struct queue *txq;
  int idx;
};

static void *rx_func(void *userdata)
{
  struct rx_args *args = userdata;
  struct ll_alloc_st st;
  int i, j;
  struct port outport;
  struct ldpfunc2_userdata ud;
  struct timeval tv1;
  struct periodic_userdata periodic = {};
  struct allocif intf = {.ops = &ll_allocif_ops_st, .userdata = &st};

  gettimeofday(&tv1, NULL);

  ud.intf = &intf;
  ud.dloutq = dloutq[args->idx];
  ud.uloutq = uloutq[args->idx];
  ud.lan = lan;
  ud.wan = wan;
  ud.out = out;
  ud.lanctx = &lanctx;
  ud.wanctx = &wanctx;
  ud.outctx = &outctx;
  outport.portfunc = ldpfunc2;
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

    if (ldp_in_eof(dlinq[args->idx]) && ldp_in_eof(ulinq[args->idx]))
    {
      break;
    }

    pfds[0].fd = dlinq[args->idx]->fd;
    pfds[0].events = POLLIN;
    pfds[1].fd = ulinq[args->idx]->fd;
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
      ldp_out_txsync(dloutq[args->idx]);
      ldp_out_txsync(uloutq[args->idx]);
      if (pfds[0].fd >= 0 && pfds[1].fd >= 0)
      {
        poll(pfds, 2, timeout);
      }
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

    struct ldp_packet pkts[1000];
    struct ldp_packet pkts2[1000];
    int num;

    num = ldp_in_nextpkts(dlinq[args->idx], pkts, sizeof(pkts)/sizeof(*pkts));
    
    j = 0;
    for (i = 0; i < num; i++)
    {
      struct packet pktstruct;
      //pktstruct = ll_alloc_st(&st, packet_size(0));
      pktstruct.data = pkts[i].data;
      pktstruct.direction = PACKET_DIRECTION_UPLINK;
      pktstruct.sz = pkts[i].sz;

      if (uplink(args->synproxy, args->local, &pktstruct, &outport, time64, &st))
      {
        //ll_free_st(&st, pktstruct);
      }
      else
      {
        pkts2[j].data = pktstruct.data;
        pkts2[j].sz = pktstruct.sz;
        j++;
      }
      periodic.ulpkts++;
      periodic.ulbytes += pkts[i].sz;
      if (in)
      {
        if (pcapng_out_ctx_write(&inctx, pkts[i].data, pkts[i].sz, gettime64(), "out"))
        {
          log_log(LOG_LEVEL_CRIT, "LDPPROXY", "can't record packet");
          exit(1);
        }
      }
      if (lan)
      {
        if (pcapng_out_ctx_write(&lanctx, pkts[i].data, pkts[i].sz, gettime64(), "in"))
        {
          log_log(LOG_LEVEL_CRIT, "LDPPROXY", "can't record packet");
          exit(1);
        }
      }
    }
    ldp_out_inject(uloutq[args->idx], pkts2, j);

    num = ldp_in_nextpkts(ulinq[args->idx], pkts, sizeof(pkts)/sizeof(*pkts));
    
    j = 0;
    for (i = 0; i < num; i++)
    {
      struct packet pktstruct;
      //pktstruct = ll_alloc_st(&st, packet_size(0));
      pktstruct.data = pkts[i].data;
      pktstruct.direction = PACKET_DIRECTION_DOWNLINK;
      pktstruct.sz = pkts[i].sz;

      if (downlink(args->synproxy, args->local, &pktstruct, &outport, time64, &st))
      {
        //ll_free_st(&st, pktstruct);
      }
      else
      {
        pkts2[j].data = pktstruct.data;
        pkts2[j].sz = pktstruct.sz;
        j++;
      }
      periodic.dlpkts++;
      periodic.dlbytes += pkts[i].sz;
      if (in)
      {
        if (pcapng_out_ctx_write(&inctx, pkts[i].data, pkts[i].sz, gettime64(), "in"))
        {
          log_log(LOG_LEVEL_CRIT, "LDPPROXY", "can't record packet");
          exit(1);
        }
      }
      if (wan)
      {
        if (pcapng_out_ctx_write(&wanctx, pkts[i].data, pkts[i].sz, gettime64(), "in"))
        {
          log_log(LOG_LEVEL_CRIT, "LDPPROXY", "can't record packet");
          exit(1);
        }
      }
    }
    ldp_out_inject(dloutq[args->idx], pkts2, j);
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
  cpu_set_t cpuset;
  struct conf conf = CONF_INITIALIZER;
  int opt;
  char *inname = NULL;
  char *outname = NULL;
  char *lanname = NULL;
  char *wanname = NULL;
  int i;
  sigset_t set;
  int pipefd[2];
  int sockfd;
  struct timer_link timer;

  log_open("LDPSYNPROXY", LOG_LEVEL_DEBUG, LOG_LEVEL_INFO);

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
        log_log(LOG_LEVEL_CRIT, "LDPPROXY", "usage: %s [-i in.pcapng] [-o out.pcapng] [-l lan.pcapng] [-w wan.pcapng] vale0:1 vale1:1", argv[0]);
        exit(1);
        break;
    }
  }

  if (argc != optind + 2)
  {
    log_log(LOG_LEVEL_CRIT, "LDPPROXY", "usage: %s [-i in.pcapng] [-o out.pcapng] [-l lan.pcapng] [-w wan.pcapng] vale0:1 vale1:1", argv[0]);
    exit(1);
  }
  if (inname != NULL)
  {
    if (pcapng_out_ctx_init(&inctx, inname) != 0)
    {
      log_log(LOG_LEVEL_CRIT, "LDPPROXY", "can't open pcap output file");
      exit(1);
    }
    in = 1;
  }
  if (outname != NULL)
  {
    if (pcapng_out_ctx_init(&outctx, outname) != 0)
    {
      log_log(LOG_LEVEL_CRIT, "LDPPROXY", "can't open pcap output file");
      exit(1);
    }
    out = 1;
  }
  if (lanname != NULL)
  {
    if (pcapng_out_ctx_init(&lanctx, lanname) != 0)
    {
      log_log(LOG_LEVEL_CRIT, "LDPPROXY", "can't open pcap output file");
      exit(1);
    }
    lan = 1;
  }
  if (wanname != NULL)
  {
    if (pcapng_out_ctx_init(&wanctx, wanname) != 0)
    {
      log_log(LOG_LEVEL_CRIT, "LDPPROXY", "can't open pcap output file");
      exit(1);
    }
    wan = 1;
  }

  int num_rx;
  int max;
  num_rx = conf.threadcount;
  if (num_rx <= 0 || num_rx > MAX_RX)
  {
    log_log(LOG_LEVEL_CRIT, "LDPPROXY", "too many threads: %d", num_rx);
    exit(1);
  }
  max = num_rx;

  dlintf = ldp_interface_open(argv[optind+0], max, max);
  if (dlintf == NULL)
  {
    log_log(LOG_LEVEL_CRIT, "LDPPROXY", "cannot open %s", argv[optind+0]);
    exit(1);
  }
  ulintf = ldp_interface_open(argv[optind+1], max, max);
  if (ulintf == NULL)
  {
    log_log(LOG_LEVEL_CRIT, "LDPPROXY", "cannot open %s", argv[optind+1]);
    exit(1);
  }
  for (i = 0; i < max; i++)
  {
    dlinq[i] = dlintf->inq[i];
    ulinq[i] = ulintf->inq[i];
    dloutq[i] = dlintf->outq[i];
    uloutq[i] = ulintf->outq[i];
  }
  
  if (ldp_interface_link_wait(dlintf) != 0)
  {
    log_log(LOG_LEVEL_CRIT, "LDPPROXY", "link %s not up", argv[optind + 0]);
    exit(1);
  }
  if (ldp_interface_link_wait(ulintf) != 0)
  {
    log_log(LOG_LEVEL_CRIT, "LDPPROXY", "link %s not up", argv[optind + 1]);
    exit(1);
  }

  worker_local_init(&local, &synproxy, 0, 1);
  if (conf.test_connections)
  {
    int j;
    for (j = 0; j < 90*6; j++)
    {
      uint32_t src, dst;
      src = htonl((10<<24)|(2*j+2));
      dst = htonl((11<<24)|(2*j+1));
      synproxy_hash_put_connected(
        &local, 4, &src, 12345, &dst, 54321,
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
    struct ldp_packet pkt = { .data = pktdl, .sz = sizeof(pktdl) };
    ldp_out_inject(dloutq[0], &pkt, 1);
    ldp_out_txsync(dloutq[0]);
  }
  if (strncmp(argv[optind+1], "vale", 4) == 0)
  {
    struct ldp_packet pkt = { .data = pktul, .sz = sizeof(pktul) };
    ldp_out_inject(uloutq[0], &pkt, 1);
    ldp_out_txsync(uloutq[0]);
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
  ldp_interface_set_promisc_mode(ulintf, 1);
  ldp_interface_set_promisc_mode(dlintf, 1);
  if (getuid() == 0 && conf.gid != 0)
  {
    if (setgid(conf.gid) != 0)
    {
      log_log(LOG_LEVEL_WARNING, "LDPPROXY", "setgid failed");
    }
    log_log(LOG_LEVEL_NOTICE, "LDPPROXY", "dropped group privileges");
  }
  if (getuid() == 0 && conf.uid != 0)
  {
    if (setuid(conf.uid) != 0)
    {
      log_log(LOG_LEVEL_WARNING, "LDPPROXY", "setuid failed");
    }
    log_log(LOG_LEVEL_NOTICE, "LDPPROXY", "dropped user privileges");
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
  log_log(LOG_LEVEL_NOTICE, "LDPPROXY", "fully running");
  for (i = 0; i < num_rx; i++)
  {
    pthread_join(rx[i], NULL);
  }
  //pthread_join(sigthr, NULL);
  if (write(pipefd[1], "X", 1) != 1)
  {
    log_log(LOG_LEVEL_WARNING, "LDPPROXY", "pipe write failed");
  }
  if (   conf.mssmode == HASHMODE_COMMANDED
      || conf.sackmode == HASHMODE_COMMANDED
      || conf.wscalemode == HASHMODE_COMMANDED)
  {
    pthread_join(ctrl, NULL);
  }

  ldp_interface_set_promisc_mode(ulintf, 0);
  ldp_interface_set_promisc_mode(dlintf, 0);
  ldp_interface_close(ulintf);
  ldp_interface_close(dlintf);
  close(pipefd[0]);
  close(pipefd[1]);
  close(sockfd);

  timer_linkheap_remove(&local.timers, &timer);
  worker_local_free(&local);
  synproxy_free(&synproxy);
  conf_free(&conf);
  log_log(LOG_LEVEL_NOTICE, "LDPPROXY", "closing log");
  log_close();

  return 0;
}
