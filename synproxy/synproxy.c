#include "synproxy.h"
#include "ipcksum.h"
#include "branchpredict.h"
#include <sys/time.h>

#define MAX_FRAG 65535

static inline uint64_t gettime64(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec*1000UL*1000UL + tv.tv_usec;
}

static inline int rst_is_valid(uint32_t rst_seq, uint32_t ref_seq)
{
  int32_t diff = rst_seq - ref_seq;
  if (diff >= 0)
  {
    if (diff > 512*1024*1024)
    {
      log_log(LOG_LEVEL_EMERG, "WORKER",
        "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u", rst_seq, ref_seq);
    }
    return diff <= 3;
  }
  if (diff < -512*1024*1024)
  {
    log_log(LOG_LEVEL_EMERG, "WORKER",
      "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u", rst_seq, ref_seq);
  }
  return diff >= -3;
}

static inline int resend_request_is_valid(uint32_t seq, uint32_t ref_seq)
{
  int32_t diff = seq - ref_seq;
  if (diff >= 0)
  {
    if (diff > 512*1024*1024)
    {
      log_log(LOG_LEVEL_EMERG, "WORKER",
        "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u", seq, ref_seq);
    }
    return diff <= 3;
  }
  if (diff < -512*1024*1024)
  {
    log_log(LOG_LEVEL_EMERG, "WORKER",
      "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u", seq, ref_seq);
  }
  return diff >= -3;
}

// caller must not have worker_local lock
// caller must have bucket lock
static void synproxy_expiry_fn(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud)
{
  struct worker_local *local = ud;
  struct synproxy_hash_entry *e;
  e = CONTAINER_OF(timer, struct synproxy_hash_entry, timer);
  hash_table_delete_already_bucket_locked(&local->hash, &e->node);
  worker_local_wrlock(local);
  if (e->was_synproxied)
  {
    local->synproxied_connections--;
  }
  else
  {
    local->direct_connections--;
  }
  if (e->flag_state == FLAG_STATE_DOWNLINK_HALF_OPEN)
  {
    linked_list_delete(&e->state_data.downlink_half_open.listnode);
    local->half_open_connections--;
  }
  worker_local_wrunlock(local);
  free(e);
}

static inline int seq_cmp(uint32_t x, uint32_t y)
{
  int32_t result = x-y;
  if (result > 512*1024*1024 || result < -512*1024*1024)
  {
    log_log(LOG_LEVEL_EMERG, "WORKER",
      "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u", x, y);
  }
  if (result > 0)
  {
    return 1;
  }
  if (result < 0)
  {
    return -1;
  }
  return result;
}

static inline uint32_t between(uint32_t a, uint32_t x, uint32_t b)
{
  if (b - a > 512*1024*1024)
  {
    log_log(LOG_LEVEL_EMERG, "WORKER",
      "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u %u", a, x, b);
  }
  if (b >= a)
  {
    return x >= a && x < b;
  }
  else
  {
    return x >= a || x < b;
  }
}

struct synproxy_hash_entry *synproxy_hash_put(
  struct worker_local *local,
  uint32_t local_ip,
  uint16_t local_port,
  uint32_t remote_ip,
  uint16_t remote_port,
  uint8_t was_synproxied,
  uint64_t time64)
{
  struct synproxy_hash_entry *e;
  struct synproxy_hash_ctx ctx;
  ctx.locked = 1;
  if (synproxy_hash_get(local, local_ip, local_port, remote_ip, remote_port, &ctx))
  {
    return NULL;
  }
  e = malloc(sizeof(*e));
  if (e == NULL)
  {
    return NULL;
  }
  memset(e, 0, sizeof(*e));
  e->local_ip = local_ip;
  e->local_port = local_port;
  e->remote_ip = remote_ip;
  e->remote_port = remote_port;
  e->was_synproxied = was_synproxied;
  e->timer.time64 = time64 + 86400ULL*1000ULL*1000ULL;
  e->timer.fn = synproxy_expiry_fn;
  e->timer.userdata = local;
  worker_local_wrlock(local);
#if 0
  timer_linkheap_add(&local->timers, &e->timer);
#endif
  hash_table_add_nogrow_already_bucket_locked(
    &local->hash, &e->node, synproxy_hash(e));
  if (was_synproxied)
  {
    local->synproxied_connections++;
  }
  else
  {
    local->direct_connections++;
  }
  worker_local_wrunlock(local);
  return e;
}


uint32_t synproxy_hash_fn(struct hash_list_node *node, void *userdata)
{
  return synproxy_hash(CONTAINER_OF(node, struct synproxy_hash_entry, node));
}

// Caller must hold worker_local mutex lock
static void send_synack(
  void *orig, struct worker_local *local, struct synproxy *synproxy,
  struct port *port, struct ll_alloc_st *st, uint64_t time64)
{
  char synack[14+20+20+12+12] = {0};
  void *ip, *origip;
  void *tcp, *origtcp;
  unsigned char *tcpopts;
  struct packet *pktstruct;
  uint32_t syn_cookie;
  struct tcp_information tcpinfo;
  struct sack_hash_data ipentry, ipportentry;
  uint16_t own_mss;
  uint8_t own_sack;
  uint32_t ts;
  uint32_t local_ip, remote_ip;
  uint16_t local_port, remote_port;

  origip = ether_payload(orig);
  origtcp = ip_payload(origip);
  tcp_parse_options(origtcp, &tcpinfo);
  if (!tcpinfo.options_valid)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "options in TCP SYN invalid");
    return;
  }
  syn_cookie = form_cookie(
    &local->info, synproxy, ip_dst(origip), ip_src(origip),
    tcp_dst_port(origtcp), tcp_src_port(origtcp),
    tcpinfo.mss, tcpinfo.wscale, tcpinfo.sack_permitted);
  ts = form_timestamp(
    &local->info, synproxy, ip_dst(origip), ip_src(origip),
    tcp_dst_port(origtcp), tcp_src_port(origtcp),
    tcpinfo.mss, tcpinfo.wscale);

  if (   synproxy->conf->mssmode == HASHMODE_HASHIPPORT
      || synproxy->conf->sackmode == HASHMODE_HASHIPPORT)
  {
    if (sack_ip_port_hash_get(&synproxy->autolearn, ip_dst(origip), tcp_dst_port(origtcp), &ipportentry) == 0)
    {
      ipportentry.sack_supported = synproxy->conf->own_sack;
      ipportentry.mss = synproxy->conf->own_mss;
    }
  }
  if (   synproxy->conf->mssmode == HASHMODE_HASHIP
      || synproxy->conf->sackmode == HASHMODE_HASHIP)
  {
    if (sack_ip_port_hash_get(&synproxy->autolearn, ip_dst(origip), 0, &ipentry) == 0)
    {
      ipentry.sack_supported = synproxy->conf->own_sack;
      ipentry.mss = synproxy->conf->own_mss;
    }
  }
  if (synproxy->conf->mssmode == HASHMODE_HASHIPPORT)
  {
    own_mss = ipportentry.mss;
  }
  else if (synproxy->conf->mssmode == HASHMODE_HASHIP)
  {
    own_mss = ipentry.mss;
  }
  else
  {
    own_mss = synproxy->conf->own_mss;
  }
  if (synproxy->conf->sackmode == HASHMODE_HASHIPPORT)
  {
    own_sack = ipportentry.sack_supported;
  }
  else if (synproxy->conf->sackmode == HASHMODE_HASHIP)
  {
    own_sack = ipentry.sack_supported;
  }
  else
  {
    own_sack = synproxy->conf->own_sack;
  }

  local_ip = ip_dst(origip);
  remote_ip = ip_src(origip);
  local_port = tcp_dst_port(origtcp);
  remote_port = tcp_src_port(origtcp);

  memcpy(ether_src(synack), ether_dst(orig), 6);
  memcpy(ether_dst(synack), ether_src(orig), 6);
  ether_set_type(synack, 0x0800);
  ip = ether_payload(synack);
  ip_set_version(ip, 4);
  ip_set_hdr_len(ip, 20);
  ip_set_total_len(ip, sizeof(synack) - 14);
  ip_set_dont_frag(ip, 1);
  ip_set_id(ip, 0); // XXX
  ip_set_ttl(ip, 64);
  ip_set_proto(ip, 6);
  ip_set_src(ip, ip_dst(origip));
  ip_set_dst(ip, ip_src(origip));
  ip_set_hdr_cksum_calc(ip, 20);
  tcp = ip_payload(ip);
  tcp_set_src_port(tcp, tcp_dst_port(origtcp));
  tcp_set_dst_port(tcp, tcp_src_port(origtcp));
  tcp_set_syn_on(tcp);
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, sizeof(synack) - 14 - 20);
  tcp_set_seq_number(tcp, syn_cookie);
  tcp_set_ack_number(tcp, tcp_seq_number(origtcp) + 1);
  tcp_set_window(tcp, 0);
  tcpopts = &((unsigned char*)tcp)[20];
  // WS, kind 3 len 3
  // NOP, kind 1 len 1
  // MSS, kind 2 len 4
  // SACK permitted, kind 4 len 2
  // endlist, kind 0 len 1
  // pad, kind 0 len 1
  tcpopts[0] = 3;
  tcpopts[1] = 3;
  tcpopts[2] = synproxy->conf->own_wscale;
  tcpopts[3] = 1;
  tcpopts[4] = 2;
  tcpopts[5] = 4;
  hdr_set16n(&tcpopts[6], own_mss);
  if (own_sack)
  {
    tcpopts[8] = 4;
    tcpopts[9] = 2;
    if (tcpinfo.options_valid && tcpinfo.ts_present)
    {
      tcpopts[10] = 1;
      tcpopts[11] = 1;
    }
    else
    {
      tcpopts[10] = 0;
      tcpopts[11] = 0;
    }
  }
  else if (tcpinfo.options_valid && tcpinfo.ts_present)
  {
    tcpopts[8] = 1;
    tcpopts[9] = 1;
    tcpopts[10] = 1;
    tcpopts[11] = 1;
  }
  else
  {
    tcpopts[8] = 0;
    tcpopts[9] = 0;
    tcpopts[10] = 0;
    tcpopts[11] = 0;
  }
  if (tcpinfo.options_valid && tcpinfo.ts_present)
  {
    tcpopts[12] = 1;
    tcpopts[13] = 1;
    tcpopts[14] = 8;
    tcpopts[15] = 10;
    hdr_set32n(&tcpopts[16], ts); // ts
    hdr_set32n(&tcpopts[20], tcpinfo.ts); // tsecho
  }
  else
  {
    memset(&tcpopts[12], 0, 12);
  }
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(synack) - 14 - 20);
  pktstruct = ll_alloc_st(st, packet_size(sizeof(synack)));
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sizeof(synack);
  memcpy(packet_data(pktstruct), synack, sizeof(synack));
  port->portfunc(pktstruct, port->userdata);

  if (synproxy->conf->halfopen_cache_max)
  {
    struct synproxy_hash_entry *e;
    struct synproxy_hash_ctx ctx;
    ctx.locked = 0;
    if (synproxy_hash_get(local, local_ip, local_port, remote_ip, remote_port,
                          &ctx))
    {
      synproxy_hash_unlock(local, &ctx);
      return; // duplicate SYN
    }
    worker_local_wrlock(local);
    if (local->half_open_connections >= synproxy->conf->halfopen_cache_max)
    {
      struct linked_list_node *node = local->half_open_list.node.next;
      uint32_t hashval;
      e = CONTAINER_OF(
            node, struct synproxy_hash_entry,
            state_data.downlink_half_open.listnode);
      hashval = synproxy_hash(e);
      linked_list_delete(&e->state_data.downlink_half_open.listnode);
#if 0
      timer_heap_remove(&local->timers, &e->timer);
#endif
      if (ctx.hashval == hashval)
      {
        hash_table_delete_already_bucket_locked(&local->hash, &e->node);
      }
      else
      {
        // Prevent lock order reversal
        worker_local_wrunlock(local);
        hash_table_delete(&local->hash, &e->node, synproxy_hash(e));
        worker_local_wrlock(local);
      }
    }
    else
    {
      local->half_open_connections++;
      local->synproxied_connections++;
      e = malloc(sizeof(*e));
      if (e == NULL)
      {
        worker_local_wrunlock(local);
        synproxy_hash_unlock(local, &ctx);
        log_log(LOG_LEVEL_ERR, "WORKER", "out of memory");
        return;
      }
    }
    memset(e, 0, sizeof(*e));
    e->local_ip = local_ip;
    e->local_port = local_port;
    e->remote_ip = remote_ip;
    e->remote_port = remote_port;
    e->was_synproxied = 1;
    e->timer.time64 = time64 + 64ULL*1000ULL*1000ULL;
    e->timer.fn = synproxy_expiry_fn;
    e->timer.userdata = local;
#if 0
    if (timer_heap_add_nogrow(&local->timers, &e->timer) != 0)
    {
      free(e);
      log_log(LOG_LEVEL_ERR, "WORKER", "out of timer heap space");
      worker_local_wrunlock(local);
      synproxy_hash_unlock(local, &ctx);
      return;
    }
#endif
    hash_table_add_nogrow(&local->hash, &e->node, synproxy_hash(e));
    linked_list_add_tail(
      &e->state_data.downlink_half_open.listnode, &local->half_open_list);
    e->flag_state = FLAG_STATE_DOWNLINK_HALF_OPEN;
    e->state_data.downlink_half_open.wscale = tcpinfo.wscale;
    e->state_data.downlink_half_open.mss = tcpinfo.mss;
    e->state_data.downlink_half_open.sack_permitted = tcpinfo.sack_permitted;
    e->state_data.downlink_half_open.remote_isn = tcp_seq_number(origtcp);
    e->state_data.downlink_half_open.local_isn = syn_cookie;

    worker_local_wrunlock(local);
    synproxy_hash_unlock(local, &ctx);
  }
}

static void send_or_resend_syn(
  void *orig, struct worker_local *local, struct port *port,
  struct ll_alloc_st *st,
  struct synproxy_hash_entry *entry)
{
  char syn[14+20+20+12+12] = {0};
  void *ip, *origip;
  void *tcp, *origtcp;
  unsigned char *tcpopts;
  struct packet *pktstruct;

  origip = ether_payload(orig);
  origtcp = ip_payload(origip);

  memcpy(ether_src(syn), ether_src(orig), 6);
  memcpy(ether_dst(syn), ether_dst(orig), 6);
  ether_set_type(syn, 0x0800);
  ip = ether_payload(syn);
  ip_set_version(ip, 4);
  ip_set_hdr_len(ip, 20);
  ip_set_total_len(ip, sizeof(syn) - 14);
  ip_set_dont_frag(ip, 1);
  ip_set_id(ip, 0); // XXX
  ip_set_ttl(ip, 64);
  ip_set_proto(ip, 6);
  ip_set_src(ip, ip_src(origip));
  ip_set_dst(ip, ip_dst(origip));
  ip_set_hdr_cksum_calc(ip, 20);
  tcp = ip_payload(ip);
  tcp_set_src_port(tcp, tcp_src_port(origtcp));
  tcp_set_dst_port(tcp, tcp_dst_port(origtcp));
  tcp_set_syn_on(tcp);
  tcp_set_data_offset(tcp, sizeof(syn) - 14 - 20);
  tcp_set_seq_number(tcp, entry->state_data.downlink_syn_sent.remote_isn);
  tcp_set_ack_number(tcp, 0);
  tcp_set_window(tcp, tcp_window(origtcp));
  tcpopts = &((unsigned char*)tcp)[20];
  // WS, kind 3 len 3
  // NOP, kind 1 len 1
  // MSS, kind 2 len 4
  // SACK permitted, kind 4 len 2
  // endlist, kind 0 len 1
  // pad, kind 0 len 1
  tcpopts[0] = 3;
  tcpopts[1] = 3;
  tcpopts[2] = entry->wan_wscale;
  tcpopts[3] = 1;
  tcpopts[4] = 2;
  tcpopts[5] = 4;
  hdr_set16n(&tcpopts[6], entry->state_data.downlink_syn_sent.mss);
  if (entry->state_data.downlink_syn_sent.sack_permitted)
  {
    tcpopts[8] = 4;
    tcpopts[9] = 2;
    if (entry->state_data.downlink_syn_sent.timestamp_present)
    {
      tcpopts[10] = 1;
      tcpopts[11] = 1;
    }
    else
    {
      tcpopts[10] = 0;
      tcpopts[11] = 0;
    }
  }
  else if (entry->state_data.downlink_syn_sent.timestamp_present)
  {
    tcpopts[8] = 1;
    tcpopts[9] = 1;
    tcpopts[10] = 1;
    tcpopts[11] = 1;
  }
  else
  {
    tcpopts[8] = 0;
    tcpopts[9] = 0;
    tcpopts[10] = 0;
    tcpopts[11] = 0;
  }
  if (entry->state_data.downlink_syn_sent.timestamp_present)
  {
    tcpopts[12] = 1;
    tcpopts[13] = 1;
    tcpopts[14] = 8;
    tcpopts[15] = 10;
    hdr_set32n(&tcpopts[16],
      entry->state_data.downlink_syn_sent.remote_timestamp);
    hdr_set32n(&tcpopts[20], 0); // tsecho
  }
  else
  {
    memset(&tcpopts[12], 0, 12);
  }
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(syn) - 14 - 20);
  pktstruct = ll_alloc_st(st, packet_size(sizeof(syn)));
  pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
  pktstruct->sz = sizeof(syn);
  memcpy(packet_data(pktstruct), syn, sizeof(syn));
  port->portfunc(pktstruct, port->userdata);
}

static void resend_syn(
  void *orig, struct worker_local *local, struct port *port,
  struct ll_alloc_st *st,
  struct synproxy_hash_entry *entry,
  uint64_t time64)
{
  void *origip;
  void *origtcp;

  if (entry->flag_state != FLAG_STATE_DOWNLINK_SYN_SENT)
  {
    abort();
  }

  origip = ether_payload(orig);
  origtcp = ip_payload(origip);

  if (seq_cmp(tcp_seq_number(origtcp), entry->wan_sent) >= 0)
  {
    entry->wan_sent = tcp_seq_number(origtcp);
  }
  if (seq_cmp(tcp_ack_number(origtcp), entry->wan_acked) >= 0)
  {
    entry->wan_acked = tcp_ack_number(origtcp);
  }
  if (seq_cmp(
    tcp_ack_number(origtcp) + (tcp_window(origtcp) << entry->wan_wscale),
    entry->wan_max) >= 0)
  {
    entry->wan_max =
      tcp_ack_number(origtcp) + (tcp_window(origtcp) << entry->wan_wscale);
  }

  if (tcp_window(origtcp) > entry->wan_max_window_unscaled)
  {
    entry->wan_max_window_unscaled = tcp_window(origtcp);
  }
  entry->timer.time64 = time64 + 120ULL*1000ULL*1000ULL;
#if 0
  timer_heap_modify(&local->timers, &entry->timer);
#endif

  send_or_resend_syn(orig, local, port, st, entry);
}

static void send_syn(
  void *orig, struct worker_local *local, struct port *port,
  struct ll_alloc_st *st,
  uint16_t mss, uint8_t wscale, uint8_t sack_permitted,
  struct synproxy_hash_entry *entry,
  uint64_t time64)
{
  void *origip;
  void *origtcp;
  struct tcp_information info;

  origip = ether_payload(orig);
  origtcp = ip_payload(origip);
  tcp_parse_options(origtcp, &info);

  if (entry == NULL)
  {
    entry = synproxy_hash_put(
      local, ip_dst(origip), tcp_dst_port(origtcp),
      ip_src(origip), tcp_src_port(origtcp),
      1, time64);
    if (entry == NULL)
    {
      log_log(LOG_LEVEL_ERR, "WORKER", "not enough memory or already existing");
      return;
    }
  }

  entry->state_data.downlink_syn_sent.mss = mss;
  entry->state_data.downlink_syn_sent.sack_permitted = sack_permitted;
  entry->state_data.downlink_syn_sent.timestamp_present = info.ts_present;
  if (info.ts_present)
  {
    entry->state_data.downlink_syn_sent.local_timestamp = info.tsecho;
    entry->state_data.downlink_syn_sent.remote_timestamp = info.ts;
  }

  entry->wan_wscale = wscale;
  entry->wan_sent = tcp_seq_number(origtcp);
  entry->wan_acked = tcp_ack_number(origtcp);
  entry->wan_max =
    tcp_ack_number(origtcp) + (tcp_window(origtcp) << entry->wan_wscale);

  entry->wan_max_window_unscaled = tcp_window(origtcp);
  if (entry->wan_max_window_unscaled == 0)
  {
    entry->wan_max_window_unscaled = 1;
  }
  entry->state_data.downlink_syn_sent.local_isn = tcp_ack_number(origtcp) - 1;
  entry->state_data.downlink_syn_sent.remote_isn = tcp_seq_number(origtcp) - 1;
  entry->flag_state = FLAG_STATE_DOWNLINK_SYN_SENT;
  entry->timer.time64 = time64 + 120ULL*1000ULL*1000ULL;
#if 0
  timer_heap_modify(&local->timers, &entry->timer);
#endif

  send_or_resend_syn(orig, local, port, st, entry);
}

static void send_ack_only(
  void *orig, struct synproxy_hash_entry *entry, struct port *port,
  struct ll_alloc_st *st)
{
  char ack[14+20+20+12] = {0};
  void *ip, *origip;
  void *tcp, *origtcp;
  struct packet *pktstruct;
  struct tcp_information tcpinfo;
  unsigned char *tcpopts;

  origip = ether_payload(orig);
  origtcp = ip_payload(origip);
  tcp_parse_options(origtcp, &tcpinfo);

  memcpy(ether_src(ack), ether_dst(orig), 6);
  memcpy(ether_dst(ack), ether_src(orig), 6);
  ether_set_type(ack, 0x0800);
  ip = ether_payload(ack);
  ip_set_version(ip, 4);
  ip_set_hdr_len(ip, 20);
  ip_set_total_len(ip, sizeof(ack) - 14);
  ip_set_dont_frag(ip, 1);
  ip_set_id(ip, 0); // XXX
  ip_set_ttl(ip, 64);
  ip_set_proto(ip, 6);
  ip_set_src(ip, ip_dst(origip));
  ip_set_dst(ip, ip_src(origip));
  ip_set_hdr_cksum_calc(ip, 20);
  tcp = ip_payload(ip);
  tcp_set_src_port(tcp, tcp_dst_port(origtcp));
  tcp_set_dst_port(tcp, tcp_src_port(origtcp));
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, sizeof(ack) - 14 - 20);
  tcp_set_seq_number(tcp, tcp_ack_number(origtcp));
  tcp_set_ack_number(tcp, tcp_seq_number(origtcp)+1);
  tcp_set_window(tcp, entry->wan_max_window_unscaled);
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(ack) - 14 - 20);

  tcpopts = &((unsigned char*)tcp)[20];

  if (tcpinfo.options_valid && tcpinfo.ts_present)
  {
    tcpopts[0] = 1;
    tcpopts[1] = 1;
    tcpopts[2] = 8;
    tcpopts[3] = 10;
    hdr_set32n(&tcpopts[4], tcpinfo.tsecho);
    hdr_set32n(&tcpopts[8], tcpinfo.ts);
  }
  else
  {
    memset(&tcpopts[0], 0, 12);
  }

  pktstruct = ll_alloc_st(st, packet_size(sizeof(ack)));
  pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
  pktstruct->sz = sizeof(ack);
  memcpy(packet_data(pktstruct), ack, sizeof(ack));
  port->portfunc(pktstruct, port->userdata);
}

static void send_ack_and_window_update(
  void *orig, struct synproxy_hash_entry *entry, struct port *port,
  struct ll_alloc_st *st)
{
  char windowupdate[14+20+20+12] = {0};
  void *ip, *origip;
  void *tcp, *origtcp;
  struct packet *pktstruct;
  struct tcp_information tcpinfo;
  unsigned char *tcpopts;

  origip = ether_payload(orig);
  origtcp = ip_payload(origip);
  tcp_parse_options(origtcp, &tcpinfo);

  send_ack_only(orig, entry, port, st); // XXX send_ack_only reparses opts

  memcpy(ether_src(windowupdate), ether_src(orig), 6);
  memcpy(ether_dst(windowupdate), ether_dst(orig), 6);
  ether_set_type(windowupdate, 0x0800);
  ip = ether_payload(windowupdate);
  ip_set_version(ip, 4);
  ip_set_hdr_len(ip, 20);
  ip_set_total_len(ip, sizeof(windowupdate) - 14);
  ip_set_dont_frag(ip, 1);
  ip_set_id(ip, 0); // XXX
  ip_set_ttl(ip, 64);
  ip_set_proto(ip, 6);
  ip_set_src(ip, ip_src(origip));
  ip_set_dst(ip, ip_dst(origip));
  ip_set_hdr_cksum_calc(ip, 20);
  tcp = ip_payload(ip);
  tcp_set_src_port(tcp, tcp_src_port(origtcp));
  tcp_set_dst_port(tcp, tcp_dst_port(origtcp));
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, sizeof(windowupdate)-14-20);
#if 0
  tcp_set_seq_number(tcp, tcp_ack_number(origtcp)); // FIXME looks suspicious
  tcp_set_ack_number(tcp, tcp_seq_number(origtcp)+1); // FIXME the same
#endif
  tcp_set_seq_number(tcp, tcp_seq_number(origtcp)+1+entry->seqoffset);
  tcp_set_ack_number(tcp, tcp_ack_number(origtcp));
  if (entry->wscalediff >= 0)
  {
    tcp_set_window(tcp, tcp_window(origtcp)>>entry->wscalediff);
  }
  else
  {
    uint64_t win64 = tcp_window(origtcp)<<entry->wscalediff;
    if (win64 > 0xFFFF)
    {
      win64 = 0xFFFF;
    }
    tcp_set_window(tcp, win64);
  }
  tcpopts = &((unsigned char*)tcp)[20];
  if (tcpinfo.options_valid && tcpinfo.ts_present)
  {
    tcpopts[0] = 1;
    tcpopts[1] = 1;
    tcpopts[2] = 8;
    tcpopts[3] = 10;
    hdr_set32n(&tcpopts[4], tcpinfo.ts+entry->tsoffset);
    hdr_set32n(&tcpopts[8], tcpinfo.tsecho);
  }
  else
  {
    memset(&tcpopts[0], 0, 12);
  }
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(windowupdate) - 14 - 20);

  pktstruct = ll_alloc_st(st, packet_size(sizeof(windowupdate)));
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sizeof(windowupdate);
  memcpy(packet_data(pktstruct), windowupdate, sizeof(windowupdate));
  port->portfunc(pktstruct, port->userdata);
}

int downlink(
  struct synproxy *synproxy, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64, struct ll_alloc_st *st)
{
  void *ether = packet_data(pkt);
  void *ip;
  void *ippay;
  size_t ether_len = pkt->sz;
  size_t ip_len;
  uint16_t ihl;
  uint32_t remote_ip;
  uint16_t remote_port;
  uint8_t protocol;
  uint32_t lan_ip;
  uint16_t lan_port;
  uint16_t tcp_len;
  struct synproxy_hash_entry *entry;
  struct synproxy_hash_ctx ctx;
  uint32_t first_seq;
  uint32_t last_seq;
  int32_t data_len;
  int todelete = 0;
  uint32_t wan_min;
  struct sack_ts_headers hdrs;

  if (ether_len < ETHER_HDR_LEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full Ether hdr");
    return 1;
  }
  if (ether_type(ether) != ETHER_TYPE_IP)
  {
    port->portfunc(pkt, port->userdata);
    return 0;
  }
  ip = ether_payload(ether);
  ip_len = ether_len - ETHER_HDR_LEN;
  if (ip_len < IP_HDR_MINLEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full IP hdr 1");
    return 1;
  }
  if (ip_version(ip) != 4)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "IP version mismatch");
    return 1;
  }
  ihl = ip_hdr_len(ip);
  if (ip_len < ihl)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full IP hdr 2");
    return 1;
  }
  if (ip_proto(ip) != 6)
  {
    port->portfunc(pkt, port->userdata);
    return 0;
  }
  if (ip_frag_off(ip) >= 60)
  {
    port->portfunc(pkt, port->userdata);
    return 0;
  }
  else if (ip_frag_off(ip) != 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "fragment has partial header");
    return 1;
  }
  if (ip_len < ip_total_len(ip))
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full IP data");
    return 1;
  }
  
  protocol = ip_proto(ip);
  ippay = ip_payload(ip);
  lan_ip = ip_dst(ip);
  remote_ip = ip_src(ip);
  if (protocol == 6)
  {
    tcp_len = ip_total_len(ip) - ihl;
    if (tcp_len < 20)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full TCP hdr");
      return 1;
    }
    if (tcp_data_offset(ippay) > tcp_len)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full TCP opts");
      return 1;
    }
    lan_port = tcp_dst_port(ippay);
    remote_port = tcp_src_port(ippay);
  }
  else
  {
    abort();
  }
  if (unlikely(tcp_syn(ippay)))
  {
    if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
      return 1;
    }
    if (tcp_cksum_calc(ip, ip_hdr_len(ip), ippay, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
      return 1;
    }
    if (tcp_fin(ippay) || tcp_rst(ippay))
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "SYN packet contains FIN or RST");
      return 1;
    }
    if (!tcp_ack(ippay))
    {
      worker_local_wrlock(local);
      if (!ip_permitted(
        ip_src(ip), synproxy->conf->ratehash.network_prefix, &local->ratelimit))
      {
        worker_local_wrunlock(local);
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "IP ratelimited");
        return 1;
      }
      send_synack(ether, local, synproxy, port, st, time64);
      worker_local_wrunlock(local);
      return 1;
    }
    else
    {
      struct tcp_information tcpinfo;
      ctx.locked = 0;
      entry = synproxy_hash_get(
        local, lan_ip, lan_port, remote_ip, remote_port, &ctx);
      if (entry == NULL)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "SA/SA but entry nonexistent");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      if (entry->flag_state == FLAG_STATE_UPLINK_SYN_RCVD &&
          entry->state_data.uplink_syn_rcvd.isn == tcp_seq_number(ippay))
      {
        // retransmit of SYN+ACK
        if (synproxy->conf->mss_clamp_enabled)
        {
          uint16_t mss;
          tcp_parse_options(ippay, &tcpinfo);
          if (tcpinfo.options_valid)
          {
            mss = tcpinfo.mss;
            if (mss > synproxy->conf->mss_clamp)
            {
              mss = synproxy->conf->mss_clamp;
            }
            if (tcpinfo.mssoff)
            {
              tcp_set_mss_cksum_update(ippay, &tcpinfo, mss);
            }
          }
        }
        synproxy_hash_unlock(local, &ctx);
        port->portfunc(pkt, port->userdata);
        return 0;
      }
      if (entry->flag_state == FLAG_STATE_ESTABLISHED &&
          entry->wan_sent-1 == tcp_seq_number(ippay))
      {
        // retransmit of SYN+ACK
        // FIXME should store the ISN for a longer duration of time...
        if (synproxy->conf->mss_clamp_enabled)
        {
          uint16_t mss;
          tcp_parse_options(ippay, &tcpinfo);
          if (tcpinfo.options_valid)
          {
            mss = tcpinfo.mss;
            if (mss > synproxy->conf->mss_clamp)
            {
              mss = synproxy->conf->mss_clamp;
            }
            if (tcpinfo.mssoff)
            {
              tcp_set_mss_cksum_update(ippay, &tcpinfo, mss);
            }
          }
        }
        synproxy_hash_unlock(local, &ctx);
        port->portfunc(pkt, port->userdata);
        return 0;
      }
      if (entry->flag_state != FLAG_STATE_UPLINK_SYN_SENT)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "SA/SA, entry != UL_SYN_SENT");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      if (tcp_ack_number(ippay) != entry->state_data.uplink_syn_sent.isn + 1)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "SA/SA, invalid ACK num");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      tcp_parse_options(ippay, &tcpinfo);
      if (!tcpinfo.options_valid)
      {
        tcpinfo.wscale = 0;
        tcpinfo.mssoff = 0;
        tcpinfo.mss = 1460;
      }
      entry->wan_wscale = tcpinfo.wscale;
      entry->wan_max_window_unscaled = tcp_window(ippay);
      if (entry->wan_max_window_unscaled == 0)
      {
        entry->wan_max_window_unscaled = 1;
      }
      entry->state_data.uplink_syn_rcvd.isn = tcp_seq_number(ippay);
      entry->wan_sent = tcp_seq_number(ippay) + 1;
      entry->wan_acked = tcp_ack_number(ippay);
      entry->wan_max =
        entry->wan_acked + (tcp_window(ippay) << entry->wan_wscale);
      entry->flag_state = FLAG_STATE_UPLINK_SYN_RCVD;
#if 0
      worker_local_wrlock(local);
#endif
      entry->timer.time64 = time64 + 60ULL*1000ULL*1000ULL;
#if 0
      timer_heap_modify(&local->timers, &entry->timer);
      worker_local_wrunlock(local);
#endif
      if (synproxy->conf->mss_clamp_enabled)
      {
        uint16_t mss;
        mss = tcpinfo.mss;
        if (mss > synproxy->conf->mss_clamp)
        {
          mss = synproxy->conf->mss_clamp;
        }
        if (tcpinfo.mssoff)
        {
          tcp_set_mss_cksum_update(ippay, &tcpinfo, mss);
        }
      }
      synproxy_hash_unlock(local, &ctx);
      port->portfunc(pkt, port->userdata);
      return 0;
    }
  }
  ctx.locked = 0;
  entry = synproxy_hash_get(
    local, lan_ip, lan_port, remote_ip, remote_port, &ctx);
  if (entry != NULL && entry->flag_state == FLAG_STATE_DOWNLINK_HALF_OPEN)
  {
    if (tcp_rst(ippay))
    {
      /*
       * Ok, here we could verify that the RST is valid and drop the half-open
       * state. But it's extremely unlikely that someone opens a connection
       * with SYN and then to the SYN+ACK responds with RST. Also, the timeout
       * for downlink half-open connections is 64 seconds, and the timeout for
       * connections in the RST state is 45 seconds. So, the additional benefit
       * for moving the connection to RST state is minimal. Also, by maintaining
       * the connection in DOWNLINK_HALF_OPEN state, we can use the linked list
       * to remove old expired connections. In reseted connections, there is no
       * such list. So, the short summary is that moving the connection to the
       * RST state is not worth it.
       */
    }
    if (tcp_ack(ippay) && !tcp_fin(ippay) && !tcp_rst(ippay) && !tcp_syn(ippay))
    {
      uint32_t ack_num = tcp_ack_number(ippay);
      if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      if (tcp_cksum_calc(ip, ip_hdr_len(ip), ippay, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      if (((uint32_t)(entry->state_data.downlink_half_open.local_isn + 1)) != ack_num)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP ACK number");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      if (((uint32_t)(entry->state_data.downlink_half_open.remote_isn + 1)) != tcp_seq_number(ippay))
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP SEQ number");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      worker_local_wrlock(local);
      ip_increment_one(
        ip_src(ip), synproxy->conf->ratehash.network_prefix, &local->ratelimit);
      log_log(
        LOG_LEVEL_NOTICE, "WORKERDOWNLINK", "SYN proxy sending SYN, found");
      linked_list_delete(&entry->state_data.downlink_half_open.listnode);
      if (local->half_open_connections <= 0)
      {
        abort();
      }
      local->half_open_connections--;
      worker_local_wrunlock(local);
      send_syn(
        ether, local, port, st,
        entry->state_data.downlink_half_open.mss,
        entry->state_data.downlink_half_open.wscale,
        entry->state_data.downlink_half_open.sack_permitted, entry, time64);
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "entry is HALF_OPEN");
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  if (entry == NULL)
  {
    if (tcp_ack(ippay) && !tcp_fin(ippay) && !tcp_rst(ippay) && !tcp_syn(ippay))
    {
      uint32_t ack_num = tcp_ack_number(ippay);
      uint16_t mss;
      uint16_t tsmss;
      uint8_t tswscale;
      uint8_t wscale, sack_permitted;
      int ok;
      struct tcp_information tcpinfo;
      if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      if (tcp_cksum_calc(ip, ip_hdr_len(ip), ippay, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      ok = verify_cookie(
        &local->info, synproxy, ip_dst(ip), ip_src(ip),
        tcp_dst_port(ippay), tcp_src_port(ippay), ack_num - 1,
        &mss, &wscale, &sack_permitted);
      tcp_parse_options(ippay, &tcpinfo); // XXX send_syn reparses
      if (tcpinfo.options_valid && tcpinfo.ts_present)
      {
        if (verify_timestamp(
          &local->info, synproxy, ip_dst(ip), ip_src(ip),
          tcp_dst_port(ippay), tcp_src_port(ippay), tcpinfo.tsecho,
          &tsmss, &tswscale))
        {
          if (tsmss > mss)
          {
            mss = tsmss;
          }
          if (tswscale > wscale)
          {
            wscale = tswscale;
          }
        }
      }
      if (!ok)
      {
        log_log(
          LOG_LEVEL_ERR, "WORKERDOWNLINK",
          "entry not found but A/SAFR set, SYN cookie invalid");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      worker_local_wrlock(local);
      ip_increment_one(
        ip_src(ip), synproxy->conf->ratehash.network_prefix, &local->ratelimit);
      worker_local_wrunlock(local);
      log_log(
        LOG_LEVEL_NOTICE, "WORKERDOWNLINK", "SYN proxy sending SYN");
      send_syn(ether, local, port, st, mss, wscale, sack_permitted, NULL, time64);
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "entry not found");
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  if (unlikely(tcp_rst(ippay)))
  {
    if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    if (tcp_cksum_calc(ip, ip_hdr_len(ip), ippay, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    if (entry->flag_state == FLAG_STATE_UPLINK_SYN_SENT)
    {
      if (!tcp_ack(ippay))
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "R/RA in UPLINK_SYN_SENT");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      if (tcp_ack_number(ippay) != entry->state_data.uplink_syn_sent.isn + 1)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "RA/RA in UL_SYN_SENT, bad seq");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
    }
    else if (entry->flag_state == FLAG_STATE_DOWNLINK_SYN_SENT)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "dropping RST in DOWNLINK_SYN_SENT");
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    else
    {
      uint32_t seq = tcp_seq_number(ippay);
      if (!rst_is_valid(seq, entry->wan_sent) &&
          !rst_is_valid(seq, entry->lan_acked))
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK",
                "RST has invalid SEQ number, %u/%u/%u",
                seq, entry->wan_sent, entry->lan_acked);
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
    }
    if (tcp_ack(ippay))
    {
      tcp_set_ack_number_cksum_update(
        ippay, tcp_len, tcp_ack_number(ippay)-entry->seqoffset);
    }
    entry->flag_state = FLAG_STATE_RESETED;
#if 0
    worker_local_wrlock(local);
#endif
    entry->timer.time64 = time64 + 45ULL*1000ULL*1000ULL;
#if 0
    timer_heap_modify(&local->timers, &entry->timer);
    worker_local_wrunlock(local);
#endif
    synproxy_hash_unlock(local, &ctx);
    port->portfunc(pkt, port->userdata);
    return 0;
  }
  if (   tcp_ack(ippay)
      && entry->flag_state == FLAG_STATE_DOWNLINK_SYN_SENT
      && resend_request_is_valid(tcp_seq_number(ippay), entry->wan_sent)
      && resend_request_is_valid(tcp_ack_number(ippay), entry->wan_acked))
  {
    log_log(LOG_LEVEL_NOTICE, "WORKERDOWNLINK", "resending SYN");
#if 0
    worker_local_wrlock(local);
#endif
    resend_syn(ether, local, port, st, entry, time64);
#if 0
    worker_local_wrunlock(local);
#endif
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  if (!synproxy_is_connected(entry) && entry->flag_state != FLAG_STATE_RESETED)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "not CONNECTED/RESETED, dropping");
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  if (!tcp_ack(ippay))
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "no TCP ACK, dropping pkt");
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  if (!between(
    entry->wan_acked - (entry->wan_max_window_unscaled<<entry->wan_wscale),
    tcp_ack_number(ippay),
    entry->lan_sent + 1 + MAX_FRAG))
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "packet has invalid ACK number");
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  first_seq = tcp_seq_number(ippay);
  data_len =
    ((int32_t)ip_len) - ((int32_t)ihl) - ((int32_t)tcp_data_offset(ippay));
  if (data_len < 0)
  {
    // This can occur in fragmented packets. We don't then know the true
    // data length, and can therefore drop packets that would otherwise be
    // valid.
    data_len = 0;
  }
  last_seq = first_seq + data_len - 1;
  if (unlikely(tcp_fin(ippay)))
  {
    if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    if (tcp_cksum_calc(ip, ip_hdr_len(ip), ippay, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    last_seq += 1;
  }
  wan_min =
    entry->wan_sent - (entry->lan_max_window_unscaled<<entry->lan_wscale);
  if (
    !between(
      wan_min, first_seq, entry->lan_max+1)
    &&
    !between(
      wan_min, last_seq, entry->lan_max+1)
    )
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "packet has invalid SEQ number");
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  if (unlikely(tcp_fin(ippay)) && entry->flag_state != FLAG_STATE_RESETED)
  {
    if (ip_more_frags(ip))
    {
      log_log(LOG_LEVEL_WARNING, "WORKERDOWNLINK", "FIN with more frags");
    }
    if (entry->flag_state & FLAG_STATE_DOWNLINK_FIN)
    {
      if (entry->state_data.established.downfin != last_seq)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "FIN seq changed");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
    }
    entry->state_data.established.downfin = last_seq;
    entry->flag_state |= FLAG_STATE_DOWNLINK_FIN;
  }
  if (unlikely(entry->flag_state & FLAG_STATE_UPLINK_FIN))
  {
    uint32_t fin = entry->state_data.established.upfin;
    if (tcp_ack(ippay) && tcp_ack_number(ippay) == fin + 1)
    {
      if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      if (tcp_cksum_calc(ip, ip_hdr_len(ip), ippay, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      entry->flag_state |= FLAG_STATE_UPLINK_FIN_ACK;
      if (entry->flag_state & FLAG_STATE_DOWNLINK_FIN_ACK)
      {
        todelete = 1;
      }
    }
  }
  if (tcp_window(ippay) > entry->wan_max_window_unscaled)
  {
    entry->wan_max_window_unscaled = tcp_window(ippay);
    if (entry->wan_max_window_unscaled == 0)
    {
      entry->wan_max_window_unscaled = 1;
    }
  }
  if (seq_cmp(last_seq, entry->wan_sent) >= 0)
  {
    entry->wan_sent = last_seq + 1;
  }
  if (likely(tcp_ack(ippay)))
  {
    uint32_t ack = tcp_ack_number(ippay);
    uint16_t window = tcp_window(ippay);
    if (seq_cmp(ack, entry->wan_acked) >= 0)
    {
      entry->wan_acked = ack;
    }
    if (seq_cmp(ack + (window << entry->wan_wscale), entry->wan_max) >= 0)
    {
      entry->wan_max = ack + (window << entry->wan_wscale);
    }
  }
#if 0
  worker_local_wrlock(local);
#endif
  if (entry->flag_state == FLAG_STATE_RESETED)
  {
    entry->timer.time64 = time64 + 45ULL*1000ULL*1000ULL;
  }
  else if ((entry->flag_state & FLAG_STATE_UPLINK_FIN) &&
           (entry->flag_state & FLAG_STATE_DOWNLINK_FIN))
  {
    entry->timer.time64 = time64 + 45ULL*1000ULL*1000ULL;
  }
  else if (entry->flag_state & (FLAG_STATE_UPLINK_FIN|FLAG_STATE_DOWNLINK_FIN))
  {
    entry->timer.time64 = time64 + 900ULL*1000ULL*1000ULL;
  }
  else
  {
    entry->timer.time64 = time64 + 86400ULL*1000ULL*1000ULL;
  }
#if 0
  timer_heap_modify(&local->timers, &entry->timer);
  worker_local_wrunlock(local);
#endif
  tcp_find_sack_ts_headers(ippay, &hdrs);
  if (tcp_ack(ippay))
  {
    tcp_set_ack_number_cksum_update(
      ippay, tcp_len, tcp_ack_number(ippay)-entry->seqoffset);
    if (hdrs.sackoff)
    {
      if (   !entry->lan_sack_was_supported
          && synproxy->conf->sackconflict == SACKCONFLICT_REMOVE)
      {
        char *cippay = ippay;
        tcp_disable_sack_cksum_update(
          ippay, &cippay[hdrs.sackoff], hdrs.sacklen, !(hdrs.sackoff%2));
      }
      else
      {
        tcp_adjust_sack_cksum_update_2(
          ippay, &hdrs, -entry->seqoffset);
      }
    }
  }
  tcp_adjust_tsecho_cksum_update(ippay, &hdrs, -entry->tsoffset);
  port->portfunc(pkt, port->userdata);
  if (todelete)
  {
#if 0
    worker_local_wrlock(local);
#endif
    entry->timer.time64 = time64 + 120ULL*1000ULL*1000ULL;
    entry->flag_state = FLAG_STATE_TIME_WAIT;
#if 0
    timer_heap_modify(&local->timers, &entry->timer);
    worker_local_wrunlock(local);
#endif
  }
  synproxy_hash_unlock(local, &ctx);
  return 0;
}

/*
  Uplink packet arrives. It has lan_ip:lan_port remote_ip:remote_port
  - Lookup by lan_ip:lan_port, verify remote_ip:remote_port
  Downlink packet arrives. It has wan_ip:wan_port remote_ip:remote_port
  - Lookup by wan_port, verify remote_ip:remote_port
 */

// return: whether to free (1) or not (0)
int uplink(
  struct synproxy *synproxy, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64, struct ll_alloc_st *st)
{
  void *ether = packet_data(pkt);
  void *ip;
  void *ippay;
  size_t ether_len = pkt->sz;
  size_t ip_len;
  uint16_t ihl;
  uint32_t remote_ip;
  uint16_t remote_port;
  uint8_t protocol;
  uint32_t lan_ip;
  uint16_t lan_port;
  uint16_t tcp_len;
  struct synproxy_hash_entry *entry;
  struct synproxy_hash_ctx ctx;
  int8_t wscalediff;
  uint32_t first_seq;
  uint32_t last_seq;
  int32_t data_len;
  int todelete = 0;
  uint32_t lan_min;
  struct sack_ts_headers hdrs;

  if (ether_len < ETHER_HDR_LEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full Ether hdr");
    return 1;
  }
  if (ether_type(ether) != ETHER_TYPE_IP)
  {
    port->portfunc(pkt, port->userdata);
    return 0;
  }
  ip = ether_payload(ether);
  ip_len = ether_len - ETHER_HDR_LEN;
  if (ip_len < IP_HDR_MINLEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full IP hdr 1");
    return 1;
  }
  if (ip_version(ip) != 4)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "IP version mismatch");
    return 1;
  }
  ihl = ip_hdr_len(ip);
  if (ip_len < ihl)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full IP hdr 2");
    return 1;
  }
  if (ip_proto(ip) != 6)
  {
    port->portfunc(pkt, port->userdata);
    return 0;
  }
  if (ip_frag_off(ip) >= 60)
  {
    port->portfunc(pkt, port->userdata);
    return 0;
  }
  else if (ip_frag_off(ip) != 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "fragment has partial header");
    return 1;
  }
  if (ip_len < ip_total_len(ip))
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full IP data");
    return 1;
  }
  
  protocol = ip_proto(ip);
  ippay = ip_payload(ip);
  lan_ip = ip_src(ip);
  remote_ip = ip_dst(ip);
  if (protocol == 6)
  {
    tcp_len = ip_total_len(ip) - ihl;
    if (tcp_len < 20)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full TCP hdr");
      return 1;
    }
    if (tcp_data_offset(ippay) > tcp_len)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full TCP opts");
      return 1;
    }
    lan_port = tcp_src_port(ippay);
    remote_port = tcp_dst_port(ippay);
  }
  else
  {
    abort();
  }
  if (unlikely(tcp_syn(ippay)))
  {
    if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid IP hdr cksum");
      return 1;
    }
    if (tcp_cksum_calc(ip, ip_hdr_len(ip), ippay, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid TCP hdr cksum");
      return 1;
    }
    if (tcp_fin(ippay) || tcp_rst(ippay))
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SYN packet contains FIN or RST");
      return 1;
    }
    if (!tcp_ack(ippay))
    {
      struct tcp_information tcpinfo;
      ctx.locked = 0;
      entry = synproxy_hash_get(
        local, lan_ip, lan_port, remote_ip, remote_port, &ctx);
      if (entry != NULL && entry->flag_state == FLAG_STATE_UPLINK_SYN_SENT &&
          entry->state_data.uplink_syn_sent.isn == tcp_seq_number(ippay))
      {
        // retransmit of SYN
        synproxy_hash_unlock(local, &ctx);
        port->portfunc(pkt, port->userdata);
        return 0;
      }
      if (entry != NULL)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "S/SA but entry exists");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      entry = synproxy_hash_put(
        local, lan_ip, lan_port, remote_ip, remote_port, 0, time64);
      if (entry == NULL)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "out of memory or already exists");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      tcp_parse_options(ippay, &tcpinfo);
      if (!tcpinfo.options_valid)
      {
        tcpinfo.wscale = 0;
        tcpinfo.mssoff = 0;
        tcpinfo.mss = 1460;
        tcpinfo.sack_permitted = 0;
      }
      entry->flag_state = FLAG_STATE_UPLINK_SYN_SENT;
      entry->state_data.uplink_syn_sent.isn = tcp_seq_number(ippay);
      entry->lan_wscale = tcpinfo.wscale;
      entry->lan_max_window_unscaled = tcp_window(ippay);
      entry->lan_sack_was_supported = tcpinfo.sack_permitted;
      if (entry->lan_max_window_unscaled == 0)
      {
        entry->lan_max_window_unscaled = 1;
      }
      entry->lan_sent = tcp_seq_number(ippay) + 1;
      if (synproxy->conf->mss_clamp_enabled)
      {
        uint16_t mss;
        mss = tcpinfo.mss;
        if (mss > synproxy->conf->mss_clamp)
        {
          mss = synproxy->conf->mss_clamp;
        }
        if (tcpinfo.mssoff)
        {
          tcp_set_mss_cksum_update(ippay, &tcpinfo, mss);
        }
      }
      port->portfunc(pkt, port->userdata);
#if 0
      worker_local_wrlock(local);
#endif
      entry->timer.time64 = time64 + 120ULL*1000ULL*1000ULL;
#if 0
      timer_heap_modify(&local->timers, &entry->timer);
      worker_local_wrunlock(local);
#endif
      synproxy_hash_unlock(local, &ctx);
      return 0;
    }
    else
    {
      struct tcp_information tcpinfo;
      struct sack_hash_data sackdata;
      ctx.locked = 0;
      entry = synproxy_hash_get(
        local, lan_ip, lan_port, remote_ip, remote_port, &ctx);
      if (entry == NULL)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SA/SA but entry nonexistent");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      if (entry->flag_state == FLAG_STATE_ESTABLISHED)
      {
        // FIXME we should store the ISN permanently...
        if (tcp_ack_number(ippay) == entry->lan_acked &&
            tcp_seq_number(ippay) + 1 + entry->seqoffset == entry->lan_sent)
        {
          log_log(LOG_LEVEL_NOTICE, "WORKERUPLINK", "resending ACK");
          send_ack_only(ether, entry, port, st);
          synproxy_hash_unlock(local, &ctx);
          return 1;
        }
      }
      if (entry->flag_state != FLAG_STATE_DOWNLINK_SYN_SENT)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SA/SA, entry != DL_SYN_SENT");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      if (tcp_ack_number(ippay) != entry->state_data.downlink_syn_sent.remote_isn + 1)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SA/SA, invalid ACK num");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      tcp_parse_options(ippay, &tcpinfo);
      if (!tcpinfo.options_valid)
      {
        tcpinfo.mss = synproxy->conf->own_mss;
        tcpinfo.wscale = 0;
        tcpinfo.sack_permitted = 0;
      }
      sackdata.sack_supported = tcpinfo.sack_permitted;
      sackdata.mss = tcpinfo.mss;
      if (sackdata.mss == 0)
      {
        sackdata.mss = synproxy->conf->own_mss;
      }
      if (   synproxy->conf->sackmode == HASHMODE_HASHIPPORT
          || synproxy->conf->mssmode == HASHMODE_HASHIPPORT)
      {
        sack_ip_port_hash_add(
          &synproxy->autolearn, ip_src(ip), tcp_src_port(ippay), &sackdata);
      }
      if (   synproxy->conf->sackmode == HASHMODE_HASHIP
          || synproxy->conf->mssmode == HASHMODE_HASHIP)
      {
        sack_ip_port_hash_add(
          &synproxy->autolearn, ip_src(ip), 0, &sackdata);
      }
      entry->wscalediff =
        ((int)synproxy->conf->own_wscale) - ((int)tcpinfo.wscale);
      entry->seqoffset =
        entry->state_data.downlink_syn_sent.local_isn - tcp_seq_number(ippay);
      entry->lan_wscale = tcpinfo.wscale;
      entry->lan_sent = tcp_seq_number(ippay) + 1 + entry->seqoffset;
      entry->lan_acked = tcp_ack_number(ippay);
      entry->lan_max = tcp_ack_number(ippay) + (tcp_window(ippay) << entry->lan_wscale);
      entry->lan_max_window_unscaled = tcp_window(ippay);
      entry->lan_sack_was_supported = tcpinfo.sack_permitted;
      if (entry->lan_max_window_unscaled == 0)
      {
        entry->lan_max_window_unscaled = 1;
      }
      entry->flag_state = FLAG_STATE_ESTABLISHED;
#if 0
      worker_local_wrlock(local);
#endif
      entry->timer.time64 = time64 + 86400ULL*1000ULL*1000ULL;
#if 0
      timer_heap_modify(&local->timers, &entry->timer);
      worker_local_wrunlock(local);
#endif
      send_ack_and_window_update(ether, entry, port, st);
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
  }
  ctx.locked = 0;
  entry = synproxy_hash_get(
    local, lan_ip, lan_port, remote_ip, remote_port, &ctx);
  if (entry == NULL)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "entry not found");
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  if (unlikely(entry->flag_state == FLAG_STATE_UPLINK_SYN_RCVD))
  {
    if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid IP hdr cksum");
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    if (tcp_cksum_calc(ip, ip_hdr_len(ip), ippay, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid TCP hdr cksum");
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    if (tcp_rst(ippay))
    {
      uint32_t seq = tcp_seq_number(ippay) + entry->seqoffset;
      if (!rst_is_valid(seq, entry->lan_sent) &&
          !rst_is_valid(seq, entry->wan_acked))
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK",
                "invalid SEQ num in RST, %u/%u/%u",
                seq, entry->lan_sent, entry->wan_acked);
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      entry->flag_state = FLAG_STATE_RESETED;
#if 0
      worker_local_wrlock(local);
#endif
      entry->timer.time64 = time64 + 45ULL*1000ULL*1000ULL;
#if 0
      timer_heap_modify(&local->timers, &entry->timer);
      worker_local_wrunlock(local);
#endif
      port->portfunc(pkt, port->userdata);
      synproxy_hash_unlock(local, &ctx);
      return 0;
    }
    if (tcp_ack(ippay))
    {
      uint32_t ack = tcp_ack_number(ippay);
      uint16_t window = tcp_window(ippay);
      if (tcp_ack_number(ippay) != entry->state_data.uplink_syn_rcvd.isn + 1)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid ACK number");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      first_seq = tcp_seq_number(ippay);
      data_len =
        ((int32_t)ip_len) - ((int32_t)ihl) - ((int32_t)tcp_data_offset(ippay));
      if (data_len < 0)
      {
        // This can occur in fragmented packets. We don't then know the true
        // data length, and can therefore drop packets that would otherwise be
        // valid.
        data_len = 0;
      }
      last_seq = first_seq + data_len - 1;
      if (seq_cmp(last_seq, entry->lan_sent) >= 0)
      {
        entry->lan_sent = last_seq + 1;
      }
      entry->lan_acked = ack;
      entry->lan_max = ack + (window << entry->lan_wscale);
      entry->flag_state = FLAG_STATE_ESTABLISHED;
#if 0
      worker_local_wrlock(local);
#endif
      entry->timer.time64 = time64 + 86400ULL*1000ULL*1000ULL;
#if 0
      timer_heap_modify(&local->timers, &entry->timer);
      worker_local_wrunlock(local);
#endif
      port->portfunc(pkt, port->userdata);
      synproxy_hash_unlock(local, &ctx);
      return 0;
    }
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "UPLINK_SYN_RECEIVED w/o ACK");
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  if (unlikely(tcp_rst(ippay)))
  {
    if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid IP hdr cksum");
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    if (tcp_cksum_calc(ip, ip_hdr_len(ip), ippay, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid TCP hdr cksum");
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    if (entry->flag_state == FLAG_STATE_UPLINK_SYN_SENT)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "dropping RST in UPLINK_SYN_SENT");
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    else if (entry->flag_state == FLAG_STATE_DOWNLINK_SYN_SENT)
    {
      if (!tcp_ack(ippay))
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "R/RA in DOWNLINK_SYN_SENT");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      if (tcp_ack_number(ippay) != entry->state_data.downlink_syn_sent.remote_isn + 1)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "RA/RA in DL_SYN_SENT, bad seq");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      tcp_set_seq_number_cksum_update(
        ippay, tcp_len, entry->state_data.downlink_syn_sent.local_isn + 1);
      tcp_set_ack_off_cksum_update(ippay);
      tcp_set_ack_number_cksum_update(
        ippay, tcp_len, 0);
      entry->flag_state = FLAG_STATE_RESETED;
#if 0
      worker_local_wrlock(local);
#endif
      entry->timer.time64 = time64 + 45ULL*1000ULL*1000ULL;
#if 0
      timer_heap_modify(&local->timers, &entry->timer);
      worker_local_wrunlock(local);
#endif
      port->portfunc(pkt, port->userdata);
      synproxy_hash_unlock(local, &ctx);
      return 0;
    }
    else
    {
      uint32_t seq = tcp_seq_number(ippay) + entry->seqoffset;
      if (!rst_is_valid(seq, entry->lan_sent) &&
          !rst_is_valid(seq, entry->wan_acked))
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK",
                "invalid SEQ num in RST, %u/%u/%u",
                seq, entry->lan_sent, entry->wan_acked);
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
    }
    tcp_set_seq_number_cksum_update(
      ippay, tcp_len, tcp_seq_number(ippay)+entry->seqoffset);
    entry->flag_state = FLAG_STATE_RESETED;
#if 0
    worker_local_wrlock(local);
#endif
    entry->timer.time64 = time64 + 45ULL*1000ULL*1000ULL;
#if 0
    timer_heap_modify(&local->timers, &entry->timer);
    worker_local_wrunlock(local);
#endif
    port->portfunc(pkt, port->userdata);
    synproxy_hash_unlock(local, &ctx);
    return 0;
  }
  if (!synproxy_is_connected(entry) && entry->flag_state != FLAG_STATE_RESETED)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "not CONNECTED/RESETED, dropping");
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  if (!tcp_ack(ippay))
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "no TCP ACK, dropping pkt");
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  if (!between(
    entry->lan_acked - (entry->lan_max_window_unscaled<<entry->lan_wscale),
    tcp_ack_number(ippay),
    entry->wan_sent + 1 + MAX_FRAG))
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "packet has invalid ACK number");
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  first_seq = tcp_seq_number(ippay);
  data_len =
    ((int32_t)ip_len) - ((int32_t)ihl) - ((int32_t)tcp_data_offset(ippay));
  if (data_len < 0)
  {
    // This can occur in fragmented packets. We don't then know the true
    // data length, and can therefore drop packets that would otherwise be
    // valid.
    data_len = 0;
  }
  last_seq = first_seq + data_len - 1;
  if (unlikely(tcp_fin(ippay)))
  {
    if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid IP hdr cksum");
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    if (tcp_cksum_calc(ip, ip_hdr_len(ip), ippay, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid TCP hdr cksum");
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    last_seq += 1;
  }
  lan_min =
    entry->lan_sent - (entry->wan_max_window_unscaled<<entry->wan_wscale);
  first_seq += entry->seqoffset;
  last_seq += entry->seqoffset;
  if (
    !between(
      lan_min, first_seq, entry->wan_max+1)
    &&
    !between(
      lan_min, last_seq, entry->wan_max+1)
    )
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "packet has invalid SEQ number");
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  if (tcp_window(ippay) > entry->lan_max_window_unscaled)
  {
    entry->lan_max_window_unscaled = tcp_window(ippay);
    if (entry->lan_max_window_unscaled == 0)
    {
      entry->lan_max_window_unscaled = 1;
    }
  }
  if (unlikely(tcp_fin(ippay)) && entry->flag_state != FLAG_STATE_RESETED)
  {
    if (ip_more_frags(ip))
    {
      log_log(LOG_LEVEL_WARNING, "WORKERUPLINK", "FIN with more frags");
    }
    if (entry->flag_state & FLAG_STATE_UPLINK_FIN)
    {
      if (entry->state_data.established.upfin != last_seq)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "FIN seq changed");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
    }
    entry->state_data.established.upfin = last_seq;
    entry->flag_state |= FLAG_STATE_UPLINK_FIN;
  }
  if (unlikely(entry->flag_state & FLAG_STATE_DOWNLINK_FIN))
  {
    uint32_t fin = entry->state_data.established.downfin;
    if (tcp_ack(ippay) && tcp_ack_number(ippay) == fin + 1)
    {
      if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid IP hdr cksum");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      if (tcp_cksum_calc(ip, ip_hdr_len(ip), ippay, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid TCP hdr cksum");
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
      entry->flag_state |= FLAG_STATE_DOWNLINK_FIN_ACK;
      if (entry->flag_state & FLAG_STATE_UPLINK_FIN_ACK)
      {
        todelete = 1;
      }
    }
  }
  if (seq_cmp(last_seq, entry->lan_sent) >= 0)
  {
    entry->lan_sent = last_seq + 1;
  }
  if (likely(tcp_ack(ippay)))
  {
    uint32_t ack = tcp_ack_number(ippay);
    uint16_t window = tcp_window(ippay);
    if (seq_cmp(ack, entry->lan_acked) >= 0)
    {
      entry->lan_acked = ack;
    }
    if (seq_cmp(ack + (window << entry->lan_wscale), entry->lan_max) >= 0)
    {
      entry->lan_max = ack + (window << entry->lan_wscale);
    }
  }
#if 0
  worker_local_wrlock(local);
#endif
  if (entry->flag_state == FLAG_STATE_RESETED)
  {
    entry->timer.time64 = time64 + 45ULL*1000ULL*1000ULL;
  }
  else if ((entry->flag_state & FLAG_STATE_UPLINK_FIN) &&
           (entry->flag_state & FLAG_STATE_DOWNLINK_FIN))
  {
    entry->timer.time64 = time64 + 45ULL*1000ULL*1000ULL;
  }
  else if (entry->flag_state & (FLAG_STATE_UPLINK_FIN|FLAG_STATE_DOWNLINK_FIN))
  {
    entry->timer.time64 = time64 + 900ULL*1000ULL*1000ULL;
  }
  else
  {
    entry->timer.time64 = time64 + 86400ULL*1000ULL*1000ULL;
  }
#if 0
  timer_linkheap_modify(&local->timers, &entry->timer);
  worker_local_wrunlock(local);
#endif
  tcp_set_seq_number_cksum_update(
    ippay, tcp_len, tcp_seq_number(ippay)+entry->seqoffset);
  wscalediff = entry->wscalediff;
  if (wscalediff > 0)
  {
    tcp_set_window_cksum_update(
      ippay, tcp_len, tcp_window(ippay) >> entry->wscalediff);
  }
  else
  {
    uint64_t win64 = ((uint64_t)tcp_window(ippay)) << (-(entry->wscalediff));
    if (win64 > 65535 || win64 < tcp_window(ippay))
    {
      win64 = 65535;
    }
    tcp_set_window_cksum_update(ippay, tcp_len, win64);
  }
  tcp_find_sack_ts_headers(ippay, &hdrs);
  tcp_adjust_tsval_cksum_update(ippay, &hdrs, entry->tsoffset);
  port->portfunc(pkt, port->userdata);
  if (todelete)
  {
#if 0
    worker_local_wrlock(local);
#endif
    entry->timer.time64 = time64 + 120ULL*1000ULL*1000ULL;
    entry->flag_state = FLAG_STATE_TIME_WAIT;
#if 0
    timer_heap_modify(&local->timers, &entry->timer);
    worker_local_wrunlock(local);
#endif
  }
  synproxy_hash_unlock(local, &ctx);
  return 0;
}
