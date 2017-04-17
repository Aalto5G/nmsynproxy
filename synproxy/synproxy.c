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
  if (rst_seq >= ref_seq)
  {
    return rst_seq - ref_seq <= 3;
  }
  return ref_seq - rst_seq <= 3;
}

static void synproxy_expiry_fn(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud)
{
  struct worker_local *local = ud;
  struct synproxy_hash_entry *e;
  e = CONTAINER_OF(timer, struct synproxy_hash_entry, timer);
  hash_table_delete(&local->hash, &e->node);
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
  uint16_t remote_port)
{
  struct synproxy_hash_entry *e;
  if (synproxy_hash_get(local, local_ip, local_port, remote_ip, remote_port))
  {
    abort();
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
  e->timer.time64 = gettime64() + 86400ULL*1000ULL*1000ULL;
  e->timer.fn = synproxy_expiry_fn;
  e->timer.userdata = local;
  timer_linkheap_add(&local->timers, &e->timer);
  hash_table_add_nogrow(&local->hash, &e->node, synproxy_hash(e));
  return e;
}


uint32_t synproxy_hash_fn(struct hash_list_node *node, void *userdata)
{
  return synproxy_hash(CONTAINER_OF(node, struct synproxy_hash_entry, node));
}

static void send_synack(
  void *orig, struct worker_local *local, struct synproxy *synproxy,
  struct port *port, struct ll_alloc_st *st)
{
  char synack[14+20+20+12] = {0};
  void *ip, *origip;
  void *tcp, *origtcp;
  unsigned char *tcpopts;
  struct packet *pktstruct;
  uint32_t syn_cookie;
  struct tcp_information tcpinfo;

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
  tcpopts[2] = synproxy->conf->own_wscale;
  tcpopts[3] = 1;
  tcpopts[4] = 2;
  tcpopts[5] = 4;
  hdr_set16n(&tcpopts[6], synproxy->conf->own_mss);
  // FIXME implement learning
  if (synproxy->conf->own_sack)
  {
    tcpopts[8] = 4;
    tcpopts[9] = 2;
    tcpopts[10] = 0;
    tcpopts[11] = 0;
  }
  else
  {
    tcpopts[8] = 0;
    tcpopts[9] = 0;
    tcpopts[10] = 0;
    tcpopts[11] = 0;
  }
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(synack) - 14 - 20);
  // FIXME timestamps
  pktstruct = ll_alloc_st(st, packet_size(sizeof(synack)));
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sizeof(synack);
  memcpy(packet_data(pktstruct), synack, sizeof(synack));
  port->portfunc(pktstruct, port->userdata);
}

static void send_syn(
  void *orig, struct worker_local *local, struct port *port,
  struct ll_alloc_st *st,
  uint16_t mss, uint8_t wscale, uint8_t sack_permitted)
{
  char syn[14+20+20+12] = {0};
  void *ip, *origip;
  void *tcp, *origtcp;
  unsigned char *tcpopts;
  struct packet *pktstruct;
  struct synproxy_hash_entry *entry;

  origip = ether_payload(orig);
  origtcp = ip_payload(origip);

  entry = synproxy_hash_put(
    local, ip_dst(origip), tcp_dst_port(origtcp),
    ip_src(origip), tcp_src_port(origtcp));

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
  entry->state_data.downlink_syn_sent.this_isn = tcp_ack_number(origtcp) - 1;
  entry->state_data.downlink_syn_sent.isn = tcp_seq_number(origtcp) - 1;
  entry->flag_state = FLAG_STATE_DOWNLINK_SYN_SENT;
  entry->timer.time64 = gettime64() + 120ULL*1000ULL*1000ULL;
  timer_heap_modify(&local->timers, &entry->timer);

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
  tcp_set_seq_number(tcp, tcp_seq_number(origtcp) - 1);
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
  tcpopts[2] = wscale;
  tcpopts[3] = 1;
  tcpopts[4] = 2;
  tcpopts[5] = 4;
  hdr_set16n(&tcpopts[6], mss);
  if (sack_permitted)
  {
    tcpopts[8] = 4;
    tcpopts[9] = 2;
    tcpopts[10] = 0;
    tcpopts[11] = 0;
  }
  else
  {
    tcpopts[8] = 0;
    tcpopts[9] = 0;
    tcpopts[10] = 0;
    tcpopts[11] = 0;
  }
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(syn) - 14 - 20);
  // FIXME timestamps
  pktstruct = ll_alloc_st(st, packet_size(sizeof(syn)));
  pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
  pktstruct->sz = sizeof(syn);
  memcpy(packet_data(pktstruct), syn, sizeof(syn));
  port->portfunc(pktstruct, port->userdata);
}

static void send_ack_only(
  void *orig, struct synproxy_hash_entry *entry, struct port *port,
  struct ll_alloc_st *st)
{
  char ack[14+20+20] = {0};
  void *ip, *origip;
  void *tcp, *origtcp;
  struct packet *pktstruct;

  origip = ether_payload(orig);
  origtcp = ip_payload(origip);

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
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, tcp_ack_number(origtcp));
  tcp_set_ack_number(tcp, tcp_seq_number(origtcp)+1);
  tcp_set_window(tcp, entry->wan_max_window_unscaled);
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(ack) - 14 - 20);

  // FIXME timestamps, etc

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
  char windowupdate[14+20+20] = {0};
  void *ip, *origip;
  void *tcp, *origtcp;
  struct packet *pktstruct;

  origip = ether_payload(orig);
  origtcp = ip_payload(origip);

  send_ack_only(orig, entry, port, st);

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
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, tcp_ack_number(origtcp));
  tcp_set_ack_number(tcp, tcp_seq_number(origtcp)+1);
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
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(windowupdate) - 14 - 20);

  // FIXME timestamps, etc

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
  uint32_t first_seq;
  uint32_t last_seq;
  int32_t data_len;
  int todelete = 0;
  uint32_t wan_min;

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
      if (!ip_permitted(
        ip_src(ip), synproxy->conf->ratehash.network_prefix, &local->ratelimit))
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "IP ratelimited");
        return 1;
      }
      send_synack(ether, local, synproxy, port, st);
      return 1;
    }
    else
    {
      struct tcp_information tcpinfo;
      entry = synproxy_hash_get(
        local, lan_ip, lan_port, remote_ip, remote_port);
      if (entry == NULL)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "SA/SA but entry nonexistent");
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
        port->portfunc(pkt, port->userdata);
        return 0;
      }
      if (entry->flag_state != FLAG_STATE_UPLINK_SYN_SENT)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "SA/SA, entry != UL_SYN_SENT");
        return 1;
      }
      if (tcp_ack_number(ippay) != entry->state_data.uplink_syn_sent.isn + 1)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "SA/SA, invalid ACK num");
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
      entry->timer.time64 = time64 + 60ULL*1000ULL*1000ULL;
      timer_heap_modify(&local->timers, &entry->timer);
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
      return 0;
    }
  }
  entry = synproxy_hash_get(
    local, lan_ip, lan_port, remote_ip, remote_port);
  if (entry == NULL)
  {
    if (tcp_ack(ippay) && !tcp_fin(ippay) && !tcp_rst(ippay) && !tcp_syn(ippay))
    {
      uint32_t ack_num = tcp_ack_number(ippay);
      uint16_t mss;
      uint8_t wscale, sack_permitted;
      int ok;
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
      ok = verify_cookie(
        &local->info, synproxy, ip_dst(ip), ip_src(ip),
        tcp_dst_port(ippay), tcp_src_port(ippay), ack_num - 1,
        &mss, &wscale, &sack_permitted);
      if (!ok)
      {
        log_log(
          LOG_LEVEL_ERR, "WORKERDOWNLINK",
          "entry not found but A/SAFR set, SYN cookie invalid");
        return 1;
      }
      ip_increment_one(
        ip_src(ip), synproxy->conf->ratehash.network_prefix, &local->ratelimit);
      log_log(
        LOG_LEVEL_NOTICE, "WORKERDOWNLINK", "SYN proxy sending SYN");
      send_syn(ether, local, port, st, mss, wscale, sack_permitted);
      return 1;
    }
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "entry not found");
    return 1;
  }
  if (unlikely(tcp_rst(ippay)))
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
    if (entry->flag_state == FLAG_STATE_UPLINK_SYN_SENT)
    {
      if (!tcp_ack(ippay))
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "R/RA in UPLINK_SYN_SENT");
        return 1;
      }
      if (tcp_ack_number(ippay) != entry->state_data.uplink_syn_sent.isn + 1)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "RA/RA in UL_SYN_SENT, bad seq");
        return 1;
      }
    }
    else if (entry->flag_state == FLAG_STATE_DOWNLINK_SYN_SENT)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "dropping RST in DOWNLINK_SYN_SENT");
      return 1;
    }
    else
    {
      uint32_t seq = tcp_seq_number(ippay);
      if (!rst_is_valid(seq, entry->wan_sent))
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "RST has invalid SEQ number");
        return 1;
      }
    }
    if (tcp_ack(ippay))
    {
      tcp_set_ack_number_cksum_update(
        ippay, tcp_len, tcp_ack_number(ippay)-entry->seqoffset);
    }
    synproxy_hash_del(local, entry);
    port->portfunc(pkt, port->userdata);
    return 0;
  }
  if (!synproxy_is_connected(entry))
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "not CONNECTED, dropping pkt");
    return 1;
  }
  if (!tcp_ack(ippay))
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "no TCP ACK, dropping pkt");
    return 1;
  }
  if (!between(
    entry->wan_acked - (entry->wan_max_window_unscaled<<entry->wan_wscale),
    tcp_ack_number(ippay),
    entry->lan_sent + 1 + MAX_FRAG))
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "packet has invalid ACK number");
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
      return 1;
    }
    if (tcp_cksum_calc(ip, ip_hdr_len(ip), ippay, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
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
    return 1;
  }
  if (unlikely(tcp_fin(ippay)))
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
        return 1;
      }
      if (tcp_cksum_calc(ip, ip_hdr_len(ip), ippay, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
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
  if ((entry->flag_state & FLAG_STATE_UPLINK_FIN) &&
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
  timer_heap_modify(&local->timers, &entry->timer);
  if (tcp_ack(ippay))
  {
    void *sackhdr;
    size_t sacklen;
    int sixteen_bit_align;
    tcp_set_ack_number_cksum_update(
      ippay, tcp_len, tcp_ack_number(ippay)-entry->seqoffset);
    sackhdr = tcp_find_sack_header(ippay, &sacklen, &sixteen_bit_align);
    if (sackhdr != NULL)
    {
      tcp_adjust_sack_cksum_update(
        ippay, sackhdr, sacklen, sixteen_bit_align, -entry->seqoffset);
    }
  }
  port->portfunc(pkt, port->userdata);
  if (todelete)
  {
    entry->timer.time64 = time64 + 120ULL*1000ULL*1000ULL;
    entry->flag_state = FLAG_STATE_TIME_WAIT;
    timer_heap_modify(&local->timers, &entry->timer);
  }
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
  int8_t wscalediff;
  uint32_t first_seq;
  uint32_t last_seq;
  int32_t data_len;
  int todelete = 0;
  uint32_t lan_min;

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
      entry = synproxy_hash_get(
        local, lan_ip, lan_port, remote_ip, remote_port);
      if (entry != NULL && entry->flag_state == FLAG_STATE_UPLINK_SYN_SENT &&
          entry->state_data.uplink_syn_sent.isn == tcp_seq_number(ippay))
      {
        // retransmit of SYN
        port->portfunc(pkt, port->userdata);
        return 0;
      }
      if (entry != NULL)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "S/SA but entry exists");
        return 1;
      }
      entry = synproxy_hash_put(
        local, lan_ip, lan_port, remote_ip, remote_port);
      if (entry == NULL)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "out of memory");
        return 1;
      }
      tcp_parse_options(ippay, &tcpinfo);
      if (!tcpinfo.options_valid)
      {
        tcpinfo.wscale = 0;
        tcpinfo.mssoff = 0;
        tcpinfo.mss = 1460;
      }
      entry->flag_state = FLAG_STATE_UPLINK_SYN_SENT;
      entry->state_data.uplink_syn_sent.isn = tcp_seq_number(ippay);
      entry->lan_wscale = tcpinfo.wscale;
      entry->lan_max_window_unscaled = tcp_window(ippay);
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
      entry->timer.time64 = time64 + 120ULL*1000ULL*1000ULL;
      timer_heap_modify(&local->timers, &entry->timer);
      return 0;
    }
    else
    {
      struct tcp_information tcpinfo;
      entry = synproxy_hash_get(
        local, lan_ip, lan_port, remote_ip, remote_port);
      if (entry == NULL)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SA/SA but entry nonexistent");
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
          return 1;
        }
      }
      if (entry->flag_state != FLAG_STATE_DOWNLINK_SYN_SENT)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SA/SA, entry != DL_SYN_SENT");
        return 1;
      }
      if (tcp_ack_number(ippay) != entry->state_data.downlink_syn_sent.isn + 1)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SA/SA, invalid ACK num");
        return 1;
      }
      tcp_parse_options(ippay, &tcpinfo);
      if (!tcpinfo.options_valid)
      {
        tcpinfo.wscale = 0;
        tcpinfo.sack_permitted = 0;
      }
      if (!tcpinfo.sack_permitted && synproxy->conf->own_sack)
      {
        log_log(LOG_LEVEL_NOTICE, "WORKERUPLINK", "SACK conflict");
      }
      entry->wscalediff =
        ((int)synproxy->conf->own_wscale) - ((int)tcpinfo.wscale);
      entry->seqoffset =
        entry->state_data.downlink_syn_sent.this_isn - tcp_seq_number(ippay);
      entry->lan_wscale = tcpinfo.wscale;
      entry->lan_sent = tcp_seq_number(ippay) + 1 + entry->seqoffset;
      entry->lan_acked = tcp_ack_number(ippay);
      entry->lan_max = tcp_ack_number(ippay) + (tcp_window(ippay) << entry->lan_wscale);
      entry->lan_max_window_unscaled = tcp_window(ippay);
      if (entry->lan_max_window_unscaled == 0)
      {
        entry->lan_max_window_unscaled = 1;
      }
      entry->flag_state = FLAG_STATE_ESTABLISHED;
      entry->timer.time64 = time64 + 86400ULL*1000ULL*1000ULL;
      timer_heap_modify(&local->timers, &entry->timer);
      send_ack_and_window_update(ether, entry, port, st);
      return 1;
    }
  }
  entry = synproxy_hash_get(
    local, lan_ip, lan_port, remote_ip, remote_port);
  if (entry == NULL)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "entry not found");
    return 1;
  }
  if (unlikely(entry->flag_state == FLAG_STATE_UPLINK_SYN_RCVD))
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
    if (tcp_rst(ippay))
    {
      uint32_t seq = tcp_seq_number(ippay);
      if (!rst_is_valid(seq, entry->lan_sent))
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid SEQ num in RST");
        return 1;
      }
      synproxy_hash_del(local, entry);
      port->portfunc(pkt, port->userdata);
      return 0;
    }
    if (tcp_ack(ippay))
    {
      uint32_t ack = tcp_ack_number(ippay);
      uint16_t window = tcp_window(ippay);
      if (tcp_ack_number(ippay) != entry->state_data.uplink_syn_rcvd.isn + 1)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid ACK number");
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
      entry->timer.time64 = time64 + 86400ULL*1000ULL*1000ULL;
      timer_heap_modify(&local->timers, &entry->timer);
      port->portfunc(pkt, port->userdata);
      return 0;
    }
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "UPLINK_SYN_RECEIVED w/o ACK");
    return 1;
  }
  if (unlikely(tcp_rst(ippay)))
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
    if (entry->flag_state == FLAG_STATE_UPLINK_SYN_SENT)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "dropping RST in UPLINK_SYN_SENT");
      return 1;
    }
    else if (entry->flag_state == FLAG_STATE_DOWNLINK_SYN_SENT)
    {
      if (!tcp_ack(ippay))
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "R/RA in DOWNLINK_SYN_SENT");
        return 1;
      }
      if (tcp_ack_number(ippay) != entry->state_data.downlink_syn_sent.isn + 1)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "RA/RA in DL_SYN_SENT, bad seq");
        return 1;
      }
      tcp_set_seq_number_cksum_update(
        ippay, tcp_len, entry->state_data.downlink_syn_sent.this_isn + 1);
      tcp_set_ack_off_cksum_update(ippay);
      tcp_set_ack_number_cksum_update(
        ippay, tcp_len, 0);
      synproxy_hash_del(local, entry);
      port->portfunc(pkt, port->userdata);
      return 0;
    }
    else
    {
      uint32_t seq = tcp_seq_number(ippay);
      if (!rst_is_valid(seq, entry->lan_sent))
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid SEQ num in RST");
        return 1;
      }
    }
    tcp_set_seq_number_cksum_update(
      ippay, tcp_len, tcp_seq_number(ippay)+entry->seqoffset);
    synproxy_hash_del(local, entry);
    port->portfunc(pkt, port->userdata);
    return 0;
  }
  if (!synproxy_is_connected(entry))
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "not CONNECTED, dropping pkt");
    return 1;
  }
  if (!tcp_ack(ippay))
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "no TCP ACK, dropping pkt");
    return 1;
  }
  if (!between(
    entry->lan_acked - (entry->lan_max_window_unscaled<<entry->lan_wscale),
    tcp_ack_number(ippay),
    entry->wan_sent + 1 + MAX_FRAG))
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "packet has invalid ACK number");
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
      return 1;
    }
    if (tcp_cksum_calc(ip, ip_hdr_len(ip), ippay, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid TCP hdr cksum");
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
  if (unlikely(tcp_fin(ippay)))
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
        return 1;
      }
      if (tcp_cksum_calc(ip, ip_hdr_len(ip), ippay, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid TCP hdr cksum");
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
  if ((entry->flag_state & FLAG_STATE_UPLINK_FIN) &&
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
  timer_linkheap_modify(&local->timers, &entry->timer);
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
  port->portfunc(pkt, port->userdata);
  if (todelete)
  {
    entry->timer.time64 = time64 + 120ULL*1000ULL*1000ULL;
    entry->flag_state = FLAG_STATE_TIME_WAIT;
    timer_heap_modify(&local->timers, &entry->timer);
  }
  return 0;
}
