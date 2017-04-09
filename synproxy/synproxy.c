#include "synproxy.h"
#include "ipcksum.h"
#include "branchpredict.h"
#include <sys/time.h>

static inline uint64_t gettime64(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec*1000UL*1000UL + tv.tv_usec;
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

/*
  Uplink packet arrives. It has lan_ip:lan_port remote_ip:remote_port
  - Lookup by lan_ip:lan_port, verify remote_ip:remote_port
  Downlink packet arrives. It has wan_ip:wan_port remote_ip:remote_port
  - Lookup by wan_port, verify remote_ip:remote_port
 */

// return: whether to free (1) or not (0)
int uplink(
  struct synproxy *synproxy, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64)
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
  if (ip_frag_off(ip) >= 20)
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
    lan_port = tcp_src_port(ippay);
    remote_port = tcp_dst_port(ippay);
  }
  else
  {
    abort();
  }
  if (unlikely(tcp_syn(ippay)))
  {
    if (tcp_fin(ippay) || tcp_rst(ippay))
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SYN packet contains FIN or RST");
      return 1;
    }
    if (!tcp_ack(ippay))
    {
      entry = synproxy_hash_get(
        local, lan_ip, lan_port, remote_ip, remote_port);
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
      entry->flag_state = FLAG_STATE_UPLINK_SYN_SENT;
      entry->state_data.uplink_syn_sent.isn = tcp_seq_num(ippay);
      port->portfunc(pkt, port->userdata);
      return 0;
    }
    else
    {
      entry = synproxy_hash_get(
        local, lan_ip, lan_port, remote_ip, remote_port);
      if (entry == NULL)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SA/SA but entry nonexistent");
        return 1;
      }
      if (entry->flag_state != FLAG_STATE_DOWNLINK_SYN_SENT)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SA/SA, entry != DL_SYN_SENT");
        return 1;
      }
      if (tcp_ack_num(ippay) != entry->state_data.downlink_syn_sent.isn + 1)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SA/SA, invalid ACK num");
        return 1;
      }
      entry->flag_state = FLAG_STATE_ESTABLISHED;
      entry->timer.time64 = time64 + 86400ULL*1000ULL*1000ULL;
      timer_heap_modify(&local->timers, &entry->timer);
      // FIXME send ACK and ACK window update
      abort();
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
    if (tcp_rst(ippay))
    {
      if (!between(
        entry->lan_next, tcp_seq_num(ippay), entry->lan_next+entry->lan_window))
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
      if (tcp_ack_num(ippay) != entry->state_data.uplink_syn_rcvd.isn + 1)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid ACK number");
        return 1;
      }
      entry->flag_state = FLAG_STATE_ESTABLISHED;
      entry->timer.time64 = time64 + 86400ULL*1000ULL*1000ULL;
      timer_heap_modify(&local->timers, &entry->timer);
      port->portfunc(pkt, port->userdata);
      return 0;
    }
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "UPLINK_SYN_RECEIVED w/o ACK");
    return 1;
  }
  if (!synproxy_is_connected(entry))
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "not CONNECTED, dropping pkt");
    return 1;
  }
  if (unlikely(tcp_rst(ippay)))
  {
    if (!between(
      entry->lan_next, tcp_seq_num(ippay), entry->lan_next+entry->lan_window))
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "RST has invalid SEQ number");
      return 1;
    }
    tcp_set_seq_number_cksum_update(
      ippay, tcp_len, tcp_seq_number(ippay)+entry->seqoffset);
    synproxy_hash_del(local, entry);
    port->portfunc(pkt, port->userdata);
    return 0;
  }
  first_seq = tcp_seq_num(ippay);
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
    last_seq += 1;
  }
  if (
    !between(
      entry->lan_next, first_seq, entry->lan_next+entry->lan_window)
    &&
    !between(
      entry->lan_next, last_seq, entry->lan_next+entry->lan_window)
    )
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "packet has invalid SEQ number");
    return 1;
  }
  if (unlikely(tcp_fin(ippay)))
  {
    if (ip_more_frags(ip))
    {
      log_log(LOG_LEVEL_WARNING, "WORKERUPLINK", "FIN with more frags");
    }
    entry->state_data.established.upfin = last_seq;
    entry->flag_state |= FLAG_STATE_UPLINK_FIN;
  }
  if (unlikely(entry->flag_state & FLAG_STATE_DOWNLINK_FIN))
  {
    uint32_t fin = entry->state_data.established.downfin;
    if (tcp_ack_num(ippay) == fin)
    {
      entry->flag_state |= FLAG_STATE_DOWNLINK_FIN_ACK;
      if (entry->flag_state & FLAG_STATE_UPLINK_FIN_ACK)
      {
        todelete = 1;
      }
    }
  }
  if (likely(tcp_ack(ippay)))
  {
    uint32_t ack = tcp_ack_num(ippay);
    uint16_t window = tcp_window(ippay);
    if (seq_cmp(ack, entry->wan_next) >= 0)
    {
      entry->wan_next = ack;
      entry->wan_window = window << entry->wan_wscale;
    }
  }
  entry->timer.time64 = time64 + 86400ULL*1000ULL*1000ULL;
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
    tcp_set_window_cksum_update(
      ippay, tcp_len, tcp_window(ippay) << (-(entry->wscalediff)));
  }
  port->portfunc(pkt, port->userdata);
  if (todelete)
  {
    synproxy_hash_del(local, entry);
  }
  return 0;
}
