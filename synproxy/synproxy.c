#include "synproxy.h"
#include "ipcksum.h"
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

void synproxy_hash_put(
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
    abort();
  }
  memset(e, 0, sizeof(*e));
  e->local_ip = local_ip;
  e->local_port = local_port;
  e->remote_ip = remote_ip;
  e->remote_port = remote_port;
  hash_table_add(&local->hash, &e->node, synproxy_hash(e));
  e->timer.time64 = gettime64() + 86400ULL*1000ULL*1000ULL;
  e->timer.fn = synproxy_expiry_fn;
  e->timer.userdata = local;
  timer_linkheap_add(&local->timers, &e->timer);
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
  if (ip_frag_off(ip) != 0)
  {
    port->portfunc(pkt, port->userdata);
    return 0;
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
  entry = synproxy_hash_get(
    local, lan_ip, lan_port, remote_ip, remote_port);
  if (entry == NULL)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "entry not found");
    return 1;
  }
  if (tcp_syn(ippay))
  {
    abort();
  }
  if (!synproxy_is_connected(entry))
  {
    abort();
  }
  if (tcp_rst(ippay))
  {
    abort();
  }
  if (tcp_fin(ippay))
  {
    abort();
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
  return 0;
}
