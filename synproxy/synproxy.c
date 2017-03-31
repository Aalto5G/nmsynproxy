#include "synproxy.h"
#include "ipcksum.h"

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
  e->local_ip = local_ip;
  e->local_port = local_port;
  e->remote_ip = remote_ip;
  e->remote_port = remote_port;
  hash_table_add(&local->hash, &e->node, synproxy_hash(e));
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
  struct port *port)
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
  struct synproxy_hash_entry *entry;
  if (ether_len < ETHER_HDR_LEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full Ether hdr");
    return 1;
  }
  if (ether_type(ether) != ETHER_TYPE_IP)
  {
    log_log(LOG_LEVEL_WARNING, "WORKERUPLINK", "not IPv4");
    return 1;
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
  if (ip_ttl(ip) <= 1)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt has TTL <= 1");
  }
#if 0
  if (ip_hdr_cksum_calc(ip, ihl) != 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt has invalid IP hdr cksum");
    return 1;
  }
#endif
  if (ip_frag_off(ip) != 0 || ip_more_frags(ip))
  {
    log_log(LOG_LEVEL_WARNING, "WORKERUPLINK", "pkt is fragmented");
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
    uint16_t tcp_len = ip_total_len(ip) - ihl;
    if (tcp_len < 20)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full TCP hdr");
      return 1;
    }
#if 0
    if (tcp_cksum_calc(ip, ihl, ippay, tcp_len) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt has invalid TCP cksum");
      return 1;
    }
#endif
    lan_port = tcp_src_port(ippay);
    remote_port = tcp_dst_port(ippay);
    if (tcp_syn(ippay))
    {
      abort();
    }
  }
  else if (protocol == 17)
  {
    uint16_t udp_len = ip_total_len(ip) - ihl;
    if (udp_len < 8)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full UDP hdr");
      return 1;
    }
#if 0
    if (udp_cksum_calc(ip, ihl, ippay, udp_len) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt has invalid UDP cksum");
      return 1;
    }
#endif
    lan_port = udp_src_port(ippay);
    remote_port = udp_dst_port(ippay);
  }
  else
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt not TCP or UDP");
    return 1;
  }
  entry = synproxy_hash_get(
    local, lan_ip, lan_port, remote_ip, remote_port);
  if (entry == NULL)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "entry not found");
    return 1;
  }
#if 0
  ip_set_hdr_cksum_calc(ip, ihl);
#endif
  port->portfunc(pkt, port->userdata);
  return 0;
}
