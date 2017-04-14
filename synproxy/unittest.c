#define _GNU_SOURCE
#include <pthread.h>
#include "synproxy.h"
#include "iphdr.h"
#include "ipcksum.h"
#include "packet.h"
#include "hashseed.h"
#include "log.h"

static inline uint64_t gettime64(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec*1000UL*1000UL + tv.tv_usec;
}

static struct packet *fetch_packet(struct linked_list_head *head)
{
  struct linked_list_node *n;
  if (linked_list_is_empty(head))
  {
    return NULL;
  }
  n = head->node.next;
  linked_list_delete(n);
  return CONTAINER_OF(n, struct packet, node);
}

#define POOL_SIZE 300
#define BLOCK_SIZE 1800

static void closed_port(void)
{
  struct port outport;
  uint64_t time64;
  struct packet *pktstruct;
  struct linked_list_head head;
  struct linkedlistfunc_userdata ud;
  char pkt[14+20+20] = {0};
  void *ether, *ip, *tcp;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct synproxy_hash_entry *e;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  hash_table_init(&local.hash, 8, synproxy_hash_fn, NULL);
  timer_heap_init_capacity(&local.timers, 131072);

  linked_list_head_init(&head);
  ud.head = &head;
  outport.userdata = &ud;
  outport.portfunc = linkedlistfunc;

  time64 = gettime64();

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
  ip_set_src(ip, (10<<24)|8);
  ip_set_dst(ip, (11<<24)|7);
  ip_set_hdr_cksum_calc(ip, 20);
  tcp = ip_payload(ip);
  tcp_set_src_port(tcp, 12345);
  tcp_set_dst_port(tcp, 54321);
  tcp_set_syn_on(tcp);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, isn1);
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);

  pktstruct = ll_alloc_st(&st, packet_size(sizeof(pkt)));
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sizeof(pkt);
  memcpy(packet_data(pktstruct), pkt, sizeof(pkt));
  if (uplink(&synproxy, &local, pktstruct, &outport, time64, &st))
  {
    ll_free_st(&st, pktstruct);
  }

  pktstruct = fetch_packet(&head);
  if (pktstruct == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "no packet out");
    exit(1);
  }
  if (pktstruct->sz != sizeof(pkt))
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
    exit(1);
  }
  if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
    exit(1);
  }
  if (memcmp(packet_data(pktstruct), pkt, sizeof(pkt)) != 0)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
    exit(1);
  }
  pktstruct = fetch_packet(&head);
  if (pktstruct != NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
    exit(1);
  }

  e = synproxy_hash_get(&local, (10<<24)|8, 12345, (11<<24)|7, 54321);
  if (e == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry not found");
    exit(1);
  }
  if (e->flag_state != FLAG_STATE_UPLINK_SYN_SENT)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "invalid flag state");
    exit(1);
  }

  ether = pkt;
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
  ip_set_src(ip, (11<<24)|7);
  ip_set_dst(ip, (10<<24)|8);
  ip_set_hdr_cksum_calc(ip, 20);
  tcp = ip_payload(ip);
  tcp_set_src_port(tcp, 54321);
  tcp_set_dst_port(tcp, 12345);
  tcp_set_rst_on(tcp);
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, isn2);
  tcp_set_ack_number(tcp, isn1 + 1);
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);

  pktstruct = ll_alloc_st(&st, packet_size(sizeof(pkt)));
  pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
  pktstruct->sz = sizeof(pkt);
  memcpy(packet_data(pktstruct), pkt, sizeof(pkt));
  if (downlink(&synproxy, &local, pktstruct, &outport, time64, &st))
  {
    ll_free_st(&st, pktstruct);
  }

  pktstruct = fetch_packet(&head);
  if (pktstruct == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "no packet out");
    exit(1);
  }
  if (pktstruct->sz != sizeof(pkt))
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
    exit(1);
  }
  if (pktstruct->direction != PACKET_DIRECTION_DOWNLINK)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
    exit(1);
  }
  if (memcmp(packet_data(pktstruct), pkt, sizeof(pkt)) != 0)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
    exit(1);
  }
  pktstruct = fetch_packet(&head);
  if (pktstruct != NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
    exit(1);
  }
  e = synproxy_hash_get(&local, (10<<24)|8, 12345, (11<<24)|7, 54321);
  if (e != NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry found");
    exit(1);
  }
}

static void three_way_handshake_impl(
  struct synproxy *synproxy,
  struct worker_local *local, struct ll_alloc_st *loc,
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2,
  unsigned transcli, unsigned transsrv)
{
  struct port outport;
  uint64_t time64;
  struct packet *pktstruct;
  struct linked_list_head head;
  struct linkedlistfunc_userdata ud;
  char pkt[14+20+20] = {0};
  void *ether, *ip, *tcp;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct synproxy_hash_entry *e = NULL;
  unsigned i;

  linked_list_head_init(&head);
  ud.head = &head;
  outport.userdata = &ud;
  outport.portfunc = linkedlistfunc;

  time64 = gettime64();

  for (i = 0; i < transcli; i++)
  {
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
    ip_set_src(ip, ip1);
    ip_set_dst(ip, ip2);
    ip_set_hdr_cksum_calc(ip, 20);
    tcp = ip_payload(ip);
    tcp_set_src_port(tcp, port1);
    tcp_set_dst_port(tcp, port2);
    tcp_set_syn_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, isn1);
    tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);
  
    pktstruct = ll_alloc_st(loc, packet_size(sizeof(pkt)));
    pktstruct->direction = PACKET_DIRECTION_UPLINK;
    pktstruct->sz = sizeof(pkt);
    memcpy(packet_data(pktstruct), pkt, sizeof(pkt));
    if (uplink(synproxy, local, pktstruct, &outport, time64, loc))
    {
      ll_free_st(loc, pktstruct);
    }
  
    pktstruct = fetch_packet(&head);
    if (pktstruct == NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "no packet out");
      exit(1);
    }
    if (pktstruct->sz != sizeof(pkt))
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
      exit(1);
    }
    if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
      exit(1);
    }
    if (memcmp(packet_data(pktstruct), pkt, sizeof(pkt)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
      exit(1);
    }
    pktstruct = fetch_packet(&head);
    if (pktstruct != NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
      exit(1);
    }
  
    e = synproxy_hash_get(local, ip1, port1, ip2, port2);
    if (e == NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "state entry not found");
      exit(1);
    }
    if (e->flag_state != FLAG_STATE_UPLINK_SYN_SENT)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid flag state");
      exit(1);
    }
  }

  for (i = 0; i < transsrv; i++)
  {
    ether = pkt;
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
    ip_set_src(ip, ip2);
    ip_set_dst(ip, ip1);
    ip_set_hdr_cksum_calc(ip, 20);
    tcp = ip_payload(ip);
    tcp_set_src_port(tcp, port2);
    tcp_set_dst_port(tcp, port1);
    tcp_set_syn_on(tcp);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, isn2);
    tcp_set_ack_number(tcp, isn1 + 1);
    tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);
  
    pktstruct = ll_alloc_st(loc, packet_size(sizeof(pkt)));
    pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
    pktstruct->sz = sizeof(pkt);
    memcpy(packet_data(pktstruct), pkt, sizeof(pkt));
    if (downlink(synproxy, local, pktstruct, &outport, time64, loc))
    {
      ll_free_st(loc, pktstruct);
    }
  
    pktstruct = fetch_packet(&head);
    if (pktstruct == NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "no packet out");
      exit(1);
    }
    if (pktstruct->sz != sizeof(pkt))
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
      exit(1);
    }
    if (pktstruct->direction != PACKET_DIRECTION_DOWNLINK)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
      exit(1);
    }
    if (memcmp(packet_data(pktstruct), pkt, sizeof(pkt)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
      exit(1);
    }
    pktstruct = fetch_packet(&head);
    if (pktstruct != NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
      exit(1);
    }
    if (e->flag_state != FLAG_STATE_UPLINK_SYN_RCVD)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid flag state");
      exit(1);
    }
  }

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
  ip_set_src(ip, ip1);
  ip_set_dst(ip, ip2);
  ip_set_hdr_cksum_calc(ip, 20);
  tcp = ip_payload(ip);
  tcp_set_src_port(tcp, port1);
  tcp_set_dst_port(tcp, port2);
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, isn1 + 1);
  tcp_set_ack_number(tcp, isn2 + 1);
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);

  pktstruct = ll_alloc_st(loc, packet_size(sizeof(pkt)));
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sizeof(pkt);
  memcpy(packet_data(pktstruct), pkt, sizeof(pkt));
  if (uplink(synproxy, local, pktstruct, &outport, time64, loc))
  {
    ll_free_st(loc, pktstruct);
  }

  pktstruct = fetch_packet(&head);
  if (pktstruct == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "no packet out");
    exit(1);
  }
  if (pktstruct->sz != sizeof(pkt))
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
    exit(1);
  }
  if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
    exit(1);
  }
  if (memcmp(packet_data(pktstruct), pkt, sizeof(pkt)) != 0)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
    exit(1);
  }
  pktstruct = fetch_packet(&head);
  if (pktstruct != NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
    exit(1);
  }
  if (e->flag_state != FLAG_STATE_ESTABLISHED)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "invalid flag state");
    exit(1);
  }
}

static void four_way_fin_impl(
  struct synproxy *synproxy,
  struct worker_local *local, struct ll_alloc_st *loc,
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2,
  unsigned transcli, unsigned transsrv)
{
  struct port outport;
  uint64_t time64;
  struct packet *pktstruct;
  struct linked_list_head head;
  struct linkedlistfunc_userdata ud;
  char pkt[14+20+20] = {0};
  void *ether, *ip, *tcp;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct synproxy_hash_entry *e;
  unsigned i;

  linked_list_head_init(&head);
  ud.head = &head;
  outport.userdata = &ud;
  outport.portfunc = linkedlistfunc;

  time64 = gettime64();

  e = synproxy_hash_get(local, ip1, port1, ip2, port2);
  if (e == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry not found");
    exit(1);
  }

  for (i = 0; i < transcli; i++)
  {
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
    ip_set_src(ip, ip1);
    ip_set_dst(ip, ip2);
    ip_set_hdr_cksum_calc(ip, 20);
    tcp = ip_payload(ip);
    tcp_set_src_port(tcp, port1);
    tcp_set_dst_port(tcp, port2);
    tcp_set_ack_on(tcp);
    tcp_set_fin_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, isn1 + 1);
    tcp_set_ack_number(tcp, isn2 + 1);
    tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);
  
    pktstruct = ll_alloc_st(loc, packet_size(sizeof(pkt)));
    pktstruct->direction = PACKET_DIRECTION_UPLINK;
    pktstruct->sz = sizeof(pkt);
    memcpy(packet_data(pktstruct), pkt, sizeof(pkt));
    if (uplink(synproxy, local, pktstruct, &outport, time64, loc))
    {
      ll_free_st(loc, pktstruct);
    }
  
    pktstruct = fetch_packet(&head);
    if (pktstruct == NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "no packet out");
      exit(1);
    }
    if (pktstruct->sz != sizeof(pkt))
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
      exit(1);
    }
    if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
      exit(1);
    }
    if (memcmp(packet_data(pktstruct), pkt, sizeof(pkt)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
      exit(1);
    }
    pktstruct = fetch_packet(&head);
    if (pktstruct != NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
      exit(1);
    }
    if (e->flag_state != (FLAG_STATE_ESTABLISHED|FLAG_STATE_UPLINK_FIN))
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid flag state");
      exit(1);
    }
  }

  ether = pkt;
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
  ip_set_src(ip, ip2);
  ip_set_dst(ip, ip1);
  ip_set_hdr_cksum_calc(ip, 20);
  tcp = ip_payload(ip);
  tcp_set_src_port(tcp, port2);
  tcp_set_dst_port(tcp, port1);
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, isn2 + 1);
  tcp_set_ack_number(tcp, isn1 + 2);
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);

  pktstruct = ll_alloc_st(loc, packet_size(sizeof(pkt)));
  pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
  pktstruct->sz = sizeof(pkt);
  memcpy(packet_data(pktstruct), pkt, sizeof(pkt));
  if (downlink(synproxy, local, pktstruct, &outport, time64, loc))
  {
    ll_free_st(loc, pktstruct);
  }

  pktstruct = fetch_packet(&head);
  if (pktstruct == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "no packet out");
    exit(1);
  }
  if (pktstruct->sz != sizeof(pkt))
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
    exit(1);
  }
  if (pktstruct->direction != PACKET_DIRECTION_DOWNLINK)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
    exit(1);
  }
  if (memcmp(packet_data(pktstruct), pkt, sizeof(pkt)) != 0)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
    exit(1);
  }
  pktstruct = fetch_packet(&head);
  if (pktstruct != NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
    exit(1);
  }
  if (e->flag_state != (FLAG_STATE_ESTABLISHED|FLAG_STATE_UPLINK_FIN|FLAG_STATE_UPLINK_FIN_ACK))
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "invalid flag state");
    exit(1);
  }

  for (i = 0; i < transsrv; i++)
  {
    ether = pkt;
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
    ip_set_src(ip, ip2);
    ip_set_dst(ip, ip1);
    ip_set_hdr_cksum_calc(ip, 20);
    tcp = ip_payload(ip);
    tcp_set_src_port(tcp, port2);
    tcp_set_dst_port(tcp, port1);
    tcp_set_ack_on(tcp);
    tcp_set_fin_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, isn2 + 1);
    tcp_set_ack_number(tcp, isn1 + 2);
    tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);
  
    pktstruct = ll_alloc_st(loc, packet_size(sizeof(pkt)));
    pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
    pktstruct->sz = sizeof(pkt);
    memcpy(packet_data(pktstruct), pkt, sizeof(pkt));
    if (downlink(synproxy, local, pktstruct, &outport, time64, loc))
    {
      ll_free_st(loc, pktstruct);
    }
  
    pktstruct = fetch_packet(&head);
    if (pktstruct == NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "no packet out");
      exit(1);
    }
    if (pktstruct->sz != sizeof(pkt))
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
      exit(1);
    }
    if (pktstruct->direction != PACKET_DIRECTION_DOWNLINK)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
      exit(1);
    }
    if (memcmp(packet_data(pktstruct), pkt, sizeof(pkt)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
      exit(1);
    }
    pktstruct = fetch_packet(&head);
    if (pktstruct != NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
      exit(1);
    }
    if (e->flag_state != (FLAG_STATE_ESTABLISHED|FLAG_STATE_UPLINK_FIN|FLAG_STATE_UPLINK_FIN_ACK|FLAG_STATE_DOWNLINK_FIN))
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid flag state");
      exit(1);
    }
  }

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
  ip_set_src(ip, ip1);
  ip_set_dst(ip, ip2);
  ip_set_hdr_cksum_calc(ip, 20);
  tcp = ip_payload(ip);
  tcp_set_src_port(tcp, port1);
  tcp_set_dst_port(tcp, port2);
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, isn1 + 2);
  tcp_set_ack_number(tcp, isn2 + 2);
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);

  pktstruct = ll_alloc_st(loc, packet_size(sizeof(pkt)));
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sizeof(pkt);
  memcpy(packet_data(pktstruct), pkt, sizeof(pkt));
  if (uplink(synproxy, local, pktstruct, &outport, time64, loc))
  {
    ll_free_st(loc, pktstruct);
  }

  pktstruct = fetch_packet(&head);
  if (pktstruct == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "no packet out");
    exit(1);
  }
  if (pktstruct->sz != sizeof(pkt))
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
    exit(1);
  }
  if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
    exit(1);
  }
  if (memcmp(packet_data(pktstruct), pkt, sizeof(pkt)) != 0)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
    exit(1);
  }
  pktstruct = fetch_packet(&head);
  if (pktstruct != NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
    exit(1);
  }
  if (e->flag_state != FLAG_STATE_TIME_WAIT)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "invalid flag state");
    exit(1);
  }
}

static void three_way_handshake_four_way_fin(void)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  hash_table_init(&local.hash, 8, synproxy_hash_fn, NULL);
  timer_heap_init_capacity(&local.timers, 131072);

  three_way_handshake_impl(
    &synproxy, &local, &loc, (10<<24)|2, (11<<24)|1, 12345, 54321, 1, 1);
  four_way_fin_impl(
    &synproxy, &local, &loc, (10<<24)|2, (11<<24)|1, 12345, 54321, 1, 1);
}

static void established_rst_uplink(void)
{
  struct port outport;
  uint64_t time64;
  struct packet *pktstruct;
  struct linked_list_head head;
  struct linkedlistfunc_userdata ud;
  char pkt[14+20+20] = {0};
  void *ether, *ip, *tcp;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  uint32_t isn1 = 0x12345678;
  //uint32_t isn2 = 0x87654321;
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct synproxy_hash_entry *e;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  hash_table_init(&local.hash, 8, synproxy_hash_fn, NULL);
  timer_heap_init_capacity(&local.timers, 131072);

  linked_list_head_init(&head);
  ud.head = &head;
  outport.userdata = &ud;
  outport.portfunc = linkedlistfunc;

  time64 = gettime64();

  three_way_handshake_impl(
    &synproxy, &local, &loc, (10<<24)|4, (11<<24)|3, 12345, 54321, 1, 1);

  e = synproxy_hash_get(&local, (10<<24)|4, 12345, (11<<24)|3, 54321);
  if (e == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry not found");
    exit(1);
  }

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
  ip_set_src(ip, (10<<24)|4);
  ip_set_dst(ip, (11<<24)|3);
  ip_set_hdr_cksum_calc(ip, 20);
  tcp = ip_payload(ip);
  tcp_set_src_port(tcp, 12345);
  tcp_set_dst_port(tcp, 54321);
  tcp_set_rst_on(tcp);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, isn1 + 1);
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);

  pktstruct = ll_alloc_st(&st, packet_size(sizeof(pkt)));
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sizeof(pkt);
  memcpy(packet_data(pktstruct), pkt, sizeof(pkt));
  if (uplink(&synproxy, &local, pktstruct, &outport, time64, &st))
  {
    ll_free_st(&st, pktstruct);
  }

  pktstruct = fetch_packet(&head);
  if (pktstruct == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "no packet out");
    exit(1);
  }
  if (pktstruct->sz != sizeof(pkt))
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
    exit(1);
  }
  if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
    exit(1);
  }
  if (memcmp(packet_data(pktstruct), pkt, sizeof(pkt)) != 0)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
    exit(1);
  }
  pktstruct = fetch_packet(&head);
  if (pktstruct != NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
    exit(1);
  }
  e = synproxy_hash_get(&local, (10<<24)|4, 12345, (11<<24)|3, 54321);
  if (e != NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry found");
    exit(1);
  }
}

static void established_rst_downlink(void)
{
  struct port outport;
  uint64_t time64;
  struct packet *pktstruct;
  struct linked_list_head head;
  struct linkedlistfunc_userdata ud;
  char pkt[14+20+20] = {0};
  void *ether, *ip, *tcp;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  //uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct synproxy_hash_entry *e;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  hash_table_init(&local.hash, 8, synproxy_hash_fn, NULL);
  timer_heap_init_capacity(&local.timers, 131072);

  linked_list_head_init(&head);
  ud.head = &head;
  outport.userdata = &ud;
  outport.portfunc = linkedlistfunc;

  time64 = gettime64();

  three_way_handshake_impl(
    &synproxy, &local, &loc, (10<<24)|6, (11<<24)|5, 12345, 54321, 1, 1);

  e = synproxy_hash_get(&local, (10<<24)|6, 12345, (11<<24)|5, 54321);
  if (e == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry not found");
    exit(1);
  }

  ether = pkt;
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
  ip_set_src(ip, (11<<24)|5);
  ip_set_dst(ip, (10<<24)|6);
  ip_set_hdr_cksum_calc(ip, 20);
  tcp = ip_payload(ip);
  tcp_set_src_port(tcp, 54321);
  tcp_set_dst_port(tcp, 12345);
  tcp_set_rst_on(tcp);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, isn2 + 1);
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);

  pktstruct = ll_alloc_st(&st, packet_size(sizeof(pkt)));
  pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
  pktstruct->sz = sizeof(pkt);
  memcpy(packet_data(pktstruct), pkt, sizeof(pkt));
  if (downlink(&synproxy, &local, pktstruct, &outport, time64, &st))
  {
    ll_free_st(&st, pktstruct);
  }

  pktstruct = fetch_packet(&head);
  if (pktstruct == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "no packet out");
    exit(1);
  }
  if (pktstruct->sz != sizeof(pkt))
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
    exit(1);
  }
  if (pktstruct->direction != PACKET_DIRECTION_DOWNLINK)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
    exit(1);
  }
  if (memcmp(packet_data(pktstruct), pkt, sizeof(pkt)) != 0)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
    exit(1);
  }
  pktstruct = fetch_packet(&head);
  if (pktstruct != NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
    exit(1);
  }
  e = synproxy_hash_get(&local, (10<<24)|6, 12345, (11<<24)|5, 54321);
  if (e != NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry found");
    exit(1);
  }
}

static void three_way_handshake_ulretransmit(void)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  hash_table_init(&local.hash, 8, synproxy_hash_fn, NULL);
  timer_heap_init_capacity(&local.timers, 131072);

  three_way_handshake_impl(
    &synproxy, &local, &st, (10<<24)|10, (11<<24)|9, 12345, 54321, 2, 1);
  four_way_fin_impl(
    &synproxy, &local, &st, (10<<24)|10, (11<<24)|9, 12345, 54321, 1, 1);
}

static void three_way_handshake_dlretransmit(void)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  hash_table_init(&local.hash, 8, synproxy_hash_fn, NULL);
  timer_heap_init_capacity(&local.timers, 131072);

  three_way_handshake_impl(
    &synproxy, &local, &st, (10<<24)|12, (11<<24)|11, 12345, 54321, 1, 2);
  four_way_fin_impl(
    &synproxy, &local, &st, (10<<24)|12, (11<<24)|11, 12345, 54321, 1, 1);
}

int main(int argc, char **argv)
{
  hash_seed_init();
  setlinebuf(stdout);

  three_way_handshake_four_way_fin();

  established_rst_uplink();

  established_rst_downlink();

  closed_port();

  three_way_handshake_ulretransmit();

  three_way_handshake_dlretransmit();

  return 0;
}
