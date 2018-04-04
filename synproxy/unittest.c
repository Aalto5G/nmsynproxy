#define _GNU_SOURCE
#include <pthread.h>
#include "synproxy.h"
#include "iphdr.h"
#include "ipcksum.h"
#include "packet.h"
#include "hashseed.h"
#include "log.h"
#include "yyutils.h"
#include "time64.h"

const char *argv0;

struct tcp_ctx {
  int version;
  uint32_t seq;
  uint32_t seq1;
  uint32_t seq2;
  uint32_t ulflowlabel;
  uint32_t dlflowlabel;
  union {
    char ipv6[16];
    uint32_t ipv4;
  } ip1;
  union {
    char ipv6[16];
    uint32_t ipv4;
  } ip2;
  uint16_t port1;
  uint16_t port2;
};

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

static void uplink_impl(
  struct synproxy *synproxy,
  struct worker_local *local, struct ll_alloc_st *loc,
  struct tcp_ctx *ctx,
  unsigned pkts)
{
  struct port outport;
  uint64_t time64;
  struct packet *pktstruct;
  struct linked_list_head head;
  struct linkedlistfunc_userdata ud;
  char pkt[1514] = {0};
  char pktsmall[14+20+40] = {0};
  void *ether, *ip, *tcp;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  unsigned i;
  
  linked_list_head_init(&head);
  ud.head = &head;
  outport.userdata = &ud;
  outport.portfunc = linkedlistfunc;

  time64 = gettime64();

  if (ctx->version != 4 && ctx->version != 6)
  {
    abort();
  }

  for (i = 0; i < pkts; i++)
  {
    ether = pkt;
    memset(pkt, 0, sizeof(pkt));
    memcpy(ether_dst(ether), lan_mac, 6);
    memcpy(ether_src(ether), cli_mac, 6);
    ether_set_type(ether, ctx->version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
    ip = ether_payload(ether);
    ip_set_version(ip, ctx->version);
    ip46_set_min_hdr_len(ip);
    ip46_set_total_len(ip, sizeof(pkt) - 14);
    ip46_set_dont_frag(ip, 1);
    ip46_set_flow_label(ip, ctx->ulflowlabel);
    ip46_set_id(ip, 0);
    ip46_set_ttl(ip, 64);
    ip46_set_proto(ip, 6);
    ip46_set_src(ip, &ctx->ip1);
    ip46_set_dst(ip, &ctx->ip2);
    ip46_set_hdr_cksum_calc(ip);
    tcp = ip46_payload(ip);
    tcp_set_src_port(tcp, ctx->port1);
    tcp_set_dst_port(tcp, ctx->port2);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, ctx->seq1);
    tcp_set_ack_number(tcp, ctx->seq2);
    tcp46_set_cksum_calc(ip);
    ctx->seq1 += sizeof(pkt) - 14 - ip46_hdr_len(ip) - 20;
    ctx->seq += sizeof(pkt) - 14 - ip46_hdr_len(ip) - 20;

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
    if (pktstruct->sz != 1514)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
      exit(1);
    }
    if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
      exit(1);
    }
    ip = ether_payload(packet_data(pktstruct));
    if (memcmp(ip46_src(ip), &ctx->ip1, ctx->version == 4 ? 4 : 16) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
      exit(1);
    }
    if (memcmp(ip46_dst(ip), &ctx->ip2, ctx->version == 4 ? 4 : 16) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
      exit(1);
    }
    if (ip46_proto(ip) != 6)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
      exit(1);
    }
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
      exit(1);
    }
    tcp = ip46_payload(ip);
    if (tcp_syn(tcp) || !tcp_ack(tcp))
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet flags don't agree");
      exit(1);
    }
    if (tcp_src_port(tcp) != ctx->port1)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src port doesn't agree");
      exit(1);
    }
    if (tcp_dst_port(tcp) != ctx->port2)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst port doesn't agree");
      exit(1);
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid TCP checksum");
      exit(1);
    }
    ll_free_st(loc, pktstruct);
    pktstruct = fetch_packet(&head);
    if (pktstruct != NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
      exit(1);
    }

    ether = pktsmall;
    memset(pktsmall, 0, sizeof(pktsmall));
    memcpy(ether_dst(ether), cli_mac, 6);
    memcpy(ether_src(ether), lan_mac, 6);
    ether_set_type(ether, ctx->version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
    ip = ether_payload(ether);
    ip_set_version(ip, ctx->version);
    ip46_set_min_hdr_len(ip);
    ip46_set_payload_len(ip, 20);
    ip46_set_dont_frag(ip, 1);
    ip46_set_id(ip, 0);
    ip46_set_ttl(ip, 64);
    ip46_set_proto(ip, 6);
    ip46_set_src(ip, &ctx->ip2);
    ip46_set_dst(ip, &ctx->ip1);
    ip46_set_hdr_cksum_calc(ip);
    tcp = ip46_payload(ip);
    tcp_set_src_port(tcp, ctx->port2);
    tcp_set_dst_port(tcp, ctx->port1);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, ctx->seq2);
    tcp_set_ack_number(tcp, ctx->seq);
    tcp46_set_cksum_calc(ip);

    pktstruct = ll_alloc_st(loc, packet_size(14 + ip46_total_len(ip)));
    pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
    pktstruct->sz = 14 + ip46_total_len(ip);
    memcpy(packet_data(pktstruct), pktsmall, 14 + ip46_total_len(ip));
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
    if (pktstruct->sz != 14 + (ctx->version == 4 ? 20 : 40) + 20)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
      exit(1);
    }
    if (pktstruct->direction != PACKET_DIRECTION_DOWNLINK)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
      exit(1);
    }
    ip = ether_payload(packet_data(pktstruct));
    if (memcmp(ip46_src(ip), &ctx->ip2, ctx->version == 4 ? 4 : 16) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
      exit(1);
    }
    if (memcmp(ip46_dst(ip), &ctx->ip1, ctx->version == 4 ? 4 : 16) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
      exit(1);
    }
    if (ip46_proto(ip) != 6)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
      exit(1);
    }
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
      exit(1);
    }
    tcp = ip46_payload(ip);
    if (tcp_syn(tcp) || !tcp_ack(tcp))
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet flags don't agree");
      exit(1);
    }
    if (tcp_src_port(tcp) != ctx->port2)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src port doesn't agree");
      exit(1);
    }
    if (tcp_dst_port(tcp) != ctx->port1)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst port doesn't agree");
      exit(1);
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid TCP checksum");
      exit(1);
    }
    ll_free_st(loc, pktstruct);
    pktstruct = fetch_packet(&head);
    if (pktstruct != NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
      exit(1);
    }
  }
}

static void downlink_impl(
  struct synproxy *synproxy,
  struct worker_local *local, struct ll_alloc_st *loc,
  struct tcp_ctx *ctx,
  unsigned pkts)
{
  struct port outport;
  uint64_t time64;
  struct packet *pktstruct;
  struct linked_list_head head;
  struct linkedlistfunc_userdata ud;
  char pkt[1514] = {0};
  char pktsmall[14+20+20] = {0};
  void *ether, *ip, *tcp;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  unsigned i;
  
  linked_list_head_init(&head);
  ud.head = &head;
  outport.userdata = &ud;
  outport.portfunc = linkedlistfunc;

  time64 = gettime64();

  if (ctx->version != 4 && ctx->version != 6)
  {
    abort();
  }

  for (i = 0; i < pkts; i++)
  {
    ether = pkt;
    memset(pkt, 0, sizeof(pkt));
    memcpy(ether_dst(ether), cli_mac, 6);
    memcpy(ether_src(ether), lan_mac, 6);
    ether_set_type(ether, ctx->version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
    ip = ether_payload(ether);
    ip_set_version(ip, ctx->version);
    ip46_set_min_hdr_len(ip);
    ip46_set_total_len(ip, sizeof(pkt) - 14);
    ip46_set_dont_frag(ip, 1);
    ip46_set_id(ip, 0);
    ip46_set_ttl(ip, 64);
    ip46_set_proto(ip, 6);
    ip46_set_src(ip, &ctx->ip2);
    ip46_set_dst(ip, &ctx->ip1);
    ip46_set_hdr_cksum_calc(ip);
    tcp = ip46_payload(ip);
    tcp_set_src_port(tcp, ctx->port2);
    tcp_set_dst_port(tcp, ctx->port1);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, ctx->seq2);
    tcp_set_ack_number(tcp, ctx->seq);
    tcp46_set_cksum_calc(ip);
    ctx->seq2 += sizeof(pkt) - 14 - ip46_hdr_len(ip) - 20;

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
    if (pktstruct->sz != 1514)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
      exit(1);
    }
    if (pktstruct->direction != PACKET_DIRECTION_DOWNLINK)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
      exit(1);
    }
    ip = ether_payload(packet_data(pktstruct));
    if (memcmp(ip46_src(ip), &ctx->ip2, ctx->version == 4 ? 4 : 16) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
      exit(1);
    }
    if (memcmp(ip46_dst(ip), &ctx->ip1, ctx->version == 4 ? 4 : 16) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
      exit(1);
    }
    if (ip46_proto(ip) != 6)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
      exit(1);
    }
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
      exit(1);
    }
    tcp = ip46_payload(ip);
    if (tcp_syn(tcp) || !tcp_ack(tcp))
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet flags don't agree");
      exit(1);
    }
    if (tcp_src_port(tcp) != ctx->port2)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src port doesn't agree");
      exit(1);
    }
    if (tcp_dst_port(tcp) != ctx->port1)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst port doesn't agree");
      exit(1);
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid TCP checksum");
      exit(1);
    }
    ll_free_st(loc, pktstruct);
    pktstruct = fetch_packet(&head);
    if (pktstruct != NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
      exit(1);
    }

    ether = pktsmall;
    memset(pktsmall, 0, sizeof(pktsmall));
    memcpy(ether_dst(ether), lan_mac, 6);
    memcpy(ether_src(ether), cli_mac, 6);
    ether_set_type(ether, ctx->version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
    ip = ether_payload(ether);
    ip_set_version(ip, ctx->version);
    ip46_set_min_hdr_len(ip);
    ip46_set_payload_len(ip, 20);
    ip46_set_dont_frag(ip, 1);
    ip46_set_id(ip, 0);
    ip46_set_ttl(ip, 64);
    ip46_set_proto(ip, 6);
    ip46_set_src(ip, &ctx->ip1);
    ip46_set_dst(ip, &ctx->ip2);
    ip46_set_hdr_cksum_calc(ip);
    tcp = ip46_payload(ip);
    tcp_set_src_port(tcp, ctx->port1);
    tcp_set_dst_port(tcp, ctx->port2);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, ctx->seq1);
    tcp_set_ack_number(tcp, ctx->seq2);
    tcp46_set_cksum_calc(ip);

    pktstruct = ll_alloc_st(loc, packet_size(14 + ip46_total_len(ip)));
    pktstruct->direction = PACKET_DIRECTION_UPLINK;
    pktstruct->sz = 14 + ip46_total_len(ip);
    memcpy(packet_data(pktstruct), pktsmall, 14 + ip46_total_len(ip));
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
    if (pktstruct->sz != 14 + 20 + (ctx->version == 4 ? 20 : 40))
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
      exit(1);
    }
    if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
      exit(1);
    }
    ip = ether_payload(packet_data(pktstruct));
    if (memcmp(ip46_src(ip), &ctx->ip1, ctx->version == 4 ? 4 : 16) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
      exit(1);
    }
    if (memcmp(ip46_dst(ip), &ctx->ip2, ctx->version == 4 ? 4 : 16) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
      exit(1);
    }
    if (ip46_proto(ip) != 6)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
      exit(1);
    }
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
      exit(1);
    }
    tcp = ip46_payload(ip);
    if (tcp_syn(tcp) || !tcp_ack(tcp))
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet flags don't agree");
      exit(1);
    }
    if (tcp_src_port(tcp) != ctx->port1)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src port doesn't agree");
      exit(1);
    }
    if (tcp_dst_port(tcp) != ctx->port2)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst port doesn't agree");
      exit(1);
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid TCP checksum");
      exit(1);
    }
    ll_free_st(loc, pktstruct);
    pktstruct = fetch_packet(&head);
    if (pktstruct != NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
      exit(1);
    }
  }
}

struct synproxy_hash_ctx hashctx = {
  .locked = 1
};

static void synproxy_closed_port_impl(
  struct synproxy *synproxy,
  struct worker_local *local, struct ll_alloc_st *loc,
  int version,
  const void *ip1, const void *ip2, uint16_t port1, uint16_t port2,
  uint32_t *isn,
  unsigned transsyn, unsigned transack, unsigned transrst)
{
  struct port outport;
  uint64_t time64;
  struct packet *pktstruct;
  struct linked_list_head head;
  struct linkedlistfunc_userdata ud;
  char pkt[14+40+20] = {0};
  void *ether, *ip, *tcp;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  //uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct synproxy_hash_entry *e = NULL;
  unsigned i;
  size_t sz = (version == 4) ? sizeof(pkt) - 20 : sizeof(pkt);

  linked_list_head_init(&head);
  ud.head = &head;
  outport.userdata = &ud;
  outport.portfunc = linkedlistfunc;

  time64 = gettime64();

  for (i = 0; i < transsyn; i++)
  {
    ether = pkt;
    memset(pkt, 0, sizeof(pkt));
    memcpy(ether_dst(ether), cli_mac, 6);
    memcpy(ether_src(ether), lan_mac, 6);
    ether_set_type(ether, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
    ip = ether_payload(ether);
    ip_set_version(ip, version);
    ip46_set_min_hdr_len(ip);
    ip46_set_payload_len(ip, 20);
    ip46_set_dont_frag(ip, 1);
    ip46_set_id(ip, 0);
    ip46_set_ttl(ip, 64);
    ip46_set_proto(ip, 6);
    ip46_set_src(ip, ip2);
    ip46_set_dst(ip, ip1);
    ip46_set_hdr_cksum_calc(ip);
    tcp = ip46_payload(ip);
    tcp_set_src_port(tcp, port2);
    tcp_set_dst_port(tcp, port1);
    tcp_set_syn_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, isn2);
    tcp46_set_cksum_calc(ip);
  
    pktstruct = ll_alloc_st(loc, packet_size(sz));
    pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
    pktstruct->sz = sz;
    memcpy(packet_data(pktstruct), pkt, sz);
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
    if (pktstruct->sz < ((version == 4) ? 14+20+20 : 14+40+20))
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
      exit(1);
    }
    if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
      exit(1);
    }
    ip = ether_payload(packet_data(pktstruct));
    if (memcmp(ip46_src(ip), ip1, version == 4 ? 4 : 16) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
      exit(1);
    }
    if (memcmp(ip46_dst(ip), ip2, version == 4 ? 4 : 16) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
      exit(1);
    }
    if (ip46_proto(ip) != 6)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
      exit(1);
    }
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
      exit(1);
    }
    tcp = ip46_payload(ip);
    if (!tcp_syn(tcp) || !tcp_ack(tcp))
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet flags don't agree");
      exit(1);
    }
    if (tcp_src_port(tcp) != port1)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src port doesn't agree");
      exit(1);
    }
    if (tcp_dst_port(tcp) != port2)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst port doesn't agree");
      exit(1);
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid TCP checksum");
      exit(1);
    }
    *isn = tcp_seq_number(tcp);
    ll_free_st(loc, pktstruct);
    pktstruct = fetch_packet(&head);
    if (pktstruct != NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
      exit(1);
    }
  
    e = synproxy_hash_get(local, version, ip1, port1, ip2, port2, &hashctx);
    if (e != NULL && synproxy->conf->halfopen_cache_max == 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "state entry found");
      exit(1);
    }
  }

  for (i = 0; i < transack; i++)
  {
    ether = pkt;
    memset(pkt, 0, sizeof(pkt));
    memcpy(ether_dst(ether), cli_mac, 6);
    memcpy(ether_src(ether), lan_mac, 6);
    ether_set_type(ether, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
    ip = ether_payload(ether);
    ip_set_version(ip, version);
    ip46_set_min_hdr_len(ip);
    ip46_set_total_len(ip, sizeof(pkt) - 14);
    ip46_set_dont_frag(ip, 1);
    ip46_set_id(ip, 0);
    ip46_set_ttl(ip, 64);
    ip46_set_proto(ip, 6);
    ip46_set_src(ip, ip2);
    ip46_set_dst(ip, ip1);
    ip46_set_hdr_cksum_calc(ip);
    tcp = ip46_payload(ip);
    tcp_set_src_port(tcp, port2);
    tcp_set_dst_port(tcp, port1);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, isn2 + 1);
    tcp_set_ack_number(tcp, (*isn) + 1);
    tcp46_set_cksum_calc(ip);
  
    pktstruct = ll_alloc_st(loc, packet_size(sizeof(pkt)));
    pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
    pktstruct->sz = sizeof(pkt);
    memcpy(packet_data(pktstruct), pkt, sizeof(pkt));
    if (downlink(synproxy, local, pktstruct, &outport, time64, loc))
    {
      ll_free_st(loc, pktstruct);
    }
  
    pktstruct = fetch_packet(&head);
    if (i == 0)
    {
      if (pktstruct == NULL)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "no packet out");
        exit(1);
      }
      if (pktstruct->sz < 14+20+20)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
        exit(1);
      }
      if (pktstruct->direction != PACKET_DIRECTION_DOWNLINK)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
        exit(1);
      }
      ip = ether_payload(packet_data(pktstruct));
      if (memcmp(ip46_src(ip), ip2, version == 4 ? 4 : 16) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
        exit(1);
      }
      if (memcmp(ip46_dst(ip), ip1, version == 4 ? 4 : 16) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
        exit(1);
      }
      if (ip46_proto(ip) != 6)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
        exit(1);
      }
      if (ip46_hdr_cksum_calc(ip) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
        exit(1);
      }
      tcp = ip46_payload(ip);
      if (!tcp_syn(tcp) || tcp_ack(tcp))
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet flags don't agree");
        exit(1);
      }
      if (tcp_src_port(tcp) != port2)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet src port doesn't agree");
        exit(1);
      }
      if (tcp_dst_port(tcp) != port1)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst port doesn't agree");
        exit(1);
      }
      if (tcp46_cksum_calc(ip) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid TCP checksum");
        exit(1);
      }
      ll_free_st(loc, pktstruct);
    }
    pktstruct = fetch_packet(&head);
    if (pktstruct != NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
      exit(1);
    }
    e = synproxy_hash_get(local, version, ip1, port1, ip2, port2, &hashctx);
    if (e == NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "state entry not found");
      exit(1);
    }
    if (e->flag_state != FLAG_STATE_DOWNLINK_SYN_SENT)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid flag state");
      exit(1);
    }
  }

  for (i = 0; i < transrst; i++)
  {
    ether = pkt;
    memset(pkt, 0, sizeof(pkt));
    memcpy(ether_dst(ether), lan_mac, 6);
    memcpy(ether_src(ether), cli_mac, 6);
    ether_set_type(ether, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
    ip = ether_payload(ether);
    ip_set_version(ip, version);
    ip46_set_min_hdr_len(ip);
    ip46_set_total_len(ip, sizeof(pkt) - 14);
    ip46_set_dont_frag(ip, 1);
    ip46_set_id(ip, 0);
    ip46_set_ttl(ip, 64);
    ip46_set_proto(ip, 6);
    ip46_set_src(ip, ip1);
    ip46_set_dst(ip, ip2);
    ip46_set_hdr_cksum_calc(ip);
    tcp = ip46_payload(ip);
    tcp_set_src_port(tcp, port1);
    tcp_set_dst_port(tcp, port2);
    tcp_set_rst_on(tcp);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, 0);
    tcp_set_ack_number(tcp, isn2 + 1);
    tcp46_set_cksum_calc(ip);
  
    pktstruct = ll_alloc_st(loc, packet_size(sizeof(pkt)));
    pktstruct->direction = PACKET_DIRECTION_UPLINK;
    pktstruct->sz = sizeof(pkt);
    memcpy(packet_data(pktstruct), pkt, sizeof(pkt));
    if (uplink(synproxy, local, pktstruct, &outport, time64, loc))
    {
      ll_free_st(loc, pktstruct);
    }
  
    if (i == 0)
    {
      pktstruct = fetch_packet(&head);
      if (pktstruct == NULL)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "no packet out");
        exit(1);
      }
      if (pktstruct->sz < 14+20+20)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
        exit(1);
      }
      if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
        exit(1);
      }
      ip = ether_payload(packet_data(pktstruct));
      if (memcmp(ip46_src(ip), ip1, version == 4 ? 4 : 16))
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
        exit(1);
      }
      if (memcmp(ip46_dst(ip), ip2, version == 4 ? 4 : 16))
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
        exit(1);
      }
      if (ip46_proto(ip) != 6)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
        exit(1);
      }
      if (ip46_hdr_cksum_calc(ip) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
        exit(1);
      }
      tcp = ip46_payload(ip);
      if (tcp_syn(tcp) || tcp_ack(tcp) || tcp_fin(tcp) || !tcp_rst(tcp))
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet flags don't agree");
        exit(1);
      }
      if (tcp_seq_number(tcp) != (*isn) + 1)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet SEQ number doesn't agree");
        exit(1);
      }
      if (tcp_ack_number(tcp) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet ACK number doesn't agree");
        exit(1);
      }
      if (tcp_src_port(tcp) != port1)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet src port doesn't agree");
        exit(1);
      }
      if (tcp_dst_port(tcp) != port2)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst port doesn't agree");
        exit(1);
      }
      if (tcp46_cksum_calc(ip) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid TCP checksum");
        exit(1);
      }
      ll_free_st(loc, pktstruct);
    }
    pktstruct = fetch_packet(&head);
    if (pktstruct != NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
      exit(1);
    }
    e = synproxy_hash_get(local, version, ip1, port1, ip2, port2, &hashctx);
    if (e == NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "entry not found");
      exit(1);
    }
    if (e->flag_state != FLAG_STATE_RESETED)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "entry not RESETED");
      exit(1);
    }
  }
}

static void closed_port(int version)
{
  struct port outport;
  uint64_t time64;
  struct packet *pktstruct;
  struct linked_list_head head;
  struct linkedlistfunc_userdata ud;
  char pkt[14+40+20] = {0};
  void *ether, *ip, *tcp;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct synproxy_hash_entry *e;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  linked_list_head_init(&head);
  ud.head = &head;
  outport.userdata = &ud;
  outport.portfunc = linkedlistfunc;

  time64 = gettime64();

  ether = pkt;
  memset(pkt, 0, sizeof(pkt));
  memcpy(ether_dst(ether), lan_mac, 6);
  memcpy(ether_src(ether), cli_mac, 6);
  ether_set_type(ether, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(ether);
  ip_set_version(ip, version);
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, 20);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0);
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, src);
  ip46_set_dst(ip, dst);
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, 12345);
  tcp_set_dst_port(tcp, 54321);
  tcp_set_syn_on(tcp);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, isn1);
  tcp46_set_cksum_calc(ip);

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
  ll_free_st(&st, pktstruct);
  pktstruct = fetch_packet(&head);
  if (pktstruct != NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
    exit(1);
  }

  e = synproxy_hash_get(&local, version, src, 12345, dst, 54321, &hashctx);
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
  ether_set_type(ether, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(ether);
  ip_set_version(ip, version);
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, 20);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0);
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, dst);
  ip46_set_dst(ip, src);
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, 54321);
  tcp_set_dst_port(tcp, 12345);
  tcp_set_rst_on(tcp);
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, isn2);
  tcp_set_ack_number(tcp, isn1 + 1);
  tcp46_set_cksum_calc(ip);

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
  ll_free_st(&st, pktstruct);
  pktstruct = fetch_packet(&head);
  if (pktstruct != NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
    exit(1);
  }
  e = synproxy_hash_get(&local, version, src, 12345, dst, 54321, &hashctx);
  if (e == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry not found");
    exit(1);
  }
  if (e->flag_state != FLAG_STATE_RESETED)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry not RESETED");
    exit(1);
  }

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void three_way_handshake_impl(
  struct synproxy *synproxy,
  struct worker_local *local, struct ll_alloc_st *loc,
  int version,
  const void *ip1, const void *ip2, uint16_t port1, uint16_t port2,
  unsigned transcli, unsigned transsrv)
{
  struct port outport;
  uint64_t time64;
  struct packet *pktstruct;
  struct linked_list_head head;
  struct linkedlistfunc_userdata ud;
  char pkt[14+40+20] = {0};
  void *ether, *ip, *tcp;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct synproxy_hash_entry *e = NULL;
  unsigned i;
  size_t sz = ((version == 4) ? (sizeof(pkt) - 20) : sizeof(pkt));

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
    ether_set_type(ether, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
    ip = ether_payload(ether);
    ip_set_version(ip, version);
    ip46_set_min_hdr_len(ip);
    ip46_set_payload_len(ip, 20);
    ip46_set_dont_frag(ip, 1);
    ip46_set_id(ip, 0);
    ip46_set_ttl(ip, 64);
    ip46_set_proto(ip, 6);
    ip46_set_src(ip, ip1);
    ip46_set_dst(ip, ip2);
    ip46_set_hdr_cksum_calc(ip);
    tcp = ip46_payload(ip);
    tcp_set_src_port(tcp, port1);
    tcp_set_dst_port(tcp, port2);
    tcp_set_syn_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, isn1);
    tcp46_set_cksum_calc(ip);
  
    pktstruct = ll_alloc_st(loc, packet_size(sz));
    pktstruct->direction = PACKET_DIRECTION_UPLINK;
    pktstruct->sz = sz;
    memcpy(packet_data(pktstruct), pkt, sz);
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
    if (pktstruct->sz != sz)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
      exit(1);
    }
    if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
      exit(1);
    }
    if (memcmp(packet_data(pktstruct), pkt, sz) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
      exit(1);
    }
    ll_free_st(loc, pktstruct);
    pktstruct = fetch_packet(&head);
    if (pktstruct != NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
      exit(1);
    }
  
    e = synproxy_hash_get(local, version, ip1, port1, ip2, port2, &hashctx);
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
    ether_set_type(ether, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
    ip = ether_payload(ether);
    ip_set_version(ip, version);
    ip46_set_min_hdr_len(ip);
    ip46_set_payload_len(ip, 20);
    ip46_set_dont_frag(ip, 1);
    ip46_set_id(ip, 0);
    ip46_set_ttl(ip, 64);
    ip46_set_proto(ip, 6);
    ip46_set_src(ip, ip2);
    ip46_set_dst(ip, ip1);
    ip46_set_hdr_cksum_calc(ip);
    tcp = ip46_payload(ip);
    tcp_set_src_port(tcp, port2);
    tcp_set_dst_port(tcp, port1);
    tcp_set_syn_on(tcp);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, isn2);
    tcp_set_ack_number(tcp, isn1 + 1);
    tcp46_set_cksum_calc(ip);
  
    pktstruct = ll_alloc_st(loc, packet_size(sz));
    pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
    pktstruct->sz = sz;
    memcpy(packet_data(pktstruct), pkt, sz);
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
    if (pktstruct->sz != sz)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
      exit(1);
    }
    if (pktstruct->direction != PACKET_DIRECTION_DOWNLINK)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
      exit(1);
    }
    if (memcmp(packet_data(pktstruct), pkt, sz) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
      exit(1);
    }
    ll_free_st(loc, pktstruct);
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
  ether_set_type(ether, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(ether);
  ip_set_version(ip, version);
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, 20);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0);
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, ip1);
  ip46_set_dst(ip, ip2);
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, port1);
  tcp_set_dst_port(tcp, port2);
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, isn1 + 1);
  tcp_set_ack_number(tcp, isn2 + 1);
  tcp46_set_cksum_calc(ip);

  pktstruct = ll_alloc_st(loc, packet_size(sz));
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sz;
  memcpy(packet_data(pktstruct), pkt, sz);
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
  if (pktstruct->sz != sz)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
    exit(1);
  }
  if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
    exit(1);
  }
  if (memcmp(packet_data(pktstruct), pkt, sz) != 0)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
    exit(1);
  }
  ll_free_st(loc, pktstruct);
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

static void synproxy_handshake_impl(
  struct synproxy *synproxy,
  struct worker_local *local, struct ll_alloc_st *loc,
  int version,
  const void *ip1, const void *ip2, uint16_t port1, uint16_t port2,
  uint32_t *isn,
  unsigned transsyn, unsigned transack, unsigned transsynack,
  int keepalive, int one_byte_payload)
{
  struct port outport;
  uint64_t time64;
  struct packet *pktstruct;
  struct linked_list_head head;
  struct linkedlistfunc_userdata ud;
  char pkt[14+40+20+1] = {0};
  void *ether, *ip, *tcp;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct synproxy_hash_entry *e = NULL;
  unsigned i;
  size_t sz;
  sz = version == 4 ? sizeof(pkt) - 20 : sizeof(pkt);

  linked_list_head_init(&head);
  ud.head = &head;
  outport.userdata = &ud;
  outport.portfunc = linkedlistfunc;

  time64 = gettime64();

  for (i = 0; i < transsyn; i++)
  {
    ether = pkt;
    memset(pkt, 0, sizeof(pkt));
    memcpy(ether_dst(ether), cli_mac, 6);
    memcpy(ether_src(ether), lan_mac, 6);
    ether_set_type(ether, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
    ip = ether_payload(ether);
    ip_set_version(ip, version);
    ip46_set_min_hdr_len(ip);
    ip46_set_payload_len(ip, 20);
    ip46_set_dont_frag(ip, 1);
    ip46_set_id(ip, 0);
    ip46_set_ttl(ip, 64);
    ip46_set_proto(ip, 6);
    ip46_set_src(ip, ip2);
    ip46_set_dst(ip, ip1);
    ip46_set_hdr_cksum_calc(ip);
    tcp = ip46_payload(ip);
    tcp_set_src_port(tcp, port2);
    tcp_set_dst_port(tcp, port1);
    tcp_set_syn_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, isn2);
    tcp46_set_cksum_calc(ip);
    
    pktstruct = ll_alloc_st(loc, packet_size(sz - 1));
    pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
    pktstruct->sz = sz - 1;
    memcpy(packet_data(pktstruct), pkt, sz - 1);
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
    if (pktstruct->sz < (uint32_t)(version == 4 ? 14+20+20 : 14+40+20))
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
      exit(1);
    }
    if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
      exit(1);
    }
    ip = ether_payload(packet_data(pktstruct));
    if (memcmp(ip46_src(ip), ip1, version == 4 ? 4 :16) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
      exit(1);
    }
    if (memcmp(ip46_dst(ip), ip2, version == 4 ? 4 :16) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
      exit(1);
    }
    if (ip46_proto(ip) != 6)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
      exit(1);
    }
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
      exit(1);
    }
    tcp = ip46_payload(ip);
    if (!tcp_syn(tcp) || !tcp_ack(tcp))
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet flags don't agree");
      exit(1);
    }
    if (tcp_src_port(tcp) != port1)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src port doesn't agree");
      exit(1);
    }
    if (tcp_dst_port(tcp) != port2)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst port doesn't agree");
      exit(1);
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid TCP checksum");
      exit(1);
    }
    *isn = tcp_seq_number(tcp);
    ll_free_st(loc, pktstruct);
    pktstruct = fetch_packet(&head);
    if (pktstruct != NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
      exit(1);
    }
  
    e = synproxy_hash_get(local, version, ip1, port1, ip2, port2, &hashctx);
    if (e != NULL && synproxy->conf->halfopen_cache_max == 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "state entry found");
      exit(1);
    }
  }

  for (i = 0; i < transack; i++)
  {
    ether = pkt;
    memset(pkt, 0, sizeof(pkt));
    memcpy(ether_dst(ether), cli_mac, 6);
    memcpy(ether_src(ether), lan_mac, 6);
    ether_set_type(ether, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
    ip = ether_payload(ether);
    ip_set_version(ip, version);
    ip46_set_min_hdr_len(ip);
    ip46_set_payload_len(ip, 20 + (!!one_byte_payload));
    ip46_set_dont_frag(ip, 1);
    ip46_set_id(ip, 0);
    ip46_set_ttl(ip, 64);
    ip46_set_proto(ip, 6);
    ip46_set_src(ip, ip2);
    ip46_set_dst(ip, ip1);
    ip46_set_hdr_cksum_calc(ip);
    tcp = ip46_payload(ip);
    tcp_set_src_port(tcp, port2);
    tcp_set_dst_port(tcp, port1);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, isn2 + 1 - (!!keepalive));
    tcp_set_ack_number(tcp, (*isn) + 1);
    tcp46_set_cksum_calc(ip);
  
    pktstruct = ll_alloc_st(loc, packet_size(sz - 1 + (!!one_byte_payload)));
    pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
    pktstruct->sz = sz - 1 + (!!one_byte_payload);
    memcpy(packet_data(pktstruct), pkt, sz - 1 + (!!one_byte_payload));
    if (downlink(synproxy, local, pktstruct, &outport, time64, loc))
    {
      ll_free_st(loc, pktstruct);
    }
  
    pktstruct = fetch_packet(&head);
    //if (i == 0)
    {
      if (pktstruct == NULL)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "no packet out");
        exit(1);
      }
      if (pktstruct->sz < (uint32_t)(version == 4 ? 14+20+20 : 14+40+20))
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
        exit(1);
      }
      if (pktstruct->direction != PACKET_DIRECTION_DOWNLINK)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
        exit(1);
      }
      ip = ether_payload(packet_data(pktstruct));
      if (memcmp(ip46_src(ip), ip2, version == 4 ? 4 : 16) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
        exit(1);
      }
      if (memcmp(ip46_dst(ip), ip1, version == 4 ? 4 : 16) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
        exit(1);
      }
      if (ip46_proto(ip) != 6)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
        exit(1);
      }
      if (ip46_hdr_cksum_calc(ip) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
        exit(1);
      }
      tcp = ip46_payload(ip);
      if (!tcp_syn(tcp) || tcp_ack(tcp))
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet flags don't agree");
        exit(1);
      }
      if (tcp_src_port(tcp) != port2)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet src port doesn't agree");
        exit(1);
      }
      if (tcp_dst_port(tcp) != port1)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst port doesn't agree");
        exit(1);
      }
      if (tcp46_cksum_calc(ip) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid TCP checksum");
        exit(1);
      }
      ll_free_st(loc, pktstruct);
    }
    pktstruct = fetch_packet(&head);
    if (pktstruct != NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
      exit(1);
    }
    e = synproxy_hash_get(local, version, ip1, port1, ip2, port2, &hashctx);
    if (e == NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "state entry not found");
      exit(1);
    }
    if (e->flag_state != FLAG_STATE_DOWNLINK_SYN_SENT)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid flag state");
      exit(1);
    }
  }

  for (i = 0; i < transsynack; i++)
  {
    ether = pkt;
    memset(pkt, 0, sizeof(pkt));
    memcpy(ether_dst(ether), lan_mac, 6);
    memcpy(ether_src(ether), cli_mac, 6);
    ether_set_type(ether, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
    ip = ether_payload(ether);
    ip_set_version(ip, version);
    ip46_set_min_hdr_len(ip);
    ip46_set_payload_len(ip, 20);
    ip46_set_dont_frag(ip, 1);
    ip46_set_id(ip, 0);
    ip46_set_ttl(ip, 64);
    ip46_set_proto(ip, 6);
    ip46_set_src(ip, ip1);
    ip46_set_dst(ip, ip2);
    ip46_set_hdr_cksum_calc(ip);
    tcp = ip46_payload(ip);
    tcp_set_src_port(tcp, port1);
    tcp_set_dst_port(tcp, port2);
    tcp_set_syn_on(tcp);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    //tcp_set_seq_number(tcp, isn1 + 1);
    tcp_set_seq_number(tcp, isn1);
    tcp_set_ack_number(tcp, isn2 + 1);
    tcp46_set_cksum_calc(ip);
  
    pktstruct = ll_alloc_st(loc, packet_size(sizeof(pkt) - 1));
    pktstruct->direction = PACKET_DIRECTION_UPLINK;
    pktstruct->sz = sizeof(pkt) - 1;
    memcpy(packet_data(pktstruct), pkt, sizeof(pkt) - 1);
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
    if (pktstruct->sz < 14+20+20)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
      exit(1);
    }
    if (pktstruct->direction != PACKET_DIRECTION_DOWNLINK)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
      exit(1);
    }
    ip = ether_payload(packet_data(pktstruct));
    if (memcmp(ip46_src(ip), ip2, version == 4 ? 4 : 16) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
      exit(1);
    }
    if (memcmp(ip46_dst(ip), ip1, version == 4 ? 4 : 16) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
      exit(1);
    }
    if (ip46_proto(ip) != 6)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
      exit(1);
    }
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
      exit(1);
    }
    tcp = ip46_payload(ip);
    if (tcp_syn(tcp) || !tcp_ack(tcp) || tcp_fin(tcp) || tcp_rst(tcp))
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet flags don't agree");
      exit(1);
    }
    if (tcp_src_port(tcp) != port2)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src port doesn't agree");
      exit(1);
    }
    if (tcp_dst_port(tcp) != port1)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst port doesn't agree");
      exit(1);
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid TCP checksum");
      exit(1);
    }
    ll_free_st(loc, pktstruct);
    if (i == 0)
    {
      pktstruct = fetch_packet(&head);
      if (pktstruct == NULL)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "no packet out");
        exit(1);
      }
      if (pktstruct->sz < 14+20+20)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
        exit(1);
      }
      if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
        exit(1);
      }
      ip = ether_payload(packet_data(pktstruct));
      if (memcmp(ip46_src(ip), ip1, version == 4 ? 4 : 16) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
        exit(1);
      }
      if (memcmp(ip46_dst(ip), ip2, version == 4 ? 4 : 16) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
        exit(1);
      }
      if (ip46_proto(ip) != 6)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
        exit(1);
      }
      if (ip46_hdr_cksum_calc(ip) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
        exit(1);
      }
      tcp = ip46_payload(ip);
      if (tcp_syn(tcp) || !tcp_ack(tcp) || tcp_fin(tcp) || tcp_rst(tcp))
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet flags don't agree");
        exit(1);
      }
      if (tcp_src_port(tcp) != port1)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet src port doesn't agree");
        exit(1);
      }
      if (tcp_dst_port(tcp) != port2)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst port doesn't agree");
        exit(1);
      }
      if (tcp46_cksum_calc(ip) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid TCP checksum");
        exit(1);
      }
      ll_free_st(loc, pktstruct);
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
}

static void four_way_fin_seq_impl(
  struct synproxy *synproxy,
  struct worker_local *local, struct ll_alloc_st *loc,
  int version,
  const void *ip1, const void *ip2, uint16_t port1, uint16_t port2,
  uint32_t isn1, uint32_t isn2, uint32_t isn,
  unsigned transcli, unsigned transsrv)
{
  struct port outport;
  uint64_t time64;
  struct packet *pktstruct;
  struct linked_list_head head;
  struct linkedlistfunc_userdata ud;
  char pkt[14+40+20] = {0};
  void *ether, *ip, *tcp;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  struct synproxy_hash_entry *e;
  unsigned i;
  size_t sz = (version == 4) ? 14+20+20 : 14+40+20;

  linked_list_head_init(&head);
  ud.head = &head;
  outport.userdata = &ud;
  outport.portfunc = linkedlistfunc;

  time64 = gettime64();

  e = synproxy_hash_get(local, version, ip1, port1, ip2, port2, &hashctx);
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
    ether_set_type(ether, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
    ip = ether_payload(ether);
    ip_set_version(ip, version);
    ip46_set_min_hdr_len(ip);
    ip46_set_payload_len(ip, 20);
    ip46_set_dont_frag(ip, 1);
    ip46_set_id(ip, 0);
    ip46_set_ttl(ip, 64);
    ip46_set_proto(ip, 6);
    ip46_set_src(ip, ip1);
    ip46_set_dst(ip, ip2);
    ip46_set_hdr_cksum_calc(ip);
    tcp = ip46_payload(ip);
    tcp_set_src_port(tcp, port1);
    tcp_set_dst_port(tcp, port2);
    tcp_set_ack_on(tcp);
    tcp_set_fin_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, isn1 + 1);
    tcp_set_ack_number(tcp, isn2 + 1);
    tcp46_set_cksum_calc(ip);
  
    pktstruct = ll_alloc_st(loc, packet_size(sz));
    pktstruct->direction = PACKET_DIRECTION_UPLINK;
    pktstruct->sz = sz;
    memcpy(packet_data(pktstruct), pkt, sz);
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
    if (pktstruct->sz != sz)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
      exit(1);
    }
    if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
      exit(1);
    }
    tcp_set_seq_number(tcp, isn1 + 1);
    tcp46_set_cksum_calc(ip);
    if (version == 6)
    {
      ipv6_set_flow_label(ether_payload(packet_data(pktstruct)), ipv6_flow_label(ip));
    }
    if (memcmp(packet_data(pktstruct), pkt, version == 4 ? 14+20 : 14+40) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
      exit(1);
    }
    ll_free_st(loc, pktstruct);
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
  ether_set_type(ether, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(ether);
  ip_set_version(ip, version);
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, 20);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0);
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, ip2);
  ip46_set_dst(ip, ip1);
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, port2);
  tcp_set_dst_port(tcp, port1);
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, isn2 + 1);
  tcp_set_ack_number(tcp, isn + 2);
  tcp46_set_cksum_calc(ip);

  pktstruct = ll_alloc_st(loc, packet_size(sz));
  pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
  pktstruct->sz = sz;
  memcpy(packet_data(pktstruct), pkt, sz);
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
  if (pktstruct->sz != sz)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
    exit(1);
  }
  if (pktstruct->direction != PACKET_DIRECTION_DOWNLINK)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
    exit(1);
  }
  tcp_set_ack_number(tcp, isn1 + 2);
  tcp46_set_cksum_calc(ip);
  if (memcmp(packet_data(pktstruct), pkt, sz) != 0)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
    exit(1);
  }
  ll_free_st(loc, pktstruct);
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
    ether_set_type(ether, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
    ip = ether_payload(ether);
    ip_set_version(ip, version);
    ip46_set_min_hdr_len(ip);
    ip46_set_payload_len(ip, 20);
    ip46_set_dont_frag(ip, 1);
    ip46_set_id(ip, 0);
    ip46_set_ttl(ip, 64);
    ip46_set_proto(ip, 6);
    ip46_set_src(ip, ip2);
    ip46_set_dst(ip, ip1);
    ip46_set_hdr_cksum_calc(ip);
    tcp = ip46_payload(ip);
    tcp_set_src_port(tcp, port2);
    tcp_set_dst_port(tcp, port1);
    tcp_set_ack_on(tcp);
    tcp_set_fin_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, isn2 + 1);
    tcp_set_ack_number(tcp, isn + 2);
    tcp46_set_cksum_calc(ip);
  
    pktstruct = ll_alloc_st(loc, packet_size(sz));
    pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
    pktstruct->sz = sz;
    memcpy(packet_data(pktstruct), pkt, sz);
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
    if (pktstruct->sz != sz)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
      exit(1);
    }
    if (pktstruct->direction != PACKET_DIRECTION_DOWNLINK)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
      exit(1);
    }
    tcp_set_ack_number(tcp, isn1 + 2);
    tcp46_set_cksum_calc(ip);
    if (memcmp(packet_data(pktstruct), pkt, sz) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
      exit(1);
    }
    ll_free_st(loc, pktstruct);
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
  ether_set_type(ether, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(ether);
  ip_set_version(ip, version);
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, 20);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0);
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, ip1);
  ip46_set_dst(ip, ip2);
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, port1);
  tcp_set_dst_port(tcp, port2);
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, isn1 + 2);
  tcp_set_ack_number(tcp, isn2 + 2);
  tcp46_set_cksum_calc(ip);

  pktstruct = ll_alloc_st(loc, packet_size(sz));
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sz;
  memcpy(packet_data(pktstruct), pkt, sz);
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
  if (pktstruct->sz != sz)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
    exit(1);
  }
  if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
    exit(1);
  }
  tcp_set_seq_number(tcp, isn + 2);
  tcp46_set_cksum_calc(ip);
  if (version == 6)
  {
    ipv6_set_flow_label(ether_payload(packet_data(pktstruct)), ipv6_flow_label(ip));
  }
  if (memcmp(packet_data(pktstruct), pkt, sz) != 0)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
    exit(1);
  }
  ll_free_st(loc, pktstruct);
  pktstruct = fetch_packet(&head);
  if (pktstruct != NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
    exit(1);
  }
  if (e->flag_state != FLAG_STATE_TIME_WAIT)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "invalid flag state");
    abort();
    exit(1);
  }
}

static void four_way_fin_impl(
  struct synproxy *synproxy,
  struct worker_local *local, struct ll_alloc_st *loc,
  int version,
  const void *ip1, const void *ip2, uint16_t port1, uint16_t port2,
  unsigned transcli, unsigned transsrv)
{
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  four_way_fin_seq_impl(
    synproxy, local, loc, version,
    ip1, ip2, port1, port2, isn1, isn2, isn1,
    transcli, transsrv);
}

static void three_way_handshake_four_way_fin(int version)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  three_way_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321, 1, 1);
  four_way_fin_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321, 1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void established_rst_uplink(int version)
{
  struct port outport;
  uint64_t time64;
  struct packet *pktstruct;
  struct linked_list_head head;
  struct linkedlistfunc_userdata ud;
  char pkt[14+40+20] = {0};
  void *ether, *ip, *tcp;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  uint32_t isn1 = 0x12345678;
  //uint32_t isn2 = 0x87654321;
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct synproxy_hash_entry *e;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  size_t sz = (version == 4) ? 14+20+20 : 14+40+20;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  linked_list_head_init(&head);
  ud.head = &head;
  outport.userdata = &ud;
  outport.portfunc = linkedlistfunc;

  time64 = gettime64();

  three_way_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321, 1, 1);

  e = synproxy_hash_get(&local, version, src, 12345, dst, 54321, &hashctx);
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
  ip_set_version(ip, version);
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, 20);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0);
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, src);
  ip46_set_dst(ip, dst);
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, 12345);
  tcp_set_dst_port(tcp, 54321);
  tcp_set_rst_on(tcp);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, isn1 + 1);
  tcp46_set_cksum_calc(ip);

  pktstruct = ll_alloc_st(&st, packet_size(sz));
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sz;
  memcpy(packet_data(pktstruct), pkt, sz);
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
  if (pktstruct->sz != sz)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
    exit(1);
  }
  if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
    exit(1);
  }
  if (memcmp(packet_data(pktstruct), pkt, sz) != 0)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
    exit(1);
  }
  ll_free_st(&st, pktstruct);
  pktstruct = fetch_packet(&head);
  if (pktstruct != NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
    exit(1);
  }
  e = synproxy_hash_get(&local, version, src, 12345, dst, 54321, &hashctx);
  if (e == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry not found");
    exit(1);
  }
  if (e->flag_state != FLAG_STATE_RESETED)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry not RESETED");
    exit(1);
  }

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void established_rst_downlink(int version)
{
  struct port outport;
  uint64_t time64;
  struct packet *pktstruct;
  struct linked_list_head head;
  struct linkedlistfunc_userdata ud;
  char pkt[14+40+20] = {0};
  void *ether, *ip, *tcp;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  //uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct synproxy_hash_entry *e;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  size_t sz = (version == 4) ? 14+20+20 : 14+40+20;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  linked_list_head_init(&head);
  ud.head = &head;
  outport.userdata = &ud;
  outport.portfunc = linkedlistfunc;

  time64 = gettime64();

  three_way_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321, 1, 1);

  e = synproxy_hash_get(&local, version, src, 12345, dst, 54321, &hashctx);
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
  ip_set_version(ip, version);
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, 20);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0);
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, dst);
  ip46_set_dst(ip, src);
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, 54321);
  tcp_set_dst_port(tcp, 12345);
  tcp_set_rst_on(tcp);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, isn2 + 1);
  tcp46_set_cksum_calc(ip);

  pktstruct = ll_alloc_st(&st, packet_size(sz));
  pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
  pktstruct->sz = sz;
  memcpy(packet_data(pktstruct), pkt, sz);
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
  if (pktstruct->sz != sz)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
    exit(1);
  }
  if (pktstruct->direction != PACKET_DIRECTION_DOWNLINK)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
    exit(1);
  }
  if (memcmp(packet_data(pktstruct), pkt, sz) != 0)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
    exit(1);
  }
  ll_free_st(&st, pktstruct);
  pktstruct = fetch_packet(&head);
  if (pktstruct != NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
    exit(1);
  }
  e = synproxy_hash_get(&local, version, src, 12345, dst, 54321, &hashctx);
  if (e == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry not found");
    exit(1);
  }
  if (e->flag_state != FLAG_STATE_RESETED)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry not RESETED");
    exit(1);
  }

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void syn_proxy_rst_uplink(int version)
{
  struct port outport;
  uint64_t time64;
  struct packet *pktstruct;
  struct linked_list_head head;
  struct linkedlistfunc_userdata ud;
  char pkt[14+40+20] = {0};
  void *ether, *ip, *tcp;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  uint32_t isn1 = 0x12345678;
  uint32_t isn;
  //uint32_t isn2 = 0x87654321;
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct synproxy_hash_entry *e;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  size_t sz = (version == 4) ? 14+20+20 : 14+40+20;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  linked_list_head_init(&head);
  ud.head = &head;
  outport.userdata = &ud;
  outport.portfunc = linkedlistfunc;

  time64 = gettime64();

  synproxy_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    &isn, 1, 1, 1, 0, 0);

  e = synproxy_hash_get(&local, version, src, 12345, dst, 54321, &hashctx);
  if (e == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry not found");
    exit(1);
  }

  ether = pkt;
  memset(pkt, 0, sizeof(pkt));
  memcpy(ether_dst(ether), lan_mac, 6);
  memcpy(ether_src(ether), cli_mac, 6);
  ether_set_type(ether, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(ether);
  ip_set_version(ip, version);
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, 20);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0);
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, src);
  ip46_set_dst(ip, dst);
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, 12345);
  tcp_set_dst_port(tcp, 54321);
  tcp_set_rst_on(tcp);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, isn1 + 1);
  tcp46_set_cksum_calc(ip);

  pktstruct = ll_alloc_st(&st, packet_size(sz));
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sz;
  memcpy(packet_data(pktstruct), pkt, sz);
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
  if (pktstruct->sz != sz)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
    exit(1);
  }
  if (pktstruct->direction != PACKET_DIRECTION_UPLINK)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
    exit(1);
  }
  tcp_set_seq_number(tcp, isn + 1);
  tcp46_set_cksum_calc(ip);
  if (memcmp(packet_data(pktstruct), pkt, sz) != 0)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
    exit(1);
  }
  ll_free_st(&st, pktstruct);
  pktstruct = fetch_packet(&head);
  if (pktstruct != NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
    exit(1);
  }
  e = synproxy_hash_get(&local, version, src, 12345, dst, 54321, &hashctx);
  if (e == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry not found");
    exit(1);
  }
  else if (e->flag_state != FLAG_STATE_RESETED)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry not RESETED");
    exit(1);
  }

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void syn_proxy_rst_downlink(int version)
{
  struct port outport;
  uint64_t time64;
  struct packet *pktstruct;
  struct linked_list_head head;
  struct linkedlistfunc_userdata ud;
  char pkt[14+40+20] = {0};
  void *ether, *ip, *tcp;
  char cli_mac[6] = {0x02,0,0,0,0,0x04};
  char lan_mac[6] = {0x02,0,0,0,0,0x01};
  //uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  uint32_t isn;
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct synproxy_hash_entry *e;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  size_t sz = (version == 4) ? 14+20+20 : 14+40+20;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  linked_list_head_init(&head);
  ud.head = &head;
  outport.userdata = &ud;
  outport.portfunc = linkedlistfunc;

  time64 = gettime64();

  synproxy_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    &isn, 1, 1, 1, 0, 0);

  e = synproxy_hash_get(&local, version, src, 12345, dst, 54321, &hashctx);
  if (e == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry not found");
    exit(1);
  }

  ether = pkt;
  memset(pkt, 0, sizeof(pkt));
  memcpy(ether_dst(ether), cli_mac, 6);
  memcpy(ether_src(ether), lan_mac, 6);
  ether_set_type(ether, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(ether);
  ip_set_version(ip, version);
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, 20);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0);
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, dst);
  ip46_set_dst(ip, src);
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, 54321);
  tcp_set_dst_port(tcp, 12345);
  tcp_set_rst_on(tcp);
  tcp_set_data_offset(tcp, 20);
  tcp_set_seq_number(tcp, isn2 + 1);
  tcp46_set_cksum_calc(ip);

  pktstruct = ll_alloc_st(&st, packet_size(sz));
  pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
  pktstruct->sz = sz;
  memcpy(packet_data(pktstruct), pkt, sz);
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
  if (pktstruct->sz != sz)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet size doesn't agree");
    exit(1);
  }
  if (pktstruct->direction != PACKET_DIRECTION_DOWNLINK)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet direction doesn't agree");
    exit(1);
  }
  if (memcmp(packet_data(pktstruct), pkt, sz) != 0)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "output packet data doesn't agree");
    exit(1);
  }
  ll_free_st(&st, pktstruct);
  pktstruct = fetch_packet(&head);
  if (pktstruct != NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
    exit(1);
  }
  e = synproxy_hash_get(&local, version, src, 12345, dst, 54321, &hashctx);
  if (e == NULL)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry not found");
    exit(1);
  }
  if (e->flag_state != FLAG_STATE_RESETED)
  {
    log_log(LOG_LEVEL_ERR, "UNIT", "state entry not RESETED");
    exit(1);
  }

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void three_way_handshake_ulretransmit(int version)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  three_way_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321, 2, 1);
  four_way_fin_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321, 1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void three_way_handshake_dlretransmit(int version)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  three_way_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321, 1, 2);
  four_way_fin_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321, 1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void three_way_handshake_findlretransmit(int version)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  three_way_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321, 1, 1);
  four_way_fin_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321, 1, 2);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void three_way_handshake_finulretransmit(int version)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  three_way_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321, 1, 1);
  four_way_fin_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321, 2, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void syn_proxy_handshake(int version)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  uint32_t isn;
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  synproxy_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    &isn, 1, 1, 1, 0, 0);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    isn1, isn2, isn,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void syn_proxy_uplink(int version)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  uint32_t isn;
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct tcp_ctx ctx;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  synproxy_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    &isn, 1, 1, 1, 0, 0);
  ctx.version = version;
  ctx.ulflowlabel = 0;
  ctx.dlflowlabel = 0;
  memcpy(&ctx.ip1, src, version == 4 ? 4 : 16);
  memcpy(&ctx.ip2, dst, version == 4 ? 4 : 16);
  ctx.port1 = 12345;
  ctx.port2 = 54321;
  ctx.seq1 = isn1 + 1;
  ctx.seq2 = isn2 + 1;
  ctx.seq = isn + 1;
  uplink_impl(&synproxy, &local, &st, &ctx, 10000);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    ctx.seq1 - 1, ctx.seq2 - 1, ctx.seq - 1,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  synproxy_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    &isn, 1, 1, 1, 1, 0);
  ctx.version = version;
  ctx.ulflowlabel = 0;
  ctx.dlflowlabel = 0;
  memcpy(&ctx.ip1, src, version == 4 ? 4 : 16);
  memcpy(&ctx.ip2, dst, version == 4 ? 4 : 16);
  ctx.port1 = 12345;
  ctx.port2 = 54321;
  ctx.seq1 = isn1 + 1;
  ctx.seq2 = isn2 + 1;
  ctx.seq = isn + 1;
  uplink_impl(&synproxy, &local, &st, &ctx, 10000);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    ctx.seq1 - 1, ctx.seq2 - 1, ctx.seq - 1,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  synproxy_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    &isn, 1, 1, 1, 0, 1);
  ctx.version = version;
  ctx.ulflowlabel = 0;
  ctx.dlflowlabel = 0;
  memcpy(&ctx.ip1, src, version == 4 ? 4 : 16);
  memcpy(&ctx.ip2, dst, version == 4 ? 4 : 16);
  ctx.port1 = 12345;
  ctx.port2 = 54321;
  ctx.seq1 = isn1 + 1;
  ctx.seq2 = isn2 + 1;
  ctx.seq = isn + 1;
  uplink_impl(&synproxy, &local, &st, &ctx, 10000);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    ctx.seq1 - 1, ctx.seq2 - 1, ctx.seq - 1,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void syn_proxy_downlink(int version)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  uint32_t isn;
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct tcp_ctx ctx;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  synproxy_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    &isn, 1, 1, 1, 0, 0);
  ctx.version = version;
  ctx.ulflowlabel = 0;
  ctx.dlflowlabel = 0;
  memcpy(&ctx.ip1, src, version == 4 ? 4 : 16);
  memcpy(&ctx.ip2, dst, version == 4 ? 4 : 16);
  ctx.port1 = 12345;
  ctx.port2 = 54321;
  ctx.seq1 = isn1 + 1;
  ctx.seq2 = isn2 + 1;
  ctx.seq = isn + 1;
  downlink_impl(&synproxy, &local, &st, &ctx, 10000);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    ctx.seq1 - 1, ctx.seq2 - 1, ctx.seq - 1,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  synproxy_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    &isn, 1, 1, 1, 1, 0);
  ctx.version = version;
  ctx.ulflowlabel = 0;
  ctx.dlflowlabel = 0;
  memcpy(&ctx.ip1, src, version == 4 ? 4 : 16);
  memcpy(&ctx.ip2, dst, version == 4 ? 4 : 16);
  ctx.port1 = 12345;
  ctx.port2 = 54321;
  ctx.seq1 = isn1 + 1;
  ctx.seq2 = isn2 + 1;
  ctx.seq = isn + 1;
  downlink_impl(&synproxy, &local, &st, &ctx, 10000);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    ctx.seq1 - 1, ctx.seq2 - 1, ctx.seq - 1,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  synproxy_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    &isn, 1, 1, 1, 0, 1);
  ctx.version = version;
  ctx.ulflowlabel = 0;
  ctx.dlflowlabel = 0;
  memcpy(&ctx.ip1, src, version == 4 ? 4 : 16);
  memcpy(&ctx.ip2, dst, version == 4 ? 4 : 16);
  ctx.port1 = 12345;
  ctx.port2 = 54321;
  ctx.seq1 = isn1 + 1;
  ctx.seq2 = isn2 + 1;
  ctx.seq = isn + 1;
  downlink_impl(&synproxy, &local, &st, &ctx, 10000);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    ctx.seq1 - 1, ctx.seq2 - 1, ctx.seq - 1,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void syn_proxy_uplink_downlink(int version)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  uint32_t isn;
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct tcp_ctx ctx;
  int i;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  synproxy_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    &isn, 1, 1, 1, 0, 0);
  ctx.version = version;
  ctx.ulflowlabel = 0;
  ctx.dlflowlabel = 0;
  memcpy(&ctx.ip1, src, version == 4 ? 4 : 16);
  memcpy(&ctx.ip2, dst, version == 4 ? 4 : 16);
  ctx.port1 = 12345;
  ctx.port2 = 54321;
  ctx.seq1 = isn1 + 1;
  ctx.seq2 = isn2 + 1;
  ctx.seq = isn + 1;
  for (i = 0; i < 100; i++)
  {
    uplink_impl(&synproxy, &local, &st, &ctx, 100);
    downlink_impl(&synproxy, &local, &st, &ctx, 100);
  }
  four_way_fin_seq_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    ctx.seq1 - 1, ctx.seq2 - 1, ctx.seq - 1,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void syn_proxy_closed_port(int version)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  uint32_t isn;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  synproxy_closed_port_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    &isn, 1, 1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void syn_proxy_handshake_2_1_1(int version)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  uint32_t isn;
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  synproxy_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    &isn, 2, 1, 1, 0, 0);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    isn1, isn2, isn,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void syn_proxy_handshake_1_2_1(int version)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  uint32_t isn;
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  synproxy_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    &isn, 1, 2, 1, 0, 0);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    isn1, isn2, isn,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void syn_proxy_handshake_1_1_2(int version)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  uint32_t isn;
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  synproxy_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    &isn, 1, 1, 2, 0, 0);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    isn1, isn2, isn,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void syn_proxy_handshake_1_1_1_keepalive(int version)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  uint32_t isn;
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  synproxy_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    &isn, 1, 1, 2, 1, 0);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    isn1, isn2, isn,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

static void syn_proxy_handshake_1_1_1_zerowindowprobe(int version)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  uint32_t isn;
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct conf conf = CONF_INITIALIZER;
  uint32_t src4 = htonl((10<<24)|8);
  uint32_t dst4 = htonl((11<<24)|7);
  char src6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
  char dst6[16] = {0xfd,0x80,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
  void *src, *dst;
  if (version == 4)
  {
    src = &src4;
    dst = &dst4;
  }
  else
  {
    src = src6;
    dst = dst6;
  }

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, &synproxy, 1, 0);

  synproxy_handshake_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    &isn, 1, 1, 2, 0, 1);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, version, src, dst, 12345, 54321,
    isn1, isn2, isn,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
  conf_free(&conf);
  synproxy_free(&synproxy);
}

int main(int argc, char **argv)
{
  argv0 = argv[0];

  hash_seed_init();
  setlinebuf(stdout);

  three_way_handshake_four_way_fin(4);
  three_way_handshake_four_way_fin(6);

  established_rst_uplink(4);
  established_rst_uplink(6);

  established_rst_downlink(4);
  established_rst_downlink(6);

  closed_port(4);
  closed_port(6);

  three_way_handshake_ulretransmit(4);
  three_way_handshake_ulretransmit(6);

  three_way_handshake_dlretransmit(4);
  three_way_handshake_dlretransmit(6);

  three_way_handshake_finulretransmit(4);
  three_way_handshake_finulretransmit(6);

  three_way_handshake_findlretransmit(4);
  three_way_handshake_findlretransmit(6);

  syn_proxy_handshake(4);
  syn_proxy_handshake(6);

  syn_proxy_handshake_2_1_1(4);
  syn_proxy_handshake_2_1_1(6);

  syn_proxy_handshake_1_2_1(4);
  syn_proxy_handshake_1_2_1(6);

  syn_proxy_handshake_1_1_2(4);
  syn_proxy_handshake_1_1_2(6);

  syn_proxy_handshake_1_1_1_keepalive(4);
  syn_proxy_handshake_1_1_1_keepalive(6);

  syn_proxy_handshake_1_1_1_zerowindowprobe(4);
  syn_proxy_handshake_1_1_1_zerowindowprobe(6);

  syn_proxy_closed_port(4);
  syn_proxy_closed_port(6);

  syn_proxy_uplink(4);
  syn_proxy_uplink(6);

  syn_proxy_downlink(4);
  syn_proxy_downlink(6);

  syn_proxy_uplink_downlink(4);
  syn_proxy_uplink_downlink(6);

  syn_proxy_rst_uplink(4);
  syn_proxy_rst_uplink(6);

  syn_proxy_rst_downlink(4);
  syn_proxy_rst_downlink(6);

  printf("UNIT TEST SUCCESSFUL!\n");

  return 0;
}
