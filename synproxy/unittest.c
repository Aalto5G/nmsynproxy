#define _GNU_SOURCE
#include <pthread.h>
#include "synproxy.h"
#include "iphdr.h"
#include "ipcksum.h"
#include "packet.h"
#include "hashseed.h"
#include "log.h"
#include "yyutils.h"

const char *argv0;

struct tcp_ctx {
  uint32_t seq;
  uint32_t seq1;
  uint32_t seq2;
  uint32_t ip1;
  uint32_t ip2;
  uint16_t port1;
  uint16_t port2;
};

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

  for (i = 0; i < pkts; i++)
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
    ip_set_src(ip, ctx->ip1);
    ip_set_dst(ip, ctx->ip2);
    ip_set_hdr_cksum_calc(ip, 20);
    tcp = ip_payload(ip);
    tcp_set_src_port(tcp, ctx->port1);
    tcp_set_dst_port(tcp, ctx->port2);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, ctx->seq1);
    tcp_set_ack_number(tcp, ctx->seq2);
    tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);
    ctx->seq1 += sizeof(pkt) - 14 - 20 - 20;
    ctx->seq += sizeof(pkt) - 14 - 20 - 20;

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
    if (ip_src(ip) != ctx->ip1)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
      exit(1);
    }
    if (ip_dst(ip) != ctx->ip2)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
      exit(1);
    }
    if (ip_proto(ip) != 6)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
      exit(1);
    }
    if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
      exit(1);
    }
    tcp = ip_payload(ip);
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
    if (tcp_cksum_calc(ip, ip_hdr_len(ip), tcp, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
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
    ether_set_type(ether, ETHER_TYPE_IP);
    ip = ether_payload(ether);
    ip_set_version(ip, 4);
    ip_set_hdr_len(ip, 20);
    ip_set_total_len(ip, sizeof(pktsmall) - 14);
    ip_set_dont_frag(ip, 1);
    ip_set_id(ip, 123);
    ip_set_ttl(ip, 64);
    ip_set_proto(ip, 6);
    ip_set_src(ip, ctx->ip2);
    ip_set_dst(ip, ctx->ip1);
    ip_set_hdr_cksum_calc(ip, 20);
    tcp = ip_payload(ip);
    tcp_set_src_port(tcp, ctx->port2);
    tcp_set_dst_port(tcp, ctx->port1);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, ctx->seq2);
    tcp_set_ack_number(tcp, ctx->seq);
    tcp_set_cksum_calc(ip, 20, tcp, sizeof(pktsmall) - 14 - 20);

    pktstruct = ll_alloc_st(loc, packet_size(sizeof(pktsmall)));
    pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
    pktstruct->sz = sizeof(pktsmall);
    memcpy(packet_data(pktstruct), pktsmall, sizeof(pktsmall));
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
    if (pktstruct->sz != sizeof(pktsmall))
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
    if (ip_src(ip) != ctx->ip2)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
      exit(1);
    }
    if (ip_dst(ip) != ctx->ip1)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
      exit(1);
    }
    if (ip_proto(ip) != 6)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
      exit(1);
    }
    if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
      exit(1);
    }
    tcp = ip_payload(ip);
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
    if (tcp_cksum_calc(ip, ip_hdr_len(ip), tcp, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
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

  for (i = 0; i < pkts; i++)
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
    ip_set_src(ip, ctx->ip2);
    ip_set_dst(ip, ctx->ip1);
    ip_set_hdr_cksum_calc(ip, 20);
    tcp = ip_payload(ip);
    tcp_set_src_port(tcp, ctx->port2);
    tcp_set_dst_port(tcp, ctx->port1);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, ctx->seq2);
    tcp_set_ack_number(tcp, ctx->seq);
    tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);
    ctx->seq2 += sizeof(pkt) - 14 - 20 - 20;

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
    if (ip_src(ip) != ctx->ip2)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
      exit(1);
    }
    if (ip_dst(ip) != ctx->ip1)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
      exit(1);
    }
    if (ip_proto(ip) != 6)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
      exit(1);
    }
    if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
      exit(1);
    }
    tcp = ip_payload(ip);
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
    if (tcp_cksum_calc(ip, ip_hdr_len(ip), tcp, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
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
    ether_set_type(ether, ETHER_TYPE_IP);
    ip = ether_payload(ether);
    ip_set_version(ip, 4);
    ip_set_hdr_len(ip, 20);
    ip_set_total_len(ip, sizeof(pktsmall) - 14);
    ip_set_dont_frag(ip, 1);
    ip_set_id(ip, 123);
    ip_set_ttl(ip, 64);
    ip_set_proto(ip, 6);
    ip_set_src(ip, ctx->ip1);
    ip_set_dst(ip, ctx->ip2);
    ip_set_hdr_cksum_calc(ip, 20);
    tcp = ip_payload(ip);
    tcp_set_src_port(tcp, ctx->port1);
    tcp_set_dst_port(tcp, ctx->port2);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, ctx->seq1);
    tcp_set_ack_number(tcp, ctx->seq2);
    tcp_set_cksum_calc(ip, 20, tcp, sizeof(pktsmall) - 14 - 20);

    pktstruct = ll_alloc_st(loc, packet_size(sizeof(pktsmall)));
    pktstruct->direction = PACKET_DIRECTION_UPLINK;
    pktstruct->sz = sizeof(pktsmall);
    memcpy(packet_data(pktstruct), pktsmall, sizeof(pktsmall));
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
    if (pktstruct->sz != sizeof(pktsmall))
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
    if (ip_src(ip) != ctx->ip1)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
      exit(1);
    }
    if (ip_dst(ip) != ctx->ip2)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
      exit(1);
    }
    if (ip_proto(ip) != 6)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
      exit(1);
    }
    if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
      exit(1);
    }
    tcp = ip_payload(ip);
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
    if (tcp_cksum_calc(ip, ip_hdr_len(ip), tcp, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
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

static void synproxy_closed_port_impl(
  struct synproxy *synproxy,
  struct worker_local *local, struct ll_alloc_st *loc,
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2,
  uint32_t *isn,
  unsigned transsyn, unsigned transack, unsigned transrst)
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
  struct synproxy_hash_entry *e = NULL;
  unsigned i;

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
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, isn2);
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
    if (ip_src(ip) != ip1)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
      exit(1);
    }
    if (ip_dst(ip) != ip2)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
      exit(1);
    }
    if (ip_proto(ip) != 6)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
      exit(1);
    }
    if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
      exit(1);
    }
    tcp = ip_payload(ip);
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
    if (tcp_cksum_calc(ip, ip_hdr_len(ip), tcp, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid TCP checksum");
      exit(1);
    }
    *isn = tcp_seq_num(tcp);
    ll_free_st(loc, pktstruct);
    pktstruct = fetch_packet(&head);
    if (pktstruct != NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
      exit(1);
    }
  
    e = synproxy_hash_get(local, ip1, port1, ip2, port2);
    if (e != NULL)
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
    tcp_set_ack_number(tcp, (*isn) + 1);
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
      if (ip_src(ip) != ip2)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
        exit(1);
      }
      if (ip_dst(ip) != ip1)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
        exit(1);
      }
      if (ip_proto(ip) != 6)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
        exit(1);
      }
      if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
        exit(1);
      }
      tcp = ip_payload(ip);
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
      if (tcp_cksum_calc(ip, ip_hdr_len(ip), tcp, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
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
    e = synproxy_hash_get(local, ip1, port1, ip2, port2);
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
    tcp_set_rst_on(tcp);
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, 0);
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
      if (ip_src(ip) != ip1)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
        exit(1);
      }
      if (ip_dst(ip) != ip2)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
        exit(1);
      }
      if (ip_proto(ip) != 6)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
        exit(1);
      }
      if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
        exit(1);
      }
      tcp = ip_payload(ip);
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
      if (tcp_cksum_calc(ip, ip_hdr_len(ip), tcp, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
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
    e = synproxy_hash_get(local, ip1, port1, ip2, port2);
    if (e != NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "entry found");
      exit(1);
    }
  }
}

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
  struct conf conf = CONF_INITIALIZER;

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy.conf = &conf;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, 131072, 131072, 131072);

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
  ll_free_st(&st, pktstruct);
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
  ll_free_st(&st, pktstruct);
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

  ll_alloc_st_free(&st);
  worker_local_free(&local);
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
    ll_free_st(loc, pktstruct);
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
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2,
  uint32_t *isn,
  unsigned transsyn, unsigned transack, unsigned transsynack)
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

  for (i = 0; i < transsyn; i++)
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
    tcp_set_data_offset(tcp, 20);
    tcp_set_seq_number(tcp, isn2);
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
    if (ip_src(ip) != ip1)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
      exit(1);
    }
    if (ip_dst(ip) != ip2)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
      exit(1);
    }
    if (ip_proto(ip) != 6)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
      exit(1);
    }
    if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
      exit(1);
    }
    tcp = ip_payload(ip);
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
    if (tcp_cksum_calc(ip, ip_hdr_len(ip), tcp, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid TCP checksum");
      exit(1);
    }
    *isn = tcp_seq_num(tcp);
    ll_free_st(loc, pktstruct);
    pktstruct = fetch_packet(&head);
    if (pktstruct != NULL)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "extra packet out");
      exit(1);
    }
  
    e = synproxy_hash_get(local, ip1, port1, ip2, port2);
    if (e != NULL)
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
    tcp_set_ack_number(tcp, (*isn) + 1);
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
      if (ip_src(ip) != ip2)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
        exit(1);
      }
      if (ip_dst(ip) != ip1)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
        exit(1);
      }
      if (ip_proto(ip) != 6)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
        exit(1);
      }
      if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
        exit(1);
      }
      tcp = ip_payload(ip);
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
      if (tcp_cksum_calc(ip, ip_hdr_len(ip), tcp, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
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
    e = synproxy_hash_get(local, ip1, port1, ip2, port2);
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
    tcp_set_ack_on(tcp);
    tcp_set_data_offset(tcp, 20);
    //tcp_set_seq_number(tcp, isn1 + 1);
    tcp_set_seq_number(tcp, isn1);
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
    if (ip_src(ip) != ip2)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
      exit(1);
    }
    if (ip_dst(ip) != ip1)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
      exit(1);
    }
    if (ip_proto(ip) != 6)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
      exit(1);
    }
    if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
    {
      log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
      exit(1);
    }
    tcp = ip_payload(ip);
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
    if (tcp_cksum_calc(ip, ip_hdr_len(ip), tcp, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
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
      if (ip_src(ip) != ip1)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet src IP doesn't agree");
        exit(1);
      }
      if (ip_dst(ip) != ip2)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "output packet dst IP doesn't agree");
        exit(1);
      }
      if (ip_proto(ip) != 6)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP protocol");
        exit(1);
      }
      if (ip_hdr_cksum_calc(ip, ip_hdr_len(ip)) != 0)
      {
        log_log(LOG_LEVEL_ERR, "UNIT", "invalid IP checksum");
        exit(1);
      }
      tcp = ip_payload(ip);
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
      if (tcp_cksum_calc(ip, ip_hdr_len(ip), tcp, ip_total_len(ip)-ip_hdr_len(ip)) != 0)
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
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2,
  uint32_t isn1, uint32_t isn2, uint32_t isn,
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
    tcp_set_seq_number(tcp, isn1 + 1);
    tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);
    if (memcmp(packet_data(pktstruct), pkt, 14+20) != 0)
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
  tcp_set_ack_number(tcp, isn + 2);
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
  tcp_set_ack_number(tcp, isn1 + 2);
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);
  if (memcmp(packet_data(pktstruct), pkt, sizeof(pkt)) != 0)
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
    tcp_set_ack_number(tcp, isn + 2);
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
    tcp_set_ack_number(tcp, isn1 + 2);
    tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);
    if (memcmp(packet_data(pktstruct), pkt, sizeof(pkt)) != 0)
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
  tcp_set_seq_number(tcp, isn + 2);
  tcp_set_cksum_calc(ip, 20, tcp, sizeof(pkt) - 14 - 20);
  if (memcmp(packet_data(pktstruct), pkt, sizeof(pkt)) != 0)
  {
    printf("%u %u\n", isn1 + 2, tcp_seq_number(ip_payload(ether_payload(packet_data(pktstruct)))));
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
    exit(1);
  }
}

static void four_way_fin_impl(
  struct synproxy *synproxy,
  struct worker_local *local, struct ll_alloc_st *loc,
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2,
  unsigned transcli, unsigned transsrv)
{
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  four_way_fin_seq_impl(
    synproxy, local, loc,
    ip1, ip2, port1, port2, isn1, isn2, isn1,
    transcli, transsrv);
}

static void three_way_handshake_four_way_fin(void)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct conf conf = CONF_INITIALIZER;

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy.conf = &conf;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, 131072, 131072, 131072);

  three_way_handshake_impl(
    &synproxy, &local, &st, (10<<24)|2, (11<<24)|1, 12345, 54321, 1, 1);
  four_way_fin_impl(
    &synproxy, &local, &st, (10<<24)|2, (11<<24)|1, 12345, 54321, 1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
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
  struct conf conf = CONF_INITIALIZER;

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy.conf = &conf;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, 131072, 131072, 131072);

  linked_list_head_init(&head);
  ud.head = &head;
  outport.userdata = &ud;
  outport.portfunc = linkedlistfunc;

  time64 = gettime64();

  three_way_handshake_impl(
    &synproxy, &local, &st, (10<<24)|4, (11<<24)|3, 12345, 54321, 1, 1);

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
  ll_free_st(&st, pktstruct);
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

  ll_alloc_st_free(&st);
  worker_local_free(&local);
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
  struct conf conf = CONF_INITIALIZER;

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy.conf = &conf;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, 131072, 131072, 131072);

  linked_list_head_init(&head);
  ud.head = &head;
  outport.userdata = &ud;
  outport.portfunc = linkedlistfunc;

  time64 = gettime64();

  three_way_handshake_impl(
    &synproxy, &local, &st, (10<<24)|6, (11<<24)|5, 12345, 54321, 1, 1);

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
  ll_free_st(&st, pktstruct);
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

  ll_alloc_st_free(&st);
  worker_local_free(&local);
}

static void three_way_handshake_ulretransmit(void)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct conf conf = CONF_INITIALIZER;

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy.conf = &conf;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, 131072, 131072, 131072);

  three_way_handshake_impl(
    &synproxy, &local, &st, (10<<24)|10, (11<<24)|9, 12345, 54321, 2, 1);
  four_way_fin_impl(
    &synproxy, &local, &st, (10<<24)|10, (11<<24)|9, 12345, 54321, 1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
}

static void three_way_handshake_dlretransmit(void)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct conf conf = CONF_INITIALIZER;

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy.conf = &conf;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, 131072, 131072, 131072);

  three_way_handshake_impl(
    &synproxy, &local, &st, (10<<24)|12, (11<<24)|11, 12345, 54321, 1, 2);
  four_way_fin_impl(
    &synproxy, &local, &st, (10<<24)|12, (11<<24)|11, 12345, 54321, 1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
}

static void three_way_handshake_findlretransmit(void)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct conf conf = CONF_INITIALIZER;

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy.conf = &conf;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, 131072, 131072, 131072);

  three_way_handshake_impl(
    &synproxy, &local, &st, (10<<24)|14, (11<<24)|13, 12345, 54321, 1, 1);
  four_way_fin_impl(
    &synproxy, &local, &st, (10<<24)|14, (11<<24)|13, 12345, 54321, 1, 2);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
}

static void three_way_handshake_finulretransmit(void)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  struct conf conf = CONF_INITIALIZER;

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy.conf = &conf;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, 131072, 131072, 131072);

  three_way_handshake_impl(
    &synproxy, &local, &st, (10<<24)|16, (11<<24)|15, 12345, 54321, 1, 1);
  four_way_fin_impl(
    &synproxy, &local, &st, (10<<24)|16, (11<<24)|15, 12345, 54321, 2, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
}

static void syn_proxy_handshake(void)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  uint32_t isn;
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct conf conf = CONF_INITIALIZER;

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy.conf = &conf;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, 131072, 131072, 131072);

  synproxy_handshake_impl(
    &synproxy, &local, &st, (10<<24)|18, (11<<24)|17, 12345, 54321,
    &isn, 1, 1, 1);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, (10<<24)|18, (11<<24)|17, 12345, 54321,
    isn1, isn2, isn,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
}

static void syn_proxy_uplink(void)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  uint32_t isn;
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct tcp_ctx ctx;
  struct conf conf = CONF_INITIALIZER;

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy.conf = &conf;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, 131072, 131072, 131072);

  synproxy_handshake_impl(
    &synproxy, &local, &st, (10<<24)|18, (11<<24)|17, 12345, 54321,
    &isn, 1, 1, 1);
  ctx.ip1 = (10<<24)|18;
  ctx.ip2 = (11<<24)|17;
  ctx.port1 = 12345;
  ctx.port2 = 54321;
  ctx.seq1 = isn1 + 1;
  ctx.seq2 = isn2 + 1;
  ctx.seq = isn + 1;
  uplink_impl(&synproxy, &local, &st, &ctx, 10000);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, (10<<24)|18, (11<<24)|17, 12345, 54321,
    ctx.seq1 - 1, ctx.seq2 - 1, ctx.seq - 1,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
}

static void syn_proxy_downlink(void)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  uint32_t isn;
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct tcp_ctx ctx;
  struct conf conf = CONF_INITIALIZER;

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy.conf = &conf;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, 131072, 131072, 131072);

  synproxy_handshake_impl(
    &synproxy, &local, &st, (10<<24)|18, (11<<24)|17, 12345, 54321,
    &isn, 1, 1, 1);
  ctx.ip1 = (10<<24)|18;
  ctx.ip2 = (11<<24)|17;
  ctx.port1 = 12345;
  ctx.port2 = 54321;
  ctx.seq1 = isn1 + 1;
  ctx.seq2 = isn2 + 1;
  ctx.seq = isn + 1;
  downlink_impl(&synproxy, &local, &st, &ctx, 10000);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, (10<<24)|18, (11<<24)|17, 12345, 54321,
    ctx.seq1 - 1, ctx.seq2 - 1, ctx.seq - 1,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
}

static void syn_proxy_uplink_downlink(void)
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

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy.conf = &conf;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, 131072, 131072, 131072);

  synproxy_handshake_impl(
    &synproxy, &local, &st, (10<<24)|18, (11<<24)|17, 12345, 54321,
    &isn, 1, 1, 1);
  ctx.ip1 = (10<<24)|18;
  ctx.ip2 = (11<<24)|17;
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
    &synproxy, &local, &st, (10<<24)|18, (11<<24)|17, 12345, 54321,
    ctx.seq1 - 1, ctx.seq2 - 1, ctx.seq - 1,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
}

static void syn_proxy_closed_port(void)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  uint32_t isn;
  struct conf conf = CONF_INITIALIZER;

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy.conf = &conf;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, 131072, 131072, 131072);

  synproxy_closed_port_impl(
    &synproxy, &local, &st, (10<<24)|18, (11<<24)|17, 12345, 54321,
    &isn, 1, 1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
}

static void syn_proxy_handshake_2_1_1(void)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  uint32_t isn;
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct conf conf = CONF_INITIALIZER;

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy.conf = &conf;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, 131072, 131072, 131072);

  synproxy_handshake_impl(
    &synproxy, &local, &st, (10<<24)|18, (11<<24)|17, 12345, 54321,
    &isn, 2, 1, 1);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, (10<<24)|18, (11<<24)|17, 12345, 54321,
    isn1, isn2, isn,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
}

static void syn_proxy_handshake_1_2_1(void)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  uint32_t isn;
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct conf conf = CONF_INITIALIZER;

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy.conf = &conf;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, 131072, 131072, 131072);

  synproxy_handshake_impl(
    &synproxy, &local, &st, (10<<24)|18, (11<<24)|17, 12345, 54321,
    &isn, 1, 2, 1);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, (10<<24)|18, (11<<24)|17, 12345, 54321,
    isn1, isn2, isn,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
}

static void syn_proxy_handshake_1_1_2(void)
{
  struct synproxy synproxy;
  struct ll_alloc_st st;
  struct worker_local local;
  uint32_t isn;
  uint32_t isn1 = 0x12345678;
  uint32_t isn2 = 0x87654321;
  struct conf conf = CONF_INITIALIZER;

  confyydirparse(argv0, "conf.txt", &conf, 0);
  synproxy.conf = &conf;

  if (ll_alloc_st_init(&st, POOL_SIZE, BLOCK_SIZE) != 0)
  {
    abort();
  }

  worker_local_init(&local, 131072, 131072, 131072);

  synproxy_handshake_impl(
    &synproxy, &local, &st, (10<<24)|18, (11<<24)|17, 12345, 54321,
    &isn, 1, 1, 2);
  four_way_fin_seq_impl(
    &synproxy, &local, &st, (10<<24)|18, (11<<24)|17, 12345, 54321,
    isn1, isn2, isn,
    1, 1);

  ll_alloc_st_free(&st);
  worker_local_free(&local);
}

int main(int argc, char **argv)
{
  argv0 = argv[0];

  hash_seed_init();
  setlinebuf(stdout);

  three_way_handshake_four_way_fin();

  established_rst_uplink();

  established_rst_downlink();

  closed_port();

  three_way_handshake_ulretransmit();

  three_way_handshake_dlretransmit();

  three_way_handshake_finulretransmit();

  three_way_handshake_findlretransmit();

  syn_proxy_handshake();

  syn_proxy_handshake_2_1_1();

  syn_proxy_handshake_1_2_1();

  syn_proxy_handshake_1_1_2();

  syn_proxy_closed_port();

  syn_proxy_uplink();

  syn_proxy_downlink();

  syn_proxy_uplink_downlink();

  return 0;
}
