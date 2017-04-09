#ifndef _SYNPROXY_H_
#define _SYNPROXY_H_

#include "ports.h"
#include "packet.h"
#include "iphdr.h"
#include "log.h"
#include "hashtable.h"
#include "linkedlist.h"
#include "containerof.h"
#include "siphash.h"
#include "timerlink.h"
#include <stdio.h>
#include "hashseed.h"

struct synproxy {
};

struct synproxy_hash_entry {
  struct hash_list_node node;
  struct timer_link timer;
  uint32_t local_ip;
  uint32_t remote_ip;
  uint16_t local_port;
  uint16_t remote_port;
  uint16_t flag_state;
  int8_t wscalediff;
  uint8_t lan_wscale;
  uint8_t wan_wscale;
  uint16_t window_size;
  uint32_t isn;
  uint32_t other_isn;
  uint32_t seqoffset;
  uint32_t timestamp;
  uint32_t lan_next;
  uint32_t wan_next;
  uint32_t lan_window; // FIXME make unscaled to save space
  uint32_t wan_window; // FIXME make unscaled to save space
  uint16_t lan_max_window_unscaled;
  uint16_t wan_max_window_unscaled;
  union {
    struct {
      uint32_t isn;
    } uplink_syn_rcvd;
    struct {
      uint32_t isn;
    } uplink_syn_sent;
    struct {
      uint32_t isn;
    } downlink_syn_sent;
    struct {
      uint32_t upfin; // valid if FLAG_STATE_UPLINK_FIN
      uint32_t downfin; // valid if FLAG_STATE_DOWNLINK_FIN
    } established;
  } state_data;
};

enum flag_state {
  FLAG_STATE_UPLINK_SYN_SENT = 1, // may not have other bits
  FLAG_STATE_UPLINK_SYN_RCVD = 2, // may not have other bits
  FLAG_STATE_DOWNLINK_SYN_SENT = 4, // may not have other bits
  FLAG_STATE_ESTABLISHED = 8, // may have also FIN bits
  FLAG_STATE_UPLINK_FIN = 16, // always with ESTABLISHED
  FLAG_STATE_UPLINK_FIN_ACK = 32, // always with UPLINK_FIN|ESTABLISHED
  FLAG_STATE_DOWNLINK_FIN = 64, // always with ESTABLISHED
  FLAG_STATE_DOWNLINK_FIN_ACK = 128, // always with DOWNLINK_FIN|ESTABLSIHED
  FLAG_STATE_TIME_WAIT = 256, // may not have other bits
};

static inline int synproxy_is_connected(struct synproxy_hash_entry *e)
{
  return (e->flag_state & FLAG_STATE_ESTABLISHED) == FLAG_STATE_ESTABLISHED;
}

static inline uint32_t synproxy_hash_separate(
  uint32_t local_ip, uint16_t local_port, uint32_t remote_ip, uint16_t remote_port)
{
  struct siphash_ctx ctx;
  siphash_init(&ctx, hash_seed_get());
  siphash_feed_u64(&ctx, (((uint64_t)local_ip) << 32) | remote_ip);
  siphash_feed_u64(&ctx, (((uint64_t)local_port) << 32) | remote_port);
  return siphash_get(&ctx);
}

static inline uint32_t synproxy_hash(struct synproxy_hash_entry *e)
{
  return synproxy_hash_separate(e->local_ip, e->local_port, e->remote_ip, e->remote_port);
}

uint32_t synproxy_hash_fn(struct hash_list_node *node, void *userdata);

struct worker_local {
  struct hash_table hash;
  struct timer_linkheap timers;
};

static inline struct synproxy_hash_entry *synproxy_hash_get(
  struct worker_local *local,
  uint32_t local_ip, uint16_t local_port, uint32_t remote_ip, uint16_t remote_port)
{
  uint32_t hashval;
  struct hash_list_node *node;
  hashval = synproxy_hash_separate(local_ip, local_port, remote_ip, remote_port);
  HASH_TABLE_FOR_EACH_POSSIBLE(&local->hash, node, hashval)
  {
    struct synproxy_hash_entry *entry;
    entry = CONTAINER_OF(node, struct synproxy_hash_entry, node);
    if (   entry->local_ip == local_ip
        && entry->local_port == local_port
        && entry->remote_ip == remote_ip
        && entry->remote_port == remote_port)
    {
      return entry;
    }
  }
  return NULL;
}

struct synproxy_hash_entry *synproxy_hash_put(
  struct worker_local *local,
  uint32_t local_ip,
  uint16_t local_port,
  uint32_t remote_ip,
  uint16_t remote_port);

static inline void synproxy_hash_put_connected(
  struct worker_local *local,
  uint32_t local_ip,
  uint16_t local_port,
  uint32_t remote_ip,
  uint16_t remote_port)
{
  struct synproxy_hash_entry *e;
  e = synproxy_hash_put(local, local_ip, local_port, remote_ip, remote_port);
  e->flag_state = FLAG_STATE_ESTABLISHED;
  e->lan_window = 32768;
  e->lan_next = 0;
  e->lan_wscale = 0;
}

static inline void synproxy_hash_del(
  struct worker_local *local,
  struct synproxy_hash_entry *e)
{
  hash_table_delete(&local->hash, &e->node);
  timer_heap_remove(&local->timers, &e->timer);
  free(e);
}

int downlink(
  struct synproxy *synproxy, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64);

int uplink(
  struct synproxy *synproxy, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64);

#endif
