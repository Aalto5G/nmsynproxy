#ifndef _SYNPROXY_H_
#define _SYNPROXY_H_

#include "ports.h"
#include "llalloc.h"
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
#include "secret.h"
#include "iphash.h"
#include "sackhash.h"
#include "conf.h"
#include "threetuple.h"

struct synproxy {
  struct conf *conf;
  struct sack_ip_port_hash autolearn;
  struct threetuplectx threetuplectx;
};

struct synproxy_hash_entry {
  struct hash_list_node node;
  struct timer_link timer;
  union {
    uint32_t ipv4;
    char ipv6[16];
  } local_ip;
  union {
    uint32_t ipv4;
    char ipv6[16];
  } remote_ip;
  uint16_t local_port;
  uint16_t remote_port;
  uint16_t flag_state;
  uint8_t version; // 4 or 6, IPv4 or IPv6
  int8_t wscalediff;
  uint8_t lan_wscale;
  uint8_t wan_wscale;
  uint8_t was_synproxied;
  uint8_t lan_sack_was_supported;
  uint32_t seqoffset;
  uint32_t tsoffset;
  uint32_t lan_sent; // what LAN has sent plus 1
  uint32_t wan_sent; // what WAN has sent plus 1
  uint32_t lan_acked; // what WAN has sent and LAN has acked plus 1
  uint32_t wan_acked; // what LAN has sent and WAN has acked plus 1
  uint32_t lan_max; // lan_acked + (tcp_window()<<lan_wscale)
  uint32_t wan_max; // wan_acked + (tcp_window()<<wan_wscale)
#if 0
  uint32_t lan_next;
  uint32_t wan_next;
  uint32_t lan_window; // FIXME make unscaled to save space
  uint32_t wan_window; // FIXME make unscaled to save space
#endif
  uint16_t lan_max_window_unscaled; // max window LAN has advertised
  uint16_t wan_max_window_unscaled; // max window WAN has advertised
  union {
    struct {
      uint32_t isn;
    } uplink_syn_rcvd;
    struct {
      uint32_t isn;
    } uplink_syn_sent;
    struct {
      uint32_t local_isn; // ACK number - 1 of ACK packet
      uint32_t remote_isn; // SEQ number - 1 of ACK packet
      uint16_t mss;
      uint8_t sack_permitted;
      uint8_t timestamp_present;
      uint32_t local_timestamp;
      uint32_t remote_timestamp;
    } downlink_syn_sent;
    struct {
      uint32_t upfin; // valid if FLAG_STATE_UPLINK_FIN
      uint32_t downfin; // valid if FLAG_STATE_DOWNLINK_FIN
    } established;
    struct {
      struct linked_list_node listnode;
      uint8_t wscale;
      uint8_t sack_permitted;
      uint16_t mss;
      uint32_t remote_isn;
      uint32_t local_isn;
    } downlink_half_open;
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
  FLAG_STATE_DOWNLINK_HALF_OPEN = 512, // may not have other bits
  FLAG_STATE_RESETED = 1024, // may not have other bits
};

static inline int synproxy_is_connected(struct synproxy_hash_entry *e)
{
  return (e->flag_state & FLAG_STATE_ESTABLISHED) == FLAG_STATE_ESTABLISHED;
}

static inline uint32_t synproxy_hash_separate4(
  uint32_t local_ip, uint16_t local_port, uint32_t remote_ip, uint16_t remote_port)
{
  struct siphash_ctx ctx;
  siphash_init(&ctx, hash_seed_get());
  siphash_feed_u64(&ctx, (((uint64_t)local_ip) << 32) | remote_ip);
  siphash_feed_u64(&ctx, (((uint64_t)local_port) << 32) | remote_port);
  return siphash_get(&ctx);
}

static inline uint32_t synproxy_hash_separate6(
  const void *local_ip, uint16_t local_port, const void *remote_ip, uint16_t remote_port)
{
  struct siphash_ctx ctx;
  siphash_init(&ctx, hash_seed_get());
  siphash_feed_buf(&ctx, local_ip, 16);
  siphash_feed_buf(&ctx, remote_ip, 16);
  siphash_feed_u64(&ctx, (((uint64_t)local_port) << 32) | remote_port);
  return siphash_get(&ctx);
}

static inline uint32_t synproxy_hash(struct synproxy_hash_entry *e)
{
  if (e->version == 4)
  {
    return synproxy_hash_separate4(ntohl(e->local_ip.ipv4), e->local_port, ntohl(e->remote_ip.ipv4), e->remote_port);
  }
  else
  {
    return synproxy_hash_separate6(&e->local_ip, e->local_port, &e->remote_ip, e->remote_port);
  }
}

uint32_t synproxy_hash_fn(struct hash_list_node *node, void *userdata);

struct worker_local {
  struct hash_table hash;
  int locked;
  pthread_rwlock_t rwlock; // Lock order: first hash bucket lock, then mutex, then global hash lock
  struct timer_linkheap timers;
  struct secretinfo info;
  struct ip_hash ratelimit;
  uint32_t synproxied_connections;
  uint32_t direct_connections;
  uint32_t half_open_connections;
  struct linked_list_head half_open_list;
};

static inline void worker_local_rdlock(struct worker_local *local)
{
  if (!local->locked)
  {
    return;
  }
  pthread_rwlock_rdlock(&local->rwlock);
}

static inline void worker_local_rdunlock(struct worker_local *local)
{
  if (!local->locked)
  {
    return;
  }
  pthread_rwlock_unlock(&local->rwlock);
}

static inline void worker_local_wrlock(struct worker_local *local)
{
  if (!local->locked)
  {
    return;
  }
  pthread_rwlock_wrlock(&local->rwlock);
}

static inline void worker_local_wrunlock(struct worker_local *local)
{
  if (!local->locked)
  {
    return;
  }
  pthread_rwlock_unlock(&local->rwlock);
}

static inline void worker_local_init(
  struct worker_local *local, struct synproxy *synproxy, int deterministic,
  int locked)
{
  if (locked)
  {
    hash_table_init_locked(
      &local->hash, synproxy->conf->conntablesize, synproxy_hash_fn, NULL, 2); // WAS: 0
    local->locked = 1;
    if (pthread_rwlock_init(&local->rwlock, NULL) != 0)
    {
      abort();
    }
  }
  else
  {
    hash_table_init(
      &local->hash, synproxy->conf->conntablesize, synproxy_hash_fn, NULL);
    local->locked = 0;
  }
  timer_linkheap_init(&local->timers);
  if (deterministic)
  {
    secret_init_deterministic(&local->info);
  }
  else
  {
    secret_init_random(&local->info);
  }
  local->ratelimit.hash_size = synproxy->conf->ratehash.size;
  local->ratelimit.batch_size = 16384;
  if (local->ratelimit.batch_size > local->ratelimit.hash_size)
  {
    local->ratelimit.batch_size = local->ratelimit.hash_size;
  }
  local->ratelimit.initial_tokens = synproxy->conf->ratehash.initial_tokens;
  local->ratelimit.timer_add = synproxy->conf->ratehash.timer_add;
  local->ratelimit.timer_period = synproxy->conf->ratehash.timer_period_usec;
  local->synproxied_connections = 0;
  local->direct_connections = 0;
  local->half_open_connections = 0;
  ip_hash_init(&local->ratelimit, &local->timers, locked ? &local->rwlock : NULL);
  linked_list_head_init(&local->half_open_list);
}

static inline void worker_local_free(struct worker_local *local)
{
  struct hash_list_node *x, *n;
  size_t bucket;
  ip_hash_free(&local->ratelimit, &local->timers);
  HASH_TABLE_FOR_EACH_SAFE(&local->hash, bucket, n, x)
  {
    struct synproxy_hash_entry *e;
    e = CONTAINER_OF(n, struct synproxy_hash_entry, node);
    hash_table_delete(&local->hash, &e->node, synproxy_hash(e));
    timer_linkheap_remove(&local->timers, &e->timer);
    free(e);
  }
  hash_table_free(&local->hash);
  timer_linkheap_free(&local->timers);
}

struct synproxy_hash_ctx {
  int locked;
  uint32_t hashval;
  //struct synproxy_hash_entry *entry;
};

static inline void synproxy_hash_unlock(
  struct worker_local *local, struct synproxy_hash_ctx *ctx)
{
  if (ctx->locked)
  {
    hash_table_unlock_bucket(&local->hash, ctx->hashval);
    ctx->locked = 0;
  }
}

static inline struct synproxy_hash_entry *synproxy_hash_get(
  struct worker_local *local, int version,
  const void *local_ip, uint16_t local_port, const void *remote_ip, uint16_t remote_port, struct synproxy_hash_ctx *ctx)
{
  struct hash_list_node *node;
  if (version == 4)
  {
    ctx->hashval = synproxy_hash_separate4(hdr_get32n(local_ip), local_port, hdr_get32n(remote_ip), remote_port);
  }
  else
  {
    ctx->hashval = synproxy_hash_separate6(local_ip, local_port, remote_ip, remote_port);
  }
  if (!ctx->locked)
  {
    hash_table_lock_bucket(&local->hash, ctx->hashval);
    ctx->locked = 1;
  }
  HASH_TABLE_FOR_EACH_POSSIBLE(&local->hash, node, ctx->hashval)
  {
    struct synproxy_hash_entry *entry;
    entry = CONTAINER_OF(node, struct synproxy_hash_entry, node);
    if (   entry->version == version
        && memcmp(&entry->local_ip, local_ip, (version == 4) ? 4 : 16) == 0
        && entry->local_port == local_port
        && memcmp(&entry->remote_ip, remote_ip, (version == 4) ? 4 : 16) == 0
        && entry->remote_port == remote_port)
    {
      //ctx->entry = entry;
      return entry;
    }
  }
  return NULL;
}

static inline struct synproxy_hash_entry *synproxy_hash_get4(
  struct worker_local *local,
  uint32_t local_ip, uint16_t local_port, uint32_t remote_ip, uint16_t remote_port, struct synproxy_hash_ctx *ctx)
{
  local_ip = htonl(local_ip);
  remote_ip = htonl(remote_ip);
  return synproxy_hash_get(local, 4, &local_ip, local_port, &remote_ip, remote_port, ctx);
}

struct synproxy_hash_entry *synproxy_hash_put(
  struct worker_local *local,
  int version,
  const void *local_ip,
  uint16_t local_port,
  const void *remote_ip,
  uint16_t remote_port,
  uint8_t was_synproxied,
  uint64_t time64);

static inline void synproxy_hash_put_connected(
  struct worker_local *local,
  int version,
  const void *local_ip,
  uint16_t local_port,
  const void *remote_ip,
  uint16_t remote_port,
  uint64_t time64)
{
  struct synproxy_hash_entry *e;
  e = synproxy_hash_put(
    local, version, local_ip, local_port, remote_ip, remote_port, 0, time64);
  e->flag_state = FLAG_STATE_ESTABLISHED;
  e->lan_max = 32768;
  e->lan_sent = 0;
  e->lan_acked = 0;
  e->wan_wscale = 0;
  e->wan_max_window_unscaled = 65535;
}

static inline void synproxy_init(
  struct synproxy *synproxy,
  struct conf *conf)
{
  synproxy->conf = conf;
  sack_ip_port_hash_init(&synproxy->autolearn, conf->learnhashsize);
  threetuplectx_init(&synproxy->threetuplectx);
}

static inline void synproxy_free(
  struct synproxy *synproxy)
{
  synproxy->conf = NULL;
  sack_ip_port_hash_free(&synproxy->autolearn);
  threetuplectx_free(&synproxy->threetuplectx);
}

static inline void synproxy_hash_del(
  struct worker_local *local,
  struct synproxy_hash_entry *e)
{
  hash_table_delete(&local->hash, &e->node, synproxy_hash(e));
  timer_linkheap_remove(&local->timers, &e->timer);
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
  free(e);
}

int downlink(
  struct synproxy *synproxy, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64, struct ll_alloc_st *st);

int uplink(
  struct synproxy *synproxy, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64, struct ll_alloc_st *st);

#endif
