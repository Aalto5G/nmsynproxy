#include <stdint.h>
#include <errno.h>
#include "siphash.h"
#include "hashseed.h"
#include "hashtable.h"
#include "containerof.h"
#include "threetuple.h"


static inline uint32_t threetuple_iphash(uint32_t ip)
{
  return siphash64(hash_seed_get(), ip);
}

static inline uint32_t threetuple_ip6hash(const void *ipv6)
{
  return siphash_buf(hash_seed_get(), ipv6, 16);
}

static inline uint32_t threetuple_hash(struct threetupleentry *e)
{
  if (e->version == 4)
  {
    return threetuple_iphash(e->ip.ipv4);
  }
  else
  {
    return threetuple_ip6hash(&e->ip);
  }
}


static uint32_t threetuple_hash_fn(struct hash_list_node *node, void *userdata)
{
  struct threetupleentry *e = CONTAINER_OF(node, struct threetupleentry, node);
  return threetuple_hash(e);
}

int threetuplectx_add(
  struct threetuplectx *ctx,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload)
{
  struct threetupleentry *e = malloc(sizeof(*e));
  uint32_t hashval;
  struct hash_list_node *node;
  port_valid = !!port_valid;
  proto_valid = !!proto_valid;
  if (!port_valid)
  {
    port = 0;
  }
  if (!proto_valid)
  {
    proto = 0;
  }
  e->version = 4;
  e->ip.ipv4 = ip;
  e->port = port;
  e->proto = proto;
  e->port_valid = port_valid;
  e->proto_valid = proto_valid;
  e->payload = *payload;
  hashval = threetuple_hash(e);
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e2 =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e2->version == e->version &&
        e2->ip.ipv4 == ip && e2->port == port && e2->proto == proto &&
        e2->port_valid == port_valid && e2->proto_valid == proto_valid)
    {
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      free(e);
      return -EEXIST;
    }
  }
  hash_table_add_nogrow_already_bucket_locked(
    &ctx->tbl, &e->node, threetuple_hash(e));
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return 0;
}

int threetuplectx_add6(
  struct threetuplectx *ctx,
  const void *ipv6,
  uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload)
{
  struct threetupleentry *e = malloc(sizeof(*e));
  uint32_t hashval;
  struct hash_list_node *node;
  port_valid = !!port_valid;
  proto_valid = !!proto_valid;
  if (!port_valid)
  {
    port = 0;
  }
  if (!proto_valid)
  {
    proto = 0;
  }
  e->version = 6;
  memcpy(&e->ip, ipv6, 16);
  e->port = port;
  e->proto = proto;
  e->port_valid = port_valid;
  e->proto_valid = proto_valid;
  e->payload = *payload;
  hashval = threetuple_hash(e);
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e2 =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e2->version == e->version && memcmp(&e2->ip, ipv6, 16) == 0 && 
        e2->port == port && e2->proto == proto &&
        e2->port_valid == port_valid && e2->proto_valid == proto_valid)
    {
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      free(e);
      return -EEXIST;
    }
  }
  hash_table_add_nogrow_already_bucket_locked(
    &ctx->tbl, &e->node, threetuple_hash(e));
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return 0;
}

int threetuplectx_modify(
  struct threetuplectx *ctx,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload)
{
  uint32_t hashval = threetuple_iphash(ip);
  struct hash_list_node *node;
  port_valid = !!port_valid;
  proto_valid = !!proto_valid;
  if (!port_valid)
  {
    port = 0;
  }
  if (!proto_valid)
  {
    proto = 0;
  }
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->version == 4 && e->ip.ipv4 == ip &&
        e->port == port && e->proto == proto &&
        e->port_valid == port_valid && e->proto_valid == proto_valid)
    {
      e->payload = *payload;
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      return 0;
    }
  }
  struct threetupleentry *e = malloc(sizeof(*e));
  e->ip.ipv4 = ip;
  e->port = port;
  e->proto = proto;
  e->port_valid = port_valid;
  e->proto_valid = proto_valid;
  e->payload = *payload;
  hash_table_add_nogrow_already_bucket_locked(
    &ctx->tbl, &e->node, threetuple_hash(e));
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return 0;
}

int threetuplectx_modify6(
  struct threetuplectx *ctx,
  const void *ipv6,
  uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload)
{
  uint32_t hashval = threetuple_ip6hash(ipv6);
  struct hash_list_node *node;
  port_valid = !!port_valid;
  proto_valid = !!proto_valid;
  if (!port_valid)
  {
    port = 0;
  }
  if (!proto_valid)
  {
    proto = 0;
  }
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->version == 6 && memcmp(&e->ip, ipv6, 16) == 0 &&
        e->port == port && e->proto == proto &&
        e->port_valid == port_valid && e->proto_valid == proto_valid)
    {
      e->payload = *payload;
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      return 0;
    }
  }
  struct threetupleentry *e = malloc(sizeof(*e));
  e->version = 6;
  memcpy(&e->ip, ipv6, 16);
  e->port = port;
  e->proto = proto;
  e->port_valid = port_valid;
  e->proto_valid = proto_valid;
  e->payload = *payload;
  hash_table_add_nogrow_already_bucket_locked(
    &ctx->tbl, &e->node, threetuple_hash(e));
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return 0;
}

int threetuplectx_find(
  struct threetuplectx *ctx,
  uint32_t ip, uint16_t port, uint8_t proto,
  struct threetuplepayload *payload)
{
  uint32_t hashval = threetuple_iphash(ip);
  struct hash_list_node *node;
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->version == 4 && e->ip.ipv4 == ip &&
        (e->port == port || !e->port_valid) &&
        (e->proto == proto || !e->proto_valid))
    {
      if (payload)
      {
        *payload = e->payload;
      }
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      return 0;
    }
  }
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return -ENOENT;
}

int threetuplectx_find6(
  struct threetuplectx *ctx,
  const void *ipv6, uint16_t port, uint8_t proto,
  struct threetuplepayload *payload)
{
  uint32_t hashval = threetuple_ip6hash(ipv6);
  struct hash_list_node *node;
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->version == 6 && memcmp(&e->ip, ipv6, 16) == 0 &&
        (e->port == port || !e->port_valid) &&
        (e->proto == proto || !e->proto_valid))
    {
      if (payload)
      {
        *payload = e->payload;
      }
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      return 0;
    }
  }
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return -ENOENT;
}

int threetuplectx_delete(
  struct threetuplectx *ctx,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid)
{
  uint32_t hashval = threetuple_iphash(ip);
  struct hash_list_node *node;
  port_valid = !!port_valid;
  proto_valid = !!proto_valid;
  if (!port_valid)
  {
    port = 0;
  }
  if (!proto_valid)
  {
    proto = 0;
  }
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->version == 4 && e->ip.ipv4 == ip &&
        e->port == port && e->proto == proto &&
        e->port_valid == port_valid && e->proto_valid == proto_valid)
    {
      hash_table_delete_already_bucket_locked(&ctx->tbl, &e->node);
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      free(e);
      return 0;
    }
  }
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return -ENOENT;
}

int threetuplectx_delete6(
  struct threetuplectx *ctx,
  const void *ipv6,
  uint16_t port, uint8_t proto, int port_valid, int proto_valid)
{
  uint32_t hashval = threetuple_ip6hash(ipv6);
  struct hash_list_node *node;
  port_valid = !!port_valid;
  proto_valid = !!proto_valid;
  if (!port_valid)
  {
    port = 0;
  }
  if (!proto_valid)
  {
    proto = 0;
  }
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->version == 6 && memcmp(&e->ip, ipv6, 16) == 0 &&
        e->port == port && e->proto == proto &&
        e->port_valid == port_valid && e->proto_valid == proto_valid)
    {
      hash_table_delete_already_bucket_locked(&ctx->tbl, &e->node);
      hash_table_unlock_bucket(&ctx->tbl, hashval);
      free(e);
      return 0;
    }
  }
  hash_table_unlock_bucket(&ctx->tbl, hashval);
  return -ENOENT;
}

void threetuplectx_flush(struct threetuplectx *ctx)
{
  unsigned bucket;
  struct hash_list_node *x, *n;
  for (bucket = 0; bucket < ctx->tbl.bucketcnt; bucket++)
  {
    hash_table_lock_bucket(&ctx->tbl, bucket);
    HASH_TABLE_FOR_EACH_POSSIBLE_SAFE(&ctx->tbl, n, x, bucket)
    {
      struct threetupleentry *e =
        CONTAINER_OF(n, struct threetupleentry, node);
      hash_table_delete_already_bucket_locked(&ctx->tbl, n);
      free(e);
    }
    hash_table_unlock_bucket(&ctx->tbl, bucket);
  }
}

void threetuplectx_flush_ip(struct threetuplectx *ctx, uint32_t ip)
{
  uint32_t hashval = threetuple_iphash(ip);
  struct hash_list_node *x, *n;
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE_SAFE(&ctx->tbl, n, x, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(n, struct threetupleentry, node);
    if (e->version == 4 && e->ip.ipv4 == ip)
    {
      hash_table_delete_already_bucket_locked(&ctx->tbl, n);
      free(e);
    }
  }
  hash_table_unlock_bucket(&ctx->tbl, hashval);
}

void threetuplectx_flush_ip6(struct threetuplectx *ctx, const void *ipv6)
{
  uint32_t hashval = threetuple_ip6hash(ipv6);
  struct hash_list_node *x, *n;
  hash_table_lock_bucket(&ctx->tbl, hashval);
  HASH_TABLE_FOR_EACH_POSSIBLE_SAFE(&ctx->tbl, n, x, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(n, struct threetupleentry, node);
    if (e->version == 6 && memcmp(&e->ip, ipv6, 16) == 0)
    {
      hash_table_delete_already_bucket_locked(&ctx->tbl, n);
      free(e);
    }
  }
  hash_table_unlock_bucket(&ctx->tbl, hashval);
}

void threetuplectx_init(struct threetuplectx *ctx)
{
  if (hash_table_init_locked(&ctx->tbl, 256, threetuple_hash_fn, NULL, 0))
  {
    abort();
  }
}

void threetuplectx_free(struct threetuplectx *ctx)
{
  struct hash_list_node *node, *tmp;
  unsigned bucket;
  HASH_TABLE_FOR_EACH_SAFE(&ctx->tbl, bucket, node, tmp)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    hash_table_delete(&ctx->tbl, node, threetuple_hash(e));
    free(e);
  }
  hash_table_free(&ctx->tbl);
}
