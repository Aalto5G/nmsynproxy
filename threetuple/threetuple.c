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

static inline uint32_t threetuple_hash(struct threetupleentry *e)
{
  return threetuple_iphash(e->ip);
}


static uint32_t threetuple_hash_fn(struct hash_list_node *node, void *userdata)
{
  struct threetupleentry *e = CONTAINER_OF(node, struct threetupleentry, node);
  return threetuple_hash(e);
}

int threetuplectx_add(
  struct threetuplectx *ctx,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  uint16_t mss, uint8_t sack_supported, uint8_t wscaleshift)
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
  e->ip = ip;
  e->port = port;
  e->proto = proto;
  e->port_valid = port_valid;
  e->proto_valid = proto_valid;
  e->mss = mss;
  e->sack_supported = sack_supported;
  e->wscaleshift = wscaleshift;
  hashval = threetuple_hash(e);
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e2 =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e2->ip == ip && e2->port == port && e2->proto == proto &&
        e2->port_valid == port_valid && e2->proto_valid == proto_valid)
    {
      return -EEXIST;
    }
  }
  hash_table_add_nogrow(&ctx->tbl, &e->node, threetuple_hash(e));
  return 0;
}

struct threetupleentry *threetuplectx_find(
  struct threetuplectx *ctx,
  uint32_t ip, uint16_t port, uint8_t proto)
{
  uint32_t hashval = threetuple_iphash(ip);
  struct hash_list_node *node;
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->ip == ip && (e->port == port || !e->port_valid) &&
        (e->proto == proto || !e->proto_valid))
    {
      return e;
    }
  }
  return NULL;
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
  HASH_TABLE_FOR_EACH_POSSIBLE(&ctx->tbl, node, hashval)
  {
    struct threetupleentry *e =
      CONTAINER_OF(node, struct threetupleentry, node);
    if (e->ip == ip && e->port == port && e->proto == proto &&
        e->port_valid == port_valid && e->proto_valid == proto_valid)
    {
      hash_table_delete(&ctx->tbl, &e->node, threetuple_hash(e));
      return 0;
    }
  }
  return -ENOENT;
}

void threetuplectx_init(struct threetuplectx *ctx)
{
  if (hash_table_init(&ctx->tbl, 256, threetuple_hash_fn, NULL))
  {
    abort();
  }
}

void threetuplectx_free(struct threetuplectx *ctx)
{
  hash_table_free(&ctx->tbl);
}
