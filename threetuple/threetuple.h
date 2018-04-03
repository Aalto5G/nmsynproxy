#ifndef _THREETUPLE_H_
#define _THREETUPLE_H_

#include <stdint.h>
#include "hashtable.h"

struct threetuplepayload {
  uint16_t mss;
  uint8_t sack_supported;
  uint8_t wscaleshift;
};

struct threetupleentry {
  struct hash_list_node node;
  union {
    uint32_t ipv4;
    char ipv6[16];
  } ip;
  uint16_t port;
  uint8_t proto;
  uint8_t port_valid:1;
  uint8_t proto_valid:1;
  uint8_t version:4;
  struct threetuplepayload payload;
};
struct threetuplectx {
  struct hash_table tbl;
};

int threetuplectx_add(
  struct threetuplectx *ctx,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload);

int threetuplectx_add6(
  struct threetuplectx *ctx,
  const void *ipv6,
  uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload);

int threetuplectx_modify(
  struct threetuplectx *ctx,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload);

int threetuplectx_modify6(
  struct threetuplectx *ctx,
  const void *ipv6,
  uint16_t port, uint8_t proto, int port_valid, int proto_valid,
  const struct threetuplepayload *payload);

int threetuplectx_delete(
  struct threetuplectx *ctx,
  uint32_t ip, uint16_t port, uint8_t proto, int port_valid, int proto_valid);

int threetuplectx_delete6(
  struct threetuplectx *ctx,
  const void *ipv6,
  uint16_t port, uint8_t proto, int port_valid, int proto_valid);

int threetuplectx_find(
  struct threetuplectx *ctx,
  uint32_t ip, uint16_t port, uint8_t proto,
  struct threetuplepayload *payload);

int threetuplectx_find6(
  struct threetuplectx *ctx,
  const void *ipv6, uint16_t port, uint8_t proto,
  struct threetuplepayload *payload);

void threetuplectx_flush(struct threetuplectx *ctx);

void threetuplectx_flush_ip(struct threetuplectx *ctx, uint32_t ip);

void threetuplectx_flush_ip6(struct threetuplectx *ctx, const void *ipv6);

void threetuplectx_init(struct threetuplectx *ctx);

void threetuplectx_free(struct threetuplectx *ctx);


#endif
