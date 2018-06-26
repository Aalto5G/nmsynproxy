#ifndef _SECRET_H_
#define _SECRET_H_

#include <stdlib.h>
#include "timerlink.h"
#include "chacha.h"

struct synproxy;

struct secret {
  char data[16];
};

struct secretinfo {
  struct secret secrets[2];
  int current_secret_index;
  struct chacha20_ctx chachactx;
  pthread_rwlock_t lock;
};

void secret_init_deterministic(struct secretinfo *info);

void secret_init_random(struct secretinfo *info);

void revolve_secret_impl(struct secretinfo *info);

void revolve_secret(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud, void *td);

int verify_cookie(
  struct secretinfo *info,
  struct synproxy *synproxy,
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2, uint32_t isn,
  uint16_t *mss, uint8_t *wscale, uint8_t *sack_permitted,
  uint32_t other_isn);

uint32_t form_cookie(
  struct secretinfo *info,
  struct synproxy *synproxy,
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2,
  uint16_t mss, uint8_t wscale, uint8_t sack_permitted,
  uint32_t other_isn);

int verify_timestamp(
  struct secretinfo *info,
  struct synproxy *synproxy,
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2, uint32_t isn,
  uint16_t *mss, uint8_t *wscale);

uint32_t form_timestamp(
  struct secretinfo *info,
  struct synproxy *synproxy,
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2,
  uint16_t mss, uint8_t wscale);

int verify_cookie6(
  struct secretinfo *info,
  struct synproxy *synproxy,
  const void *ip1, const void *ip2, uint16_t port1, uint16_t port2, uint32_t isn,
  uint16_t *mss, uint8_t *wscale, uint8_t *sack_permitted,
  uint32_t other_isn);

uint32_t form_cookie6(
  struct secretinfo *info,
  struct synproxy *synproxy,
  const void *ip1, const void *ip2, uint16_t port1, uint16_t port2,
  uint16_t mss, uint8_t wscale, uint8_t sack_permitted,
  uint32_t other_isn);

int verify_timestamp6(
  struct secretinfo *info,
  struct synproxy *synproxy,
  const void *ip1, const void *ip2, uint16_t port1, uint16_t port2, uint32_t isn,
  uint16_t *mss, uint8_t *wscale);

uint32_t form_timestamp6(
  struct secretinfo *info,
  struct synproxy *synproxy,
  const void *ip1, const void *ip2, uint16_t port1, uint16_t port2,
  uint16_t mss, uint8_t wscale);

#endif
