#ifndef _SECRET_H_
#define _SECRET_H_

#include <stdlib.h>
#include "timerlink.h"
#include "chacha.h"

struct secret {
  char data[16];
};

struct secretinfo {
  struct secret secrets[2];
  int current_secret_index;
  struct chacha20_ctx chachactx;
};

void secret_init_deterministic(struct secretinfo *info);

void secret_init_random(struct secretinfo *info);

void revolve_secret_impl(struct secretinfo *info);

void revolve_secret(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud);

int verify_cookie(
  struct secretinfo *info,
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2, uint32_t isn,
  uint16_t *mss, uint8_t *wscale);

uint32_t form_cookie(
  struct secretinfo *info,
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2,
  uint16_t mss, uint8_t wscale);

#endif
