#include <stdlib.h>
#include "timerlink.h"
#include "siphash.h"
#include "chacha.h"
#include "secret.h"

#if 0
struct secret secrets[2] = {};

int current_secret_index = 0;

struct chacha20_ctx chachactx;
#endif

void secret_init_deterministic(struct secretinfo *info)
{
  chacha20_init_deterministic(&info->chachactx);
  revolve_secret_impl(info);
  revolve_secret_impl(info);
}

void secret_init_random(struct secretinfo *info)
{
  chacha20_init_devrandom(&info->chachactx);
  revolve_secret_impl(info);
  revolve_secret_impl(info);
}

void revolve_secret_impl(struct secretinfo *info)
{
  int new_secret_index = !info->current_secret_index;
  struct secret new_secret;
  char buf[64];
  chacha20_next_block(&info->chachactx, buf);
  memcpy(new_secret.data, buf, 16);
  info->secrets[new_secret_index] = new_secret;
  info->current_secret_index = new_secret_index;
}

void revolve_secret(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud)
{
  struct secretinfo *info = ud;
  revolve_secret_impl(info);
  timer->time64 += 32*1000*1000;
  timer_linkheap_add(heap, timer);
}

const uint16_t msstab[] = {216, 1200, 1400, 1460};
const uint8_t wstab[] = {0, 2, 4, 7};

int verify_cookie(
  struct secretinfo *info,
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2, uint32_t isn,
  uint16_t *mss, uint8_t *wscale)
{
  int current_secret = info->current_secret_index;
  struct secret secret1 = info->secrets[current_secret];
  struct secret secret2 = info->secrets[!current_secret];
  uint16_t additional_bits = (isn>>28)&0xF;
  struct siphash_ctx ctx;
  uint32_t hash;
  siphash_init(&ctx, secret1.data);
  siphash_feed_u64(&ctx, (((uint64_t)ip1)<<32) | ip2);
  siphash_feed_u64(&ctx, (((uint64_t)port1)<<48) | (((uint64_t)port2)<<32) | additional_bits);
  hash = siphash_get(&ctx) & 0xfffffff;
  if (hash == (isn & 0xfffffff))
  {
    if (wscale)
    {
      *wscale = wstab[additional_bits&3];
    }
    if (mss)
    {
      *mss = msstab[(additional_bits>>2)&3];
    }
    return 1;
  }
  siphash_init(&ctx, secret2.data);
  siphash_feed_u64(&ctx, (((uint64_t)ip1)<<32) | ip2);
  siphash_feed_u64(&ctx, (((uint64_t)port1)<<48) | (((uint64_t)port2)<<32) | additional_bits);
  hash = siphash_get(&ctx) & 0xfffffff;
  if (hash == (isn & 0xfffffff))
  {
    if (wscale)
    {
      *wscale = wstab[additional_bits&3];
    }
    if (mss)
    {
      *mss = msstab[(additional_bits>>2)&3];
    }
    return 1;
  }
  return 0;
}

uint32_t form_cookie(
  struct secretinfo *info,
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2,
  uint16_t mss, uint8_t wscale)
{
  uint8_t wsbits;
  uint8_t mssbits;
  uint8_t additional_bits;
  int i;
  int current_secret = info->current_secret_index;
  struct secret secret1 = info->secrets[current_secret];
  struct siphash_ctx ctx;
  uint32_t hash;
  for (i = 0; i < 4; i++)
  {
    if (wstab[i] > wscale)
    {
      break;
    }
  }
  i--;
  wsbits = i;
  for (i = 0; i < 4; i++)
  {
    if (msstab[i] > mss)
    {
      break;
    }
  }
  if (i > 0)
  {
    i--;
  }
  mssbits = i;
  additional_bits = (mssbits<<2) | wsbits;
  siphash_init(&ctx, secret1.data);
  siphash_feed_u64(&ctx, (((uint64_t)ip1)<<32) | ip2);
  siphash_feed_u64(&ctx, (((uint64_t)port1)<<48) | (((uint64_t)port2)<<32) | additional_bits);
  hash = siphash_get(&ctx) & 0xfffffff;
  return (additional_bits<<28) | hash;
}
