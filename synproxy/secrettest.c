#include <stdlib.h>
#include "timerlink.h"
#include "siphash.h"
#include "chacha.h"

struct secret {
  char data[16];
};

struct secret secrets[2] = {};

int current_secret_index = 0;

struct chacha20_ctx chachactx;

static void revolve_secret_impl(void)
{
  int new_secret_index = !current_secret_index;
  struct secret new_secret;
  char buf[64];
  chacha20_next_block(&chachactx, buf);
  memcpy(new_secret.data, buf, 16);
  secrets[new_secret_index] = new_secret;
  current_secret_index = new_secret_index;
}

static void __attribute__((unused)) revolve_secret(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud)
{
  revolve_secret_impl();
  timer->time64 += 32*1000*1000;
  timer_linkheap_add(heap, timer);
}

static inline int verify_cookie(
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2, uint32_t isn)
{
  int current_secret = current_secret_index;
  struct secret secret1 = secrets[current_secret];
  struct secret secret2 = secrets[!current_secret];
  uint16_t additional_bits = (isn>>28)&0xF;
  struct siphash_ctx ctx;
  uint32_t hash;
  siphash_init(&ctx, secret1.data);
  siphash_feed_u64(&ctx, (((uint64_t)ip1)<<32) | ip2);
  siphash_feed_u64(&ctx, (((uint64_t)port1)<<48) | (((uint64_t)port2)<<32) | additional_bits);
  hash = siphash_get(&ctx) & 0xfffffff;
  if (hash == (isn & 0xfffffff))
  {
    return 1;
  }
  siphash_init(&ctx, secret2.data);
  siphash_feed_u64(&ctx, (((uint64_t)ip1)<<32) | ip2);
  siphash_feed_u64(&ctx, (((uint64_t)port1)<<48) | (((uint64_t)port2)<<32) | additional_bits);
  hash = siphash_get(&ctx) & 0xfffffff;
  if (hash == (isn & 0xfffffff))
  {
    return 1;
  }
  return 0;
}

const uint16_t msstab[] = {216, 1200, 1400, 1460};
const uint8_t wstab[] = {0, 2, 4, 7};

static uint32_t form_cookie(
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2,
  uint16_t mss, uint8_t wscale)
{
  uint8_t wsbits;
  uint8_t mssbits;
  uint8_t additional_bits;
  int i;
  int current_secret = current_secret_index;
  struct secret secret1 = secrets[current_secret];
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

int main(int argc, char **argv)
{
  uint16_t port1 = rand(), port2 = rand();
  uint32_t ip1 = rand(), ip2 = rand();
  uint8_t wscale = 6;
  uint16_t mss = 1450;
  uint32_t cookie;

  chacha20_init_deterministic(&chachactx);
  revolve_secret_impl();
  revolve_secret_impl();
  cookie = form_cookie(ip1, ip2, port1, port2, mss, wscale);
  if (!verify_cookie(ip1, ip2, port1, port2, cookie))
  {
    abort();
  }
  revolve_secret_impl();
  if (!verify_cookie(ip1, ip2, port1, port2, cookie))
  {
    abort();
  }
  revolve_secret_impl();
  if (verify_cookie(ip1, ip2, port1, port2, cookie))
  {
    abort();
  }
  return 0;
}
