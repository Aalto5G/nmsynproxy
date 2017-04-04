#include <stdlib.h>
#include <stdatomic.h>
#include "timerlink.h"
#include "siphash.h"

/*
 * We use only 64 bits of secret because most implementations don't have
 * 128-bit atomic variables.
 *
 * Or actually, we could use per-thread secrets. That would work and would
 * allow 128-bit secrets.
 */
atomic_uint_fast64_t secrets[2] = {ATOMIC_VAR_INIT(0), ATOMIC_VAR_INIT(0)};
atomic_int current_secret_index = ATOMIC_VAR_INIT(0);

static void revolve_secret_impl(void)
{
  int new_secret_index = !atomic_load(&current_secret_index);
  // FIXME better implementation:
  uint64_t new_secret = rand() + (((uint64_t)rand())<<32);
  atomic_store(&secrets[new_secret_index], new_secret);
  atomic_store(&current_secret_index, new_secret_index);
}

static void __attribute__((unused)) revolve_secret(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud)
{
  revolve_secret_impl();
  timer->time64 += 32*1000*1000;
  timer_linkheap_add(heap, timer);
}

static inline void fetch_secret(char key[16])
{
  int current_secret = atomic_load(&current_secret_index);
  uint64_t secret = atomic_load(&secrets[current_secret]);
  memcpy(key, &secret, 8);
  memcpy(key+8, &secret, 8);
}

static inline int verify_cookie(
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2, uint32_t isn)
{
  int current_secret = atomic_load(&current_secret_index);
  uint64_t secret1 = atomic_load(&secrets[current_secret]);
  uint64_t secret2 = atomic_load(&secrets[!current_secret]);
  uint16_t additional_bits = (isn>>28)&0xF;
  char key1[16], key2[16];
  struct siphash_ctx ctx;
  uint32_t hash;
  memcpy(key1, &secret1, 8);
  memcpy(key1+8, &secret1, 8);
  memcpy(key2, &secret2, 8);
  memcpy(key2+8, &secret2, 8);
  siphash_init(&ctx, key1);
  siphash_feed_u64(&ctx, (((uint64_t)ip1)<<32) | ip2);
  siphash_feed_u64(&ctx, (((uint64_t)port1)<<48) | (((uint64_t)port2)<<32) | additional_bits);
  hash = siphash_get(&ctx) & 0xfffffff;
  if (hash == (isn & 0xfffffff))
  {
    return 1;
  }
  siphash_init(&ctx, key2);
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
  int current_secret = atomic_load(&current_secret_index);
  uint64_t secret1 = atomic_load(&secrets[current_secret]);
  struct siphash_ctx ctx;
  uint32_t hash;
  char key1[16];
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
  memcpy(key1, &secret1, 8);
  memcpy(key1+8, &secret1, 8);
  additional_bits = (mssbits<<2) | wsbits;
  siphash_init(&ctx, key1);
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
