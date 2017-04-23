#include <stdlib.h>
#include "timerlink.h"
#include "siphash.h"
#include "chacha.h"
#include "secret.h"
#include "conf.h"
#include "synproxy.h"

static inline uint64_t gettime64(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec*1000UL*1000UL + tv.tv_usec;
}

void secret_init_deterministic(struct secretinfo *info)
{
  info->current_secret_index = 0;
  chacha20_init_deterministic(&info->chachactx);
  revolve_secret_impl(info);
  revolve_secret_impl(info);
}

void secret_init_random(struct secretinfo *info)
{
  info->current_secret_index = 0;
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

int verify_cookie(
  struct secretinfo *info,
  struct synproxy *synproxy,
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2, uint32_t isn,
  uint16_t *mss, uint8_t *wscale, uint8_t *sack_permitted)
{
  struct conf *conf = synproxy->conf;
  int total_bits = 1 + conf->msslist_bits + conf->wscalelist_bits;
  int current_secret = info->current_secret_index;
  struct secret secret1 = info->secrets[current_secret];
  struct secret secret2 = info->secrets[!current_secret];
  uint16_t additional_bits = (isn>>(32-total_bits))&((1<<total_bits)-1);
  uint32_t bitmask = ((1<<(32-total_bits))-1);
  uint32_t mssmask = ((1<<(conf->msslist_bits))-1);
  uint32_t wsmask = ((1<<(conf->wscalelist_bits))-1);
  struct siphash_ctx ctx;
  uint32_t hash;
  uint16_t *msstab = &DYNARR_GET(&conf->msslist, 0);
  uint8_t *wstab = &DYNARR_GET(&conf->wscalelist, 0);
  siphash_init(&ctx, secret1.data);
  siphash_feed_u64(&ctx, (((uint64_t)ip1)<<32) | ip2);
  siphash_feed_u64(&ctx, (((uint64_t)port1)<<48) | (((uint64_t)port2)<<32) | additional_bits);
  hash = siphash_get(&ctx) & bitmask;
  if (hash == (isn & bitmask))
  {
    if (wscale)
    {
      *wscale = wstab[additional_bits&wsmask];
    }
    if (mss)
    {
      *mss = msstab[(additional_bits>>(conf->wscalelist_bits))&mssmask];
    }
    if (sack_permitted)
    {
      *sack_permitted =
        (additional_bits>>(conf->wscalelist_bits+conf->msslist_bits))&1;
    }
    return 1;
  }
  siphash_init(&ctx, secret2.data);
  siphash_feed_u64(&ctx, (((uint64_t)ip1)<<32) | ip2);
  siphash_feed_u64(&ctx, (((uint64_t)port1)<<48) | (((uint64_t)port2)<<32) | additional_bits);
  hash = siphash_get(&ctx) & bitmask;
  if (hash == (isn & bitmask))
  {
    if (wscale)
    {
      *wscale = wstab[additional_bits&wsmask];
    }
    if (mss)
    {
      *mss = msstab[(additional_bits>>(conf->wscalelist_bits))&mssmask];
    }
    if (sack_permitted)
    {
      *sack_permitted =
        (additional_bits>>(conf->wscalelist_bits+conf->msslist_bits))&1;
    }
    return 1;
  }
  return 0;
}

uint32_t form_cookie(
  struct secretinfo *info,
  struct synproxy *synproxy,
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2,
  uint16_t mss, uint8_t wscale, uint8_t sack_permitted)
{
  struct conf *conf = synproxy->conf;
  int total_bits = 1 + conf->msslist_bits + conf->wscalelist_bits;
  uint32_t wsbits;
  uint32_t mssbits;
  uint32_t additional_bits;
  int i;
  int current_secret = info->current_secret_index;
  struct secret secret1 = info->secrets[current_secret];
  struct siphash_ctx ctx;
  uint32_t hash;
  int wscnt = DYNARR_SIZE(&synproxy->conf->wscalelist);
  int msscnt = DYNARR_SIZE(&synproxy->conf->msslist);
  uint16_t *msstab = &DYNARR_GET(&conf->msslist, 0);
  uint8_t *wstab = &DYNARR_GET(&conf->wscalelist, 0);
  uint32_t bitmask = ((1<<(32-total_bits))-1);
  for (i = 0; i < wscnt; i++)
  {
    if (wstab[i] > wscale)
    {
      break;
    }
  }
  i--;
  wsbits = i;
  for (i = 0; i < msscnt; i++)
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
  sack_permitted = !!sack_permitted;
  additional_bits =
      (sack_permitted<<(conf->wscalelist_bits+conf->msslist_bits))
    | (mssbits<<conf->wscalelist_bits)
    | wsbits;
  siphash_init(&ctx, secret1.data);
  siphash_feed_u64(&ctx, (((uint64_t)ip1)<<32) | ip2);
  siphash_feed_u64(&ctx, (((uint64_t)port1)<<48) | (((uint64_t)port2)<<32) | additional_bits);
  hash = siphash_get(&ctx) & bitmask;
  return (additional_bits<<(32-total_bits)) | hash;
}

int verify_timestamp(
  struct secretinfo *info,
  struct synproxy *synproxy,
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2, uint32_t isn,
  uint16_t *mss, uint8_t *wscale)
{
  struct conf *conf = synproxy->conf;
  int total_bits =
    conf->ts_bits + conf->tsmsslist_bits + conf->tswscalelist_bits;
  int current_secret = info->current_secret_index;
  struct secret secret1 = info->secrets[current_secret];
  struct secret secret2 = info->secrets[!current_secret];
  uint16_t additional_bits = (isn>>(32-total_bits))&((1<<total_bits)-1);
  uint32_t bitmask = ((1<<(32-total_bits))-1);
  uint32_t mssmask = ((1<<(conf->msslist_bits))-1);
  uint32_t wsmask = ((1<<(conf->wscalelist_bits))-1);
  struct siphash_ctx ctx;
  uint32_t hash;
  uint16_t *msstab = &DYNARR_GET(&conf->tsmsslist, 0);
  uint8_t *wstab = &DYNARR_GET(&conf->tswscalelist, 0);
  siphash_init(&ctx, secret1.data);
  siphash_feed_u64(&ctx, (((uint64_t)ip1)<<32) | ip2);
  siphash_feed_u64(&ctx, (((uint64_t)port1)<<48) | (((uint64_t)port2)<<32) | additional_bits);
  hash = siphash_get(&ctx) & bitmask;
  if (hash == (isn & bitmask))
  {
    if (wscale)
    {
      *wscale = wstab[additional_bits&wsmask];
    }
    if (mss)
    {
      *mss = msstab[(additional_bits>>(conf->wscalelist_bits))&mssmask];
    }
    return 1;
  }
  siphash_init(&ctx, secret2.data);
  siphash_feed_u64(&ctx, (((uint64_t)ip1)<<32) | ip2);
  siphash_feed_u64(&ctx, (((uint64_t)port1)<<48) | (((uint64_t)port2)<<32) | additional_bits);
  hash = siphash_get(&ctx) & bitmask;
  if (hash == (isn & bitmask))
  {
    if (wscale)
    {
      *wscale = wstab[additional_bits&wsmask];
    }
    if (mss)
    {
      *mss = msstab[(additional_bits>>(conf->wscalelist_bits))&mssmask];
    }
    return 1;
  }
  return 0;
}

uint32_t form_timestamp(
  struct secretinfo *info,
  struct synproxy *synproxy,
  uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2,
  uint16_t mss, uint8_t wscale)
{
  struct conf *conf = synproxy->conf;
  int total_bits =
    conf->ts_bits + conf->tsmsslist_bits + conf->tswscalelist_bits;
  uint32_t wsbits;
  uint32_t mssbits;
  uint32_t additional_bits;
  int i;
  int current_secret = info->current_secret_index;
  struct secret secret1 = info->secrets[current_secret];
  struct siphash_ctx ctx;
  uint32_t hash;
  int wscnt = DYNARR_SIZE(&synproxy->conf->tswscalelist);
  int msscnt = DYNARR_SIZE(&synproxy->conf->tsmsslist);
  uint16_t *msstab = &DYNARR_GET(&conf->tsmsslist, 0);
  uint8_t *wstab = &DYNARR_GET(&conf->tswscalelist, 0);
  uint32_t bitmask = ((1<<(32-total_bits))-1);
  uint32_t ts = (gettime64() % 32000000)*(1<<conf->ts_bits) / 32000000;
  for (i = 0; i < wscnt; i++)
  {
    if (wstab[i] > wscale)
    {
      break;
    }
  }
  i--;
  wsbits = i;
  for (i = 0; i < msscnt; i++)
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
  additional_bits =
      (ts<<(conf->tswscalelist_bits+conf->tsmsslist_bits))
    | (mssbits<<conf->tswscalelist_bits)
    | wsbits;
  siphash_init(&ctx, secret1.data);
  siphash_feed_u64(&ctx, (((uint64_t)ip1)<<32) | ip2);
  siphash_feed_u64(&ctx, (((uint64_t)port1)<<48) | (((uint64_t)port2)<<32) | additional_bits);
  hash = siphash_get(&ctx) & bitmask;
  return (additional_bits<<(32-total_bits)) | hash;
}
