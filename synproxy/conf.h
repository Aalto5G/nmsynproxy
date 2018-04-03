#ifndef _CONF_H_
#define _CONF_H_

#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include "dynarr.h"
#include "log.h"

enum sackmode {
  SACKMODE_ENABLE,
  SACKMODE_DISABLE,
  SACKMODE_HASHIP,
  SACKMODE_HASHIPPORT,
};
enum learnmode {
  HASHMODE_DEFAULT,
  HASHMODE_HASHIP,
  HASHMODE_HASHIPPORT,
  HASHMODE_COMMANDED,
};
enum sackconflict {
  SACKCONFLICT_REMOVE,
  SACKCONFLICT_RETAIN,
};

struct ratehashconf {
  size_t size;
  uint32_t timer_period_usec;
  uint32_t timer_add;
  uint32_t initial_tokens;
  uint8_t network_prefix;
  uint8_t network_prefix6;
};

struct conf {
  enum learnmode sackmode;
  enum sackconflict sackconflict;
  enum learnmode mssmode;
  enum learnmode wscalemode;
  size_t learnhashsize;
  size_t conntablesize;
  unsigned threadcount;
  struct ratehashconf ratehash;
  DYNARR(uint16_t) msslist;
  DYNARR(uint8_t) wscalelist;
  DYNARR(uint16_t) tsmsslist;
  DYNARR(uint8_t) tswscalelist;
  uint32_t halfopen_cache_max;
  int msslist_present;
  int wscalelist_present;
  int tsmsslist_present;
  int tswscalelist_present;
  uint8_t msslist_bits;
  uint8_t wscalelist_bits;
  uint8_t tsmsslist_bits;
  uint8_t tswscalelist_bits;
  uint8_t ts_bits;
  uint16_t own_mss;
  uint8_t own_wscale;
  uint8_t mss_clamp_enabled;
  uint16_t mss_clamp;
  uint8_t own_sack;
  uid_t uid;
  gid_t gid;
  int test_connections;
  uint16_t port;
};

#define CONF_INITIALIZER { \
  .sackmode = SACKMODE_HASHIP, \
  .sackconflict = SACKCONFLICT_RETAIN, \
  .mssmode = HASHMODE_HASHIP, \
  .learnhashsize = 131072, \
  .conntablesize = 131072, \
  .ratehash = { \
    .size = 131072, \
    .timer_period_usec = (1000*1000), \
    .timer_add = 400, \
    .initial_tokens = 2000, \
    .network_prefix = 24, \
    .network_prefix6 = 64, \
  }, \
  .msslist = DYNARR_INITER, \
  .wscalelist = DYNARR_INITER, \
  .tsmsslist = DYNARR_INITER, \
  .tswscalelist = DYNARR_INITER, \
  .msslist_present = 0, \
  .wscalelist_present = 0, \
  .own_mss = 1460, \
  .own_wscale = 7, \
  .mss_clamp_enabled = 0, \
  .mss_clamp = 1460, \
  .ts_bits = 5, \
  .halfopen_cache_max = 0, \
  .threadcount = 1, \
  .uid = 0, \
  .gid = 0, \
  .test_connections = 0, \
  .port = 12345, \
}

static inline void conf_free(struct conf *conf)
{
  DYNARR_FREE(&conf->msslist);
  DYNARR_FREE(&conf->wscalelist);
  DYNARR_FREE(&conf->tsmsslist);
  DYNARR_FREE(&conf->tswscalelist);
}

static inline int conf_postprocess(struct conf *conf)
{
  uint8_t bits = 0;
  if (!conf->wscalelist_present)
  {
    if (!DYNARR_PUSH_BACK(&conf->wscalelist, 0))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->wscalelist, 2))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->wscalelist, 4))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->wscalelist, 7))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    conf->wscalelist_present = 1;
  }
  if (!conf->tswscalelist_present)
  {
    if (!DYNARR_PUSH_BACK(&conf->tswscalelist, 0))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tswscalelist, 1))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tswscalelist, 3))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tswscalelist, 5))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tswscalelist, 6))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tswscalelist, 8))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tswscalelist, 9))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tswscalelist, 10))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    conf->tswscalelist_present = 1;
  }
  if (!conf->msslist_present)
  {
    if (!DYNARR_PUSH_BACK(&conf->msslist, 216))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->msslist, 1200))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->msslist, 1400))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->msslist, 1460))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    conf->msslist_present = 1;
  }
  if (!conf->tsmsslist_present)
  {
    if (!DYNARR_PUSH_BACK(&conf->tsmsslist, 216))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tsmsslist, 344))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tsmsslist, 536))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tsmsslist, 712))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tsmsslist, 940))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tsmsslist, 1360))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tsmsslist, 1440))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    if (!DYNARR_PUSH_BACK(&conf->tsmsslist, 1452))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "out of memory");
      return -ENOMEM;
    }
    conf->tsmsslist_present = 1;
  }
  conf->msslist_bits = 255;
  for (bits = 0; bits <= 32; bits++)
  {
    if ((1U<<bits) == DYNARR_SIZE(&conf->msslist))
    {
      conf->msslist_bits = bits;
      break;
    }
  }
  conf->wscalelist_bits = 255;
  for (bits = 0; bits <= 32; bits++)
  {
    if ((1U<<bits) == DYNARR_SIZE(&conf->wscalelist))
    {
      conf->wscalelist_bits = bits;
      break;
    }
  }
  conf->tsmsslist_bits = 255;
  for (bits = 0; bits <= 32; bits++)
  {
    if ((1U<<bits) == DYNARR_SIZE(&conf->tsmsslist))
    {
      conf->tsmsslist_bits = bits;
      break;
    }
  }
  conf->tswscalelist_bits = 255;
  for (bits = 0; bits <= 32; bits++)
  {
    if ((1U<<bits) == DYNARR_SIZE(&conf->tswscalelist))
    {
      conf->tswscalelist_bits = bits;
      break;
    }
  }
  if (conf->msslist_bits + conf->wscalelist_bits + 1 > 12)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "too long lists, too little cryptographic security");
    return -EINVAL;
  }
  if (conf->tsmsslist_bits + conf->tswscalelist_bits + conf->ts_bits > 12)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "too long lists, too little TS cryptographic security");
    return -EINVAL;
  }
  if (DYNARR_GET(&conf->wscalelist, 0) != 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "first element of wscale list must be 0");
    return -EINVAL;
  }
  if (DYNARR_GET(&conf->tswscalelist, 0) != 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "first element of ts wscale list must be 0");
    return -EINVAL;
  }
  return 0;
}

#endif
