#ifndef _CONF_H_
#define _CONF_H_

#include <stdint.h>
#include <stddef.h>
#include "dynarr.h"

enum sackmode {
  SACKMODE_ENABLE,
  SACKMODE_DISABLE,
  SACKMODE_HASHIP,
  SACKMODE_HASHIPPORT,
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
};

struct conf {
  enum sackmode sackmode;
  enum sackconflict sackconflict;
  size_t sackhashsize;
  size_t conntablesize;
  size_t timerheapsize;
  struct ratehashconf ratehash;
  DYNARR(uint16_t) msslist;
  DYNARR(uint8_t) wscalelist;
  int msslist_present;
  int wscalelist_present;
  uint8_t msslist_bits;
  uint8_t wscalelist_bits;
  uint16_t own_mss;
  uint8_t own_wscale;
  uint8_t mss_clamp_enabled;
  uint16_t mss_clamp;
};

#define CONF_INITIALIZER { \
  .sackmode = SACKMODE_HASHIP, \
  .sackconflict = SACKCONFLICT_RETAIN, \
  .sackhashsize = 131072, \
  .conntablesize = 131072, \
  .timerheapsize = 131072, \
  .ratehash = { \
    .size = 131072, \
    .timer_period_usec = (1000*1000), \
    .timer_add = 400, \
    .initial_tokens = 2000, \
  }, \
  .msslist = DYNARR_INITER, \
  .wscalelist = DYNARR_INITER, \
  .msslist_present = 0, \
  .wscalelist_present = 0, \
  .own_mss = 1460, \
  .own_wscale = 7, \
  .mss_clamp_enabled = 0, \
  .mss_clamp = 1460, \
}

#endif
