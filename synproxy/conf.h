#ifndef _CONF_H_
#define _CONF_H_

enum sackmode {
  SACKMODE_ENABLE,
  SACKMODE_DISABLE,
  SACKMODE_HASHIP,
  SACKMODE_HASHIPPORT,
};


struct conf {
  enum sackmode sackmode;
};

#define CONF_INITIALIZER { \
  .sackmode = SACKMODE_HASHIP, \
}

#endif
