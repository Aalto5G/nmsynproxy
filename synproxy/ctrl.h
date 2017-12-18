#ifndef _CTRL_H_
#define _CTRL_H_

#include "synproxy.h"

struct ctrl_args {
  struct synproxy *synproxy;
  int piperd;
};

void *ctrl_func(void *userdata);

#endif
