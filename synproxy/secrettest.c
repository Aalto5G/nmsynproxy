#include <stdlib.h>
#include "timerlink.h"
#include "secret.h"
#include "synproxy.h"
#include "conf.h"
#include "yyutils.h"

int main(int argc, char **argv)
{
  uint16_t port1 = rand(), port2 = rand();
  uint32_t ip1 = rand(), ip2 = rand();
  uint8_t wscale = 6;
  uint16_t mss = 1450;
  uint32_t cookie;
  uint32_t ts;
  struct secretinfo info;
  struct synproxy synproxy;
  struct conf conf = CONF_INITIALIZER;
  confyydirparse(argv[0], "conf.txt", &conf, 0);
  synproxy_init(&synproxy, &conf);

  secret_init_deterministic(&info);
  cookie = form_cookie(&info, &synproxy, ip1, ip2, port1, port2, mss, wscale, 1);
  ts = form_timestamp(&info, &synproxy, ip1, ip2, port1, port2, mss, wscale);
  if (!verify_cookie(&info, &synproxy, ip1, ip2, port1, port2, cookie, NULL, NULL, NULL))
  {
    abort();
  }
  if (!verify_timestamp(&info, &synproxy, ip1, ip2, port1, port2, ts, NULL, NULL))
  {
    abort();
  }
  revolve_secret_impl(&info);
  if (!verify_cookie(&info, &synproxy, ip1, ip2, port1, port2, cookie, NULL, NULL, NULL))
  {
    abort();
  }
  if (!verify_timestamp(&info, &synproxy, ip1, ip2, port1, port2, ts, NULL, NULL))
  {
    abort();
  }
  revolve_secret_impl(&info);
  if (verify_cookie(&info, &synproxy, ip1, ip2, port1, port2, cookie, NULL, NULL, NULL))
  {
    abort();
  }
  if (verify_timestamp(&info, &synproxy, ip1, ip2, port1, port2, ts, NULL, NULL))
  {
    abort();
  }
  synproxy_free(&synproxy);
  return 0;
}
