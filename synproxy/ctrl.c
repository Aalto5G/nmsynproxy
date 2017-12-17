#include "ctrl.h"
#include "databuf.h"
#include "read.h"

void *ctrl_func(void *userdata)
{
  struct ctrl_args *args = userdata;
  int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  int fd2;
  struct sockaddr_in sin;
  int enable = 1;
  if (fd < 0)
  {
    log_log(LOG_LEVEL_ERR, "CTRL", "can't create socket");
    abort();
  }
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
  {
    log_log(LOG_LEVEL_ERR, "CTRL", "setting SO_REUSEADDR failed");
    abort();
  }
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_ANY);
  sin.sin_port = htons(12345);
  if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) != 0)
  {
    log_log(LOG_LEVEL_ERR, "CTRL", "can't bind");
    abort();
  }
  if (listen(fd, 16) != 0)
  {
    log_log(LOG_LEVEL_ERR, "CTRL", "can't listen");
    abort();
  }
  fd2 = accept(fd, NULL, NULL);
  log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
  for (;;)
  {
    char buf[12];
    uint32_t ip;
    uint16_t port;
    uint8_t proto;
    uint8_t operation;
    struct threetuplepayload payload;
    struct datainbuf inbuf;
    if (readall(fd2, buf, sizeof(buf)) != sizeof(buf))
    {
      close(fd2);
      log_log(LOG_LEVEL_ERR, "CTRL", "can't read, reopening connection");
      fd2 = accept(fd, NULL, NULL);
      log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
      continue;
    }
    datainbuf_init(&inbuf, buf, sizeof(buf));
    if (datainbuf_get_u32(&inbuf, &ip) != 0)
    {
      abort();
    }
    if (datainbuf_get_u16(&inbuf, &port) != 0)
    {
      abort();
    }
    if (datainbuf_get_u8(&inbuf, &proto) != 0)
    {
      abort();
    }
    if (datainbuf_get_u8(&inbuf, &operation) != 0)
    {
      abort();
    }
    if (datainbuf_get_u16(&inbuf, &payload.mss) != 0)
    {
      abort();
    }
    if (datainbuf_get_u8(&inbuf, &payload.sack_supported) != 0)
    {
      abort();
    }
    if (datainbuf_get_u8(&inbuf, &payload.wscaleshift) != 0)
    {
      abort();
    }
    if (operation & (1<<0))
    {
      log_log(
             LOG_LEVEL_NOTICE, "CTRL",
             "rm %d.%d.%d.%d:%d proto %d port_valid %d proto_valid %d",
             (uint8_t)(ip>>24),
             (uint8_t)(ip>>16),
             (uint8_t)(ip>>8),
             (uint8_t)(ip>>0),
             (uint16_t)port,
             (uint8_t)proto,
             !!(operation&(1<<1)),
             !!(operation&(1<<2)));
      if (threetuplectx_delete(&args->synproxy->threetuplectx, ip, port, proto,
                               !!(operation & (1<<1)), !!(operation & (1<<2)))
          == 0)
      {
        if (write(fd2, "1\n", 2) != 2)
        {
          close(fd2);
          log_log(LOG_LEVEL_ERR, "CTRL", "can't write, reopening connection");
          fd2 = accept(fd, NULL, NULL);
          log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
          continue;
        }
      }
      else
      {
        if (write(fd2, "0\n", 2) != 2)
        {
          close(fd2);
          log_log(LOG_LEVEL_ERR, "CTRL", "can't write, reopening connection");
          fd2 = accept(fd, NULL, NULL);
          log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
          continue;
        }
      }
       
    }
    else
    {
      log_log(
             LOG_LEVEL_NOTICE, "CTRL",
             "add %d.%d.%d.%d:%d proto %d port_valid %d proto_valid %d"
             " mss %d sack %d wscaleshift %d",
             (uint8_t)(ip>>24),
             (uint8_t)(ip>>16),
             (uint8_t)(ip>>8),
             (uint8_t)(ip>>0),
             (uint16_t)port,
             (uint8_t)proto,
             !!(operation&(1<<1)),
             !!(operation&(1<<2)),
             payload.mss,
             payload.sack_supported,
             payload.wscaleshift);
      if (threetuplectx_add(&args->synproxy->threetuplectx, ip, port, proto,
                            !!(operation & (1<<1)), !!(operation & (1<<2)),
                            &payload) == 0)
      {
        if (write(fd2, "1\n", 2) != 2)
        {
          close(fd2);
          log_log(LOG_LEVEL_ERR, "CTRL", "can't write, reopening connection");
          fd2 = accept(fd, NULL, NULL);
          log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
          continue;
        }
      }
      else
      {
        if (write(fd2, "0\n", 2) != 2)
        {
          close(fd2);
          log_log(LOG_LEVEL_ERR, "CTRL", "can't write, reopening connection");
          fd2 = accept(fd, NULL, NULL);
          log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
          continue;
        }
      }
    }
  }
  return 0;
}
