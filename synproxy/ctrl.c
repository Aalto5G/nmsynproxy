#include "ctrl.h"
#include "databuf.h"
#include "read.h"
#include <fcntl.h>
#include <arpa/inet.h>

static void set_nonblock(int fd)
{
  int opt;
  opt = fcntl(fd, F_GETFL);
  if (opt < 0)
  {
    abort();
  }
  opt |= O_NONBLOCK;
  if (fcntl(fd, F_SETFL, opt) < 0)
  {
    abort();
  }
}

void *ctrl_func(void *userdata)
{
  struct ctrl_args *args = userdata;
  int fd;
  int fd6;
  int fd2;
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  int enable;
  set_nonblock(args->piperd);
  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd < 0)
  {
    log_log(LOG_LEVEL_ERR, "CTRL", "can't create socket");
    abort();
  }
  fd6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
  if (fd6 < 0)
  {
    log_log(LOG_LEVEL_ERR, "CTRL", "can't create socket6");
    abort();
  }
  enable = 1;
  if (setsockopt(fd6, IPPROTO_IPV6, IPV6_V6ONLY, &enable, sizeof(int)) < 0)
  {
    log_log(LOG_LEVEL_ERR, "CTRL", "setting IPV6_V6ONLY failed");
    abort();
  }
  enable = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
  {
    log_log(LOG_LEVEL_ERR, "CTRL", "setting SO_REUSEADDR failed");
    abort();
  }
  enable = 1;
  if (setsockopt(fd6, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
  {
    log_log(LOG_LEVEL_ERR, "CTRL", "setting SO_REUSEADDR failed for IPv6");
    abort();
  }
  sin6.sin6_family = AF_INET6;
  memcpy(&sin6.sin6_addr, &in6addr_any, sizeof(sin6.sin6_addr));
  sin6.sin6_port = htons(args->synproxy->conf->port);
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_ANY);
  sin.sin_port = htons(args->synproxy->conf->port);
  if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) != 0)
  {
    log_log(LOG_LEVEL_ERR, "CTRL", "can't bind");
    abort();
  }
  if (bind(fd6, (struct sockaddr*)&sin6, sizeof(sin6)) != 0)
  {
    log_log(LOG_LEVEL_ERR, "CTRL", "can't bind IPv6");
    abort();
  }
  if (listen(fd, 16) != 0)
  {
    log_log(LOG_LEVEL_ERR, "CTRL", "can't listen");
    abort();
  }
  if (listen(fd6, 16) != 0)
  {
    log_log(LOG_LEVEL_ERR, "CTRL", "can't listen IPv6");
    abort();
  }
  fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
  if (fd2 < 0 && errno == EINTR)
  {
    log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
    return NULL;
  }
  set_nonblock(fd2);
  log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
  for (;;)
  {
    char buf[12];
    char ip6[16];
    char str6[INET6_ADDRSTRLEN] = {0};
    struct in6_addr in6;
    uint32_t ip;
    uint16_t port;
    uint8_t proto;
    uint8_t operation;
    struct threetuplepayload payload;
    struct datainbuf inbuf;
    errno = 0;
    if (readall_interrupt(fd2, buf, sizeof(buf), args->piperd) != sizeof(buf))
    {
      if (errno == EINTR)
      {
        log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
        close(fd2);
        close(fd);
        close(fd6);
        return NULL;
      }
      close(fd2);
      log_log(LOG_LEVEL_ERR, "CTRL", "can't read, reopening connection");
      fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
      if (fd2 < 0 && errno == EINTR)
      {
        log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
        return NULL;
      }
      set_nonblock(fd2);
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
    if (operation & (1<<7))
    {
      if (readall_interrupt(fd2, ip6, sizeof(ip6), args->piperd) != sizeof(ip6))
      {
        if (errno == EINTR)
        {
          log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
          close(fd2);
          close(fd);
          close(fd6);
          return NULL;
        }
        close(fd2);
        log_log(LOG_LEVEL_ERR, "CTRL", "can't read, reopening connection");
        fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
        if (fd2 < 0 && errno == EINTR)
        {
          log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
          return NULL;
        }
        set_nonblock(fd2);
        log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
        continue;
      }
      memcpy(in6.s6_addr, ip6, 16);
      if (inet_ntop(AF_INET6, &in6, str6, sizeof(str6)) == NULL)
      {
        strncpy(str6, "UNKNOWN", sizeof(str6));
      }
    }
    if (operation == ((1<<7)|(1<<3)))
    {
      log_log(
             LOG_LEVEL_NOTICE, "CTRL",
             "rm [%s]:%d proto %d port_valid %d proto_valid %d",
             str6,
             (uint16_t)port,
             (uint8_t)proto,
             port != 0,
             proto != 0);
      if (threetuplectx_delete6(&args->synproxy->threetuplectx, ip6,
                                port, proto, (port != 0), (proto != 0))
          == 0)
      {
        if (write(fd2, "1\n", 2) != 2)
        {
          close(fd2);
          log_log(LOG_LEVEL_ERR, "CTRL", "can't write, reopening connection");
          fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
          if (fd2 < 0 && errno == EINTR)
          {
            log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
            return NULL;
          }
          set_nonblock(fd2);
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
          fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
          if (fd2 < 0 && errno == EINTR)
          {
            log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
            return NULL;
          }
          set_nonblock(fd2);
          log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
          continue;
        }
      }
    }
    else if (operation == (1<<3))
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
             port != 0,
             proto != 0);
      if (threetuplectx_delete(&args->synproxy->threetuplectx, ip, port, proto,
                               (port != 0), (proto != 0))
          == 0)
      {
        if (write(fd2, "1\n", 2) != 2)
        {
          close(fd2);
          log_log(LOG_LEVEL_ERR, "CTRL", "can't write, reopening connection");
          fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
          if (fd2 < 0 && errno == EINTR)
          {
            log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
            return NULL;
          }
          set_nonblock(fd2);
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
          fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
          if (fd2 < 0 && errno == EINTR)
          {
            log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
            return NULL;
          }
          set_nonblock(fd2);
          log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
          continue;
        }
      }
    }
    else if (operation == ((1<<7)|(1<<2)))
    {
      log_log(
             LOG_LEVEL_NOTICE, "CTRL",
             "mod [%s]:%d proto %d port_valid %d proto_valid %d"
             " mss %d sack %d wscaleshift %d",
             str6,
             (uint16_t)port,
             (uint8_t)proto,
             port != 0,
             proto != 0,
             payload.mss,
             payload.sack_supported,
             payload.wscaleshift);
      if (threetuplectx_modify6(&args->synproxy->threetuplectx, ip6,
                                port, proto, (port != 0), (proto != 0),
                                &payload) == 0)
      {
        if (write(fd2, "1\n", 2) != 2)
        {
          close(fd2);
          log_log(LOG_LEVEL_ERR, "CTRL", "can't write, reopening connection");
          fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
          if (fd2 < 0 && errno == EINTR)
          {
            log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
            return NULL;
          }
          set_nonblock(fd2);
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
          fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
          if (fd2 < 0 && errno == EINTR)
          {
            log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
            return NULL;
          }
          set_nonblock(fd2);
          log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
          continue;
        }
      }
    }
    else if (operation == (1<<2))
    {
      log_log(
             LOG_LEVEL_NOTICE, "CTRL",
             "mod %d.%d.%d.%d:%d proto %d port_valid %d proto_valid %d"
             " mss %d sack %d wscaleshift %d",
             (uint8_t)(ip>>24),
             (uint8_t)(ip>>16),
             (uint8_t)(ip>>8),
             (uint8_t)(ip>>0),
             (uint16_t)port,
             (uint8_t)proto,
             port != 0,
             proto != 0,
             payload.mss,
             payload.sack_supported,
             payload.wscaleshift);
      if (threetuplectx_modify(&args->synproxy->threetuplectx, ip, port, proto,
                               (port != 0), (proto != 0),
                               &payload) == 0)
      {
        if (write(fd2, "1\n", 2) != 2)
        {
          close(fd2);
          log_log(LOG_LEVEL_ERR, "CTRL", "can't write, reopening connection");
          fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
          if (fd2 < 0 && errno == EINTR)
          {
            log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
            return NULL;
          }
          set_nonblock(fd2);
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
          fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
          if (fd2 < 0 && errno == EINTR)
          {
            log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
            return NULL;
          }
          set_nonblock(fd2);
          log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
          continue;
        }
      }
    }
    else if (operation == ((1<<7)|(1<<0)))
    {
      log_log(
             LOG_LEVEL_NOTICE, "CTRL",
             "flush [%s]", str6);
      threetuplectx_flush_ip6(&args->synproxy->threetuplectx, ip6);
      if (write(fd2, "1\n", 2) != 2)
      {
        close(fd2);
        log_log(LOG_LEVEL_ERR, "CTRL", "can't write, reopening connection");
        fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
        if (fd2 < 0 && errno == EINTR)
        {
          log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
          return NULL;
        }
        set_nonblock(fd2);
        log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
        continue;
      }
    }
    else if (operation == (1<<0))
    {
      if (ip == 0)
      {
        log_log(
               LOG_LEVEL_NOTICE, "CTRL",
               "flush all");
        threetuplectx_flush(&args->synproxy->threetuplectx);
      }
      else
      {
        log_log(
               LOG_LEVEL_NOTICE, "CTRL",
               "flush %d.%d.%d.%d",
               (uint8_t)(ip>>24),
               (uint8_t)(ip>>16),
               (uint8_t)(ip>>8),
               (uint8_t)(ip>>0));
        threetuplectx_flush_ip(&args->synproxy->threetuplectx, ip);
      }
      if (write(fd2, "1\n", 2) != 2)
      {
        close(fd2);
        log_log(LOG_LEVEL_ERR, "CTRL", "can't write, reopening connection");
        fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
        if (fd2 < 0 && errno == EINTR)
        {
          log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
          return NULL;
        }
        set_nonblock(fd2);
        log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
        continue;
      }
    }
    else if (operation == ((1<<7)|(1<<1)))
    {
      log_log(
             LOG_LEVEL_NOTICE, "CTRL",
             "add [%s]:%d proto %d port_valid %d proto_valid %d"
             " mss %d sack %d wscaleshift %d",
             str6,
             (uint16_t)port,
             (uint8_t)proto,
             port != 0,
             proto != 0,
             payload.mss,
             payload.sack_supported,
             payload.wscaleshift);
      if (threetuplectx_add6(&args->synproxy->threetuplectx, ip6,
                             port, proto, (port != 0), (proto != 0),
                             &payload) == 0)
      {
        if (write(fd2, "1\n", 2) != 2)
        {
          close(fd2);
          log_log(LOG_LEVEL_ERR, "CTRL", "can't write, reopening connection");
          fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
          if (fd2 < 0 && errno == EINTR)
          {
            log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
            return NULL;
          }
          set_nonblock(fd2);
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
          fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
          if (fd2 < 0 && errno == EINTR)
          {
            log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
            return NULL;
          }
          set_nonblock(fd2);
          log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
          continue;
        }
      }
    }
    else if (operation == (1<<1))
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
             port != 0,
             proto != 0,
             payload.mss,
             payload.sack_supported,
             payload.wscaleshift);
      if (threetuplectx_add(&args->synproxy->threetuplectx, ip, port, proto,
                            (port != 0), (proto != 0),
                            &payload) == 0)
      {
        if (write(fd2, "1\n", 2) != 2)
        {
          close(fd2);
          log_log(LOG_LEVEL_ERR, "CTRL", "can't write, reopening connection");
          fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
          if (fd2 < 0 && errno == EINTR)
          {
            log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
            return NULL;
          }
          set_nonblock(fd2);
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
          fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
          if (fd2 < 0 && errno == EINTR)
          {
            log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
            return NULL;
          }
          set_nonblock(fd2);
          log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
          continue;
        }
      }
    }
    else if (operation & (1<<7))
    {
      log_log(
             LOG_LEVEL_NOTICE, "CTRL",
             "invalid [%s]:%d proto %d port_valid %d proto_valid %d"
             " mss %d sack %d wscaleshift %d",
             str6,
             (uint16_t)port,
             (uint8_t)proto,
             port != 0,
             proto != 0,
             payload.mss,
             payload.sack_supported,
             payload.wscaleshift);
      if (write(fd2, "0\n", 2) != 2)
      {
        close(fd2);
        log_log(LOG_LEVEL_ERR, "CTRL", "can't write, reopening connection");
        fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
        if (fd2 < 0 && errno == EINTR)
        {
          log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
          return NULL;
        }
        set_nonblock(fd2);
        log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
        continue;
      }
    }
    else
    {
      log_log(
             LOG_LEVEL_NOTICE, "CTRL",
             "invalid %d.%d.%d.%d:%d proto %d port_valid %d proto_valid %d"
             " mss %d sack %d wscaleshift %d",
             (uint8_t)(ip>>24),
             (uint8_t)(ip>>16),
             (uint8_t)(ip>>8),
             (uint8_t)(ip>>0),
             (uint16_t)port,
             (uint8_t)proto,
             port != 0,
             proto != 0,
             payload.mss,
             payload.sack_supported,
             payload.wscaleshift);
      if (write(fd2, "0\n", 2) != 2)
      {
        close(fd2);
        log_log(LOG_LEVEL_ERR, "CTRL", "can't write, reopening connection");
        fd2 = accept_interrupt_dual(fd, fd6, NULL, NULL, args->piperd, NULL);
        if (fd2 < 0 && errno == EINTR)
        {
          log_log(LOG_LEVEL_NOTICE, "CTRL", "exiting");
          return NULL;
        }
        set_nonblock(fd2);
        log_log(LOG_LEVEL_NOTICE, "CTRL", "accepted");
        continue;
      }
    }
  }
  return 0;
}
