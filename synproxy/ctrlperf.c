#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include "read.h"

#define MSGS 16384

int main(int argc, char **argv)
{
  int sock;
  struct sockaddr_in sin;
  uint32_t u32;
  uint16_t u16;
  uint8_t u8;
  int i;
  char msg[12] = {0};
  char msgs[12*MSGS];
  char resp[2*MSGS];
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0)
  {
    abort();
  }
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sin.sin_port = htons(12345);
  if (connect(sock, (struct sockaddr*)&sin, sizeof(sin)) < 0)
  {
    perror("connect failed");
    abort();
  }
  u32 = htonl(0);
  memcpy(&msg[0], &u32, 4);
  u16 = htons(0);
  memcpy(&msg[4], &u16, 2);
  u8 = 0;
  memcpy(&msg[6], &u8, 1);
  u8 = 1<<1;
  memcpy(&msg[7], &u8, 1);
  u16 = htons(1460);
  memcpy(&msg[8], &u16, 2);
  u8 = 1;
  memcpy(&msg[10], &u8, 1);
  u8 = 7;
  memcpy(&msg[11], &u8, 1);
  for (i = 0; i < MSGS; i++)
  {
    memcpy(&msgs[12*i], msg, 12);
  }
  for (i = 0; i < 1048576/MSGS; i++)
  {
    if (write(sock, msgs, sizeof(msgs)) != sizeof(msgs))
    {
      abort();
    }
    if (readall(sock, resp, sizeof(resp)) != sizeof(resp))
    {
      abort();
    }
  }
  close(sock);
  return 0;
}
