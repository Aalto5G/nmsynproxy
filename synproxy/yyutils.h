#ifndef _YYUTILS_H_
#define _YYUTILS_H_

#include <stdio.h>
#include "conf.h"

void confyydoparse(FILE *filein, struct conf *conf);

void confyydomemparse(char *filedata, size_t filesize, struct conf *conf);

void confyynameparse(const char *fname, struct conf *conf, int require);

void confyydirparse(
  const char *argv0, const char *fname, struct conf *conf, int require);

char *yy_escape_string(char *orig);

#endif

