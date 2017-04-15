#ifndef _YYUTILS_H_
#define _YYUTILS_H_

#include <stdio.h>
#include "conf.h"

void confyydoparse(FILE *filein, struct conf *conf);

void confyydomemparse(char *filedata, size_t filesize, struct conf *conf);

char *yy_escape_string(char *orig);

#endif

