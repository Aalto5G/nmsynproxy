#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <libgen.h>
#include "conf.h"
#include "log.h"
#include "yyutils.h"

typedef void *yyscan_t;
extern int confyyparse(yyscan_t scanner, struct conf *conf);
extern int confyylex_init(yyscan_t *scanner);
extern void confyyset_in(FILE *in_str, yyscan_t yyscanner);
extern int confyylex_destroy(yyscan_t yyscanner);

void confyydoparse(FILE *filein, struct conf *conf)
{
  yyscan_t scanner;
  confyylex_init(&scanner);
  confyyset_in(filein, scanner);
  if (confyyparse(scanner, conf) != 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER", "parsing failed");
    exit(1);
  }
  confyylex_destroy(scanner);
  if (!feof(filein))
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER", "error: additional data at end of config");
    exit(1);
  }
}

void confyydomemparse(char *filedata, size_t filesize, struct conf *conf)
{
  FILE *myfile;
  myfile = fmemopen(filedata, filesize, "r");
  if (myfile == NULL)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER", "can't open memory file");
    exit(1);
  }
  confyydoparse(myfile, conf);
  if (fclose(myfile) != 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER", "can't close memory file");
    exit(1);
  }
}

char *yy_escape_string(char *orig)
{
  char *buf = NULL;
  char *result = NULL;
  size_t j = 0;
  size_t capacity = 0;
  size_t i = 1;
  while (orig[i] != '"')
  {
    if (j >= capacity)
    {
      char *buf2;
      capacity = 2*capacity+10;
      buf2 = realloc(buf, capacity);
      if (buf2 == NULL)
      {
        free(buf);
        return NULL;
      }
      buf = buf2;
    }
    if (orig[i] != '\\')
    {
      buf[j++] = orig[i++];
    }
    else
    {
      buf[j++] = orig[i+1];
      i += 2;
    }
  }
  if (j >= capacity)
  {
    char *buf2;
    capacity = 2*capacity+10;
    buf2 = realloc(buf, capacity);
    if (buf2 == NULL)
    {
      free(buf);
      return NULL;
    }
    buf = buf2;
  }
  buf[j++] = '\0';
  result = strdup(buf);
  free(buf);
  return result;
}

void confyynameparse(const char *fname, struct conf *conf, int require)
{
  FILE *conffile;
  conffile = fopen(fname, "r");
  if (conffile == NULL)
  {
    if (require)
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER", "File %s cannot be opened", fname);
      exit(1);
    }
    if (conf_postprocess(conf) != 0)
    {
      exit(1);
    }
    return;
  }
  confyydoparse(conffile, conf);
  if (conf_postprocess(conf) != 0)
  {
    exit(1);
  }
  fclose(conffile);
}

void confyydirparse(
  const char *argv0, const char *fname, struct conf *conf, int require)
{
  const char *dir;
  char *copy = strdup(argv0);
  char pathbuf[PATH_MAX];
  dir = dirname(copy); // NB: not for multi-threaded operation!
  snprintf(pathbuf, sizeof(pathbuf), "%s/%s", dir, fname);
  free(copy);
  confyynameparse(pathbuf, conf, require);
}
