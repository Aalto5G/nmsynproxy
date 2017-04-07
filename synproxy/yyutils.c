#include <stdio.h>
#include <stdlib.h>
#include "conf.h"
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
    fprintf(stderr, "parsing failed\n");
    exit(1);
  }
  confyylex_destroy(scanner);
  if (!feof(filein))
  {
    fprintf(stderr,"error: additional data at end of config\n");
    exit(1);
  }
}

void confyydomemparse(char *filedata, size_t filesize, struct conf *conf)
{
  FILE *myfile;
  myfile = fmemopen(filedata, filesize, "r");
  if (myfile == NULL)
  {
    printf("can't open memory file\n");
    exit(1);
  }
  confyydoparse(myfile, conf);
  if (fclose(myfile) != 0)
  {
    fprintf(stderr, "can't close memory file");
    exit(1);
  }
}
