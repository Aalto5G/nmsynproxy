%code requires {
#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void *yyscan_t;
#endif
#include "conf.h"
}

%define api.prefix {confyy}

%{

#include "conf.h"
#include "conf.tab.h"
#include "conf.lex.h"

void confyyerror(YYLTYPE *yylloc, yyscan_t scanner, struct conf *conf, const char *str)
{
        fprintf(stderr,"error: %s at line %d col %d\n",str, yylloc->first_line, yylloc->first_column);
}

int confyywrap(yyscan_t scanner)
{
        return 1;
}

%}

%pure-parser
%lex-param {yyscan_t scanner}
%parse-param {yyscan_t scanner}
%parse-param {struct conf *conf}
%locations

%union {
  int i;
}

%token ENABLE DISABLE HASHIP HASHIPPORT SACKHASHMODE EQUALS SEMICOLON OPENBRACE CLOSEBRACE SYNPROXYCONF ERROR_TOK
%type<i> sackhashval

%%

synproxyconf: SYNPROXYCONF OPENBRACE conflist CLOSEBRACE
;

sackhashval:
  ENABLE
{
  $$ = SACKMODE_ENABLE;
}
| DISABLE
{
  $$ = SACKMODE_DISABLE;
}
| HASHIP
{
  $$ = SACKMODE_HASHIP;
}
| HASHIPPORT
{
  $$ = SACKMODE_HASHIPPORT;
}
;

conflist:
| conflist conflist_entry
;

conflist_entry:
SACKHASHMODE EQUALS sackhashval SEMICOLON
{
  conf->sackmode = $3;
}
;
