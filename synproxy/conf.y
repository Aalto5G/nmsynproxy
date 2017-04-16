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
#include "yyutils.h"
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
  char *s;
}

%destructor { free ($$); } STRING_LITERAL

%token ENABLE DISABLE HASHIP HASHIPPORT SACKHASHMODE EQUALS SEMICOLON OPENBRACE CLOSEBRACE SYNPROXYCONF ERROR_TOK INT_LITERAL
%token SACKHASHSIZE RATEHASH SIZE TIMER_PERIOD_USEC TIMER_ADD INITIAL_TOKENS
%token CONNTABLESIZE TIMERHEAPSIZE
%token COMMA MSS WSCALE OWN_MSS OWN_WSCALE
%token STRING_LITERAL
%token SACKCONFLICT REMOVE RETAIN

%type<i> sackhashval
%type<i> sackconflictval
%type<i> INT_LITERAL
%type<s> STRING_LITERAL

%%

synproxyconf: SYNPROXYCONF EQUALS OPENBRACE conflist CLOSEBRACE SEMICOLON
{
  uint8_t bits = 0;
  if (!conf->wscalelist_present)
  {
    if (!DYNARR_PUSH_BACK(&conf->wscalelist, 0))
    {
      fprintf(stderr, "out of memory at line %d col %d\n",
              @1.first_line, @1.first_column);
      YYABORT;
    }
    if (!DYNARR_PUSH_BACK(&conf->wscalelist, 2))
    {
      fprintf(stderr, "out of memory at line %d col %d\n",
              @1.first_line, @1.first_column);
      YYABORT;
    }
    if (!DYNARR_PUSH_BACK(&conf->wscalelist, 4))
    {
      fprintf(stderr, "out of memory at line %d col %d\n",
              @1.first_line, @1.first_column);
      YYABORT;
    }
    if (!DYNARR_PUSH_BACK(&conf->wscalelist, 7))
    {
      fprintf(stderr, "out of memory at line %d col %d\n",
              @1.first_line, @1.first_column);
      YYABORT;
    }
  }
  if (!conf->msslist_present)
  {
    if (!DYNARR_PUSH_BACK(&conf->msslist, 216))
    {
      fprintf(stderr, "out of memory at line %d col %d\n",
              @1.first_line, @1.first_column);
      YYABORT;
    }
    if (!DYNARR_PUSH_BACK(&conf->msslist, 1200))
    {
      fprintf(stderr, "out of memory at line %d col %d\n",
              @1.first_line, @1.first_column);
      YYABORT;
    }
    if (!DYNARR_PUSH_BACK(&conf->msslist, 1400))
    {
      fprintf(stderr, "out of memory at line %d col %d\n",
              @1.first_line, @1.first_column);
      YYABORT;
    }
    if (!DYNARR_PUSH_BACK(&conf->msslist, 1460))
    {
      fprintf(stderr, "out of memory at line %d col %d\n",
              @1.first_line, @1.first_column);
      YYABORT;
    }
  }
  conf->msslist_bits = 255;
  for (bits = 0; bits <= 32; bits++)
  {
    if ((1<<bits) == DYNARR_SIZE(&conf->msslist))
    {
      conf->msslist_bits = bits;
      break;
    }
  }
  conf->wscalelist_bits = 255;
  for (bits = 0; bits <= 32; bits++)
  {
    if ((1<<bits) == DYNARR_SIZE(&conf->wscalelist))
    {
      conf->wscalelist_bits = bits;
      break;
    }
  }
  if (conf->msslist_bits + conf->wscalelist_bits + 1 > 12)
  {
    fprintf(stderr, "too long lists, too little cryptographic security\n");
    YYABORT;
  }
}
;

maybe_comma:
| COMMA
;

sackconflictval:
  REMOVE
{
  $$ = SACKCONFLICT_REMOVE;
}
| RETAIN
{
  $$ = SACKCONFLICT_RETAIN;
}

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

ratehashlist:
| ratehashlist ratehash_entry
;

conflist:
| conflist conflist_entry
;

msslist_entry: INT_LITERAL
{
  if ($1 > 65535)
  {
    fprintf(stderr, "invalid MSS list entry: %d at line %d col %d\n",
            $1, @1.first_line, @1.first_column);
    YYABORT;
  }
  if (!DYNARR_PUSH_BACK(&conf->msslist, $1))
  {
    fprintf(stderr, "out of memory at line %d col %d\n",
            @1.first_line, @1.first_column);
    YYABORT;
  }
}
;

wscalelist_entry: INT_LITERAL
{
  if ($1 > 255)
  {
    fprintf(stderr, "invalid wscale list entry: %d at line %d col %d\n",
            $1, @1.first_line, @1.first_column);
    YYABORT;
  }
  if (!DYNARR_PUSH_BACK(&conf->wscalelist, $1))
  {
    fprintf(stderr, "out of memory at line %d col %d\n",
            @1.first_line, @1.first_column);
    YYABORT;
  }
}
;

msslist:
msslist_entry
| msslist COMMA msslist_entry
;

wscalelist:
wscalelist_entry
| wscalelist COMMA wscalelist_entry
;

msslist_maybe:
| msslist maybe_comma
;

wscalelist_maybe:
| wscalelist maybe_comma
;

conflist_entry:
MSS EQUALS OPENBRACE msslist_maybe CLOSEBRACE SEMICOLON
{
  size_t len = DYNARR_SIZE(&conf->msslist);
  size_t i;
  if ((len & (len-1)) != 0 || len == 0)
  {
    fprintf(stderr, "mss list not power of 2 in size: %zu at line %d col %d\n",
            len, @1.first_line, @1.first_column);
    YYABORT;
  }
  for (i = 1; i < len; i++)
  {
    if (DYNARR_GET(&conf->msslist, i) < DYNARR_GET(&conf->msslist, i-1))
    {
      fprintf(stderr, "mss list not increasing at line %d col %d\n",
              @1.first_line, @1.first_column);
      YYABORT;
    }
  }
  conf->msslist_present = 1;
}
| WSCALE EQUALS OPENBRACE wscalelist_maybe CLOSEBRACE SEMICOLON
{
  size_t len = DYNARR_SIZE(&conf->wscalelist);
  size_t i;
  if ((len & (len-1)) != 0 || len == 0)
  {
    fprintf(stderr, "mss list not power of 2 in size: %zu at line %d col %d\n",
            len, @1.first_line, @1.first_column);
    YYABORT;
  }
  for (i = 1; i < len; i++)
  {
    if (DYNARR_GET(&conf->wscalelist, i) < DYNARR_GET(&conf->wscalelist, i-1))
    {
      fprintf(stderr, "wscale list not increasing at line %d col %d\n",
              @1.first_line, @1.first_column);
      YYABORT;
    }
  }
  conf->wscalelist_present = 1;
}
| OWN_MSS EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0 || $3 > 65535)
  {
    fprintf(stderr, "invalid own_mss: %d at line %d col %d\n",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->own_mss = $3;
}
| OWN_WSCALE EQUALS INT_LITERAL SEMICOLON
{
  if ($3 < 0 || $3 > 14)
  {
    fprintf(stderr, "invalid own_wscale: %d at line %d col %d\n",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->own_wscale = $3;
}
| SACKHASHMODE EQUALS sackhashval SEMICOLON
{
  conf->sackmode = $3;
}
| SACKCONFLICT EQUALS sackconflictval SEMICOLON
{
  conf->sackconflict = $3;
}
| SACKHASHSIZE EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0)
  {
    fprintf(stderr, "invalid sackhash size: %d at line %d col %d\n",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  if (($3 & ($3-1)) != 0)
  {
    fprintf(stderr, "sackhash size not power of 2: %d at line %d col %d\n",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->sackhashsize = $3;
}
| CONNTABLESIZE EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0)
  {
    fprintf(stderr, "invalid conn table size: %d at line %d col %d\n",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  if (($3 & ($3-1)) != 0)
  {
    fprintf(stderr, "conn table size not power of 2: %d at line %d col %d\n",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->conntablesize = $3;
}
| TIMERHEAPSIZE EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0)
  {
    fprintf(stderr, "invalid timer heap size: %d at line %d col %d\n",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->timerheapsize = $3;
}
| RATEHASH EQUALS OPENBRACE ratehashlist CLOSEBRACE SEMICOLON
;

ratehash_entry:
SIZE EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0)
  {
    fprintf(stderr, "invalid ratehash size: %d at line %d col %d\n",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  if (($3 & ($3-1)) != 0)
  {
    fprintf(stderr, "ratehash size not power of 2: %d at line %d col %d\n",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->ratehash.size = $3;
}
| TIMER_PERIOD_USEC EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0)
  {
    fprintf(stderr, "invalid ratehash timer period: %d at line %d col %d\n",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->ratehash.timer_period_usec = $3;
}
| TIMER_ADD EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0)
  {
    fprintf(stderr, "invalid ratehash timer addition: %d at line %d col %d\n",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->ratehash.timer_add = $3;
}
| INITIAL_TOKENS EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0)
  {
    fprintf(stderr, "invalid ratehash initial tokens: %d at line %d col %d\n",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->ratehash.initial_tokens = $3;
}
;
