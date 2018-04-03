%code requires {
#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void *yyscan_t;
#endif
#include "conf.h"
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
}

%define api.prefix {confyy}

%{

#include "conf.h"
#include "log.h"
#include "yyutils.h"
#include "conf.tab.h"
#include "conf.lex.h"

void confyyerror(YYLTYPE *yylloc, yyscan_t scanner, struct conf *conf, const char *str)
{
        log_log(LOG_LEVEL_CRIT, "CONFPARSER", "error: %s at line %d col %d",str, yylloc->first_line, yylloc->first_column);
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
  struct {
    int i;
    char *s;
  } both;
}

%destructor { free ($$); } STRING_LITERAL

%token ENABLE DISABLE HASHIP HASHIPPORT COMMANDED SACKHASHMODE EQUALS SEMICOLON OPENBRACE CLOSEBRACE SYNPROXYCONF ERROR_TOK INT_LITERAL
%token LEARNHASHSIZE RATEHASH SIZE TIMER_PERIOD_USEC TIMER_ADD INITIAL_TOKENS
%token CONNTABLESIZE THREADCOUNT
%token COMMA MSS WSCALE TSMSS TSWSCALE TS_BITS OWN_MSS OWN_WSCALE OWN_SACK
%token STRING_LITERAL
%token SACKCONFLICT REMOVE RETAIN
%token MSS_CLAMP
%token NETWORK_PREFIX NETWORK_PREFIX6 MSSMODE WSCALEMODE DEFAULT HALFOPEN_CACHE_MAX
%token USER GROUP
%token TEST_CONNECTIONS
%token PORT


%type<i> sackhashval
%type<i> msshashval
%type<i> wscaleval
%type<i> sackconflictval
%type<i> own_sack
%type<i> INT_LITERAL
%type<s> STRING_LITERAL
%type<both> intorstring

%%

synproxyconf: SYNPROXYCONF EQUALS OPENBRACE conflist CLOSEBRACE SEMICOLON
;

maybe_comma:
| COMMA
;

intorstring:
  INT_LITERAL
{
  $$.i = $1;
  $$.s = NULL;
}
| STRING_LITERAL
{
  $$.i = 0;
  $$.s = $1;
}
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
;

sackhashval:
  DEFAULT
{
  $$ = HASHMODE_DEFAULT;
}
| HASHIP
{
  $$ = HASHMODE_HASHIP;
}
| HASHIPPORT
{
  $$ = HASHMODE_HASHIPPORT;
}
| COMMANDED
{
  $$ = HASHMODE_COMMANDED;
}
;

own_sack:
  ENABLE
{
  $$ = 1;
}
| DISABLE
{
  $$ = 0;
}

msshashval:
  DEFAULT
{
  $$ = HASHMODE_DEFAULT;
}
| HASHIP
{
  $$ = HASHMODE_HASHIP;
}
| HASHIPPORT
{
  $$ = HASHMODE_HASHIPPORT;
}
| COMMANDED
{
  $$ = HASHMODE_COMMANDED;
}
;

wscaleval:
  DEFAULT
{
  $$ = HASHMODE_DEFAULT;
}
| COMMANDED
{
  $$ = HASHMODE_COMMANDED;
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
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid MSS list entry: %d at line %d col %d",
            $1, @1.first_line, @1.first_column);
    YYABORT;
  }
  if (!DYNARR_PUSH_BACK(&conf->msslist, $1))
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "out of memory at line %d col %d",
            @1.first_line, @1.first_column);
    YYABORT;
  }
}
;

wscalelist_entry: INT_LITERAL
{
  if ($1 > 255)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid wscale list entry: %d at line %d col %d",
            $1, @1.first_line, @1.first_column);
    YYABORT;
  }
  if (!DYNARR_PUSH_BACK(&conf->wscalelist, $1))
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "out of memory at line %d col %d",
            @1.first_line, @1.first_column);
    YYABORT;
  }
}
;

tsmsslist_entry: INT_LITERAL
{
  if ($1 > 65535)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid TS MSS list entry: %d at line %d col %d",
            $1, @1.first_line, @1.first_column);
    YYABORT;
  }
  if (!DYNARR_PUSH_BACK(&conf->tsmsslist, $1))
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "out of memory at line %d col %d",
            @1.first_line, @1.first_column);
    YYABORT;
  }
}
;

tswscalelist_entry: INT_LITERAL
{
  if ($1 > 255)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid TS wscale list entry: %d at line %d col %d",
            $1, @1.first_line, @1.first_column);
    YYABORT;
  }
  if (!DYNARR_PUSH_BACK(&conf->tswscalelist, $1))
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "out of memory at line %d col %d",
            @1.first_line, @1.first_column);
    YYABORT;
  }
}
;

msslist:
msslist_entry
| msslist COMMA msslist_entry
;

tsmsslist:
tsmsslist_entry
| tsmsslist COMMA tsmsslist_entry
;

wscalelist:
wscalelist_entry
| wscalelist COMMA wscalelist_entry
;

tswscalelist:
tswscalelist_entry
| tswscalelist COMMA tswscalelist_entry
;

msslist_maybe:
| msslist maybe_comma
;

wscalelist_maybe:
| wscalelist maybe_comma
;

tsmsslist_maybe:
| tsmsslist maybe_comma
;

tswscalelist_maybe:
| tswscalelist maybe_comma
;

conflist_entry:
TEST_CONNECTIONS SEMICOLON
{
  conf->test_connections = 1;
}
| PORT EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0 || $3 > 65535)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid port: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->port = $3;
}
| USER EQUALS intorstring SEMICOLON
{
  uid_t uid;
  if ($3.s != NULL)
  {
    char *buf;
    char stbuf[1024];
    size_t bufsize;
    struct passwd pwd;
    struct passwd *result;

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize <= 0)
    {
      bufsize = 16384;
    }
    buf = malloc(bufsize);
    if (buf == NULL)
    {
      bufsize = sizeof(stbuf);
      buf = stbuf;
    }
    if (getpwnam_r($3.s, &pwd, buf, bufsize, &result) != 0 || result == NULL)
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER",
              "invalid user: %s at line %d col %d",
              $3.s, @3.first_line, @3.first_column);
      YYABORT;
    }
    uid = result->pw_uid;
    if (buf != stbuf)
    {
      free(buf);
    }
    free($3.s);
    $3.s = NULL;
  }
  else
  {
    uid = $3.i;
  }
  conf->uid = uid;
}
| GROUP EQUALS intorstring SEMICOLON
{
  gid_t gid;
  if ($3.s != NULL)
  {
    char *buf;
    char stbuf[1024];
    size_t bufsize;
    struct group pwd;
    struct group *result;

    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize <= 0)
    {
      bufsize = 16384;
    }
    buf = malloc(bufsize);
    if (buf == NULL)
    {
      bufsize = sizeof(stbuf);
      buf = stbuf;
    }
    if (getgrnam_r($3.s, &pwd, buf, bufsize, &result) != 0 || result == NULL)
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER",
              "invalid group: %s at line %d col %d",
              $3.s, @3.first_line, @3.first_column);
      YYABORT;
    }
    gid = result->gr_gid;
    if (buf != stbuf)
    {
      free(buf);
    }
    free($3.s);
    $3.s = NULL;
  }
  else
  {
    gid = $3.i;
  }
  conf->gid = gid;
}
| MSS_CLAMP EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0 || $3 > 65535)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid mss_clamp: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->mss_clamp_enabled = 1;
  conf->mss_clamp = $3;
}
| MSS EQUALS OPENBRACE msslist_maybe CLOSEBRACE SEMICOLON
{
  size_t len = DYNARR_SIZE(&conf->msslist);
  size_t i;
  if ((len & (len-1)) != 0 || len == 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "mss list not power of 2 in size: %zu at line %d col %d",
            len, @1.first_line, @1.first_column);
    YYABORT;
  }
  for (i = 1; i < len; i++)
  {
    if (DYNARR_GET(&conf->msslist, i) < DYNARR_GET(&conf->msslist, i-1))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER",
              "mss list not increasing at line %d col %d",
              @1.first_line, @1.first_column);
      YYABORT;
    }
  }
  conf->msslist_present = 1;
}
| TSMSS EQUALS OPENBRACE tsmsslist_maybe CLOSEBRACE SEMICOLON
{
  size_t len = DYNARR_SIZE(&conf->tsmsslist);
  size_t i;
  if ((len & (len-1)) != 0 || len == 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "tsmss list not power of 2 in size: %zu at line %d col %d\n",
            len, @1.first_line, @1.first_column);
    YYABORT;
  }
  for (i = 1; i < len; i++)
  {
    if (DYNARR_GET(&conf->tsmsslist, i) < DYNARR_GET(&conf->tsmsslist, i-1))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER",
              "tsmss list not increasing at line %d col %d",
              @1.first_line, @1.first_column);
      YYABORT;
    }
  }
  conf->tsmsslist_present = 1;
}
| WSCALE EQUALS OPENBRACE wscalelist_maybe CLOSEBRACE SEMICOLON
{
  size_t len = DYNARR_SIZE(&conf->wscalelist);
  size_t i;
  if ((len & (len-1)) != 0 || len == 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "wscale list not power of 2 in size: %zu at line %d col %d",
            len, @1.first_line, @1.first_column);
    YYABORT;
  }
  if (DYNARR_GET(&conf->wscalelist, 0) != 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "wscale list must begin with 0: %zu at line %d col %d",
            len, @1.first_line, @1.first_column);
    YYABORT;
  }
  for (i = 1; i < len; i++)
  {
    if (DYNARR_GET(&conf->wscalelist, i) < DYNARR_GET(&conf->wscalelist, i-1))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER",
              "wscale list not increasing at line %d col %d",
              @1.first_line, @1.first_column);
      YYABORT;
    }
  }
  conf->wscalelist_present = 1;
}
| TSWSCALE EQUALS OPENBRACE tswscalelist_maybe CLOSEBRACE SEMICOLON
{
  size_t len = DYNARR_SIZE(&conf->tswscalelist);
  size_t i;
  if ((len & (len-1)) != 0 || len == 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "tswscale list not power of 2 in size: %zu at line %d col %d",
            len, @1.first_line, @1.first_column);
    YYABORT;
  }
  if (DYNARR_GET(&conf->tswscalelist, 0) != 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "tswscale list must begin with 0: %zu at line %d col %d",
            len, @1.first_line, @1.first_column);
    YYABORT;
  }
  for (i = 1; i < len; i++)
  {
    if (DYNARR_GET(&conf->tswscalelist, i) < DYNARR_GET(&conf->tswscalelist, i-1))
    {
      log_log(LOG_LEVEL_CRIT, "CONFPARSER",
              "tswscale list not increasing at line %d col %d",
              @1.first_line, @1.first_column);
      YYABORT;
    }
  }
  conf->tswscalelist_present = 1;
}
| OWN_SACK EQUALS own_sack SEMICOLON
{
  conf->own_sack = $3;
}
| OWN_MSS EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0 || $3 > 65535)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid own_mss: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->own_mss = $3;
}
| OWN_WSCALE EQUALS INT_LITERAL SEMICOLON
{
  if ($3 < 0 || $3 > 14)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid own_wscale: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->own_wscale = $3;
}
| SACKHASHMODE EQUALS sackhashval SEMICOLON
{
  conf->sackmode = $3;
}
| WSCALEMODE EQUALS wscaleval SEMICOLON
{
  conf->wscalemode = $3;
}
| MSSMODE EQUALS msshashval SEMICOLON
{
  conf->mssmode = $3;
}
| SACKCONFLICT EQUALS sackconflictval SEMICOLON
{
  conf->sackconflict = $3;
}
| LEARNHASHSIZE EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid learnhash size: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  if (($3 & ($3-1)) != 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "learnhash size not power of 2: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->learnhashsize = $3;
}
| CONNTABLESIZE EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid conn table size: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  if (($3 & ($3-1)) != 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "conn table size not power of 2: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->conntablesize = $3;
}
| THREADCOUNT EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid thread count: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->threadcount = $3;
}
| TS_BITS EQUALS INT_LITERAL SEMICOLON
{
  if ($3 < 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid ts bits: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  if ($3 > 12)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid ts bits: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->ts_bits = $3;
}
| HALFOPEN_CACHE_MAX EQUALS INT_LITERAL SEMICOLON
{
  if ($3 < 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid halfopen_cache_max: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->halfopen_cache_max = $3;
}
| RATEHASH EQUALS OPENBRACE ratehashlist CLOSEBRACE SEMICOLON
;

ratehash_entry:
SIZE EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid ratehash size: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  if (($3 & ($3-1)) != 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "ratehash size not power of 2: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->ratehash.size = $3;
}
| TIMER_PERIOD_USEC EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid ratehash timer period: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->ratehash.timer_period_usec = $3;
}
| TIMER_ADD EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid ratehash timer addition: %d at line %d col %d\n",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->ratehash.timer_add = $3;
}
| INITIAL_TOKENS EQUALS INT_LITERAL SEMICOLON
{
  if ($3 <= 0)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid ratehash initial tokens: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->ratehash.initial_tokens = $3;
}
| NETWORK_PREFIX EQUALS INT_LITERAL SEMICOLON
{
  if ($3 < 0 || $3 > 32)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid ratehash network prefix: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->ratehash.network_prefix = $3;
}
| NETWORK_PREFIX6 EQUALS INT_LITERAL SEMICOLON
{
  if ($3 < 0 || $3 > 128)
  {
    log_log(LOG_LEVEL_CRIT, "CONFPARSER",
            "invalid ratehash network prefix6: %d at line %d col %d",
            $3, @3.first_line, @3.first_column);
    YYABORT;
  }
  conf->ratehash.network_prefix6 = $3;
}
;
