%option nounput noinput
%option prefix="confyy"

%{
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "conf.tab.h"
#include "yyutils.h"

#define YYSTYPE CONFYYSTYPE
#define YYLTYPE CONFYYLTYPE

#define YY_USER_ACTION yylloc->first_line = yylloc->last_line = yylineno; \
  yylloc->first_column = yycolumn; yylloc->last_column = yycolumn+yyleng-1; \
  yycolumn += yyleng;

%}

%option reentrant bison-bridge bison-locations
%x COMMENTS
%%

synproxyconf return SYNPROXYCONF;
\{           return OPENBRACE;
\}           return CLOSEBRACE;
;            return SEMICOLON;
,            return COMMA;
sackmode     return SACKHASHMODE;
=            return EQUALS;
disable      return DISABLE;
enable       return ENABLE;
haship       return HASHIP;
hashipport   return HASHIPPORT;
sackhashsize return SACKHASHSIZE;
ratehash     return RATEHASH;
size         return SIZE;
timer_period_usec return TIMER_PERIOD_USEC;
timer_add    return TIMER_ADD;
initial_tokens return INITIAL_TOKENS;
conntablesize return CONNTABLESIZE;
timerheapsize return TIMERHEAPSIZE;
mss          return MSS;
wscale       return WSCALE;
\"([^\\\"]|\\.)*\"  yylval->s=yy_escape_string(yytext); return STRING_LITERAL;

[0-9]+       yylval->i=atoi(yytext); return INT_LITERAL;

\n                                { ++yylineno; yycolumn=1; }
[ \t]+                            /* ignore whitespaces */;
\/\/.*                            /* ignore single-line comments */;
.            return ERROR_TOK;

"/*"                  BEGIN(COMMENTS);
<COMMENTS>"/*"         return ERROR_TOK;
<COMMENTS>"*/"         BEGIN(INITIAL);
<COMMENTS><<EOF>>      return ERROR_TOK;
<COMMENTS>.          ;
<COMMENTS>"\n"       { ++yylineno; yycolumn=1; }

%%
