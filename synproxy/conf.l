%option nounput noinput
%option prefix="confyy"

%{
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "conf.tab.h"

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
sackmode     return SACKHASHMODE;
=            return EQUALS;
disable      return DISABLE;
enable       return ENABLE;
haship       return HASHIP;
hashipport   return HASHIPPORT;

\n                                { ++yylineno; yycolumn=1; }
[ \t]+                            /* ignore whitespaces */;
\/\/.*                            /* ignore single-line comments */;
.            return ERROR_TOK;

%%
