/* A Bison parser, made by GNU Bison 1.875.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     TOK_STRING = 258,
     TOK_RELATION_SUBSTRING = 259,
     TOK_RELATION_REGEXP = 260,
     TOK_RELATION_GREATER = 261,
     TOK_RELATION_GREATER_OR_EQUAL = 262,
     TOK_RELATION_LESS = 263,
     TOK_RELATION_LESS_OR_EQUAL = 264,
     TOK_RELATION_EQUAL = 265,
     TOK_RELATION_NOT_EQUAL = 266,
     TOK_RELATION_IS_NULL = 267,
     TOK_OPERATOR_AND = 268,
     TOK_OPERATOR_OR = 269
   };
#endif
#define TOK_STRING 258
#define TOK_RELATION_SUBSTRING 259
#define TOK_RELATION_REGEXP 260
#define TOK_RELATION_GREATER 261
#define TOK_RELATION_GREATER_OR_EQUAL 262
#define TOK_RELATION_LESS 263
#define TOK_RELATION_LESS_OR_EQUAL 264
#define TOK_RELATION_EQUAL 265
#define TOK_RELATION_NOT_EQUAL 266
#define TOK_RELATION_IS_NULL 267
#define TOK_OPERATOR_AND 268
#define TOK_OPERATOR_OR 269




#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 66 "idmef-criteria-string.yac.y"
typedef union YYSTYPE {
	char *str;
	idmef_criterion_t *criterion;
	idmef_criteria_t *criteria;
	idmef_relation_t relation;
	idmef_operator_t operator;
} YYSTYPE;
/* Line 1240 of yacc.c.  */
#line 72 "y.tab.h"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif





