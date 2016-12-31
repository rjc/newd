/*	$OpenBSD$	*/

/*
 * Copyright (c) YYYY YOUR NAME HERE <user@your.dom.ain>
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2004 Ryan McBride <mcbride@openbsd.org>
 * Copyright (c) 2002, 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

%{
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <ifaddrs.h>
#include <imsg.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "newd.h"
#include "frontend.h"
#include "log.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	int			 lineno;
	int			 errors;
} *file, *topfile;
struct file	*pushfile(const char *, int);
int		 popfile(void);
int		 check_file_secrecy(int, const char *);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 lgetc(int);
int		 lungetc(int);
int		 findeol(void);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};
int		 symset(const char *, const char *, int);
char		*symget(const char *);

void		 clear_config(struct newd_conf *xconf);

static struct newd_conf	*conf;
static int		 errors = 0;

struct group	*group = NULL;

struct config_defaults {
	int		yesno_attribute;
	int		global_yesno_attribute;

	int		integer_attribute;
	int		global_integer_attribute;

	struct in_addr	v4address_attribute;
	struct in_addr	global_v4address_attribute;

	struct in6_addr	v6address_attribute;
	struct in6_addr	global_v6address_attribute;

	char		*string_attribute;
	char		*global_string_attribute;
};

struct group_defaults {
	int		yesno_attribute;
	int		group_yesno_attribute;

	int		integer_attribute;
	int		group_integer_attribute;

	struct in_addr	v4address_attribute;
	struct in_addr	group_v4address_attribute;

	struct in6_addr	v6address_attribute;
	struct in6_addr	group_v6address_attribute;

	char		*string_attribute;
	char		*group_string_attribute;
};

struct config_defaults	 globaldefs;
struct group_defaults	 groupdefs;
struct config_defaults	*defs;

struct group	*conf_get_group(char *);
void		*conf_del_group(struct group *);

typedef struct {
	union {
		int64_t		 number;
		char		*string;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	GROUP YES NO INCLUDE ERROR

%token	GLOBAL_YESNO_ATTRIBUTE GLOBAL_INTEGER_ATTRIBUTE GLOBAL_STRING_ATTRIBUTE
%token	GROUP_YESNO_ATTRIBUTE GROUP_INTEGER_ATTRIBUTE GROUP_STRING_ATTRIBUTE
%token	YESNO_ATTRIBUTE INTEGER_ATTRIBUTE STRING_ATTRIBUTE

%token	GLOBAL_V4ADDRESS_ATTRIBUTE GLOBAL_V6ADDRESS_ATTRIBUTE
%token	GROUP_V4ADDRESS_ATTRIBUTE GROUP_V6ADDRESS_ATTRIBUTE
%token	V4ADDRESS_ATTRIBUTE V6ADDRESS_ATTRIBUTE

%token	<v.string>	STRING
%token	<v.number>	NUMBER
%type	<v.number>	yesno
%type	<v.string>	string

%%

grammar		: /* empty */
		| grammar include '\n'
		| grammar '\n'
		| grammar conf_main '\n'
		| grammar varset '\n'
		| grammar group '\n'
		| grammar error '\n'		{ file->errors++; }
		;

include		: INCLUDE STRING		{
			struct file	*nfile;

			if ((nfile = pushfile($2, 1)) == NULL) {
				yyerror("failed to include file %s", $2);
				free($2);
				YYERROR;
			}
			free($2);

			file = nfile;
			lungetc('\n');
		}
		;

string		: string STRING	{
			if (asprintf(&$$, "%s %s", $1, $2) == -1) {
				free($1);
				free($2);
				yyerror("string: asprintf");
				YYERROR;
			}
			free($1);
			free($2);
		}
		| STRING
		;

yesno		: YES	{ $$ = 1; }
		| NO	{ $$ = 0; }
		;

varset		: STRING '=' string		{
			char *s = $1;
			if (conf->opts & OPT_VERBOSE)
				printf("%s = \"%s\"\n", $1, $3);
			while (*s++) {
				if (isspace((unsigned char)*s)) {
					yyerror("macro name cannot contain "
					    "whitespace");
					YYERROR;
				}
			}
			if (symset($1, $3, 0) == -1)
				fatal("cannot store variable");
			free($1);
			free($3);
		}
		;

conf_main	: V4ADDRESS_ATTRIBUTE STRING {
			memset(&conf->v4address_attribute, 0,
			    sizeof(conf->v4address_attribute));
			conf->v4_bits = inet_net_pton(AF_INET, $2,
			    &conf->v4address_attribute,
			    sizeof(conf->v4address_attribute));
			if (conf->v4_bits == -1) {
				yyerror("error parsing v4address_attribute");
				free($2);
				YYERROR;
			}
		}
		| GLOBAL_V4ADDRESS_ATTRIBUTE STRING {
			memset(&conf->global_v4address_attribute, 0,
			    sizeof(conf->global_v4address_attribute));
			conf->global_v4_bits = inet_net_pton(AF_INET, $2,
			    &conf->global_v4address_attribute,
			    sizeof(conf->global_v4address_attribute));
			if (conf->global_v4_bits == -1) {
				yyerror("error parsing global_v4address_attribute");
				free($2);
				YYERROR;
			}
		}
		| V6ADDRESS_ATTRIBUTE STRING {
			memset(&conf->v6address_attribute, 0,
			    sizeof(conf->v6address_attribute));
			conf->v6_bits = inet_net_pton(AF_INET6, $2,
			    &conf->v6address_attribute,
			    sizeof(conf->v6address_attribute));
			if (conf->v6_bits == -1) {
				yyerror("error parsing v6address_attribute");
				free($2);
				YYERROR;
			}
		}
		| GLOBAL_V6ADDRESS_ATTRIBUTE STRING {
			memset(&conf->global_v6address_attribute, 0,
			    sizeof(conf->global_v6address_attribute));
			conf->global_v6_bits = inet_net_pton(AF_INET6, $2,
			    &conf->global_v6address_attribute,
			    sizeof(conf->global_v6address_attribute));
			if (conf->global_v6_bits == -1) {
				yyerror("error parsing global_v6address_attribute");
				free($2);
				YYERROR;
			}
		}
		| YESNO_ATTRIBUTE yesno {
			conf->yesno_attribute = $2;
		}
		| GLOBAL_YESNO_ATTRIBUTE yesno {
			conf->global_yesno_attribute = $2;
		}
		| INTEGER_ATTRIBUTE NUMBER {
			conf->integer_attribute = $2;
		}
		| GLOBAL_INTEGER_ATTRIBUTE NUMBER {
			conf->global_integer_attribute = $2;
		}
		| STRING_ATTRIBUTE STRING {
			conf->string_attribute = $2;
		}
		| GLOBAL_STRING_ATTRIBUTE STRING {
			conf->global_string_attribute = $2;
		}

optnl		: '\n' optnl		/* zero or more newlines */
		| /*empty*/
		;

nl		: '\n' optnl		/* one or more newlines */
		;

comma		: ','			/* zero or one comma */
		| /*empty*/
		;

group		: GROUP STRING {
			group = conf_get_group($2);

			memcpy(&groupdefs, defs, sizeof(groupdefs));
			defs = &groupdefs;
		} '{' optnl groupopts_l '}' {
			group = NULL;
			defs = &globaldefs;
		}
		;

groupopts_l	: groupopts_l groupoptsl nl
		| groupoptsl optnl
		;

groupoptsl	: V4ADDRESS_ATTRIBUTE STRING {
			memset(&group->v4address_attribute, 0,
			    sizeof(group->v4address_attribute));
			group->v4_bits = inet_net_pton(AF_INET, $2,
			    &group->v4address_attribute,
			    sizeof(group->v4address_attribute));
			if (group->v4_bits == -1) {
				yyerror("error parsing v4address_attribute");
				free($2);
				YYERROR;
			}
		}
		| GROUP_V4ADDRESS_ATTRIBUTE STRING {
			memset(&group->group_v4address_attribute, 0,
			    sizeof(group->group_v4address_attribute));
			group->group_v4_bits = inet_net_pton(AF_INET, $2,
			    &group->group_v4address_attribute,
			    sizeof(group->group_v4address_attribute));
			if (group->group_v4_bits == -1) {
				yyerror("error parsing group_v4address_attribute");
				free($2);
				YYERROR;
			}
		}
		| V6ADDRESS_ATTRIBUTE STRING {
			memset(&group->v6address_attribute, 0,
			    sizeof(group->v6address_attribute));
			group->v6_bits = inet_net_pton(AF_INET6, $2,
			    &group->v6address_attribute,
			    sizeof(group->v6address_attribute));
			if (group->v6_bits == -1) {
				yyerror("error parsing v6address_attribute");
				free($2);
				YYERROR;
			}
		}
		| GROUP_V6ADDRESS_ATTRIBUTE STRING {
			memset(&group->group_v6address_attribute, 0,
			    sizeof(group->group_v6address_attribute));
			group->group_v6_bits = inet_net_pton(AF_INET6, $2,
			    &group->group_v6address_attribute,
			    sizeof(group->group_v6address_attribute));
			if (group->group_v6_bits == -1) {
				yyerror("error parsing group_v6address_attribute");
				free($2);
				YYERROR;
			}
		}
		| YESNO_ATTRIBUTE yesno {
			group->yesno_attribute = $2;
		}
		| GROUP_YESNO_ATTRIBUTE yesno {
			group->group_yesno_attribute = $2;
		}
		| INTEGER_ATTRIBUTE NUMBER {
			group->integer_attribute = $2;
		}
		| GROUP_INTEGER_ATTRIBUTE NUMBER {
			group->group_integer_attribute = $2;
		}
		| STRING_ATTRIBUTE STRING {
			group->string_attribute = $2;
		}
		| GROUP_STRING_ATTRIBUTE STRING {
			group->group_string_attribute = $2;
		}
		;

%%

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*msg;

	file->errors++;
	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		fatalx("yyerror vasprintf");
	va_end(ap);
	logit(LOG_CRIT, "%s:%d: %s", file->name, yylval.lineno, msg);
	free(msg);
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{"global-integer-attribute",	GLOBAL_INTEGER_ATTRIBUTE},
		{"global-string-attribute",	GLOBAL_STRING_ATTRIBUTE},
		{"global-v4address-attribute",	GLOBAL_V4ADDRESS_ATTRIBUTE},
		{"global-v6address-attribute",	GLOBAL_V6ADDRESS_ATTRIBUTE},
		{"global-yesno-attribute",	GLOBAL_YESNO_ATTRIBUTE},
		{"group",			GROUP},
		{"group-integer-attribute",	GROUP_INTEGER_ATTRIBUTE},
		{"group-string-attribute",	GROUP_STRING_ATTRIBUTE},
		{"group-v4address-attribute",	GROUP_V4ADDRESS_ATTRIBUTE},
		{"group-v6address-attribute",	GROUP_V6ADDRESS_ATTRIBUTE},
		{"group-yesno-attribute",	GROUP_YESNO_ATTRIBUTE},
		{"include",			INCLUDE},
		{"integer-attribute",		INTEGER_ATTRIBUTE},
		{"no",				NO},
		{"string-attribute",		STRING_ATTRIBUTE},
		{"v4address-attribute",		V4ADDRESS_ATTRIBUTE},
		{"v6address-attribute",		V6ADDRESS_ATTRIBUTE},
		{"yes",				YES},
		{"yesno-attribute",		YESNO_ATTRIBUTE}
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

#define MAXPUSHBACK	128

u_char	*parsebuf;
int	 parseindex;
u_char	 pushback_buffer[MAXPUSHBACK];
int	 pushback_index = 0;

int
lgetc(int quotec)
{
	int		c, next;

	if (parsebuf) {
		/* Read character from the parsebuffer instead of input. */
		if (parseindex >= 0) {
			c = parsebuf[parseindex++];
			if (c != '\0')
				return (c);
			parsebuf = NULL;
		} else
			parseindex++;
	}

	if (pushback_index)
		return (pushback_buffer[--pushback_index]);

	if (quotec) {
		if ((c = getc(file->stream)) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return (EOF);
			return (quotec);
		}
		return (c);
	}

	while ((c = getc(file->stream)) == '\\') {
		next = getc(file->stream);
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	while (c == EOF) {
		if (file == topfile || popfile() == EOF)
			return (EOF);
		c = getc(file->stream);
	}
	return (c);
}

int
lungetc(int c)
{
	if (c == EOF)
		return (EOF);
	if (parsebuf) {
		parseindex--;
		if (parseindex >= 0)
			return (c);
	}
	if (pushback_index < MAXPUSHBACK-1)
		return (pushback_buffer[pushback_index++] = c);
	else
		return (EOF);
}

int
findeol(void)
{
	int	c;

	parsebuf = NULL;

	/* skip to either EOF or the first real EOL */
	while (1) {
		if (pushback_index)
			c = pushback_buffer[--pushback_index];
		else
			c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

int
yylex(void)
{
	u_char	 buf[8096];
	u_char	*p, *val;
	int	 quotec, next, c;
	int	 token;

top:
	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && parsebuf == NULL) {
		while (1) {
			if ((c = lgetc(0)) == EOF)
				return (0);

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			if (isalnum(c) || c == '_') {
				*p++ = c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro '%s' not defined", buf);
			return (findeol());
		}
		parsebuf = val;
		parseindex = 0;
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || c == ' ' || c == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			} else if (c == '\0') {
				yyerror("syntax error");
				return (findeol());
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			err(1, "yylex: strdup");
		return (STRING);
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return (findeol());
			}
			return (NUMBER);
		} else {
nodigits:
			while (p > buf + 1)
				lungetc(*--p);
			c = *--p;
			if (c == '-')
				return (c);
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && \
	x != '!' && x != '=' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_') {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				err(1, "yylex: strdup");
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

int
check_file_secrecy(int fd, const char *fname)
{
	struct stat	st;

	if (fstat(fd, &st)) {
		log_warn("cannot stat %s", fname);
		return (-1);
	}
	if (st.st_uid != 0 && st.st_uid != getuid()) {
		log_warnx("%s: owner not root or current user", fname);
		return (-1);
	}
	if (st.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) {
		log_warnx("%s: group writable or world read/writable", fname);
		return (-1);
	}
	return (0);
}

struct file *
pushfile(const char *name, int secret)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		log_warn("malloc");
		return (NULL);
	}
	if ((nfile->name = strdup(name)) == NULL) {
		log_warn("malloc");
		free(nfile);
		return (NULL);
	}
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		log_warn("%s", nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	} else if (secret &&
	    check_file_secrecy(fileno(nfile->stream), nfile->name)) {
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = 1;
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return (nfile);
}

int
popfile(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file);
	file = prev;
	return (file ? 0 : EOF);
}

struct newd_conf *
parse_config(char *filename, int opts)
{
	struct sym	*sym, *next;

	if ((conf = calloc(1, sizeof(struct newd_conf))) == NULL)
		fatal("parse_config");
	conf->opts = opts;

	bzero(&globaldefs, sizeof(globaldefs));
	defs = &globaldefs;

	if ((file = pushfile(filename, !(conf->opts & OPT_NOACTION)))
	    == NULL) {
		free(conf);
		return (NULL);
	}
	topfile = file;

	LIST_INIT(&conf->group_list);

	yyparse();
	errors = file->errors;
	popfile();

	/* Free macros and check which have not been used. */
	for (sym = TAILQ_FIRST(&symhead); sym != NULL; sym = next) {
		next = TAILQ_NEXT(sym, entry);
		if ((conf->opts & OPT_VERBOSE2) && !sym->used)
			fprintf(stderr, "warning: macro '%s' not "
			    "used\n", sym->nam);
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	if (errors) {
		clear_config(conf);
		return (NULL);
	}

	return (conf);
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	for (sym = TAILQ_FIRST(&symhead); sym && strcmp(nam, sym->nam);
	    sym = TAILQ_NEXT(sym, entry))
		;	/* nothing */

	if (sym != NULL) {
		if (sym->persist == 1)
			return (0);
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return (-1);

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return (-1);
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return (-1);
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return (0);
}

int
cmdline_symset(char *s)
{
	char	*sym, *val;
	int	ret;
	size_t	len;

	if ((val = strrchr(s, '=')) == NULL)
		return (-1);

	len = strlen(s) - strlen(val) + 1;
	if ((sym = malloc(len)) == NULL)
		errx(1, "cmdline_symset: malloc");

	strlcpy(sym, s, len);

	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
}

char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry)
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	return (NULL);
}

struct group *
conf_get_group(char *name)
{
	struct group	*g;

	LIST_FOREACH(g, &conf->group_list, entry) {
		if (g->name != NULL && strcmp(name, g->name)== 0)
			return (g);
	}

	g = calloc(1, sizeof(*g));
	if (g == NULL)
		errx(1, "get_group: calloc");
	g->name = strdup(name);
	if (g->name == NULL)
		errx(1, "get_group: strdup");

	LIST_INSERT_HEAD(&conf->group_list, g, entry);

	return (g);
}

void
clear_config(struct newd_conf *xconf)
{
	struct group	*g;

	while ((g = LIST_FIRST(&xconf->group_list)) != NULL) {
		LIST_REMOVE(g, entry);
		free(g->name);
		free(g);
	}

	free(xconf);
}