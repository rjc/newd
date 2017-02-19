#	$OpenBSD$

PROG=	netcfgd
SRCS=	control.c engine.c frontend.c kroute.c log.c netcfgd.c \
	netcfgd_v4.c netcfgd_v6.c parse.y printconf.c

MAN=	netcfgd.8 netcfgd.conf.5

CFLAGS+= -Wall -I${.CURDIR}
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
YFLAGS=
LDADD+=	-levent -lutil
DPADD+= ${LIBEVENT} ${LIBUTIL}

.include <bsd.prog.mk>
