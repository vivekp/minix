# Makefile for log driver
PROG=	log
SRCS=	log.c diag.c liveupdate.c

DPADD+=	${LIBDRIVER} ${LIBSYS}
LDADD+=	-ldriver -lsys

MAN=

BINDIR?= /usr/sbin
#INSTALLFLAGS+=	-S 32k
install:
	chmem =32000 log
.include <minix.bootprog.mk>
