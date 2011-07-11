# Makefile for Scheduler (SCHED)
PROG=	sched
SRCS=	main.c schedule.c utility.c

DPADD+=	${LIBSYS} ${LIBTIMERS}
LDADD+=	-lsys -ltimers

MAN=

BINDIR?= /usr/sbin
#INSTALLFLAGS+=	-S 32k
install:
	chmem =32000 sched

CPPFLAGS.main.c+=	-I${MINIXSRCDIR}
CPPFLAGS.schedule.c+=	-I${MINIXSRCDIR}
CPPFLAGS.utility.c+=	-I${MINIXSRCDIR}

.include <minix.bootprog.mk>
