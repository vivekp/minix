# Makefile for the init program (INIT)
.include <bsd.own.mk>

PROG=	init
SRCS=	init.c

MAN=

BINDIR?= /usr/sbin
#INSTALLFLAGS+=	-S 64k
install:
	chmem =64000 init

.if ${OBJECT_FMT} == "ELF"
LDFLAGS+= -Wl,--section-start=.init=0x0
.endif

.include <bsd.prog.mk>
