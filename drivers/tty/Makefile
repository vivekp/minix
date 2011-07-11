# Makefile for terminal driver (TTY)

PROG=	tty
SRCS=	tty.c console.c keyboard.c pty.c rs232.c

DPADD+=	${LIBDRIVER} ${LIBSYS} ${LIBTIMERS}
LDADD+=	-ldriver -lsys -ltimers

MAN=

BINDIR?= /usr/sbin
#INSTALLFLAGS+=	-S 16k
install:
	chmem =16000 tty
SUBDIR= keymaps

# Needs kernel/const.h, etc
CPPFLAGS+=	-I${MINIXSRCDIR}

.include <minix.bootprog.mk>
.include <bsd.subdir.mk>
