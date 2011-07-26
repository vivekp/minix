# Makefile for commands.

.include <bsd.own.mk>

SUBDIR=	aal add_route arp at autil awk \
	backup badblocks banner basename binpackage \
	binpackages bzip2 bzip2recover cal calendar \
	cat cawf cd  cdprobe checkhier chmem \
	chroot cksum cleantmp clear cmp \
	comm compress cp crc cut \
	dd decomp16 DESCRIBE dev2name devsize df dhcpd \
	dhrystone diff dirname  dis386 dis88 diskctl du dumpcore \
	ed eject env expand factor file \
	fingerd fix fold format fortune fsck.mfs \
	ftp101 gcov-pull getty grep head hexdump host \
	hostaddr ifconfig ifdef \
	intr ipcrm irdpd isoread join kill last \
	less lex loadkeys loadramdisk look lp \
	lpd lspci M make  MAKEDEV \
	mdb mdocml mesg mined ackmkdep mkdir mkfifo mkfs.mfs mknod \
	mkproto modem mount mt netconf newroot nice acknm nohup \
	nonamed od paste patch \
	ping postinstall poweroff pr prep printf printroot \
	profile progressbar proto pr_routes ps pwd \
	ramdisk rarpd rawspeed rdate readall readclock \
	readfs remsync rev rget rmdir \
	rotate sed setup shar acksize \
	sleep slip sort spell split srccrc ackstrip \
	stty sum svclog swapfs swifi sync synctree sysenv \
	syslogd tail tcpd tcpdp tcpstat tee telnet \
	telnetd term termcap tget time tinyhalt touch tr \
	truncate tsort tty udpstat umount uname unexpand \
	unstack update uud uue version vol wc \
	whereis which who writeisofs \
	xargs yacc yes zdump zic zmodem pkgin_cd \
	mktemp

.if ${COMPILER_TYPE} == "gnu"
SUBDIR += elf2aout
.endif

.if ${ARCH} == "i386"
SUBDIR+=	atnormalize dosread fdisk loadfont \
	autopart part partition playwave postmort \
	recwave repartition screendump padtext
SUBDIR+=	acd asmconv gas2ack
.endif

#Port the NetBSD version of these utilities
#SUBDIR+= ash date find install ls man su write
#Don't compile them for now
#SUBDIR+= co ci cron crontab de elle elvis fetch finger ftpd200 \
	 id ipcs leave logger mail pax pwdauth rcp reboot \
	 rlogin rlogind rsh rshd service su tar

.include <bsd.subdir.mk>
