ETC=/etc/
USR=/usr/
USRETC=/usr/etc/
FILES1=fstab hostname.file inet.conf motd.install mtab profile \
	protocols rc services termcap ttytab utmp rc.cd binary_sizes \
	binary_sizes.big binary_sizes.xxl syslog.conf rc.daemons.dist \
	rs.inet rs.single make.conf system.conf ttys resolv.conf

FILES2=shadow
FILES3=daily dhcptags.conf rc 
FILES4=group master.passwd 

USRFILES=Makefile

TOOL_PWD_MKDB=pwd_mkdb

clean::

install::
	@echo "Installing /etc, /usr/etc and /usr/lib.."
	mkdir -p $(ETC) $(USRLIB)
	@for f in $(FILES1); do if [ -f $(ETC)/$$f ]; then :; else cp $$f $(ETC)/$$f; chmod 755 $(ETC)/$$f; fi; done
	@for f in $(FILES2); do if [ -f $(ETC)/$$f ]; then :; else cp $$f $(ETC)/$$f; chmod 600 $(ETC)/$$f; fi; done
	@for f in $(USRFILES); do cp usr/$$f $(USR)/$$f; chmod 644 $(USR)/$$f; done
	@echo "Making hierarchy.."
	sh mtree.sh mtree/minix.tree
	@for f in $(FILES3); do if [ -f $(USRETC)/$$f ]; then :; else cp usr/$$f $(USRETC); chmod 755 $(USRETC)/$$f; fi; done
	@echo "Making devices.."
	p=`pwd` && cd /dev && sh $$p/../commands/MAKEDEV/MAKEDEV.sh null
	p=`pwd` && cd /dev && sh $$p/../commands/MAKEDEV/MAKEDEV.sh std  2>/dev/null
	install -o root -g operator -m 755 crontab /usr/lib
	@echo "Making user homedirs.."
	for u in /usr/ast ~root; do cp ast/.[aepv]* $$u ; done
	@echo "Installing fonts.."
	install -m 644 -o root -g operator fonts/*.fnt /usr/lib/fonts/
	@echo "Installing /usr/lib/descr.."
	install -m 644 -o root -g operator descr /usr/lib/

installforce:: $(ETC)/rc $(ETC)/rs.inet $(ETC)/rs.single $(ETC)/system.conf $(USRETC)/rc $(USR)/Makefile

installpasswd::
	@echo "Moving old /etc/passwd to /etc/passwd.obsolete"
	`mv /etc/passwd /etc/passwd.obsolete`
	@echo "Moving old /etc/group to /etc/group.obsolete"
	`mv /etc/group /etc/group.obsolete`
	@echo "Leaving old /etc/shadow file intact for now"
	@echo "Making password databases.."
	@for f in $(FILES4); do if [ -f $(ETC)/$$f ]; then :; else cp $$f $(ETC)/$$f; chmod 600 $(ETC)/$$f; fi; done
	touch /etc/pwd.db; touch /etc/spwd.db; ${TOOL_PWD_MKDB} -p /etc/master.passwd

$(ETC)/rc: rc
	install -m 755 -o root -g operator $> $@

$(ETC)/rs.inet: rs.inet
	install -m 755 -o root -g operator $> $@

$(ETC)/rs.single: rs.single
	install -m 755 -o root -g operator $> $@

$(ETC)/system.conf: system.conf
	install -m 644 -o root -g operator $> $@

$(USRETC)/rc: usr/rc
	install -m 755 -o root -g operator $> $@

$(USR)/Makefile: usr/Makefile
	install -m 644 -o root -g operator $> $@
