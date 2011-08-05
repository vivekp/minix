#!/bin/sh
set -e

if [ $# -ne 0 ]
then	echo "Usage: $0"
	exit 1
fi

ETC=/etc
NBSD_PASSWD_ORIG=etc/master.passwd
NBSD_PASSWD_NEW=$ETC/master.passwd
PASSWD_FILE=$ETC/passwd
SHADOW_FILE=$ETC/shadow

if [ -f $ETC/pwd.db ]
then	echo "You have already switched to NetBSD passwd format."
	echo "You can't save the old user accounts now. Sorry, it's too late!"
	exit 1
fi

if [ -f $NBSD_PASSWD_NEW ]
then	`rm $NBSD_PASSWD_NEW`
	`touch $NBSD_PASSWD_NEW`	# create a new /etc/master.passwd file
fi

cat $PASSWD_FILE | while read line 	# read /etc/passwd file
do
	NF="`echo $line | awk -F ':' '{ print NF}'`"
	if [ $NF = 7 ]
	then
		user="`echo $line | awk -F ':' '{ print $1 }'`"
		flag=0
		password="*"

		while read pw_line	# read master.passwd file
		do
			pw_name="`echo $pw_line | awk -F ':' '{ print $1 }'`"
			if [ $user = $pw_name ]
			then
				while read sw_line	# read /etc/shadow file
				do
					sw_name="`echo $sw_line | awk -F ':' '{ print $1 }'`"
					if [ $user = $sw_name ]
					then
						password="`echo $sw_line | awk -F ':' '{ print $2 }'`"
						break
					else
						continue
					fi
				done<$SHADOW_FILE

				uid="`echo $pw_line | awk -F ':' '{ print $3 }'`"
				gid="`echo $pw_line | awk -F ':' '{ print $4 }'`"
				info="`echo $pw_line | awk -F ':' '{ print $8 }'`"
				homedir="`echo $pw_line | awk -F ':' '{ print $9 }'`"
				shell="`echo $pw_line | awk -F ':' '{ print $10 }'`"
				echo $user:$password:$uid:$gid::0:0:$info:$homedir:$shell >> $NBSD_PASSWD_NEW

				flag=1
				break
			else
				continue
			fi
		done<$NBSD_PASSWD_ORIG

		if [ $flag -eq 0 ]
		then
			while read sw_line	# read /etc/shadow file again
			do
				sw_name="`echo $sw_line | awk -F ':' '{ print $1 }'`"
				if [ $user = $sw_name ]
				then
					password="`echo $sw_line | awk -F ':' '{ print $2 }'`"
					break
				else
					continue
				fi
			done<$SHADOW_FILE

			uid="`echo $line | awk -F ':' '{ print $3 }'`"
			gid="`echo $line | awk -F ':' '{ print $4 }'`"
			info="`echo $line | awk -F ':' '{ print $5 }'`"
			homedir="`echo $line | awk -F ':' '{ print $6 }'`"
			shell="`echo $line | awk -F ':' '{ print $7 }'`"
			echo $user:$password:$uid:$gid::0:0:$info:$homedir:$shell >> $NBSD_PASSWD_NEW
		fi
	else
		echo corrupted passwd file : $PASSWD_FILE
		exit 1
	fi
done

echo Updated the master.passwd file with existing user accounts.
echo Now run \'make -C etc installpasswd\' to switch to new password format.
