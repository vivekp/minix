#!/bin/sh
set -e

if [ $# -ne 1 ]
then	echo "Usage: $0 passwd-file"
	exit 1
fi

NBSD_PASSWD=etc/master.passwd

cat "$1" | while read line
do
	NF="`echo $line | awk -F ':' '{ print NF}'`"
	if [ $NF = 7 ]
	then
		user="`echo $line | awk -F ':' '{ print $1 }'`"
		flag=0

		while read pw_line
		do
			pw_name="`echo $pw_line | awk -F ':' '{ print $1 }'`"
			if [ $user = $pw_name ]
			then
				flag=1
				break
			else
				continue
			fi
		done<$NBSD_PASSWD

		if [ $flag -eq 0 ]
		then
			password="`echo $line | awk -F ':' '{ print $2 }'`"
			uid="`echo $line | awk -F ':' '{ print $3 }'`"
			gid="`echo $line | awk -F ':' '{ print $4 }'`"
			info="`echo $line | awk -F ':' '{ print $5 }'`"
			homedir="`echo $line | awk -F ':' '{ print $6 }'`"
			shell="`echo $line | awk -F ':' '{ print $7 }'`"
			echo Setting empty password for $user
			echo $user::$uid:$gid::0:0:$info:$homedir:$shell >> $NBSD_PASSWD
		fi
	else
		echo corrupted passwd file : $1
		exit 1
	fi
done

echo Updated the master.passwd file with existing user accounts
echo Now run \'make -C etc installpasswd\' to switch to new password format


