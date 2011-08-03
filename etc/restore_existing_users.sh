#!/bin/sh
set -e

if [ $# -ne 1 ]
then	echo "Usage: $0 passwd-file"
	exit 1
fi

nbsd_passwd="master.passwd"

cat "$1" | while read line
do 
	NF="`echo $line | awk -F ':' '{ print NF}'`"
	if [ $NF = 7 ]
	then 
		user="`echo $line | awk -F ':' '{ print $1 }'`"
		flag=0

		cat $nbsd_passwd | while read pw_line
		do
			pw_name="`echo $pw_line | awk -F ':' '{ print $1 }'`"
			if [ $user = $pw_name ]
			then
				$flag=1
				break
			else
				continue
			fi
		done
	
		if [ $flag = 0 ]
		then
			password="`echo $line | awk -F ':' '{ print $2 }'`"
			uid="`echo $line | awk -F ':' '{ print $3 }'`"
			gid="`echo $line | awk -F ':' '{ print $4 }'`"
			info="`echo $line | awk -F ':' '{ print $5 }'`"
			homedir="`echo $line | awk -F ':' '{ print $6 }'`"
			shell="`echo $line | awk -F ':' '{ print $7 }'`"
		#	`echo $user:$password:$uid:$gid:$info:$homedir:$shell >> master.passwd`
			echo $user:$password:$uid:$gid:$info:$homedir:$shell
		fi

	else
		echo corrupted passwd file : $1
		exit 1
	fi
done
