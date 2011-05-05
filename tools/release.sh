#!/bin/sh

set -e

. release.functions

XBIN=usr/xbin
SRC=src
REPO=git://git.minix3.org/minix

# Which revision, arch are we building?
BUILDREV="`uname -r`"
BUILDARCH="`uname -p`"
PACKAGEDIR=/usr/pkgsrc/packages/$BUILDREV/$BUILDARCH/All/

# List of packages included on installation media
PACKAGELIST=packages.install
secs=`expr 32 '*' 64`
export SHELL=/bin/sh

PKG_ADD=/usr/pkg/sbin/pkg_add
PKG_INFO=/usr/pkg/sbin/pkg_info

if [ ! -x $PKG_ADD ]
then	echo Please install pkg_install from pkgsrc.
	exit 1
fi

# Packages we have to pre-install, and url to use
PREINSTALLED_PACKAGES="
	pkgin-0.4.1
	pkg_install-20101212
	bmake-20100808
	binutils-2.17nb3
	clang-2.9nb2
	compiler-rt-r123836nb3
	"

PACKAGEURL=ftp://ftp.minix3.org/pub/minix/packages/$BUILDREV/$BUILDARCH/All/
PKG_ADD_URL=$PACKAGEURL
PACKAGELOC=/usr/pkgsrc/packages/3.2.0/i386/All/

RELEASERC=$HOME/.releaserc

if [ -f $RELEASERC ]
then	. $RELEASERC
fi

set -- $* $RELOPTS

# SVN trunk repo
TRUNK=https://gforge.cs.vu.nl/svn/minix/trunk

RELEASEDIR=/usr/r-staging
RELEASEMNTDIR=/usr/r
RELEASEPACKAGE=${RELEASEDIR}/usr/install/packages

IMAGE=../boot/cdbootblock/cdbootblock
ROOTIMAGE=rootimage
CDFILES=/usr/tmp/cdreleasefiles
sh tell_config OS_RELEASE . OS_VERSION >/tmp/rel.$$
version_pretty=`sed 's/["      ]//g;/^$/d' </tmp/rel.$$`
version=`sed 's/["      ]//g;/^$/d' </tmp/rel.$$ | tr . _`
IMG_BASE=minix${version}_ide
BS=4096

HDEMU=0
COPY=0
SVNREV=""
REVTAG=""
PACKAGES=1
MINIMAL=0
MAKEMAP=0

# Do we have git?
if git --version >/dev/null
then	if [ -d ../.git ]
	then	REVTAG="`git describe --always --dirty`"
		echo "git mode; building $REVTAG"
		GITMODE=1
	fi
fi

FILENAMEOUT=""

while getopts "ls:pmMchu?r:f:" c
do
	case "$c" in
	\?)
		echo "Usage: $0 [-l] [-p] [-c] [-h] [-m] [-M] [-r <tag>] [-u] [-f <filename>] [-s <username>]" >&2
		exit 1
	;;
	h)
		echo " * Making HD image"
		IMG_BASE=minix${version}_bios
		HDEMU=1
		;;
	c)
		echo " * Copying, not SVN"
		COPY=1
		;;
	p)
		PACKAGES=0
		;;
	r)	
		SVNREV=-r$OPTARG
		;;
	u)
		echo " * Making live USB-stick image"
		IMG_BASE=minix${version}_usb
		HDEMU=1
		USB=1
		;;
	f)
		FILENAMEOUT="$OPTARG"
		;;
	s)	USERNAME="--username=$OPTARG"
		;;
	m)	MINIMAL=1
		PACKAGES=0
		;;
	M)	MAKEMAP=1
		;;
	l)	PKG_ADD_URL=file://$PACKAGEDIR
		;;
	esac
done

if [ $GITMODE -ne 1 -a $COPY -ne 1 ]
then	echo "Need git to retrieve latest minix! Copying src instead!"
	COPY=1
fi

if [ ! "$ZIP" ]
then	ZIP=bzip2
fi

if [ $PACKAGES -ne 0 ]
then	mkdir -p $PACKAGEDIR/All || true
	retrieve $PACKAGEDIR/All $PACKAGELIST packages/$BUILDARCH/$BUILDREV
fi

TMPDISKUSR=/dev/ram0
TMPDISKROOT=/dev/ram1

if [ ! -b $TMPDISKUSR -o ! $TMPDISKROOT ]
then	echo "$TMPDISKUSR or $TMPDISKROOT is not a block device.."
	exit 1
fi

if [ $TMPDISKUSR = $TMPDISKROOT ]
then
	echo "Temporary devices can't be equal."
	exit
fi

echo " * Cleanup old files"
umount $TMPDISKUSR || true
umount $TMPDISKROOT || true
umount $RELEASEMNTDIR/usr || true
umount $RELEASEMNTDIR || true

rm -rf $RELEASEDIR $RELEASEMNTDIR $IMG $ROOTIMAGE $CDFILES image*
mkdir -p $CDFILES || exit
mkdir -p $RELEASEDIR $RELEASEMNTDIR 
mkdir -m 755 $RELEASEDIR/usr
mkdir -m 1777 $RELEASEDIR/tmp

mkdir -p $RELEASEDIR/tmp
mkdir -p $RELEASEDIR/usr/tmp
mkdir -p $RELEASEDIR/$XBIN
mkdir -p $RELEASEDIR/usr/bin
mkdir -p $RELEASEDIR/bin
mkdir -p $RELEASEPACKAGE

echo " * Transfering bootstrap dirs to $RELEASEDIR"
cp -p /bin/* /usr/bin/* /sbin/* $RELEASEDIR/$XBIN
cp -rp /usr/lib $RELEASEDIR/usr
cp -rp /bin/sh /bin/echo $RELEASEDIR/bin
cp -rp /usr/bin/make /usr/bin/install /usr/bin/yacc /usr/bin/lex /usr/bin/asmconv $RELEASEDIR/usr/bin

CONFIGHEADER=$RELEASEDIR/usr/src/common/include/minix/sys_config.h

copy_local_packages

# Make sure compilers and libraries are root-owned
chown -R root $RELEASEDIR/usr/lib
chmod -R u+w $RELEASEDIR/usr/lib

if [ "$COPY" -ne 1 ]
then
	echo "Retrieving latest minix repo from $REPO."
	srcdir=$RELEASEDIR/usr/src
	git clone $REPO $srcdir
	if [ "$REVTAG" ]
	then	echo "Doing checkout of $REVTAG."
		(cd $srcdir && git checkout $REVTAG )
	else	REVTAG=`(cd $srcdir && git show-ref HEAD -s10)`
		echo "Retrieved repository head is $REVTAG."
	fi
	rm -r $srcdir/.git
	echo "
/* Added by release script  */
#ifndef _VCS_REVISION
#define _VCS_REVISION \"$REVTAG\"
#endif" >>$CONFIGHEADER
	# output image name
	if [ "$USB" -ne 0 ]; then
		IMG=${IMG_BASE}_${REVTAG}.img
	else
		IMG=${IMG_BASE}_${REVTAG}.iso
	fi
else
	echo "Copying contents from current src dir."
	( cd .. && make depend && make clean )
	srcdir=/usr/$SRC
	( cd $srcdir && tar --exclude .svn -cf - .  ) | ( cd $RELEASEDIR/usr && mkdir $SRC && cd $SRC && tar xf - )
	REVTAG=copy
	REVISION=unknown
	IMG=${IMG_BASE}_copy.iso
fi

echo " * Fixups for owners and modes of dirs and files"
chown -R root $RELEASEDIR/usr/$SRC
chmod -R u+w $RELEASEDIR/usr/$SRC 
find $RELEASEDIR/usr/$SRC -type d | xargs chmod 755
find $RELEASEDIR/usr/$SRC -type f | xargs chmod 644
find $RELEASEDIR/usr/$SRC -name configure | xargs chmod 755
find $RELEASEDIR/usr/$SRC/commands -name build | xargs chmod 755
# Bug tracking system not for on cd
rm -rf $RELEASEDIR/usr/$SRC/doc/bugs

# Make sure the CD knows it's a CD, unless it's not
if [ "$USB" -eq 0 ]
then	date >$RELEASEDIR/CD
fi
echo " * Bootstrap /usr/share/mk files"
# Need /usr/share/mk in the new system to invoke make. Real ownerships
# and permissions will be set by its own src/share/mk/Makefile.
mkdir -p $RELEASEDIR/usr/share/mk
chmod 755 $RELEASEDIR/usr/share/mk
cp $RELEASEDIR/usr/src/share/mk/* $RELEASEDIR/usr/share/mk/
chown -R root $RELEASEDIR/usr/share/mk
cp chrootmake.sh $RELEASEDIR/usr/$SRC/tools/chrootmake.sh

echo " * Make hierarchy"
chroot $RELEASEDIR "PATH=/$XBIN sh -x /usr/$SRC/tools/chrootmake.sh etcfiles" || exit 1

for p in $PREINSTALLED_PACKAGES
do	echo " * Pre-installing: $p from $PKG_ADD_URL"
    $PKG_ADD -P $RELEASEDIR $PKG_ADD_URL/$p
done

echo " * Chroot build"
chroot $RELEASEDIR "PATH=/$XBIN MAKEMAP=$MAKEMAP sh -x /usr/$SRC/tools/chrootmake.sh" || exit 1
# Copy built images for cd booting
cp $RELEASEDIR/boot/image_big image
echo " * Chroot build done"
echo " * Removing bootstrap files"
rm -rf $RELEASEDIR/$XBIN
# The build process leaves some file in $SRC as bin.
chown -R root $RELEASEDIR/usr/src*
cp issue.install $RELEASEDIR/etc/issue

echo $version_pretty, SVN revision $REVISION, generated `date` >$RELEASEDIR/etc/version
rm -rf $RELEASEDIR/tmp/*
if [ $MINIMAL -ne 0 ]
then
	if [ "$MAKEMAP" -ne 0 ]
	then
		echo " * Copying symbol map to ${IMG}-symbols.txt"
		cp $RELEASEDIR/usr/src/symbols.txt ${IMG}-symbols.txt
		$ZIP -f ${IMG}-symbols.txt
	fi

	echo " * Removing files to create minimal image"
	rm -rf $RELEASEDIR/boot/image/* $RELEASEDIR/usr/man/man*/* 	\
		$RELEASEDIR/usr/share/zoneinfo* $RELEASEDIR/usr/src
	mkdir -p $RELEASEDIR/usr/src/tools
	ln $RELEASEDIR/boot/image_big $RELEASEDIR/boot/image/$version
fi

echo " * Counting files"
extrakb=`du -s $RELEASEDIR/usr/install | awk '{ print $1 }'`
find $RELEASEDIR/usr | fgrep -v /install/ | wc -l >$RELEASEDIR/.usrfiles
find $RELEASEDIR -print -path $RELEASEDIR/usr -prune | wc -l >$RELEASEDIR/.rootfiles

echo " * Writing fstab"
if [ "$USB" -ne 0 ]
then
	echo \
'root=/dev/c0d7p0s0
usr=/dev/c0d7p0s2
' > $RELEASEDIR/etc/fstab
elif [ "$HDEMU" -ne 0 ]
then
	echo \
'root=/dev/c0d7p0s0
usr=/dev/c0d7p0s2
usr_roflag="-r"' > $RELEASEDIR/etc/fstab
fi

echo " * Mounting $TMPDISKROOT as $RELEASEMNTDIR"
fitfs $RELEASEDIR $TMPDISKROOT 64 256 "$ROOTMB"
ROOTBLOCKS=$blocks
ROOTSECTS="`expr $blocks \* \( $BS / 512 \)`"
mount $TMPDISKROOT $RELEASEMNTDIR || exit

echo " * Mounting $TMPDISKUSR as $RELEASEMNTDIR/usr"
fitfs $RELEASEDIR/usr $TMPDISKUSR 0 0 "$USRMB"
USRBLOCKS=$blocks
USRSECTS="`expr $blocks \* \( $BS / 512 \)`"
mkdir -m 755 $RELEASEMNTDIR/usr
mount $TMPDISKUSR $RELEASEMNTDIR/usr || exit

echo " * Copying files from staging to image"
synctree -f $RELEASEDIR $RELEASEMNTDIR > /dev/null || true
expr `df $TMPDISKUSR | tail -1 | awk '{ print $4 }'` - $extrakb >$RELEASEMNTDIR/.usrkb

echo " * Unmounting $TMPDISKUSR from $RELEASEMNTDIR/usr"
umount $TMPDISKUSR || exit
echo " * Unmounting $TMPDISKROOT from $RELEASEMNTDIR"
umount $TMPDISKROOT || exit
rm -r $RELEASEMNTDIR

echo " * Making image bootable"
if [ "$USB" -ne 0 ]
then
	usb_root_changes
elif [ "$HDEMU" -ne 0 ]
then
	hdemu_root_changes
else
	cd_root_changes
fi

# Clean up: RELEASEDIR no longer needed
rm -r $RELEASEDIR

(cd ../boot && make)
dd if=$TMPDISKROOT of=$ROOTIMAGE bs=$BS count=$ROOTBLOCKS
cp release/cd/* $CDFILES || true
echo "This is Minix version $version_pretty prepared `date`." >$CDFILES/VERSION.TXT

boottype=-n
bootimage=$IMAGE
if [ "$HDEMU" -ne 0 ]; then
	make_hdimage
	boottype='-h'
	bootimage=hdimage
fi

if [ "$USB" -ne 0 ]; then
	mv $bootimage $IMG
else
	cp ../boot/boot/boot $CDFILES
	writeisofs -s0x0 -l MINIX -a boot -b $bootimage $boottype $CDFILES $IMG || exit 1

	if [ "$HDEMU" -eq 0 ]
	then
		echo "Appending Minix root and usr filesystem"
		# Pad ISO out to cylinder boundary
		isobytes=`stat -size $IMG`
		isosects=`expr $isobytes / 512`
		isopad=`expr $secs - '(' $isosects % $secs ')'`
		dd if=/dev/zero count=$isopad >>$IMG
		# number of sectors
		isosects=`expr $isosects + $isopad`
		( cat $IMG $ROOTIMAGE ;
			dd if=$TMPDISKUSR bs=$BS count=$USRBLOCKS ) >m
		mv m $IMG
		# Make CD partition table
		installboot -m $IMG /usr/mdec/masterboot
		# Make sure there is no hole..! Otherwise the ISO format is
		# unreadable.
		partition -m $IMG 0 81:$isosects 81:$ROOTSECTS 81:$USRSECTS
	fi
fi
echo "${ZIP}ping $IMG"
$ZIP -f $IMG

if [ "$FILENAMEOUT" ]
then	echo "$IMG" >$FILENAMEOUT
fi

echo " * Freeing up memory used by ramdisks"
ramdisk 1 $TMPDISKROOT
ramdisk 1 $TMPDISKUSR
