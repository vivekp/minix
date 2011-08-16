#include <sys/cdefs.h>
#include "namespace.h"
#include <lib.h>

#include <unistd.h>

#ifdef __weak_alias
__weak_alias(chroot, _chroot)
#endif

PUBLIC int chroot(name)
_CONST char *name;
{
  message m;

  _loadname(name, &m);
  return(_syscall(VFS_PROC_NR, CHROOT, &m));
}

PUBLIC int fchroot(fd)
int fd;
{
  message m;

  m.m1_i1 = fd;
  return(_syscall(VFS_PROC_NR, FCHROOT, &m));
}
