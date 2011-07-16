
#ifndef _MMAN_H
#define _MMAN_H

#ifndef _TYPE_H
#include <minix/type.h>
#endif

/* prot argument for mmap() */
#define PROT_NONE       0x00    /* no permissions */
#define PROT_READ       0x01    /* pages can be read */
#define PROT_WRITE      0x02    /* pages can be written */
#define PROT_EXEC       0x04    /* pages can be executed */

/* flags argument for mmap()  */
#define MAP_PRIVATE     0x0002          /* changes are private */
#define MAP_ANON	0x0004          /* anonymous memory */
#define MAP_PREALLOC	0x0008		/* not on-demand */
#define MAP_CONTIG	0x0010		/* contiguous in physical memory */
#define MAP_LOWER16M	0x0020		/* physically below 16MB */
#define MAP_ALIGN64K	0x0040		/* physically aligned at 64kB */
#define MAP_LOWER1M	0x0080		/* physically below 16MB */
#define MAP_IPC_SHARED  0x0100          /* used to implement shared memory */

/* mmap() error return */
#define MAP_FAILED      ((void *)-1)

_PROTOTYPE( void *mmap, (void *, size_t, int, int, int, off_t));
_PROTOTYPE( int munmap, (void *, size_t));
_PROTOTYPE( int munmap_text, (void *, size_t));
_PROTOTYPE( void *vm_remap, (endpoint_t d, endpoint_t s, void *da,
				void *sa, size_t si));
_PROTOTYPE( int vm_unmap, (endpoint_t endpt, void *addr));
_PROTOTYPE( unsigned long vm_getphys, (endpoint_t endpt, void *addr));
_PROTOTYPE( u8_t vm_getrefcount, (endpoint_t endpt, void *addr));

#endif /* _MMAN_H */
