#include "fs.h"
#include <assert.h>
#include <minix/callnr.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <minix/dmap.h>
#include <minix/endpoint.h>
#include <minix/vfsif.h>
#include "buf.h"
#include "inode.h"
#include "drivers.h"


/* Declare some local functions. */
FORWARD _PROTOTYPE(void get_work, (message *m_in)			);
FORWARD _PROTOTYPE( void reply, (endpoint_t who, message *m_out)		);

/* SEF functions and variables. */
FORWARD _PROTOTYPE( void sef_local_startup, (void) );
FORWARD _PROTOTYPE( int sef_cb_init_fresh, (int type, sef_init_info_t *info) );
FORWARD _PROTOTYPE( void sef_cb_signal_handler, (int signo) );

/*===========================================================================*
 *				main                                         *
 *===========================================================================*/
PUBLIC int main(int argc, char *argv[])
{
/* This is the main routine of this service. The main loop consists of 
 * three major activities: getting new work, processing the work, and
 * sending the reply. The loop never terminates, unless a panic occurs.
 */
  int error, ind, transid;

  /* SEF local startup. */
  env_setargs(argc, argv);
  sef_local_startup();

  while(!unmountdone || !exitsignaled) {
	endpoint_t src;

	/* Wait for request message. */
	get_work(&fs_m_in);
	
	transid = TRNS_GET_ID(fs_m_in.m_type);
	fs_m_in.m_type = TRNS_DEL_ID(fs_m_in.m_type);
	if (fs_m_in.m_type == 0) {
		assert(!IS_VFS_FS_TRANSID(transid));
		fs_m_in.m_type = transid;	/* Backwards compat. */
		transid = 0;
	} else
		assert(IS_VFS_FS_TRANSID(transid));

	src = fs_m_in.m_source;
	error = OK;
	caller_uid = INVAL_UID;	/* To trap errors */
	caller_gid = INVAL_GID;
	req_nr = fs_m_in.m_type;

	if (req_nr < VFS_BASE) {
		fs_m_in.m_type += VFS_BASE;
		req_nr = fs_m_in.m_type;
	}
	ind = req_nr - VFS_BASE;

	if (ind < 0 || ind >= NREQS) {
		printf("MFS: bad request %d from %d\n", req_nr, src);
		printf("ind = %d\n", ind);
		error = EINVAL;
	} else {
		error = (*fs_call_vec[ind])();
		/*cch_check();*/
	}

	fs_m_out.m_type = error; 
	if (IS_VFS_FS_TRANSID(transid)) {
		/* If a transaction ID was set, reset it */
		fs_m_out.m_type = TRNS_ADD_ID(fs_m_out.m_type, transid);
	}
	reply(src, &fs_m_out);

	if (error == OK) 
		read_ahead(); /* do block read ahead */
      
  }
}

/*===========================================================================*
 *			       sef_local_startup			     *
 *===========================================================================*/
PRIVATE void sef_local_startup()
{
  /* Register init callbacks. */
  sef_setcb_init_fresh(sef_cb_init_fresh);
  sef_setcb_init_restart(sef_cb_init_fail);

  /* No live update support for now. */

  /* Register signal callbacks. */
  sef_setcb_signal_handler(sef_cb_signal_handler);

  /* Let SEF perform startup. */
  sef_startup();
}

/*===========================================================================*
 *		            sef_cb_init_fresh                                *
 *===========================================================================*/
PRIVATE int sef_cb_init_fresh(int type, sef_init_info_t *info)
{
/* Initialize the Minix file server. */
  int i;

  may_use_vmcache = 1;

  /* Init inode table */
  for (i = 0; i < NR_INODES; ++i) {
	inode[i].i_count = 0;
	cch[i] = 0;
  }
	
  init_inode_cache();

  /* Init driver mapping */
  for (i = 0; i < NR_DEVICES; ++i) 
	driver_endpoints[i].driver_e = NONE;
	
  SELF_E = getprocnr();
  buf_pool(DEFAULT_NR_BUFS);
  fs_block_size = _MIN_BLOCK_SIZE;

  return(OK);
}

/*===========================================================================*
 *		           sef_cb_signal_handler                             *
 *===========================================================================*/
PRIVATE void sef_cb_signal_handler(int signo)
{
  /* Only check for termination signal, ignore anything else. */
  if (signo != SIGTERM) return;

  exitsignaled = 1;
  (void) fs_sync();

  /* If unmounting has already been performed, exit immediately.
   * We might not get another message.
   */
  if (unmountdone) exit(0);
}

/*===========================================================================*
 *				get_work				     *
 *===========================================================================*/
PRIVATE void get_work(m_in)
message *m_in;				/* pointer to message */
{
  int r, srcok = 0;
  endpoint_t src;

  do {
	if ((r = sef_receive(ANY, m_in)) != OK) 	/* wait for message */
		panic("sef_receive failed: %d", r);
	src = m_in->m_source;

	if(src == VFS_PROC_NR) {
		if(unmountdone) 
			printf("MFS: unmounted: unexpected message from FS\n");
		else 
			srcok = 1;		/* Normal FS request. */
		
	} else
		printf("MFS: unexpected source %d\n", src);
  } while(!srcok);

   assert((src == VFS_PROC_NR && !unmountdone));
}


/*===========================================================================*
 *				reply					     *
 *===========================================================================*/
PRIVATE void reply(
  endpoint_t who,
  message *m_out                       	/* report result */
)
{
  if (OK != send(who, m_out))    /* send the message */
	printf("MFS(%d) was unable to send reply\n", SELF_E);
}


#if 0
/*===========================================================================*
 *				cch_check				     *	
 *===========================================================================*/
PRIVATE void cch_check(void) 
{
  int i;

  for (i = 0; i < NR_INODES; ++i) {
	if (inode[i].i_count != cch[i] && req_nr != REQ_GETNODE &&
	    req_nr != REQ_PUTNODE && req_nr != REQ_READSUPER &&
	    req_nr != REQ_MOUNTPOINT && req_nr != REQ_UNMOUNT &&
	    req_nr != REQ_SYNC && req_nr != REQ_LOOKUP) {
		printf("MFS(%d) inode(%lu) cc: %d req_nr: %d\n", SELF_E,
			inode[i].i_num, inode[i].i_count - cch[i], req_nr);
	}
	  
	cch[i] = inode[i].i_count;
  }
}
#endif

