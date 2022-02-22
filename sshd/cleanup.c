/*
 * Copyright (c) 2003 Markus Friedl <markus@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "includes.h"
RCSID("$OpenBSD: cleanup.c,v 1.1 2003/09/23 20:17:11 markus Exp $");

#include "log.h"
#include "misc.h"
#include "ThreadLocal.h"

extern void channel_free_all(void);

/* default implementation */
void
cleanup_exit(int i)
{
	int mode;
	/* close all channels */
	channel_free_all();

	do_cleanup(THREAD_LOCAL(the_authctxt));

	packet_close();

	
	shutdown(THREAD_LOCAL(connection_in), SD_BOTH);
	shutdown(THREAD_LOCAL(connection_out), SD_BOTH);
	SocketClose(THREAD_LOCAL(connection_in));		
	SocketClose(THREAD_LOCAL(connection_out));		


	cipher_cleanup(&THREAD_LOCAL(send_context));
	cipher_cleanup(&THREAD_LOCAL(receive_context));

	for (mode = 0; mode < MODE_MAX; mode++) 
	{
		if (THREAD_LOCAL(newkeys)[mode] != NULL) 
		{
			debug("set_newkeys: rekeying");
			
			xfree(THREAD_LOCAL(newkeys)[mode]->enc.name);
			xfree(THREAD_LOCAL(newkeys)[mode]->enc.iv);
			xfree(THREAD_LOCAL(newkeys)[mode]->enc.key);
			xfree(THREAD_LOCAL(newkeys)[mode]->mac.name);
			xfree(THREAD_LOCAL(newkeys)[mode]->mac.key);
			xfree(THREAD_LOCAL(newkeys)[mode]->comp.name);
			xfree(THREAD_LOCAL(newkeys)[mode]);
		}
	}



	if (THREAD_LOCAL(xxx_kex))
	{
		buffer_free(&THREAD_LOCAL(xxx_kex)->peer);
		buffer_free(&THREAD_LOCAL(xxx_kex)->my);
	}
	

	if (THREAD_LOCAL(the_authctxt))
	{
		buffer_free(THREAD_LOCAL(the_authctxt)->loginmsg);		
		XFREE_IF_NOT_NULL(THREAD_LOCAL(the_authctxt)->user);
		XFREE_IF_NOT_NULL(THREAD_LOCAL(the_authctxt)->service);
		XFREE_IF_NOT_NULL(THREAD_LOCAL(the_authctxt)->style);	
		pwrelease(THREAD_LOCAL(the_authctxt)->pw);
	}
	XFREE_IF_NOT_NULL(THREAD_LOCAL(channels));

	/* Free the thread local */
	ReleaseThreadLocalStorage((T_SSHD_THREAD_LOCAL_VARIABLES*) TlsGetValue(g_dwThreadLocalIndex));

	TerminateThread(GetCurrentThread(),-1);
}
