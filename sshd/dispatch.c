/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "includes.h"
RCSID("$OpenBSD: dispatch.c,v 1.16 2003/04/08 20:21:28 itojun Exp $");

//#include "ssh1.h"
#include "ssh2.h"
#include "log.h"
#include "dispatch.h"
#include "packet.h"
#include "compat.h"

#include "ThreadLocal.h"


//dispatch_fn *dispatch[DISPATCH_MAX];

void
dispatch_protocol_error(int type, u_int32_t seq, void *ctxt)
{
	logit("dispatch_protocol_error: type %d seq %u", type, seq);
	if (!THREAD_LOCAL(compat20))
		fatal("protocol error");
	packet_start(SSH2_MSG_UNIMPLEMENTED);
	packet_put_int(seq);
	packet_send();
	packet_write_wait();
}
void
dispatch_protocol_ignore(int type, u_int32_t seq, void *ctxt)
{
	logit("dispatch_protocol_ignore: type %d seq %u", type, seq);
}
void
dispatch_init(dispatch_fn *dflt)
{
	u_int i;
	for (i = 0; i < DISPATCH_MAX; i++)
		THREAD_LOCAL(dispatch)[i] = dflt;
}
void
dispatch_range(u_int from, u_int to, dispatch_fn *fn)
{
	u_int i;

	for (i = from; i <= to; i++) {
		if (i >= DISPATCH_MAX)
			break;
		THREAD_LOCAL(dispatch)[i] = fn;
	}
}
void
dispatch_set(int type, dispatch_fn *fn)
{
	THREAD_LOCAL(dispatch)[type] = fn;
}
void
dispatch_run(int mode, int *done, void *ctxt)
{
	for (;;) {
		int type;
		u_int32_t seqnr;

		if (mode == DISPATCH_BLOCK) {
			type = packet_read_seqnr(&seqnr);
		} else {
			type = packet_read_poll_seqnr(&seqnr);
			if (type == SSH_MSG_NONE)
				return;
		}
		if (type > 0 && type < DISPATCH_MAX && THREAD_LOCAL(dispatch)[type] != NULL)
			(*THREAD_LOCAL(dispatch)[type])(type, seqnr, ctxt);
		else
			packet_disconnect("protocol error: rcvd type %d", type);
		if (done != NULL && *done)
			return;
	}
}
