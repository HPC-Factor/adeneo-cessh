/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file contains functions for generic socket connection forwarding.
 * There is also code for initiating connection forwarding for X11 connections,
 * arbitrary tcp/ip connections, and the authentication agent connection.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * SSH2 support added by Markus Friedl.
 * Copyright (c) 1999, 2000, 2001, 2002 Markus Friedl.  All rights reserved.
 * Copyright (c) 1999 Dug Song.  All rights reserved.
 * Copyright (c) 1999 Theo de Raadt.  All rights reserved.
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
RCSID("$OpenBSD: THREAD_LOCAL(channels).c,v 1.232 2006/01/30 12:22:22 reyk Exp $");

#include "ssh.h"
//#include "ssh1.h"
#include "ssh2.h"
#include "packet.h"
#include "xmalloc.h"
#include "log.h"
#include "misc.h"
#include "channels.h"
#include "compat.h"
#include "canohost.h"
#include "key.h"
//#include "authfd.h"
#include "pathnames.h"
#include "bufaux.h"

#include "ThreadLocal.h"

/* -- channel core */

/*
 * Pointer to an array containing all allocated THREAD_LOCAL(channels).  The array is
 * dynamically extended as needed.
 */
//Channel **channels = NULL;

/*
 * Size of the channel array.  All slots of the array must always be
 * initialized (at least the type field); unused slots set to NULL
 */
//u_int channels_alloc = 0;


#ifndef WINCE_PORT
/*
 * Maximum file descriptor value used in any of the THREAD_LOCAL(channels).  This is
 * updated in channel_new.
 */
int channel_max_fd = 0;
#endif

/* -- tcp forwarding */

/* List of all permitted host/port pairs to connect. */
//ForwardPermission permitted_opens[SSH_MAX_FORWARDS_PER_DIRECTION];

/* Number of permitted host/port pairs in the array. */
//int num_permitted_opens = 0;
/*
 * If this is true, all opens are permitted.  This is the case on the server
 * on which we have to trust the client anyway, and the user could do
 * anything after logging in anyway.
 */
//int all_opens_permitted = 0;



#define	NUM_SOCKS	10

/* AF_UNSPEC or AF_INET or AF_INET6 */
//int IPv4or6 = AF_UNSPEC;

/* helper */
static void port_open_helper(Channel *c, char *rtype);

/* -- channel core */

Channel *
channel_by_id(int id)
{
	Channel *c;

	if (id < 0 || (u_int)id >= THREAD_LOCAL(channels_alloc)) {
		logit("channel_by_id: %d: bad id", id);
		return NULL;
	}
	c = THREAD_LOCAL(channels)[id];
	if (c == NULL) {
		logit("channel_by_id: %d: bad id: channel free", id);
		return NULL;
	}
	return c;
}

/*
 * Returns the channel if it is allowed to receive protocol messages.
 * Private THREAD_LOCAL(channels), like listening sockets, may not receive messages.
 */
Channel *
channel_lookup(int id)
{
	Channel *c;

	if ((c = channel_by_id(id)) == NULL)
		return (NULL);

	switch(c->type) {
	case SSH_CHANNEL_X11_OPEN:
	case SSH_CHANNEL_LARVAL:
	case SSH_CHANNEL_CONNECTING:
	case SSH_CHANNEL_DYNAMIC:
	case SSH_CHANNEL_OPENING:
	case SSH_CHANNEL_OPEN:
	case SSH_CHANNEL_INPUT_DRAINING:
	case SSH_CHANNEL_OUTPUT_DRAINING:
		return (c);
		break;
	}
	logit("Non-public channel %d, type %d.", id, c->type);
	return (NULL);
}

/*
 * Register filedescriptors for a channel, used when allocating a channel or
 * when the channel consumer/producer is ready, e.g. shell exec'd
 */

static void
channel_register_fds(Channel *c, int rfd, int wfd, int efd,
    int extusage, int nonblock)
{
#ifndef WINCE_PORT
	/* Update the maximum file descriptor value. */
	channel_max_fd = MAX(channel_max_fd, rfd);
	channel_max_fd = MAX(channel_max_fd, wfd);
	channel_max_fd = MAX(channel_max_fd, efd);
#endif
	/* XXX set close-on-exec -markus */

	c->rfd = rfd;
	c->wfd = wfd;
	c->sock = (rfd == wfd) ? rfd : -1;
	c->ctl_fd = -1; /* XXX: set elsewhere */
	c->efd = efd;
	c->extended_usage = extusage;

#ifdef WINCE_PORT
	c->isatty = 0;
	c->wfd_isatty = 0;
#else
	/* XXX ugly hack: nonblock is only set by the server */
	if (nonblock && isatty(c->rfd)) {
		debug2("channel %d: rfd %d isatty", c->self, c->rfd);
		c->isatty = 1;
		if (!isatty(c->wfd)) {
			error("channel %d: wfd %d is not a tty?",
			    c->self, c->wfd);
		}
	} else {
		c->isatty = 0;
	}

	c->wfd_isatty = isatty(c->wfd);
#endif

	/* enable nonblocking mode */
	if (nonblock) {
		if (rfd != -1)
			set_nonblock(rfd);
		if (wfd != -1)
			set_nonblock(wfd);
		if (efd != -1)
			set_nonblock(efd);
	}
}

/*
 * Allocate a new channel object and set its type and socket. This will cause
 * remote_name to be freed.
 */

Channel *
channel_new(char *ctype, int type, int rfd, int wfd, int efd,
    u_int window, u_int maxpack, int extusage, char *remote_name, int nonblock)
{
	int found;
	u_int i;
	Channel *c;

	/* Do initial allocation if this is the first call. */
	if (THREAD_LOCAL(channels_alloc) == 0) {
		THREAD_LOCAL(channels_alloc) = 10;
		THREAD_LOCAL(channels) = xmalloc(THREAD_LOCAL(channels_alloc) * sizeof(Channel *));
		for (i = 0; i < THREAD_LOCAL(channels_alloc); i++)
			THREAD_LOCAL(channels)[i] = NULL;
	}
	/* Try to find a free slot where to put the new channel. */
	for (found = -1, i = 0; i < THREAD_LOCAL(channels_alloc); i++)
		if (THREAD_LOCAL(channels)[i] == NULL) {
			/* Found a free slot. */
			found = (int)i;
			break;
		}
	if (found < 0) {
		/* There are no free slots.  Take last+1 slot and expand the array.  */
		found = THREAD_LOCAL(channels_alloc);
		if (THREAD_LOCAL(channels_alloc) > 10000)
			fatal("channel_new: internal error: THREAD_LOCAL(channels_alloc) %d "
			    "too big.", THREAD_LOCAL(channels_alloc));
		THREAD_LOCAL(channels) = xrealloc(THREAD_LOCAL(channels),
		    (THREAD_LOCAL(channels_alloc) + 10) * sizeof(Channel *));
		THREAD_LOCAL(channels_alloc) += 10;
		debug2("channel: expanding %d", THREAD_LOCAL(channels_alloc));
		for (i = found; i < THREAD_LOCAL(channels_alloc); i++)
			THREAD_LOCAL(channels)[i] = NULL;
	}
	/* Initialize and return new channel. */
	c = THREAD_LOCAL(channels)[found] = xmalloc(sizeof(Channel));
	memset(c, 0, sizeof(Channel));
	buffer_init(&c->input);
	buffer_init(&c->output);
	buffer_init(&c->extended);
	c->ostate = CHAN_OUTPUT_OPEN;
	c->istate = CHAN_INPUT_OPEN;
	c->flags = 0;
	channel_register_fds(c, rfd, wfd, efd, extusage, nonblock);
	c->self = found;
	c->type = type;
	c->ctype = ctype;
	c->local_window = window;
	c->local_window_max = window;
	c->local_consumed = 0;
	c->local_maxpacket = maxpack;
	c->remote_id = -1;
	c->remote_name = xstrdup(remote_name);
	c->remote_window = 0;
	c->remote_maxpacket = 0;
	c->force_drain = 0;
	c->single_connection = 0;
	c->detach_user = NULL;
	c->detach_close = 0;
	c->confirm = NULL;
	c->confirm_ctx = NULL;
	c->input_filter = NULL;
	c->output_filter = NULL;
	debug("channel %d: new [%s]", found, remote_name);
	return c;
}

static int
channel_find_maxfd(void)
{
	u_int i;
	int max = 0;
	Channel *c;

	for (i = 0; i < THREAD_LOCAL(channels_alloc); i++) {
		c = THREAD_LOCAL(channels)[i];
		if (c != NULL) {
			max = MAX(max, c->rfd);
			max = MAX(max, c->wfd);
			max = MAX(max, c->efd);
		}
	}
	return max;
}

int
channel_close_fd(int *fdp)
{
	int ret = 0, fd = *fdp;

	if (fd != -1) {
		ret = SocketClose(fd);
		*fdp = -1;
#ifndef WINCE_PORT
		if (fd == channel_max_fd)
			channel_max_fd = channel_find_maxfd();
#endif
	}
	return ret;
}

/* Close all channel fd/socket. */

static void
channel_close_fds(Channel *c)
{
	debug3("channel %d: close_fds r %d w %d e %d c %d",
	    c->self, c->rfd, c->wfd, c->efd, c->ctl_fd);

	channel_close_fd(&c->sock);
	channel_close_fd(&c->ctl_fd);
	channel_close_fd(&c->rfd);
	channel_close_fd(&c->wfd);
	channel_close_fd(&c->efd);
}

/* Free the channel and close its fd/socket. */

void
channel_free(Channel *c)
{
	char *s;
	u_int i, n;

	for (n = 0, i = 0; i < THREAD_LOCAL(channels_alloc); i++)
		if (THREAD_LOCAL(channels)[i])
			n++;
	debug("channel %d: free: %s, nchannels %u", c->self,
	    c->remote_name ? c->remote_name : "???", n);

	s = channel_open_message();
	debug3("channel %d: status: %s", c->self, s);
	xfree(s);

	if (c->sock != -1)
		shutdown(c->sock, SHUT_RDWR);
	if (c->ctl_fd != -1)
		shutdown(c->ctl_fd, SHUT_RDWR);
	channel_close_fds(c);
	buffer_free(&c->input);
	buffer_free(&c->output);
	buffer_free(&c->extended);
	if (c->remote_name) {
		xfree(c->remote_name);
		c->remote_name = NULL;
	}
	THREAD_LOCAL(channels)[c->self] = NULL;
	xfree(c);
}

void
channel_free_all(void)
{
	u_int i;

	for (i = 0; i < THREAD_LOCAL(channels_alloc); i++)
		if (THREAD_LOCAL(channels)[i] != NULL)
			channel_free(THREAD_LOCAL(channels)[i]);
}

/*
 * Closes the sockets/fds of all THREAD_LOCAL(channels).  This is used to close extra file
 * descriptors after a fork.
 */

void
channel_close_all(void)
{
	u_int i;

	for (i = 0; i < THREAD_LOCAL(channels_alloc); i++)
		if (THREAD_LOCAL(channels)[i] != NULL)
			channel_close_fds(THREAD_LOCAL(channels)[i]);
}

/*
 * Stop listening to THREAD_LOCAL(channels).
 */

void
channel_stop_listening(void)
{
	u_int i;
	Channel *c;

	for (i = 0; i < THREAD_LOCAL(channels_alloc); i++) {
		c = THREAD_LOCAL(channels)[i];
		if (c != NULL) {
			switch (c->type) {
			case SSH_CHANNEL_AUTH_SOCKET:
			case SSH_CHANNEL_PORT_LISTENER:
			case SSH_CHANNEL_RPORT_LISTENER:
			case SSH_CHANNEL_X11_LISTENER:
				channel_close_fd(&c->sock);
				channel_free(c);
				break;
			}
		}
	}
}

/*
 * Returns true if no channel has too much buffered data, and false if one or
 * more channel is overfull.
 */

int
channel_not_very_much_buffered_data(void)
{
	u_int i;
	Channel *c;

	for (i = 0; i < THREAD_LOCAL(channels_alloc); i++) {
		c = THREAD_LOCAL(channels)[i];
		if (c != NULL && c->type == SSH_CHANNEL_OPEN) {
#if 0
			if (!compat20 &&
			    buffer_len(&c->input) > packet_get_maxsize()) {
				debug2("channel %d: big input buffer %d",
				    c->self, buffer_len(&c->input));
				return 0;
			}
#endif
			if (buffer_len(&c->output) > packet_get_maxsize()) {
				debug2("channel %d: big output buffer %u > %u",
				    c->self, buffer_len(&c->output),
				    packet_get_maxsize());
				return 0;
			}
		}
	}
	return 1;
}

/* Returns true if any channel is still open. */

int
channel_still_open(void)
{
	u_int i;
	Channel *c;

	for (i = 0; i < THREAD_LOCAL(channels_alloc); i++) {
		c = THREAD_LOCAL(channels)[i];
		if (c == NULL)
			continue;
		switch (c->type) {
		case SSH_CHANNEL_X11_LISTENER:
		case SSH_CHANNEL_PORT_LISTENER:
		case SSH_CHANNEL_RPORT_LISTENER:
		case SSH_CHANNEL_CLOSED:
		case SSH_CHANNEL_AUTH_SOCKET:
		case SSH_CHANNEL_DYNAMIC:
		case SSH_CHANNEL_CONNECTING:
		case SSH_CHANNEL_ZOMBIE:
			continue;
		case SSH_CHANNEL_LARVAL:
			if (!THREAD_LOCAL(compat20))
				fatal("cannot happen: SSH_CHANNEL_LARVAL");
			continue;
		case SSH_CHANNEL_OPENING:
		case SSH_CHANNEL_OPEN:
		case SSH_CHANNEL_X11_OPEN:
			return 1;
		case SSH_CHANNEL_INPUT_DRAINING:
		case SSH_CHANNEL_OUTPUT_DRAINING:
			if (!THREAD_LOCAL(compat13))
				fatal("cannot happen: OUT_DRAIN");
			return 1;
		default:
			fatal("channel_still_open: bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	return 0;
}

/* Returns the id of an open channel suitable for keepaliving */

int
channel_find_open(void)
{
	u_int i;
	Channel *c;

	for (i = 0; i < THREAD_LOCAL(channels_alloc); i++) {
		c = THREAD_LOCAL(channels)[i];
		if (c == NULL || c->remote_id < 0)
			continue;
		switch (c->type) {
		case SSH_CHANNEL_CLOSED:
		case SSH_CHANNEL_DYNAMIC:
		case SSH_CHANNEL_X11_LISTENER:
		case SSH_CHANNEL_PORT_LISTENER:
		case SSH_CHANNEL_RPORT_LISTENER:
		case SSH_CHANNEL_OPENING:
		case SSH_CHANNEL_CONNECTING:
		case SSH_CHANNEL_ZOMBIE:
			continue;
		case SSH_CHANNEL_LARVAL:
		case SSH_CHANNEL_AUTH_SOCKET:
		case SSH_CHANNEL_OPEN:
		case SSH_CHANNEL_X11_OPEN:
			return i;
		case SSH_CHANNEL_INPUT_DRAINING:
		case SSH_CHANNEL_OUTPUT_DRAINING:
			if (!THREAD_LOCAL(compat13))
				fatal("cannot happen: OUT_DRAIN");
			return i;
		default:
			fatal("channel_find_open: bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	return -1;
}


/*
 * Returns a message describing the currently open forwarded connections,
 * suitable for sending to the client.  The message contains crlf pairs for
 * newlines.
 */

char *
channel_open_message(void)
{
	Buffer buffer;
	Channel *c;
	char buf[1024], *cp;
	u_int i;

	buffer_init(&buffer);
	snprintf(buf, sizeof buf, "The following connections are open:\r\n");
	buffer_append(&buffer, buf, strlen(buf));
	for (i = 0; i < THREAD_LOCAL(channels_alloc); i++) {
		c = THREAD_LOCAL(channels)[i];
		if (c == NULL)
			continue;
		switch (c->type) {
		case SSH_CHANNEL_X11_LISTENER:
		case SSH_CHANNEL_PORT_LISTENER:
		case SSH_CHANNEL_RPORT_LISTENER:
		case SSH_CHANNEL_CLOSED:
		case SSH_CHANNEL_AUTH_SOCKET:
		case SSH_CHANNEL_ZOMBIE:
			continue;
		case SSH_CHANNEL_LARVAL:
		case SSH_CHANNEL_OPENING:
		case SSH_CHANNEL_CONNECTING:
		case SSH_CHANNEL_DYNAMIC:
		case SSH_CHANNEL_OPEN:
		case SSH_CHANNEL_X11_OPEN:
		case SSH_CHANNEL_INPUT_DRAINING:
		case SSH_CHANNEL_OUTPUT_DRAINING:
			snprintf(buf, sizeof buf,
			    "  #%d %.300s (t%d r%d i%d/%d o%d/%d fd %d/%d cfd %d)\r\n",
			    c->self, c->remote_name,
			    c->type, c->remote_id,
			    c->istate, buffer_len(&c->input),
			    c->ostate, buffer_len(&c->output),
			    c->rfd, c->wfd, c->ctl_fd);
			buffer_append(&buffer, buf, strlen(buf));
			continue;
		default:
			fatal("channel_open_message: bad channel type %d", c->type);
			/* NOTREACHED */
		}
	}
	buffer_append(&buffer, "\0", 1);
	cp = xstrdup(buffer_ptr(&buffer));
	buffer_free(&buffer);
	return cp;
}

void
channel_send_open(int id)
{
	Channel *c = channel_lookup(id);

	if (c == NULL) {
		logit("channel_send_open: %d: bad id", id);
		return;
	}
	debug2("channel %d: send open", id);
	packet_start(SSH2_MSG_CHANNEL_OPEN);
	packet_put_cstring(c->ctype);
	packet_put_int(c->self);
	packet_put_int(c->local_window);
	packet_put_int(c->local_maxpacket);
	packet_send();
}

void
channel_request_start(int id, char *service, int wantconfirm)
{
	Channel *c = channel_lookup(id);

	if (c == NULL) {
		logit("channel_request_start: %d: unknown channel id", id);
		return;
	}
	debug2("channel %d: request %s confirm %d", id, service, wantconfirm);
	packet_start(SSH2_MSG_CHANNEL_REQUEST);
	packet_put_int(c->remote_id);
	packet_put_cstring(service);
	packet_put_char(wantconfirm);
}
void
channel_register_confirm(int id, channel_callback_fn *fn, void *ctx)
{
	Channel *c = channel_lookup(id);

	if (c == NULL) {
		logit("channel_register_comfirm: %d: bad id", id);
		return;
	}
	c->confirm = fn;
	c->confirm_ctx = ctx;
}
void
channel_register_cleanup(int id, channel_callback_fn *fn, int do_close)
{
	Channel *c = channel_by_id(id);

	if (c == NULL) {
		logit("channel_register_cleanup: %d: bad id", id);
		return;
	}
	c->detach_user = fn;
	c->detach_close = do_close;
}
void
channel_cancel_cleanup(int id)
{
	Channel *c = channel_by_id(id);

	if (c == NULL) {
		logit("channel_cancel_cleanup: %d: bad id", id);
		return;
	}
	c->detach_user = NULL;
	c->detach_close = 0;
}
void
channel_register_filter(int id, channel_infilter_fn *ifn,
    channel_outfilter_fn *ofn)
{
	Channel *c = channel_lookup(id);

	if (c == NULL) {
		logit("channel_register_filter: %d: bad id", id);
		return;
	}
	c->input_filter = ifn;
	c->output_filter = ofn;
}

void
channel_set_fds(int id, int rfd, int wfd, int efd,
    int extusage, int nonblock, u_int window_max)
{
	Channel *c = channel_lookup(id);

	if (c == NULL || c->type != SSH_CHANNEL_LARVAL)
		fatal("channel_activate for non-larval channel %d.", id);
	channel_register_fds(c, rfd, wfd, efd, extusage, nonblock);
	c->type = SSH_CHANNEL_OPEN;
	c->local_window = c->local_window_max = window_max;
	packet_start(SSH2_MSG_CHANNEL_WINDOW_ADJUST);
	packet_put_int(c->remote_id);
	packet_put_int(c->local_window);
	packet_send();
}

/*
 * 'channel_pre*' are called just before select() to add any bits relevant to
 * THREAD_LOCAL(channels) in the select bitmasks.
 */
/*
 * 'channel_post*': perform any appropriate operations for THREAD_LOCAL(channels) which
 * have events pending.
 */
//chan_fn *channel_pre[SSH_CHANNEL_MAX_TYPE];
//chan_fn *channel_post[SSH_CHANNEL_MAX_TYPE];

#ifdef WINCE_PORT
	#define __FD_SET(x,y) FD_SET((SOCKET) x, y)
#else
	#define __FD_SET(x,y) FD_SET(x, y)
#endif


static void
channel_pre_listener(Channel *c, fd_set * readset, fd_set * writeset)
{
	__FD_SET(c->sock, readset);
}

static void
channel_pre_connecting(Channel *c, fd_set * readset, fd_set * writeset)
{
	debug3("channel %d: waiting for connection", c->self);
	__FD_SET(c->sock, writeset);
}

static void
channel_pre_open(Channel *c, fd_set * readset, fd_set * writeset)
{
	u_int limit = THREAD_LOCAL(compat20) ? c->remote_window : packet_get_maxsize();

	/* check buffer limits */
	limit = MIN(limit, (BUFFER_MAX_LEN - BUFFER_MAX_CHUNK - CHAN_RBUF));

	if (c->istate == CHAN_INPUT_OPEN &&
	    limit > 0 &&
	    buffer_len(&c->input) < limit)
		__FD_SET(c->rfd, readset);
	if (c->ostate == CHAN_OUTPUT_OPEN ||
	    c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
		if (buffer_len(&c->output) > 0) {
			__FD_SET(c->wfd, writeset);
		} else if (c->ostate == CHAN_OUTPUT_WAIT_DRAIN) {
			if (CHANNEL_EFD_OUTPUT_ACTIVE(c))
				debug2("channel %d: obuf_empty delayed efd %d/(%d)",
				    c->self, c->efd, buffer_len(&c->extended));
			else
				chan_obuf_empty(c);
		}
	}
	/** XXX check close conditions, too */
	if (THREAD_LOCAL(compat20) && c->efd != -1) {
		if (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    buffer_len(&c->extended) > 0)
			__FD_SET(c->efd, writeset);
		else if (!(c->flags & CHAN_EOF_SENT) &&
		    c->extended_usage == CHAN_EXTENDED_READ &&
		    buffer_len(&c->extended) < c->remote_window)
			__FD_SET(c->efd, readset);
	}
	/* XXX: What about efd? races? */
	if (THREAD_LOCAL(compat20) && c->ctl_fd != -1 &&
	    c->istate == CHAN_INPUT_OPEN && c->ostate == CHAN_OUTPUT_OPEN)
		__FD_SET(c->ctl_fd, readset);
}
static void
channel_pre_x11_open(Channel *c, fd_set * readset, fd_set * writeset)
{
	RETAILMSG(1,(TEXT("X11 forwarding not supported\r\n")));
}

/* try to decode a socks4 header */
static int
channel_decode_socks4(Channel *c, fd_set * readset, fd_set * writeset)
{
	char *p, *host;
	u_int len, have, i, found;
	char username[256];
	struct {
		u_int8_t version;
		u_int8_t command;
		u_int16_t dest_port;
		struct in_addr dest_addr;
	} s4_req, s4_rsp;

	debug2("channel %d: decode socks4", c->self);

	have = buffer_len(&c->input);
	len = sizeof(s4_req);
	if (have < len)
		return 0;
	p = buffer_ptr(&c->input);
	for (found = 0, i = len; i < have; i++) {
		if (p[i] == '\0') {
			found = 1;
			break;
		}
		if (i > 1024) {
			/* the peer is probably sending garbage */
			debug("channel %d: decode socks4: too long",
			    c->self);
			return -1;
		}
	}
	if (!found)
		return 0;
	buffer_get(&c->input, (char *)&s4_req.version, 1);
	buffer_get(&c->input, (char *)&s4_req.command, 1);
	buffer_get(&c->input, (char *)&s4_req.dest_port, 2);
	buffer_get(&c->input, (char *)&s4_req.dest_addr, 4);
	have = buffer_len(&c->input);
	p = buffer_ptr(&c->input);
	len = strlen(p);
	debug2("channel %d: decode socks4: user %s/%d", c->self, p, len);
	if (len > have)
		fatal("channel %d: decode socks4: len %d > have %d",
		    c->self, len, have);
	strlcpy(username, p, sizeof(username));
	buffer_consume(&c->input, len);
	buffer_consume(&c->input, 1);		/* trailing '\0' */

	host = inet_ntoa(s4_req.dest_addr);
	strlcpy(c->path, host, sizeof(c->path));
	c->host_port = ntohs(s4_req.dest_port);

	debug2("channel %d: dynamic request: socks4 host %s port %u command %u",
	    c->self, host, c->host_port, s4_req.command);

	if (s4_req.command != 1) {
		debug("channel %d: cannot handle: socks4 cn %d",
		    c->self, s4_req.command);
		return -1;
	}
	s4_rsp.version = 0;			/* vn: 0 for reply */
	s4_rsp.command = 90;			/* cd: req granted */
	s4_rsp.dest_port = 0;			/* ignored */
	s4_rsp.dest_addr.s_addr = INADDR_ANY;	/* ignored */
	buffer_append(&c->output, (char *)&s4_rsp, sizeof(s4_rsp));
	return 1;
}

/* try to decode a socks5 header */
#define SSH_SOCKS5_AUTHDONE	0x1000
#define SSH_SOCKS5_NOAUTH	0x00
#define SSH_SOCKS5_IPV4		0x01
#define SSH_SOCKS5_DOMAIN	0x03
#define SSH_SOCKS5_IPV6		0x04
#define SSH_SOCKS5_CONNECT	0x01
#define SSH_SOCKS5_SUCCESS	0x00

static int
channel_decode_socks5(Channel *c, fd_set * readset, fd_set * writeset)
{
	struct {
		u_int8_t version;
		u_int8_t command;
		u_int8_t reserved;
		u_int8_t atyp;
	} s5_req, s5_rsp;
	u_int16_t dest_port;
	u_char *p, dest_addr[255+1];
	u_int have, i, found, nmethods, addrlen, af;

	debug2("channel %d: decode socks5", c->self);
	p = buffer_ptr(&c->input);
	if (p[0] != 0x05)
		return -1;
	have = buffer_len(&c->input);
	if (!(c->flags & SSH_SOCKS5_AUTHDONE)) {
		/* format: ver | nmethods | methods */
		if (have < 2)
			return 0;
		nmethods = p[1];
		if (have < nmethods + 2)
			return 0;
		/* look for method: "NO AUTHENTICATION REQUIRED" */
		for (found = 0, i = 2 ; i < nmethods + 2; i++) {
			if (p[i] == SSH_SOCKS5_NOAUTH ) {
				found = 1;
				break;
			}
		}
		if (!found) {
			debug("channel %d: method SSH_SOCKS5_NOAUTH not found",
			    c->self);
			return -1;
		}
		buffer_consume(&c->input, nmethods + 2);
		buffer_put_char(&c->output, 0x05);		/* version */
		buffer_put_char(&c->output, SSH_SOCKS5_NOAUTH);	/* method */
		__FD_SET(c->sock, writeset);
		c->flags |= SSH_SOCKS5_AUTHDONE;
		debug2("channel %d: socks5 auth done", c->self);
		return 0;				/* need more */
	}
	debug2("channel %d: socks5 post auth", c->self);
	if (have < sizeof(s5_req)+1)
		return 0;			/* need more */
	memcpy((char *)&s5_req, p, sizeof(s5_req));
	if (s5_req.version != 0x05 ||
	    s5_req.command != SSH_SOCKS5_CONNECT ||
	    s5_req.reserved != 0x00) {
		debug2("channel %d: only socks5 connect supported", c->self);
		return -1;
	}
	switch (s5_req.atyp){
	case SSH_SOCKS5_IPV4:
		addrlen = 4;
		af = AF_INET;
		break;
	case SSH_SOCKS5_DOMAIN:
		addrlen = p[sizeof(s5_req)];
		af = -1;
		break;
	case SSH_SOCKS5_IPV6:
		addrlen = 16;
		af = AF_INET6;
		break;
	default:
		debug2("channel %d: bad socks5 atyp %d", c->self, s5_req.atyp);
		return -1;
	}
	if (have < 4 + addrlen + 2)
		return 0;
	buffer_consume(&c->input, sizeof(s5_req));
	if (s5_req.atyp == SSH_SOCKS5_DOMAIN)
		buffer_consume(&c->input, 1);    /* host string length */
	buffer_get(&c->input, (char *)&dest_addr, addrlen);
	buffer_get(&c->input, (char *)&dest_port, 2);
	dest_addr[addrlen] = '\0';
	if (s5_req.atyp == SSH_SOCKS5_DOMAIN)
		strlcpy(c->path, (char *)dest_addr, sizeof(c->path));
	else if (inet_ntop(af, dest_addr, c->path, sizeof(c->path)) == NULL)
		return -1;
	c->host_port = ntohs(dest_port);

	debug2("channel %d: dynamic request: socks5 host %s port %u command %u",
	    c->self, c->path, c->host_port, s5_req.command);

	s5_rsp.version = 0x05;
	s5_rsp.command = SSH_SOCKS5_SUCCESS;
	s5_rsp.reserved = 0;			/* ignored */
	s5_rsp.atyp = SSH_SOCKS5_IPV4;
	((struct in_addr *)&dest_addr)->s_addr = INADDR_ANY;
	dest_port = 0;				/* ignored */

	buffer_append(&c->output, (char *)&s5_rsp, sizeof(s5_rsp));
	buffer_append(&c->output, (char *)&dest_addr, sizeof(struct in_addr));
	buffer_append(&c->output, (char *)&dest_port, sizeof(dest_port));
	return 1;
}

/* dynamic port forwarding */
static void
channel_pre_dynamic(Channel *c, fd_set * readset, fd_set * writeset)
{
	u_char *p;
	u_int have;
	int ret;

	have = buffer_len(&c->input);
	c->delayed = 0;
	debug2("channel %d: pre_dynamic: have %d", c->self, have);
	/* buffer_dump(&c->input); */
	/* check if the fixed size part of the packet is in buffer. */
	if (have < 3) {
		/* need more */
		__FD_SET(c->sock, readset);
		return;
	}
	/* try to guess the protocol */
	p = buffer_ptr(&c->input);
	switch (p[0]) {
	case 0x04:
		ret = channel_decode_socks4(c, readset, writeset);
		break;
	case 0x05:
		ret = channel_decode_socks5(c, readset, writeset);
		break;
	default:
		ret = -1;
		break;
	}
	if (ret < 0) {
		chan_mark_dead(c);
	} else if (ret == 0) {
		debug2("channel %d: pre_dynamic: need more", c->self);
		/* need more */
		__FD_SET(c->sock, readset);
	} else {
		/* switch to the next state */
		c->type = SSH_CHANNEL_OPENING;
		port_open_helper(c, "direct-tcpip");
	}
}

/* This is our fake X11 server socket. */
static void
channel_post_x11_listener(Channel *c, fd_set * readset, fd_set * writeset)
{
	Channel *nc;
	struct sockaddr addr;
	int newsock;
	socklen_t addrlen;
	char buf[16384], *remote_ipaddr;
	int remote_port;

	if (FD_ISSET(c->sock, readset)) {
		debug("X11 connection requested.");
		addrlen = sizeof(addr);
		newsock = accept(c->sock, &addr, &addrlen);
		if (c->single_connection) {
			debug2("single_connection: closing X11 listener.");
			channel_close_fd(&c->sock);
			chan_mark_dead(c);
		}
		if (newsock < 0) {
			error("accept: %.100s", strerror(errno));
			return;
		}
		set_nodelay(newsock);
		remote_ipaddr = get_peer_ipaddr(newsock);
		remote_port = get_peer_port(newsock);
		snprintf(buf, sizeof buf, "X11 connection from %.200s port %d",
		    remote_ipaddr, remote_port);

		nc = channel_new("accepted x11 socket",
		    SSH_CHANNEL_OPENING, newsock, newsock, -1,
		    c->local_window_max, c->local_maxpacket, 0, buf, 1);
		if (THREAD_LOCAL(compat20)) {
			packet_start(SSH2_MSG_CHANNEL_OPEN);
			packet_put_cstring("x11");
			packet_put_int(nc->self);
			packet_put_int(nc->local_window_max);
			packet_put_int(nc->local_maxpacket);
			/* originator ipaddr and port */
			packet_put_cstring(remote_ipaddr);
			if (THREAD_LOCAL(datafellows) & SSH_BUG_X11FWD) {
				debug2("ssh2 x11 bug compat mode");
			} else {
				packet_put_int(remote_port);
			}
			packet_send();
		} else {
#ifdef WINCE_PORT
			ASSERT(0);
#else	
			packet_start(SSH_SMSG_X11_OPEN);
			packet_put_int(nc->self);
			if (packet_get_protocol_flags() &
			    SSH_PROTOFLAG_HOST_IN_FWD_OPEN)
				packet_put_cstring(buf);
			packet_send();
#endif
		}
		xfree(remote_ipaddr);
	}
}

static void
port_open_helper(Channel *c, char *rtype)
{
	int direct;
	char buf[1024];
	char *remote_ipaddr = get_peer_ipaddr(c->sock);
	int remote_port = get_peer_port(c->sock);

	direct = (strcmp(rtype, "direct-tcpip") == 0);

	snprintf(buf, sizeof buf,
	    "%s: listening port %d for %.100s port %d, "
	    "connect from %.200s port %d",
	    rtype, c->listening_port, c->path, c->host_port,
	    remote_ipaddr, remote_port);

	xfree(c->remote_name);
	c->remote_name = xstrdup(buf);

	if (THREAD_LOCAL(compat20)) {
		packet_start(SSH2_MSG_CHANNEL_OPEN);
		packet_put_cstring(rtype);
		packet_put_int(c->self);
		packet_put_int(c->local_window_max);
		packet_put_int(c->local_maxpacket);
		if (direct) {
			/* target host, port */
			packet_put_cstring(c->path);
			packet_put_int(c->host_port);
		} else {
			/* listen address, port */
			packet_put_cstring(c->path);
			packet_put_int(c->listening_port);
		}
		/* originator host and port */
		packet_put_cstring(remote_ipaddr);
		packet_put_int((u_int)remote_port);
		packet_send();
	} else {
#ifdef WINCE_PORT
			ASSERT(0);
#else	
		packet_start(SSH_MSG_PORT_OPEN);
		packet_put_int(c->self);
		packet_put_cstring(c->path);
		packet_put_int(c->host_port);
		if (packet_get_protocol_flags() &
		    SSH_PROTOFLAG_HOST_IN_FWD_OPEN)
			packet_put_cstring(c->remote_name);
		packet_send();
#endif
	}
	xfree(remote_ipaddr);
}

static void
channel_set_reuseaddr(int fd)
{
	int on = 1;

	/*
	 * Set socket options.
	 * Allow local port reuse in TIME_WAIT.
	 */
	if (__setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
		error("__setsockopt SO_REUSEADDR fd %d: %s", fd, strerror(errno));
}

/*
 * This socket is listening for connections to a forwarded TCP/IP port.
 */
static void
channel_post_port_listener(Channel *c, fd_set * readset, fd_set * writeset)
{
	Channel *nc;
	struct sockaddr addr;
	int newsock, nextstate;
	socklen_t addrlen;
	char *rtype;

	if (FD_ISSET(c->sock, readset)) {
		debug("Connection to port %d forwarding "
		    "to %.100s port %d requested.",
		    c->listening_port, c->path, c->host_port);

		if (c->type == SSH_CHANNEL_RPORT_LISTENER) {
			nextstate = SSH_CHANNEL_OPENING;
			rtype = "forwarded-tcpip";
		} else {
			if (c->host_port == 0) {
				nextstate = SSH_CHANNEL_DYNAMIC;
				rtype = "dynamic-tcpip";
			} else {
				nextstate = SSH_CHANNEL_OPENING;
				rtype = "direct-tcpip";
			}
		}

		addrlen = sizeof(addr);
		newsock = accept(c->sock, &addr, &addrlen);
		if (newsock < 0) {
			error("accept: %.100s", strerror(errno));
			return;
		}
		set_nodelay(newsock);
		nc = channel_new(rtype, nextstate, newsock, newsock, -1,
		    c->local_window_max, c->local_maxpacket, 0, rtype, 1);
		nc->listening_port = c->listening_port;
		nc->host_port = c->host_port;
		strlcpy(nc->path, c->path, sizeof(nc->path));

		if (nextstate == SSH_CHANNEL_DYNAMIC) {
			/*
			 * do not call the channel_post handler until
			 * this flag has been reset by a pre-handler.
			 * otherwise the FD_ISSET calls might overflow
			 */
			nc->delayed = 1;
		} else {
			port_open_helper(nc, rtype);
		}
	}
}

/*
 * This is the authentication agent socket listening for connections from
 * clients.
 */
static void
channel_post_auth_listener(Channel *c, fd_set * readset, fd_set * writeset)
{
#ifdef WINCE_PORT
#else
	Channel *nc;
	int newsock;
	struct sockaddr addr;
	socklen_t addrlen;

	if (FD_ISSET(c->sock, readset)) {
		addrlen = sizeof(addr);
		newsock = accept(c->sock, &addr, &addrlen);
		if (newsock < 0) {
			error("accept from auth socket: %.100s", strerror(errno));
			return;
		}
		nc = channel_new("accepted auth socket",
		    SSH_CHANNEL_OPENING, newsock, newsock, -1,
		    c->local_window_max, c->local_maxpacket,
		    0, "accepted auth socket", 1);
		if (THREAD_LOCAL(compat20)) {
			packet_start(SSH2_MSG_CHANNEL_OPEN);
			packet_put_cstring("auth-agent@openssh.com");
			packet_put_int(nc->self);
			packet_put_int(c->local_window_max);
			packet_put_int(c->local_maxpacket);
		} else {
#ifdef WINCE_PORT
			ASSERT(0);
#else	
			packet_start(SSH_SMSG_AGENT_OPEN);
			packet_put_int(nc->self);
#endif
		}
		packet_send();
	}
#endif
}

static void
channel_post_connecting(Channel *c, fd_set * readset, fd_set * writeset)
{
	int err = 0;
	socklen_t sz = sizeof(err);

	if (FD_ISSET(c->sock, writeset)) {
		if (__getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &sz) < 0) {
			err = errno;
			error("__getsockopt SO_ERROR failed");
		}
		if (err == 0) {
			debug("channel %d: connected", c->self);
			c->type = SSH_CHANNEL_OPEN;
			if (THREAD_LOCAL(compat20)) {
				packet_start(SSH2_MSG_CHANNEL_OPEN_CONFIRMATION);
				packet_put_int(c->remote_id);
				packet_put_int(c->self);
				packet_put_int(c->local_window);
				packet_put_int(c->local_maxpacket);
			} else {
#ifdef WINCE_PORT
				ASSERT(0);
#else	
				packet_start(SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
				packet_put_int(c->remote_id);
				packet_put_int(c->self);
#endif
			}
		} else {
			debug("channel %d: not connected: %s",
			    c->self, strerror(err));
			if (THREAD_LOCAL(compat20)) {
				packet_start(SSH2_MSG_CHANNEL_OPEN_FAILURE);
				packet_put_int(c->remote_id);
				packet_put_int(SSH2_OPEN_CONNECT_FAILED);
				if (!(THREAD_LOCAL(datafellows) & SSH_BUG_OPENFAILURE)) {
					packet_put_cstring(strerror(err));
					packet_put_cstring("");
				}
			} else {
#ifdef WINCE_PORT
			ASSERT(0);
#else	
			packet_start(SSH_MSG_CHANNEL_OPEN_FAILURE);
			packet_put_int(c->remote_id);
#endif
			}
			chan_mark_dead(c);
		}
		packet_send();
	}
}

static int
channel_handle_rfd(Channel *c, fd_set * readset, fd_set * writeset)
{
	char buf[CHAN_RBUF];
	int len;

	if (c->rfd != -1 &&
	    FD_ISSET(c->rfd, readset)) {
		len = SocketRead(c->rfd, buf, sizeof(buf));
		if (len < 0 && (h_errno == EINTR || h_errno == EAGAIN))
			return 1;
		if (len <= 0) {
			debug2("channel %d: SocketRead<=0 rfd %d len %d",
			    c->self, c->rfd, len);
			if (c->type != SSH_CHANNEL_OPEN) {
				debug2("channel %d: not open", c->self);
				chan_mark_dead(c);
				return -1;
			} else if (THREAD_LOCAL(compat13)) {
				buffer_clear(&c->output);
				c->type = SSH_CHANNEL_INPUT_DRAINING;
				debug2("channel %d: input draining.", c->self);
			} else {
				chan_read_failed(c);
			}
			return -1;
		}
		if (c->input_filter != NULL) {
			if (c->input_filter(c, buf, len) == -1) {
				debug2("channel %d: filter stops", c->self);
				chan_read_failed(c);
			}
		} else if (c->datagram) {
			buffer_put_string(&c->input, buf, len);
		} else {
			buffer_append(&c->input, buf, len);
		}
	}
	return 1;
}
static int
channel_handle_wfd(Channel *c, fd_set * readset, fd_set * writeset)
{
	//JJH struct termios tio;
	u_char *data = NULL, *buf;
	u_int dlen;
	int len;

	/* Send buffered output data to the socket. */
	if (c->wfd != -1 &&
	    FD_ISSET(c->wfd, writeset) &&
	    buffer_len(&c->output) > 0) {
		if (c->output_filter != NULL) {
			if ((buf = c->output_filter(c, &data, &dlen)) == NULL) {
				debug2("channel %d: filter stops", c->self);
				if (c->type != SSH_CHANNEL_OPEN)
					chan_mark_dead(c);
				else
					chan_write_failed(c);
				return -1;
			}
		} else if (c->datagram) {
			buf = data = buffer_get_string(&c->output, &dlen);
		} else {
			buf = data = buffer_ptr(&c->output);
			dlen = buffer_len(&c->output);
		}

		if (c->datagram) {
			/* ignore truncated writes, datagrams might get lost */
			c->local_consumed += dlen + 4;
			len = SocketWrite(c->wfd, buf, dlen);
			xfree(data);
			if (len < 0 && (errno == EINTR || errno == EAGAIN))
				return 1;
			if (len <= 0) {
				if (c->type != SSH_CHANNEL_OPEN)
					chan_mark_dead(c);
				else
					chan_write_failed(c);
				return -1;
			}
			return 1;
		}
#ifdef _AIX
		/* XXX: Later AIX versions can't push as much data to tty */
		if (THREAD_LOCAL(compat20) && c->wfd_isatty)
			dlen = MIN(dlen, 8*1024);
#endif

		len = SocketWrite(c->wfd, buf, dlen);
		if (len < 0 && (errno == EINTR || errno == EAGAIN))
			return 1;
		if (len <= 0) {
			if (c->type != SSH_CHANNEL_OPEN) {
				debug2("channel %d: not open", c->self);
				chan_mark_dead(c);
				return -1;
			} else if (THREAD_LOCAL(compat13)) {
#ifdef WINCE_PORT
				ASSERT(0);
#else
				buffer_clear(&c->output);
				debug2("channel %d: input draining.", c->self);
				c->type = SSH_CHANNEL_INPUT_DRAINING;
#endif
			} else {
				chan_write_failed(c);
			}
			return -1;
		}
		if (THREAD_LOCAL(compat20) && c->isatty && dlen >= 1 && buf[0] != '\r') {
#ifndef WINCE_PORT //See what to do with this

			if (tcgetattr(c->wfd, &tio) == 0 &&
			    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
				/*
				 * Simulate echo to reduce the impact of
				 * traffic analysis. We need to match the
				 * size of a SSH2_MSG_CHANNEL_DATA message
				 * (4 byte channel id + buf)
				 */
				packet_send_ignore(4 + len);
				packet_send();
			}
#endif
		}
		buffer_consume(&c->output, len);
		if (THREAD_LOCAL(compat20) && len > 0) {
			c->local_consumed += len;
		}
	}
	return 1;
}
static int
channel_handle_efd(Channel *c, fd_set * readset, fd_set * writeset)
{
	char buf[CHAN_RBUF];
	int len;

/** XXX handle drain efd, too */
	if (c->efd != -1) {
		if (c->extended_usage == CHAN_EXTENDED_WRITE &&
		    FD_ISSET(c->efd, writeset) &&
		    buffer_len(&c->extended) > 0) {
			len = SocketWrite(c->efd, buffer_ptr(&c->extended),
			    buffer_len(&c->extended));

			debug2("channel %d: written %d to efd %d",
			    c->self, len, c->efd);
			if (len < 0 && (errno == EINTR || errno == EAGAIN))
				return 1;
			if (len <= 0) {
				debug2("channel %d: closing write-efd %d",
				    c->self, c->efd);
				channel_close_fd(&c->efd);
			} else {
				buffer_consume(&c->extended, len);
				c->local_consumed += len;
			}
		} else if (c->extended_usage == CHAN_EXTENDED_READ &&
		    FD_ISSET(c->efd, readset)) {
			len = SocketRead(c->efd, buf, sizeof(buf));
			debug2("channel %d: SocketRead %d from efd %d",
			    c->self, len, c->efd);
			if (len < 0 && (errno == EINTR || errno == EAGAIN))
				return 1;
			if (len <= 0) {
				debug2("channel %d: closing read-efd %d",
				    c->self, c->efd);
				channel_close_fd(&c->efd);
			} else {
				buffer_append(&c->extended, buf, len);
			}
		}
	}
	return 1;
}
static int
channel_handle_ctl(Channel *c, fd_set * readset, fd_set * writeset)
{
	char buf[16];
	int len;

	/* Monitor control fd to detect if the slave client exits */
	if (c->ctl_fd != -1 && FD_ISSET(c->ctl_fd, readset)) {
		len = SocketRead(c->ctl_fd, buf, sizeof(buf));
		if (len < 0 && (errno == EINTR || errno == EAGAIN))
			return 1;
		if (len <= 0) {
			debug2("channel %d: ctl SocketRead<=0", c->self);
			if (c->type != SSH_CHANNEL_OPEN) {
				debug2("channel %d: not open", c->self);
				chan_mark_dead(c);
				return -1;
			} else {
				chan_read_failed(c);
				chan_write_failed(c);
			}
			return -1;
		} else
			fatal("%s: unexpected data on ctl fd", __func__);
	}
	return 1;
}
static int
channel_check_window(Channel *c)
{
	if (c->type == SSH_CHANNEL_OPEN &&
	    !(c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD)) &&
	    c->local_window < c->local_window_max/2 &&
	    c->local_consumed > 0) {
		packet_start(SSH2_MSG_CHANNEL_WINDOW_ADJUST);
		packet_put_int(c->remote_id);
		packet_put_int(c->local_consumed);
		packet_send();
		debug2("channel %d: window %d sent adjust %d",
		    c->self, c->local_window,
		    c->local_consumed);
		c->local_window += c->local_consumed;
		c->local_consumed = 0;
	}
	return 1;
}

static void
channel_post_open(Channel *c, fd_set * readset, fd_set * writeset)
{
	if (c->delayed)
		return;
	channel_handle_rfd(c, readset, writeset);
	channel_handle_wfd(c, readset, writeset);
	if (!THREAD_LOCAL(compat20))
		return;
	channel_handle_efd(c, readset, writeset);
	channel_handle_ctl(c, readset, writeset);
	channel_check_window(c);
}


static void
channel_handler_init_20(void)
{
	THREAD_LOCAL(channel_pre)[SSH_CHANNEL_OPEN] =			&channel_pre_open;
	THREAD_LOCAL(channel_pre)[SSH_CHANNEL_X11_OPEN] =		&channel_pre_x11_open;
	THREAD_LOCAL(channel_pre)[SSH_CHANNEL_PORT_LISTENER] =	&channel_pre_listener;
	THREAD_LOCAL(channel_pre)[SSH_CHANNEL_RPORT_LISTENER] =	&channel_pre_listener;
	THREAD_LOCAL(channel_pre)[SSH_CHANNEL_X11_LISTENER] =		&channel_pre_listener;
	THREAD_LOCAL(channel_pre)[SSH_CHANNEL_AUTH_SOCKET] =		&channel_pre_listener;
	THREAD_LOCAL(channel_pre)[SSH_CHANNEL_CONNECTING] =		&channel_pre_connecting;
	THREAD_LOCAL(channel_pre)[SSH_CHANNEL_DYNAMIC] =		&channel_pre_dynamic;

	THREAD_LOCAL(channel_post)[SSH_CHANNEL_OPEN] =		&channel_post_open;
	THREAD_LOCAL(channel_post)[SSH_CHANNEL_PORT_LISTENER] =	&channel_post_port_listener;
	THREAD_LOCAL(channel_post)[SSH_CHANNEL_RPORT_LISTENER] =	&channel_post_port_listener;
	THREAD_LOCAL(channel_post)[SSH_CHANNEL_X11_LISTENER] =	&channel_post_x11_listener;
	THREAD_LOCAL(channel_post)[SSH_CHANNEL_AUTH_SOCKET] =		&channel_post_auth_listener;
	THREAD_LOCAL(channel_post)[SSH_CHANNEL_CONNECTING] =		&channel_post_connecting;
	THREAD_LOCAL(channel_post)[SSH_CHANNEL_DYNAMIC] =		&channel_post_open;
}


static void
channel_handler_init(void)
{
	int i;

	for (i = 0; i < SSH_CHANNEL_MAX_TYPE; i++) {
		THREAD_LOCAL(channel_pre)[i] = NULL;
		THREAD_LOCAL(channel_post)[i] = NULL;
	}
	if (THREAD_LOCAL(compat20))
		channel_handler_init_20();
	else 
#ifdef WINCE_PORT
		ASSERT(0);
#else
		if (THREAD_LOCAL(compat13))
		channel_handler_init_13();
	else
		channel_handler_init_15();
#endif
}

/* gc dead THREAD_LOCAL(channels) */
static void
channel_garbage_collect(Channel *c)
{
	if (c == NULL)
		return;
	if (c->detach_user != NULL) {
		if (!chan_is_dead(c, c->detach_close))
			return;
		debug2("channel %d: gc: notify user", c->self);
		c->detach_user(c->self, NULL);
		/* if we still have a callback */
		if (c->detach_user != NULL)
			return;
		debug2("channel %d: gc: user detached", c->self);
	}
	if (!chan_is_dead(c, 1))
		return;
	debug2("channel %d: garbage collecting", c->self);
	channel_free(c);
}

#ifdef WINCE_PORT
	//int did_channel_handler_init = 0;
#endif

static void
channel_handler(chan_fn *ftab[], fd_set * readset, fd_set * writeset)
{
#ifndef WINCE_PORT
	static int did_channel_handler_init = 0;
#endif
	u_int i;
	Channel *c;

	if (!THREAD_LOCAL(did_channel_handler_init)) {
		channel_handler_init();
		THREAD_LOCAL(did_channel_handler_init) = 1;
	}
	for (i = 0; i < THREAD_LOCAL(channels_alloc); i++) {
		c = THREAD_LOCAL(channels)[i];
		if (c == NULL)
			continue;
		if (ftab[c->type] != NULL)
			(*ftab[c->type])(c, readset, writeset);
		channel_garbage_collect(c);
	}
}

/*
 * Allocate/update select bitmasks and add any bits relevant to THREAD_LOCAL(channels) in
 * select bitmasks.
 */
void
channel_prepare_select(fd_set **readsetp, fd_set **writesetp, int *maxfdp,
    u_int *nallocp, int rekeying)
{
#ifdef WINCE_PORT	


	if (maxfdp!= NULL)
	{
		ASSERT(0); // for dev only
	}
	if (nallocp!= NULL)
	{
		ASSERT(0); // for dev only
	}

	if (*readsetp == NULL)
	{
		*readsetp = xmalloc(sizeof(fd_set));		
	}
	FD_ZERO(*readsetp);
	if (*writesetp == NULL)
	{
		*writesetp = xmalloc(sizeof(fd_set));		
	}
	FD_ZERO(*writesetp);

#else
	u_int n, sz;

	n = MAX(*maxfdp, channel_max_fd);

	sz = howmany(n+1, NFDBITS) * sizeof(fd_mask);
	/* perhaps check sz < nalloc/2 and shrink? */
	if (*readsetp == NULL || sz > *nallocp) {
		*readsetp = xrealloc(*readsetp, sz);
		*writesetp = xrealloc(*writesetp, sz);
		*nallocp = sz;
	}
	*maxfdp = n;
	memset(*readsetp, 0, sz);
	memset(*writesetp, 0, sz);
#endif

	if (!rekeying)
		channel_handler(THREAD_LOCAL(channel_pre), *readsetp, *writesetp);
}

/*
 * After select, perform any appropriate operations for THREAD_LOCAL(channels) which have
 * events pending.
 */
void
channel_after_select(fd_set * readset, fd_set * writeset)
{
	channel_handler(THREAD_LOCAL(channel_post), readset, writeset);
}


/* If there is data to send to the connection, enqueue some of it now. */

void
channel_output_poll(void)
{
	Channel *c;
	u_int i, len;

	for (i = 0; i < THREAD_LOCAL(channels_alloc); i++) {
		c = THREAD_LOCAL(channels)[i];
		if (c == NULL)
			continue;

		/*
		 * We are only interested in THREAD_LOCAL(channels) that can have buffered
		 * incoming data.
		 */
		if (THREAD_LOCAL(compat13)) {
			if (c->type != SSH_CHANNEL_OPEN &&
			    c->type != SSH_CHANNEL_INPUT_DRAINING)
				continue;
		} else {
			if (c->type != SSH_CHANNEL_OPEN)
				continue;
		}
		if (THREAD_LOCAL(compat20) &&
		    (c->flags & (CHAN_CLOSE_SENT|CHAN_CLOSE_RCVD))) {
			/* XXX is this true? */
			debug3("channel %d: will not send data after close", c->self);
			continue;
		}

		/* Get the amount of buffered data for this channel. */
		if ((c->istate == CHAN_INPUT_OPEN ||
		    c->istate == CHAN_INPUT_WAIT_DRAIN) &&
		    (len = buffer_len(&c->input)) > 0) {
			if (c->datagram) {
				if (len > 0) {
					u_char *data;
					u_int dlen;

					data = buffer_get_string(&c->input,
					    &dlen);
					packet_start(SSH2_MSG_CHANNEL_DATA);
					packet_put_int(c->remote_id);
					packet_put_string(data, dlen);
					packet_send();
					c->remote_window -= dlen + 4;
					xfree(data);
				}
				continue;
			}
			/*
			 * Send some data for the other side over the secure
			 * connection.
			 */
			if (THREAD_LOCAL(compat20)) {
				if (len > c->remote_window)
					len = c->remote_window;
				if (len > c->remote_maxpacket)
					len = c->remote_maxpacket;
			} else {
				if (packet_is_interactive()) {
					if (len > 1024)
						len = 512;
				} else {
					/* Keep the packets at reasonable size. */
					if (len > packet_get_maxsize()/2)
						len = packet_get_maxsize()/2;
				}
			}
			if (len > 0) {
#ifdef WINCE_PORT
			ASSERT(THREAD_LOCAL(compat20));
			packet_start(SSH2_MSG_CHANNEL_DATA);
#else		
			packet_start(THREAD_LOCAL(compat20) ?
				    SSH2_MSG_CHANNEL_DATA : SSH_MSG_CHANNEL_DATA);
#endif
				packet_put_int(c->remote_id);
				packet_put_string(buffer_ptr(&c->input), len);
				packet_send();
				buffer_consume(&c->input, len);
				c->remote_window -= len;
			}
		} else if (c->istate == CHAN_INPUT_WAIT_DRAIN) {
			if (THREAD_LOCAL(compat13))
				fatal("cannot happen: istate == INPUT_WAIT_DRAIN for proto 1.3");
			/*
			 * input-buffer is empty and read-socket shutdown:
			 * tell peer, that we will not send more data: send IEOF.
			 * hack for extended data: delay EOF if EFD still in use.
			 */
			if (CHANNEL_EFD_INPUT_ACTIVE(c))
				debug2("channel %d: ibuf_empty delayed efd %d/(%d)",
				    c->self, c->efd, buffer_len(&c->extended));
			else
				chan_ibuf_empty(c);
		}
		/* Send extended data, i.e. stderr */
		if (THREAD_LOCAL(compat20) &&
		    !(c->flags & CHAN_EOF_SENT) &&
		    c->remote_window > 0 &&
		    (len = buffer_len(&c->extended)) > 0 &&
		    c->extended_usage == CHAN_EXTENDED_READ) {
			debug2("channel %d: rwin %u elen %u euse %d",
			    c->self, c->remote_window, buffer_len(&c->extended),
			    c->extended_usage);
			if (len > c->remote_window)
				len = c->remote_window;
			if (len > c->remote_maxpacket)
				len = c->remote_maxpacket;
			packet_start(SSH2_MSG_CHANNEL_EXTENDED_DATA);
			packet_put_int(c->remote_id);
			packet_put_int(SSH2_EXTENDED_DATA_STDERR);
			packet_put_string(buffer_ptr(&c->extended), len);
			packet_send();
			buffer_consume(&c->extended, len);
			c->remote_window -= len;
			debug2("channel %d: sent ext data %d", c->self, len);
		}
	}
}


/* -- protocol input */

void
channel_input_data(int type, u_int32_t seq, void *ctxt)
{
	int id;
	char *data;
	u_int data_len;
	Channel *c;

	/* Get the channel number and verify it. */
	id = packet_get_int();
	c = channel_lookup(id);
	if (c == NULL)
		packet_disconnect("Received data for nonexistent channel %d.", id);

	/* Ignore any data for non-open THREAD_LOCAL(channels) (might happen on close) */
	if (c->type != SSH_CHANNEL_OPEN &&
	    c->type != SSH_CHANNEL_X11_OPEN)
		return;

	/* Get the data. */
	data = packet_get_string(&data_len);

	/*
	 * Ignore data for protocol > 1.3 if output end is no longer open.
	 * For protocol 2 the sending side is reducing its window as it sends
	 * data, so we must 'fake' consumption of the data in order to ensure
	 * that window updates are sent back.  Otherwise the connection might
	 * deadlock.
	 */
	if (!THREAD_LOCAL(compat13) && c->ostate != CHAN_OUTPUT_OPEN) {
		if (THREAD_LOCAL(compat20)) {
			c->local_window -= data_len;
			c->local_consumed += data_len;
		}
		xfree(data);
		return;
	}

	if (THREAD_LOCAL(compat20)) {
		if (data_len > c->local_maxpacket) {
			logit("channel %d: rcvd big packet %d, maxpack %d",
			    c->self, data_len, c->local_maxpacket);
		}
		if (data_len > c->local_window) {
			logit("channel %d: rcvd too much data %d, win %d",
			    c->self, data_len, c->local_window);
			xfree(data);
			return;
		}
		c->local_window -= data_len;
	}
	packet_check_eom();
	if (c->datagram)
		buffer_put_string(&c->output, data, data_len);
	else
		buffer_append(&c->output, data, data_len);
	xfree(data);
}

void
channel_input_extended_data(int type, u_int32_t seq, void *ctxt)
{
	int id;
	char *data;
	u_int data_len, tcode;
	Channel *c;

	/* Get the channel number and verify it. */
	id = packet_get_int();
	c = channel_lookup(id);

	if (c == NULL)
		packet_disconnect("Received extended_data for bad channel %d.", id);
	if (c->type != SSH_CHANNEL_OPEN) {
		logit("channel %d: ext data for non open", id);
		return;
	}
	if (c->flags & CHAN_EOF_RCVD) {
		if (THREAD_LOCAL(datafellows) & SSH_BUG_EXTEOF)
			debug("channel %d: accepting ext data after eof", id);
		else
			packet_disconnect("Received extended_data after EOF "
			    "on channel %d.", id);
	}
	tcode = packet_get_int();
	if (c->efd == -1 ||
	    c->extended_usage != CHAN_EXTENDED_WRITE ||
	    tcode != SSH2_EXTENDED_DATA_STDERR) {
		logit("channel %d: bad ext data", c->self);
		return;
	}
	data = packet_get_string(&data_len);
	packet_check_eom();
	if (data_len > c->local_window) {
		logit("channel %d: rcvd too much extended_data %d, win %d",
		    c->self, data_len, c->local_window);
		xfree(data);
		return;
	}
	debug2("channel %d: rcvd ext data %d", c->self, data_len);
	c->local_window -= data_len;
	buffer_append(&c->extended, data, data_len);
	xfree(data);
}

void
channel_input_ieof(int type, u_int32_t seq, void *ctxt)
{
	int id;
	Channel *c;

	id = packet_get_int();
	packet_check_eom();
	c = channel_lookup(id);
	if (c == NULL)
		packet_disconnect("Received ieof for nonexistent channel %d.", id);
	chan_rcvd_ieof(c);

	/* XXX force input close */
	if (c->force_drain && c->istate == CHAN_INPUT_OPEN) {
		debug("channel %d: FORCE input drain", c->self);
		c->istate = CHAN_INPUT_WAIT_DRAIN;
		if (buffer_len(&c->input) == 0)
			chan_ibuf_empty(c);
	}

}

/* proto version 1.5 overloads CLOSE_CONFIRMATION with OCLOSE */
void
channel_input_oclose(int type, u_int32_t seq, void *ctxt)
{
	int id = packet_get_int();
	Channel *c = channel_lookup(id);

	packet_check_eom();
	if (c == NULL)
		packet_disconnect("Received oclose for nonexistent channel %d.", id);
	chan_rcvd_oclose(c);
}

void
channel_input_close_confirmation(int type, u_int32_t seq, void *ctxt)
{
	int id = packet_get_int();
	Channel *c = channel_lookup(id);

	packet_check_eom();
	if (c == NULL)
		packet_disconnect("Received close confirmation for "
		    "out-of-range channel %d.", id);
	if (c->type != SSH_CHANNEL_CLOSED)
		packet_disconnect("Received close confirmation for "
		    "non-closed channel %d (type %d).", id, c->type);
	channel_free(c);
}

void
channel_input_open_confirmation(int type, u_int32_t seq, void *ctxt)
{
	int id, remote_id;
	Channel *c;

	id = packet_get_int();
	c = channel_lookup(id);

	if (c==NULL || c->type != SSH_CHANNEL_OPENING)
		packet_disconnect("Received open confirmation for "
		    "non-opening channel %d.", id);
	remote_id = packet_get_int();
	/* Record the remote channel number and mark that the channel is now open. */
	c->remote_id = remote_id;
	c->type = SSH_CHANNEL_OPEN;

	if (THREAD_LOCAL(compat20)) {
		c->remote_window = packet_get_int();
		c->remote_maxpacket = packet_get_int();
		if (c->confirm) {
			debug2("callback start");
			c->confirm(c->self, c->confirm_ctx);
			debug2("callback done");
		}
		debug2("channel %d: open confirm rwindow %u rmax %u", c->self,
		    c->remote_window, c->remote_maxpacket);
	}
	packet_check_eom();
}

static char *
reason2txt(int reason)
{
	switch (reason) {
	case SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED:
		return "administratively prohibited";
	case SSH2_OPEN_CONNECT_FAILED:
		return "connect failed";
	case SSH2_OPEN_UNKNOWN_CHANNEL_TYPE:
		return "unknown channel type";
	case SSH2_OPEN_RESOURCE_SHORTAGE:
		return "resource shortage";
	}
	return "unknown reason";
}

void
channel_input_open_failure(int type, u_int32_t seq, void *ctxt)
{
	int id, reason;
	char *msg = NULL, *lang = NULL;
	Channel *c;

	id = packet_get_int();
	c = channel_lookup(id);

	if (c==NULL || c->type != SSH_CHANNEL_OPENING)
		packet_disconnect("Received open failure for "
		    "non-opening channel %d.", id);
	if (THREAD_LOCAL(compat20)) {
		reason = packet_get_int();
		if (!(THREAD_LOCAL(datafellows) & SSH_BUG_OPENFAILURE)) {
			msg  = packet_get_string(NULL);
			lang = packet_get_string(NULL);
		}
		logit("channel %d: open failed: %s%s%s", id,
		    reason2txt(reason), msg ? ": ": "", msg ? msg : "");
		if (msg != NULL)
			xfree(msg);
		if (lang != NULL)
			xfree(lang);
	}
	packet_check_eom();
	/* Free the channel.  This will also close the socket. */
	channel_free(c);
}

void
channel_input_window_adjust(int type, u_int32_t seq, void *ctxt)
{
	Channel *c;
	int id;
	u_int adjust;

	if (!THREAD_LOCAL(compat20))
		return;

	/* Get the channel number and verify it. */
	id = packet_get_int();
	c = channel_lookup(id);

	if (c == NULL) {
		logit("Received window adjust for non-open channel %d.", id);
		return;
	}
	adjust = packet_get_int();
	packet_check_eom();
	debug2("channel %d: rcvd adjust %u", id, adjust);
	c->remote_window += adjust;
}

/* -- tcp forwarding */

void
channel_set_af(int af)
{
	THREAD_LOCAL(IPv4or6) = af;
}

static int
channel_setup_fwd_listener(int type, const char *listen_addr, u_short listen_port,
    const char *host_to_connect, u_short port_to_connect, int gateway_ports)
{
	Channel *c;
	int sock, r, success = 0, wildcard = 0, is_client;
	struct addrinfo hints, *ai, *aitop;
	const char *host, *addr;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];

	host = (type == SSH_CHANNEL_RPORT_LISTENER) ?
	    listen_addr : host_to_connect;
	is_client = (type == SSH_CHANNEL_PORT_LISTENER);

	if (host == NULL) {
		error("No forward host name.");
		return 0;
	}
	if (strlen(host) > SSH_CHANNEL_PATH_LEN - 1) {
		error("Forward host name too long.");
		return 0;
	}

	/*
	 * Determine whether or not a port forward listens to loopback,
	 * specified address or wildcard. On the client, a specified bind
	 * address will always override gateway_ports. On the server, a
	 * gateway_ports of 1 (``yes'') will override the client's
	 * specification and force a wildcard bind, whereas a value of 2
	 * (``clientspecified'') will bind to whatever address the client
	 * asked for.
	 *
	 * Special-case listen_addrs are:
	 *
	 * "0.0.0.0"               -> wildcard v4/v6 if SSH_OLD_FORWARD_ADDR
	 * "" (empty string), "*"  -> wildcard v4/v6
	 * "localhost"             -> loopback v4/v6
	 */
	addr = NULL;
	if (listen_addr == NULL) {
		/* No address specified: default to gateway_ports setting */
		if (gateway_ports)
			wildcard = 1;
	} else if (gateway_ports || is_client) {
		if (((THREAD_LOCAL(datafellows) & SSH_OLD_FORWARD_ADDR) &&
		    strcmp(listen_addr, "0.0.0.0") == 0) ||
		    *listen_addr == '\0' || strcmp(listen_addr, "*") == 0 ||
		    (!is_client && gateway_ports == 1))
			wildcard = 1;
		else if (strcmp(listen_addr, "localhost") != 0)
			addr = listen_addr;
	}

	debug3("channel_setup_fwd_listener: type %d wildcard %d addr %s",
	    type, wildcard, (addr == NULL) ? "NULL" : addr);

	/*
	 * getaddrinfo returns a loopback address if the hostname is
	 * set to NULL and hints.ai_flags is not AI_PASSIVE
	 */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = THREAD_LOCAL(IPv4or6);
	hints.ai_flags = wildcard ? AI_PASSIVE : 0;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, sizeof strport, "%d", listen_port);
	if ((r = getaddrinfo(addr, strport, &hints, &aitop)) != 0) {
		if (addr == NULL) {
			/* This really shouldn't happen */
			packet_disconnect("getaddrinfo: fatal error: %s",
			    __gai_strerror(r));
		} else {
			error("channel_setup_fwd_listener: "
			    "getaddrinfo(%.64s): %s", addr, __gai_strerror(r));
		}
		return 0;
	}

	for (ai = aitop; ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;
		if (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, sizeof(ntop),
		    strport, sizeof(strport), NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error("channel_setup_fwd_listener: getnameinfo failed");
			continue;
		}
		/* Create a port to listen for the host. */
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0) {
			/* this is no error since kernel may not support ipv6 */
			verbose("socket: %.100s", strerror(errno));
			continue;
		}

		channel_set_reuseaddr(sock);

		debug("Local forwarding listening on %s port %s.", ntop, strport);

		/* Bind the socket to the address. */
		if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
			/* address can be in use ipv6 address is already bound */
			if (!ai->ai_next)
				error("bind: %.100s", strerror(errno));
			else
				verbose("bind: %.100s", strerror(errno));

			SocketClose(sock);
			continue;
		}
		/* Start listening for connections on the socket. */
		if (listen(sock, SSH_LISTEN_BACKLOG) < 0) {
			error("listen: %.100s", strerror(errno));
			SocketClose(sock);
			continue;
		}
		/* Allocate a channel number for the socket. */
		c = channel_new("port listener", type, sock, sock, -1,
		    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT,
		    0, "port listener", 1);
		strlcpy(c->path, host, sizeof(c->path));
		c->host_port = port_to_connect;
		c->listening_port = listen_port;
		success = 1;
	}
	if (success == 0)
		error("channel_setup_fwd_listener: cannot listen to port: %d",
		    listen_port);
	freeaddrinfo(aitop);
	return success;
}

int
channel_cancel_rport_listener(const char *host, u_short port)
{
	u_int i;
	int found = 0;

	for (i = 0; i < THREAD_LOCAL(channels_alloc); i++) {
		Channel *c = THREAD_LOCAL(channels)[i];

		if (c != NULL && c->type == SSH_CHANNEL_RPORT_LISTENER &&
		    strncmp(c->path, host, sizeof(c->path)) == 0 &&
		    c->listening_port == port) {
			debug2("%s: close channel %d", __func__, i);
			channel_free(c);
			found = 1;
		}
	}

	return (found);
}

/* protocol local port fwd, used by ssh (and sshd in v1) */
int
channel_setup_local_fwd_listener(const char *listen_host, u_short listen_port,
    const char *host_to_connect, u_short port_to_connect, int gateway_ports)
{
	return channel_setup_fwd_listener(SSH_CHANNEL_PORT_LISTENER,
	    listen_host, listen_port, host_to_connect, port_to_connect,
	    gateway_ports);
}

/* protocol v2 remote port fwd, used by sshd */
int
channel_setup_remote_fwd_listener(const char *listen_address,
    u_short listen_port, int gateway_ports)
{
	return channel_setup_fwd_listener(SSH_CHANNEL_RPORT_LISTENER,
	    listen_address, listen_port, NULL, 0, gateway_ports);
}


/*
 * This is called after receiving CHANNEL_FORWARDING_REQUEST.  This initates
 * listening for the port, and sends back a success reply (or disconnect
 * message if there was an error).  This never returns if there was an error.
 */

void
channel_input_port_forward_request(int is_root, int gateway_ports)
{
	u_short port, host_port;
	char *hostname;

	/* Get arguments from the packet. */
	port = packet_get_int();
	hostname = packet_get_string(NULL);
	host_port = packet_get_int();

#ifndef HAVE_CYGWIN
	/*
	 * Check that an unprivileged user is not trying to forward a
	 * privileged port.
	 */
	if (port < IPPORT_RESERVED && !is_root)
		packet_disconnect(
		    "Requested forwarding of port %d but user is not root.",
		    port);
	if (host_port == 0)
		packet_disconnect("Dynamic forwarding denied.");
#endif

	/* Initiate forwarding */
	channel_setup_local_fwd_listener(NULL, port, hostname,
	    host_port, gateway_ports);

	/* Free the argument string. */
	xfree(hostname);
}

/*
 * Permits opening to any host/port if permitted_opens[] is empty.  This is
 * usually called by the server, because the user could connect to any port
 * anyway, and the server has no way to know but to trust the client anyway.
 */
void
channel_permit_all_opens(void)
{
	if (THREAD_LOCAL(num_permitted_opens) == 0)
		THREAD_LOCAL(all_opens_permitted) = 1;
}

void
channel_add_permitted_opens(char *host, int port)
{
	if (THREAD_LOCAL(num_permitted_opens) >= SSH_MAX_FORWARDS_PER_DIRECTION)
		fatal("channel_request_remote_forwarding: too many forwards");
	debug("allow port forwarding to host %s port %d", host, port);

	THREAD_LOCAL(permitted_opens)[THREAD_LOCAL(num_permitted_opens)].host_to_connect = xstrdup(host);
	THREAD_LOCAL(permitted_opens)[THREAD_LOCAL(num_permitted_opens)].port_to_connect = port;
	THREAD_LOCAL(num_permitted_opens)++;

	THREAD_LOCAL(all_opens_permitted) = 0;
}

void
channel_clear_permitted_opens(void)
{
	int i;

	for (i = 0; i < THREAD_LOCAL(num_permitted_opens); i++)
		if (THREAD_LOCAL(permitted_opens)[i].host_to_connect != NULL)
			xfree(THREAD_LOCAL(permitted_opens)[i].host_to_connect);
	THREAD_LOCAL(num_permitted_opens) = 0;

}


/* return socket to remote host, port */
static int
connect_to(const char *host, u_short port)
{
	struct addrinfo hints, *ai, *aitop;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];
	int gaierr;
	int sock = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = THREAD_LOCAL(IPv4or6);
	hints.ai_socktype = SOCK_STREAM;
	snprintf(strport, sizeof strport, "%d", port);
	if ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0) {
		error("connect_to %.100s: unknown host (%s)", host,
		    __gai_strerror(gaierr));
		return -1;
	}
	for (ai = aitop; ai; ai = ai->ai_next) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			continue;
		if (getnameinfo(ai->ai_addr, ai->ai_addrlen, ntop, sizeof(ntop),
		    strport, sizeof(strport), NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
			error("connect_to: getnameinfo failed");
			continue;
		}
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0) {
			if (ai->ai_next == NULL)
				error("socket: %.100s", strerror(errno));
			else
				verbose("socket: %.100s", strerror(errno));
			continue;
		}
		if (set_nonblock(sock) == -1)
			fatal("%s: set_nonblock(%d)", __func__, sock);
		if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0 &&
#ifdef WINCE_PORT
			WSAGetLastError() != WSAEINPROGRESS) {
#else
		    errno != EINPROGRESS) {
#endif
			error("connect_to %.100s port %s: %.100s", ntop, strport,
			    strerror(errno));
			SocketClose(sock);
			continue;	/* fail -- try next */
		}
		break; /* success */

	}
	freeaddrinfo(aitop);
	if (!ai) {
		error("connect_to %.100s port %d: failed.", host, port);
		return -1;
	}
	/* success */
	set_nodelay(sock);
	return sock;
}

int
channel_connect_by_listen_address(u_short listen_port)
{
	int i;

	for (i = 0; i < THREAD_LOCAL(num_permitted_opens); i++)
		if (THREAD_LOCAL(permitted_opens)[i].host_to_connect != NULL &&
		    THREAD_LOCAL(permitted_opens)[i].listen_port == listen_port)
			return connect_to(
			    THREAD_LOCAL(permitted_opens)[i].host_to_connect,
			    THREAD_LOCAL(permitted_opens)[i].port_to_connect);
	error("WARNING: Server requests forwarding for unknown listen_port %d",
	    listen_port);
	return -1;
}

/* Check if connecting to that port is permitted and connect. */
int
channel_connect_to(const char *host, u_short port)
{
	int i, permit;

	permit = THREAD_LOCAL(all_opens_permitted);
	if (!permit) {
		for (i = 0; i < THREAD_LOCAL(num_permitted_opens); i++)
			if (THREAD_LOCAL(permitted_opens)[i].host_to_connect != NULL &&
			    THREAD_LOCAL(permitted_opens)[i].port_to_connect == port &&
			    strcmp(THREAD_LOCAL(permitted_opens)[i].host_to_connect, host) == 0)
				permit = 1;

	}
	if (!permit) {
		logit("Received request to connect to host %.100s port %d, "
		    "but the request was denied.", host, port);
		return -1;
	}
	return connect_to(host, port);
}

void
channel_send_window_changes(void)
{
#ifdef WINCE_PORT
	/*todo ???*/
#else
	u_int i;
	struct winsize ws;

	for (i = 0; i < THREAD_LOCAL(channels_alloc); i++) {
		if (THREAD_LOCAL(channels)[i] == NULL || !THREAD_LOCAL(channels)[i]->client_tty ||
		    THREAD_LOCAL(channels)[i]->type != SSH_CHANNEL_OPEN)
			continue;
		if (ioctl(THREAD_LOCAL(channels)[i]->rfd, TIOCGWINSZ, &ws) < 0)
			continue;
		channel_request_start(i, "window-change", 0);
		packet_put_int(ws.ws_col);
		packet_put_int(ws.ws_row);
		packet_put_int(ws.ws_xpixel);
		packet_put_int(ws.ws_ypixel);
		packet_send();
	}
#endif
}
