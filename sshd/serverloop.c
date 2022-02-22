/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Server main loop for handling the interactive session.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * SSH2 support by Markus Friedl.
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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
RCSID("$OpenBSD: serverloop.c,v 1.124 2005/12/13 15:03:02 reyk Exp $");

#include "xmalloc.h"
#include "packet.h"
#include "buffer.h"
#include "log.h"
#include "servconf.h"
#include "canohost.h"
//#include "sshpty.h"
#include "channels.h"
#include "compat.h"
#include "ssh.h"
#include "ssh2.h"
#include "auth.h"
#include "session.h"
#include "dispatch.h"
#include "auth-options.h"
#include "serverloop.h"
#include "misc.h"
#include "kex.h"

#include "ThreadLocal.h"

extern ServerOptions options;


#ifndef WINCE_PORT
static Buffer stdin_buffer;	/* Buffer for stdin data. */
static Buffer stdout_buffer;	/* Buffer for stdout data. */
static Buffer stderr_buffer;	/* Buffer for stderr data. */

static int fdin;		/* Descriptor for stdin (for writing) */
static int fdout;		/* Descriptor for stdout (for reading); May be same number as fdin. */
static int fderr;		/* Descriptor for stderr.  May be -1. */

int fdout_eof = 0;	/* EOF encountered reading from fdout. */
int fderr_eof = 0;	/* EOF encountered readung from fderr. */
int fdin_is_tty = 0;	/* fdin points to a tty. */
u_int buffer_high;	/* "Soft" max buffer size. */
#endif


/* prototypes */
static void server_init_dispatch(void);
static void
client_alive_check(void)
{
	int channel_id;

	/* timeout, check to see how many we have had */
	if (++THREAD_LOCAL(client_alive_timeouts) > options.client_alive_count_max)
		packet_disconnect("Timeout, your session not responding.");

	/*
	 * send a bogus global/channel request with "wantreply",
	 * we should get back a failure
	 */
	if ((channel_id = channel_find_open()) == -1) {
		packet_start(SSH2_MSG_GLOBAL_REQUEST);
		packet_put_cstring("keepalive@openssh.com");
		packet_put_char(1);	/* boolean: want reply */
	} else {
		channel_request_start(channel_id, "keepalive@openssh.com", 1);
	}
	packet_send();
}

/*
 * Sleep in select() until we can do something.  This will initialize the
 * select masks.  Upon return, the masks will indicate which descriptors
 * have data or can accept data.  Optionally, a maximum time can be specified
 * for the duration of the wait (0 = infinite).
 */
static void
wait_until_can_do_something(fd_set **readsetp, fd_set **writesetp, int *maxfdp,
    u_int *nallocp, u_int max_time_milliseconds)
{
	struct timeval tv, *tvp;
	int ret;
	int client_alive_scheduled = 0;

	/*
	 * if using client_alive, set the max timeout accordingly,
	 * and indicate that this particular timeout was for client
	 * alive by setting the client_alive_scheduled flag.
	 *
	 * this could be randomized somewhat to make traffic
	 * analysis more difficult, but we're not doing it yet.
	 */
	if (THREAD_LOCAL(compat20) &&
	    max_time_milliseconds == 0 && options.client_alive_interval) {
		client_alive_scheduled = 1;
		max_time_milliseconds = options.client_alive_interval * 1000;
	}

	/* Allocate and update select() masks for channel descriptors. */
#ifdef WINCE_PORT
	channel_prepare_select(readsetp, writesetp, NULL, NULL, 0);
#else
	channel_prepare_select(readsetp, writesetp, maxfdp, nallocp, 0);
#endif

	if (THREAD_LOCAL(compat20)) 
	{
		FD_SET(THREAD_LOCAL(connection_in), *readsetp);
	} 
	else 
	{
#ifdef WINCE_PORT
		ASSERT(0);
#else
		/*
		 * Read packets from the client unless we have too much
		 * buffered stdin or channel data.
		 */
		if (buffer_len(&THREAD_LOCAL(stdin_buffer)) < buffer_high &&
		    channel_not_very_much_buffered_data())
			FD_SET(connection_in, *readsetp);
		/*
		 * If there is not too much data already buffered going to
		 * the client, try to get some more data from the program.
		 */
		if (packet_not_very_much_data_to_write()) {
			if (!fdout_eof)
				FD_SET(fdout, *readsetp);
			if (!fderr_eof)
				FD_SET(fderr, *readsetp);
		}
		/*
		 * If we have buffered data, try to write some of that data
		 * to the program.
		 */
		if (fdin != -1 && buffer_len(&THREAD_LOCAL(stdin_buffer)) > 0)
			FD_SET(fdin, *writesetp);
#endif
	}
	//JJH notify_prepare(*readsetp);

	/*
	 * If we have buffered packet data going to the client, mark that
	 * descriptor.
	 */
	if (packet_have_data_to_write())
	{
		FD_SET(THREAD_LOCAL(connection_out), *writesetp);
	}

	/*
	 * If child has terminated and there is enough buffer space to read
	 * from it, then read as much as is available and exit.
	 */
	if (THREAD_LOCAL(child_terminated) && packet_not_very_much_data_to_write())
		if (max_time_milliseconds == 0 || client_alive_scheduled)
			max_time_milliseconds = 100;

	if (max_time_milliseconds == 0)
		tvp = NULL;
	else {
		tv.tv_sec = max_time_milliseconds / 1000;
		tv.tv_usec = 1000 * (max_time_milliseconds % 1000);
		tvp = &tv;
	}

	/* Wait for something to happen, or the timeout to expire. */
#ifdef WINCE_PORT
	ret = select(0, *readsetp, *writesetp, NULL, tvp);
#else
	ret = select((*maxfdp)+1, *readsetp, *writesetp, NULL, tvp);
#endif

	if (ret == -1) {
#ifdef WINCE_PORT
		FD_ZERO(*readsetp);
		FD_ZERO(*writesetp);
		if (WSAGetLastError() != WSAEINTR)
		{
			error("select: %.100s", strerror(WSAGetLastError()));
			THREAD_LOCAL(connection_closed) = TRUE;
		}

#else
		memset(*readsetp, 0, *nallocp);
		memset(*writesetp, 0, *nallocp);
		if (errno != EINTR)
			error("select: %.100s", strerror(errno));
#endif
	} else if (ret == 0 && client_alive_scheduled)
		client_alive_check();

	// JJH notify_done(*readsetp);
}

/*
 * Processes input from the client and the program.  Input data is stored
 * in buffers and processed later.
 */
static void
process_input(fd_set * readset)
{
	int len;
	char buf[16384];

	/* Read and buffer any input data from the client. */
	if (FD_ISSET(THREAD_LOCAL(connection_in), readset)) {
		len = SocketRead(THREAD_LOCAL(connection_in), buf, sizeof(buf));

		if (len == 0) {
			verbose("Connection closed by %.100s",
			    get_remote_ipaddr());
			THREAD_LOCAL(connection_closed) = 1;
			if (THREAD_LOCAL(compat20))
				return;
			cleanup_exit(255);
		} else if (len < 0) {
			if (h_errno != EINTR && h_errno != EAGAIN) {
				verbose("Read error from remote host "
				    "%.100s: %.100s",
				    get_remote_ipaddr(), strerror(errno));
				cleanup_exit(255);
			}
		} else {
			/* Buffer any received data. */
			packet_process_incoming(buf, len);
		}
	}
	if (THREAD_LOCAL(compat20))
		return;
#ifdef WINCE_PORT
	ASSERT(0);
#else
	/* Read and buffer any available stdout data from the program. */
	if (!fdout_eof && FD_ISSET(fdout, readset)) {
		len = read(fdout, buf, sizeof(buf));
		if (len < 0 && (errno == EINTR || errno == EAGAIN)) {
			/* do nothing */
		} else if (len <= 0) {
			fdout_eof = 1;
		} else {
			buffer_append(&stdout_buffer, buf, len);
			fdout_bytes += len;
		}
	}
	/* Read and buffer any available stderr data from the program. */
	if (!fderr_eof && FD_ISSET(fderr, readset)) {
		len = read(fderr, buf, sizeof(buf));
		if (len < 0 && (errno == EINTR || errno == EAGAIN)) {
			/* do nothing */
		} else if (len <= 0) {
			fderr_eof = 1;
		} else {
			buffer_append(&stderr_buffer, buf, len);
		}
	}
#endif
}

/*
 * Sends data from internal buffers to client program stdin.
 */
static void
process_output(fd_set * writeset)
{
#ifndef WINCE_PORT
	struct termios tio;
	u_char *data;
	u_int dlen;
	int len;

	/* Write buffered data to program stdin. */
	if (!THREAD_LOCAL(compat20) && fdin != -1 && FD_ISSET(fdin, writeset)) {
		data = buffer_ptr(&THREAD_LOCAL(stdin_buffer));
		dlen = buffer_len(&THREAD_LOCAL(stdin_buffer));
		len = write(fdin, data, dlen);
		if (len < 0 && (errno == EINTR || errno == EAGAIN)) {
			/* do nothing */
		} else if (len <= 0) {
			if (fdin != fdout)
				close(fdin);
			else
				shutdown(fdin, SHUT_WR); /* We will no longer send. */
			fdin = -1;
		} else {
			/* Successful write. */
			if (fdin_is_tty && dlen >= 1 && data[0] != '\r' &&
			    tcgetattr(fdin, &tio) == 0 &&
			    !(tio.c_lflag & ECHO) && (tio.c_lflag & ICANON)) {
				/*
				 * Simulate echo to reduce the impact of
				 * traffic analysis
				 */
				packet_send_ignore(len);
				packet_send();
			}
			/* Consume the data from the buffer. */
			buffer_consume(&THREAD_LOCAL(stdin_buffer), len);
			/* Update the count of bytes written to the program. */
			stdin_bytes += len;
		}
	}
#endif
	/* Send any buffered packet data to the client. */
	if (FD_ISSET(THREAD_LOCAL(connection_out), writeset))
		packet_write_poll();
}


static void
process_buffered_input_packets()
{
	dispatch_run(DISPATCH_NONBLOCK, NULL, THREAD_LOCAL(compat20) ? THREAD_LOCAL(xxx_kex) : NULL);
}
static void
collect_children(void)
{
#ifdef WINCE_PORT
//	RETAILMSG(1,(TEXT("Collecting children.. Should do something here ?\r\n")));
	session_close_all_terminated_process();
#else
	
	pid_t pid;
	sigset_t oset, nset;
	int status;

	/* block SIGCHLD while we check for dead children */

	sigemptyset(&nset);
	sigaddset(&nset, SIGCHLD);
	sigprocmask(SIG_BLOCK, &nset, &oset);

	if (THREAD_LOCAL(child_terminated)) {
		while ((pid = waitpid(-1, &status, WNOHANG)) > 0 ||
		    (pid < 0 && errno == EINTR))
			if (pid > 0)
				session_close_by_pid(pid, status);
		THREAD_LOCAL(child_terminated) = 0;
	}
	sigprocmask(SIG_SETMASK, &oset, NULL);
#endif
}

void
server_loop2(Authctxt *authctxt)
{
	fd_set *readset = NULL, *writeset = NULL;
	int rekeying = 0, max_fd, nalloc = 0;

	debug("Entering interactive session for SSH2.");

#ifndef WINCE_PORT
	mysignal(SIGCHLD, sigchld_handler);
#endif
	THREAD_LOCAL(child_terminated) = 0;
	THREAD_LOCAL(connection_in) = packet_get_connection_in();
	THREAD_LOCAL(connection_out) = packet_get_connection_out();

#ifndef WINCE_PORT
	if (!use_privsep) {
		signal(SIGTERM, sigterm_handler);
		signal(SIGINT, sigterm_handler);
		signal(SIGQUIT, sigterm_handler);
	}
#endif

	//JJH notify_setup();

	server_init_dispatch();

	for (;;) {
		process_buffered_input_packets();

		rekeying = (THREAD_LOCAL(xxx_kex) != NULL && !THREAD_LOCAL(xxx_kex)->done);

		if (!rekeying && packet_not_very_much_data_to_write())
			channel_output_poll();
		wait_until_can_do_something(&readset, &writeset, &max_fd,
		    &nalloc, 1000);

#ifdef WINCE_PORT

#else
		if (received_sigterm) {
			logit("Exiting on signal %d", received_sigterm);
			/* Clean up sessions, utmp, etc. */
			cleanup_exit(255);
		}
#endif

		collect_children();
		if (!rekeying) {
			channel_after_select(readset, writeset);
			if (packet_need_rekeying()) {
				debug("need rekeying");
				THREAD_LOCAL(xxx_kex)->done = 0;
				kex_send_kexinit(THREAD_LOCAL(xxx_kex));
			}
		}
		process_input(readset);
		if (THREAD_LOCAL(connection_closed))
			break;
		process_output(writeset);
	}
	collect_children();

	if (readset)
		xfree(readset);
	if (writeset)
		xfree(writeset);

	/* free all channels, no more reads and writes */
	channel_free_all();

}

static void
server_input_keep_alive(int type, u_int32_t seq, void *ctxt)
{
	debug("Got %d/%u for keepalive", type, seq);
	/*
	 * reset timeout, since we got a sane answer from the client.
	 * even if this was generated by something other than
	 * the bogus CHANNEL_REQUEST we send for keepalives.
	 */
	THREAD_LOCAL(client_alive_timeouts) = 0;
}


static Channel *
server_request_direct_tcpip(void)
{
	Channel *c;
	int sock;
	char *target, *originator;
	int target_port, originator_port;

	target = packet_get_string(NULL);
	target_port = packet_get_int();
	originator = packet_get_string(NULL);
	originator_port = packet_get_int();
	packet_check_eom();

	debug("server_request_direct_tcpip: originator %s port %d, target %s port %d",
	    originator, originator_port, target, target_port);

	/* XXX check permission */
	sock = channel_connect_to(target, target_port);
	xfree(target);
	xfree(originator);
	if (sock < 0)
		return NULL;
	c = channel_new("direct-tcpip", SSH_CHANNEL_CONNECTING,
	    sock, sock, -1, CHAN_TCP_WINDOW_DEFAULT,
	    CHAN_TCP_PACKET_DEFAULT, 0, "direct-tcpip", 1);
	return c;
}

static Channel *
server_request_tun(void)
{
	Channel *c = NULL;
	int mode, tun;
	int sock;

	mode = packet_get_int();
	switch (mode) {
	case SSH_TUNMODE_POINTOPOINT:
	case SSH_TUNMODE_ETHERNET:
		break;
	default:
		packet_send_debug("Unsupported tunnel device mode.");
		return NULL;
	}
	if ((options.permit_tun & mode) == 0) {
		packet_send_debug("Server has rejected tunnel device "
		    "forwarding");
		return NULL;
	}

	tun = packet_get_int();
	if (THREAD_LOCAL(forced_tun_device) != -1) {
	 	if (tun != SSH_TUNID_ANY && THREAD_LOCAL(forced_tun_device) != tun)
			goto done;
		tun = THREAD_LOCAL(forced_tun_device);
	}
	sock = tun_open(tun, mode);
	if (sock < 0)
		goto done;
	c = channel_new("tun", SSH_CHANNEL_OPEN, sock, sock, -1,
	    CHAN_TCP_WINDOW_DEFAULT, CHAN_TCP_PACKET_DEFAULT, 0, "tun", 1);
	c->datagram = 1;
#if defined(SSH_TUN_FILTER)
	if (mode == SSH_TUNMODE_POINTOPOINT)
		channel_register_filter(c->self, sys_tun_infilter,
		    sys_tun_outfilter);
#endif

 done:
	if (c == NULL)
		packet_send_debug("Failed to open the tunnel device.");
	return c;
}

static Channel *
server_request_session(void)
{
	Channel *c;

	debug("input_session_request");
	packet_check_eom();
	/*
	 * A server session has no fd to read or write until a
	 * CHANNEL_REQUEST for a shell is made, so we set the type to
	 * SSH_CHANNEL_LARVAL.  Additionally, a callback for handling all
	 * CHANNEL_REQUEST messages is registered.
	 */
	c = channel_new("session", SSH_CHANNEL_LARVAL,
	    -1, -1, -1, /*window size*/0, CHAN_SES_PACKET_DEFAULT,
	    0, "server-session", 1);
	if (session_open(THREAD_LOCAL(the_authctxt), c->self) != 1) {
		debug("session open failed, free channel %d", c->self);
		channel_free(c);
		return NULL;
	}
	channel_register_cleanup(c->self, session_close_by_channel, 0);
	return c;
}

static void
server_input_channel_open(int type, u_int32_t seq, void *ctxt)
{
	Channel *c = NULL;
	char *ctype;
	int rchan;
	u_int rmaxpack, rwindow, len;

	ctype = packet_get_string(&len);
	rchan = packet_get_int();
	rwindow = packet_get_int();
	rmaxpack = packet_get_int();

	debug("server_input_channel_open: ctype %s rchan %d win %d max %d",
	    ctype, rchan, rwindow, rmaxpack);

	if (strcmp(ctype, "session") == 0) {
		c = server_request_session();
	} else if (strcmp(ctype, "direct-tcpip") == 0) {
		c = server_request_direct_tcpip();
	} else if (strcmp(ctype, "tun@openssh.com") == 0) {
		c = server_request_tun();
	}
	if (c != NULL) {
		debug("server_input_channel_open: confirm %s", ctype);
		c->remote_id = rchan;
		c->remote_window = rwindow;
		c->remote_maxpacket = rmaxpack;
		if (c->type != SSH_CHANNEL_CONNECTING) {
			packet_start(SSH2_MSG_CHANNEL_OPEN_CONFIRMATION);
			packet_put_int(c->remote_id);
			packet_put_int(c->self);
			packet_put_int(c->local_window);
			packet_put_int(c->local_maxpacket);
			packet_send();
		}
	} else {
		debug("server_input_channel_open: failure %s", ctype);
		packet_start(SSH2_MSG_CHANNEL_OPEN_FAILURE);
		packet_put_int(rchan);
		packet_put_int(SSH2_OPEN_ADMINISTRATIVELY_PROHIBITED);
		if (!(THREAD_LOCAL(datafellows) & SSH_BUG_OPENFAILURE)) {
			packet_put_cstring("open failed");
			packet_put_cstring("");
		}
		packet_send();
	}
	xfree(ctype);
}

static void
server_input_global_request(int type, u_int32_t seq, void *ctxt)
{
	char *rtype;
	int want_reply;
	int success = 0;

	rtype = packet_get_string(NULL);
	want_reply = packet_get_char();
	debug("server_input_global_request: rtype %s want_reply %d", rtype, want_reply);

	/* -R style forwarding */
	if (strcmp(rtype, "tcpip-forward") == 0) {
		struct passwd *pw;
		char *listen_address;
		u_short listen_port;

		pw = THREAD_LOCAL(the_authctxt)->pw;
		if (pw == NULL || !THREAD_LOCAL(the_authctxt)->valid)
			fatal("server_input_global_request: no/invalid user");
		listen_address = packet_get_string(NULL);
		listen_port = (u_short)packet_get_int();
		debug("server_input_global_request: tcpip-forward listen %s port %d",
		    listen_address, listen_port);

		/* check permissions */
		if (!options.allow_tcp_forwarding ||
		    THREAD_LOCAL(no_port_forwarding_flag)
#ifndef NO_IPPORT_RESERVED_CONCEPT
		    || (listen_port < IPPORT_RESERVED && pw->pw_uid != 0)
#endif
		    ) {
			success = 0;
			packet_send_debug("Server has disabled port forwarding.");
		} else {
			/* Start listening on the port */
			success = channel_setup_remote_fwd_listener(
			    listen_address, listen_port, options.gateway_ports);
		}
		xfree(listen_address);
	} else if (strcmp(rtype, "cancel-tcpip-forward") == 0) {
		char *cancel_address;
		u_short cancel_port;

		cancel_address = packet_get_string(NULL);
		cancel_port = (u_short)packet_get_int();
		debug("%s: cancel-tcpip-forward addr %s port %d", __func__,
		    cancel_address, cancel_port);

		success = channel_cancel_rport_listener(cancel_address,
		    cancel_port);
	}
	if (want_reply) {
		packet_start(success ?
		    SSH2_MSG_REQUEST_SUCCESS : SSH2_MSG_REQUEST_FAILURE);
		packet_send();
		packet_write_wait();
	}
	xfree(rtype);
}
static void
server_input_channel_req(int type, u_int32_t seq, void *ctxt)
{
	Channel *c;
	int id, reply, success = 0;
	char *rtype;

	id = packet_get_int();
	rtype = packet_get_string(NULL);
	reply = packet_get_char();

	debug("server_input_channel_req: channel %d request %s reply %d",
	    id, rtype, reply);

	if ((c = channel_lookup(id)) == NULL)
		packet_disconnect("server_input_channel_req: "
		    "unknown channel %d", id);
	if (c->type == SSH_CHANNEL_LARVAL || c->type == SSH_CHANNEL_OPEN)
		success = session_input_channel_req(c, rtype);
	if (reply) {
		packet_start(success ?
		    SSH2_MSG_CHANNEL_SUCCESS : SSH2_MSG_CHANNEL_FAILURE);
		packet_put_int(c->remote_id);
		packet_send();
	}
	xfree(rtype);
}

static void
server_init_dispatch_20(void)
{
	debug("server_init_dispatch_20");
	dispatch_init(&dispatch_protocol_error);
	dispatch_set(SSH2_MSG_CHANNEL_CLOSE, &channel_input_oclose);
	dispatch_set(SSH2_MSG_CHANNEL_DATA, &channel_input_data);
	dispatch_set(SSH2_MSG_CHANNEL_EOF, &channel_input_ieof);
	dispatch_set(SSH2_MSG_CHANNEL_EXTENDED_DATA, &channel_input_extended_data);
	dispatch_set(SSH2_MSG_CHANNEL_OPEN, &server_input_channel_open);
	dispatch_set(SSH2_MSG_CHANNEL_OPEN_CONFIRMATION, &channel_input_open_confirmation);
	dispatch_set(SSH2_MSG_CHANNEL_OPEN_FAILURE, &channel_input_open_failure);
	dispatch_set(SSH2_MSG_CHANNEL_REQUEST, &server_input_channel_req);
	dispatch_set(SSH2_MSG_CHANNEL_WINDOW_ADJUST, &channel_input_window_adjust);
	dispatch_set(SSH2_MSG_GLOBAL_REQUEST, &server_input_global_request);
	/* client_alive */
	dispatch_set(SSH2_MSG_CHANNEL_FAILURE, &server_input_keep_alive);
	dispatch_set(SSH2_MSG_REQUEST_SUCCESS, &server_input_keep_alive);
	dispatch_set(SSH2_MSG_REQUEST_FAILURE, &server_input_keep_alive);
	/* rekeying */
	dispatch_set(SSH2_MSG_KEXINIT, &kex_input_kexinit);
}

static void
server_init_dispatch(void)
{
	if (THREAD_LOCAL(compat20))
		server_init_dispatch_20();
	else 
	{
		ASSERT(0);
	}
#ifdef WINCE_PORT
	#else
	if (compat13)
		server_init_dispatch_13();
	else
		server_init_dispatch_15();
#endif
}
