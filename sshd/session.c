/*
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
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
RCSID("$OpenBSD: session.c,v 1.191 2005/12/24 02:27:41 djm Exp $");

#include "ssh.h"
#include "ssh2.h"
#include "xmalloc.h"
//#include "sshpty.h"
#include "packet.h"
#include "buffer.h"
#include "match.h"
#include "uidswap.h"
#include "compat.h"
#include "channels.h"
#include "bufaux.h"
#include "auth.h"
#include "auth-options.h"
#include "pathnames.h"
#include "log.h"
#include "servconf.h"
//#include "sshlogin.h"
#include "serverloop.h"
#include "canohost.h"
#include "session.h"
#include "kex.h"
//#include "monitor_wrap.h"

#include "io.h"
#include "sockettofile.h"
#include "strings.h"

#include "ThreadLocal.h"


#if defined(KRB5) && defined(USE_AFS)
#include <kafs.h>
#endif

#ifdef GSSAPI
#include "ssh-gss.h"
#endif


/* import */
extern ServerOptions options;


static void
do_authenticated2(Authctxt *authctxt)
{
	server_loop2(authctxt);
}


void
do_authenticated(Authctxt *authctxt)
{
	setproctitle("%s", authctxt->pw->pw_name);

	/* setup the channel layer */
	if (!THREAD_LOCAL(no_port_forwarding_flag) && options.allow_tcp_forwarding)
		channel_permit_all_opens();

	if (THREAD_LOCAL(compat20))
		do_authenticated2(authctxt);
	else
	{
#ifdef WINCE_PORT
		ASSERT(0);
#else
		do_authenticated1(authctxt);
#endif
	}

	do_cleanup(authctxt);
}

void
session_destroy_all(void (*closefunc)(Session *))
{
	int i;
	for (i = 0; i < MAX_SESSIONS; i++) {
		Session *s = &THREAD_LOCAL(sessions)[i];
		if (s->used) {
			if (closefunc != NULL)
				closefunc(s);
			else
				session_close(s);
		}
	}
}

#ifdef WINCE_PORT
//	int do_cleanup_called = 0;
#endif
void
do_cleanup(Authctxt *authctxt)
{
#ifndef WINCE_PORT
	static int do_cleanup_called = 0;
#endif
	debug("do_cleanup");


	/* avoid double cleanup */
	if (THREAD_LOCAL(do_cleanup_called))
		return;
	THREAD_LOCAL(do_cleanup_called) = 1;

	if (authctxt == NULL)
		return;
#ifdef KRB5
	if (options.kerberos_ticket_cleanup &&
	    authctxt->krb5_ctx)
		krb5_cleanup_proc(authctxt);
#endif

#ifdef GSSAPI
	if (THREAD_LOCAL(compat20) && options.gss_cleanup_creds)
		ssh_gssapi_cleanup_creds();
#endif

#ifdef USE_PAM
	if (options.use_pam) {
		sshpam_cleanup();
		sshpam_thread_cleanup();
	}
#endif

	
	
	session_destroy_all(session_pty_cleanup2);
}


/* data */
#define MAX_SESSIONS 10
//Session	sessions[MAX_SESSIONS];


#ifdef WINCE_PORT
//	int session_new_did_init = 0;
#endif

Session *
session_new(void)
{
	int i;
#ifndef WINCE_PORT
	static int session_new_did_init = 0;
#endif

	if (!THREAD_LOCAL(session_new_did_init)) {
		debug("session_new: init");
		for (i = 0; i < MAX_SESSIONS; i++) {
			THREAD_LOCAL(sessions)[i].used = 0;
		}
		THREAD_LOCAL(session_new_did_init) = 1;
	}
	for (i = 0; i < MAX_SESSIONS; i++) {
		Session *s = &THREAD_LOCAL(sessions)[i];
		if (! s->used) {
			memset(s, 0, sizeof(*s));
			s->chanid = -1;
			s->ptyfd = -1;
			s->ttyfd = -1;
			s->used = 1;
			s->self = i;
			s->pid = INVALID_HANDLE_VALUE;
#ifndef WINCE_PORT
			s->x11_chanids = NULL;
#endif
			debug("session_new: session %d", i);
			return s;
		}
	}
	return NULL;
}

int
session_open(Authctxt *authctxt, int chanid)
{
	Session *s = session_new();
	debug("session_open: channel %d", chanid);
	if (s == NULL) {
		error("no more sessions");
		return 0;
	}
	s->authctxt = authctxt;
	s->pw = authctxt->pw;
	if (s->pw == NULL || !authctxt->valid)
		fatal("no user for session %d", s->self);
	debug("session_open: session %d: link with channel %d", s->self, chanid);
	s->chanid = chanid;
	return 1;
}


static void
session_dump(void)
{
	int i;
	for (i = 0; i < MAX_SESSIONS; i++) {
		Session *s = &THREAD_LOCAL(sessions)[i];
		debug("dump: used %d session %d %p channel %d pid %ld",
		    s->used,
		    s->self,
		    s,
		    s->chanid,
		    (long)s->pid);
	}
}

static Session *
session_by_channel(int id)
{
	int i;
	for (i = 0; i < MAX_SESSIONS; i++) {
		Session *s = &THREAD_LOCAL(sessions)[i];
		if (s->used && s->chanid == id) {
			debug("session_by_channel: session %d channel %d", i, id);
			return s;
		}
	}
	debug("session_by_channel: unknown channel %d", id);
	session_dump();
	return NULL;
}


/*
 * this is called when a channel dies before
 * the session 'child' itself dies
 */
void
session_close_by_channel(int id, void *arg)
{
	Session *s = session_by_channel(id);
	

	if (s == NULL) {
		debug("session_close_by_channel: no session for id %d", id);
		return;
	}
	debug("session_close_by_channel: channel %d child %ld",
	    id, (long)s->pid);
#ifdef WINCE_PORT
	if (s->pid != INVALID_HANDLE_VALUE) {
#else
	if (s->pid != 0) {
#endif
		debug("session_close_by_channel: channel %d: has child", id);
		/*
		 * delay detach of session, but release pty, since
		 * the fd's to the child are already closed
		 */
		//JJH if (s->ttyfd != -1)
		// JJH session_pty_cleanup(s);
		return;
	}
	/* detach by removing callback */
	channel_cancel_cleanup(s->chanid);

#ifndef WINCE_PORT
	/* Close any X11 listeners associated with this session */
	if (s->x11_chanids != NULL) {
		for (i = 0; s->x11_chanids[i] != -1; i++) {
			session_close_x11(s->x11_chanids[i]);
			s->x11_chanids[i] = -1;
		}
	}
#endif
	s->chanid = -1;
	session_close(s);
}

void
session_close(Session *s)
{
	u_int i;

	debug("session_close: session %d pid %ld", s->self, (long)s->pid);
	//JJH if (s->ttyfd != -1)
	// JJH session_pty_cleanup(s);
	if (s->term)
		xfree(s->term);
#ifndef WINCE_PORT
	if (s->display)
		xfree(s->display);
	if (s->x11_chanids)
		xfree(s->x11_chanids);
	if (s->auth_display)
		xfree(s->auth_display);
	if (s->auth_data)
		xfree(s->auth_data);
	if (s->auth_proto)
		xfree(s->auth_proto);
#endif
	s->used = 0;
	for (i = 0; i < s->num_env; i++) {
		xfree(s->env[i].name);
		xfree(s->env[i].val);
	}
	if (s->env != NULL)
		xfree(s->env);
	//JJH session_proctitle(s);
}




static int
session_x11_req(Session *s)
{
#ifdef WINCE_PORT
	return 0;
#else
	int success;

	if (s->auth_proto != NULL || s->auth_data != NULL) {
		error("session_x11_req: session %d: "
		    "x11 forwarding already active", s->self);
		return 0;
	}
	s->single_connection = packet_get_char();
	s->auth_proto = packet_get_string(NULL);
	s->auth_data = packet_get_string(NULL);
	s->screen = packet_get_int();
	packet_check_eom();

	success = session_setup_x11fwd(s);	

	if (!success) {
		xfree(s->auth_proto);
		xfree(s->auth_data);
		s->auth_proto = NULL;
		s->auth_data = NULL;
	}
	return success;
#endif
}


static int
session_window_change_req(Session *s)
{
	s->col = packet_get_int();
	s->row = packet_get_int();
	s->xpixel = packet_get_int();
	s->ypixel = packet_get_int();
	packet_check_eom();
	//JJH pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);
	return 1;
}



static int
session_env_req(Session *s)
{
	char *name, *val;
	u_int name_len, val_len, i;

	name = packet_get_string(&name_len);
	val = packet_get_string(&val_len);
	packet_check_eom();

	/* Don't set too many environment variables */
	if (s->num_env > 128) {
		debug2("Ignoring env request %s: too many env vars", name);
		goto fail;
	}

	for (i = 0; i < options.num_accept_env; i++) {
		if (match_pattern(name, options.accept_env[i])) {
			debug2("Setting env %d: %s=%s", s->num_env, name, val);
			s->env = xrealloc(s->env, sizeof(*s->env) *
			    (s->num_env + 1));
			s->env[s->num_env].name = name;
			s->env[s->num_env].val = val;
			s->num_env++;
			return (1);
		}
	}
	debug2("Ignoring env request %s: disallowed name", name);

 fail:
	xfree(name);
	xfree(val);
	return (0);
}

static int
session_break_req(Session *s)
{

	packet_get_int();	/* ignored */
	packet_check_eom();

#ifdef WINCE_PORT
	return 0;
#else
	if (s->ttyfd == -1 ||
	    tcsendbreak(s->ttyfd, 0) < 0)
		return 0;
	return 1;
#endif
}



void
session_set_fds(Session *s, int fdin, int fdout, int fderr)
{
	if (!THREAD_LOCAL(compat20))
		fatal("session_set_fds: called for proto != 2.0");
	/*
	 * now that have a child and a pipe to the child,
	 * we can activate our channel and register the fd's
	 */
	if (s->chanid == -1)
		fatal("no channel for session %d", s->self);
	channel_set_fds(s->chanid,
	    fdout, fdin, fderr,
	    fderr == -1 ? CHAN_EXTENDED_IGNORE : CHAN_EXTENDED_READ,
	    1,
	    CHAN_SES_WINDOW_DEFAULT);
}

static void
display_loginmsg(Buffer* buf)
{
	if (buffer_len(THREAD_LOCAL(the_authctxt->loginmsg)) > 0) {
		buffer_append(THREAD_LOCAL(the_authctxt->loginmsg), "\0", 1);		
		buffer_append(buf, buffer_ptr(THREAD_LOCAL(the_authctxt->loginmsg)), buffer_len(THREAD_LOCAL(the_authctxt->loginmsg)));
		buffer_clear(THREAD_LOCAL(the_authctxt->loginmsg));
	}
	
	
}

WCHAR* SplitModuleNameAndComdLine(WCHAR** pdest,WCHAR* src)
{
	WCHAR* result;
	WCHAR c;
	WCHAR tag;

	//the command can be :
	// 1) progname.exe param1 param2
	// 2) @prog name.exe@ param1 param2

	if (*src == L'@') 
	{
		tag = L'@';
		result = src + 1;
		src++;
	}
	else
	{
		tag = L' ';
		result = src;
	}

	c = *src;
	while (c != tag && c != 0)
	{		
		src++;
		c = *src;
	} 	
	*src = 0;
	if (c == 0)
	{
		*pdest = src;
	}
	else
	{
		*pdest = src + 1;
	}


	return result;
}

/*
 * This is called to fork and execute a command when we have no tty.  This
 * will call do_child from the child, and server_loop from the parent after
 * setting up file descriptors and such.
 */
BOOL
do_wince_exec(Session *s, const char *command, BOOL bUseTTY)
{
	int i;
	WCHAR* wsKey;
    SOCKET ListenningSock;
	SOCKET CommSock;
	struct sockaddr_in ServerAddr;
	PROCESS_INFORMATION processInfo;
	WCHAR wzCommand[MAX_PATH];
	WCHAR* wzModulename;
	WCHAR* wzCmdLine;
	BOOL bResult = TRUE;

	
	WCHAR wzDeviceName[6];	
	BOOL bRet;
	DWORD dwLen;
	TCHAR szStdin[MAX_PATH], szStdout[MAX_PATH], szStderr[MAX_PATH];
	int val;
	u_long enabled = 1;
	HANDLE h;
	//JJH todo store the handle so that we can deactivate the Device when no more needed
	
	asciiToUnicode(command,wzCommand);

	wzModulename = SplitModuleNameAndComdLine(&wzCmdLine,wzCommand);
	
	i = FindFreeInstanceIndex();
		
	CreateListeningSocket(&ListenningSock,&ServerAddr);
	
	PrepareRegistryForInstance(i,ServerAddr.sin_port,&wsKey, bUseTTY);
	
	h = ActivateDevice(wsKey,0);
	s->hSocketToFile = h;

	RegDeleteKey(HKEY_LOCAL_MACHINE,wsKey);
	free(wsKey);
	
	val = sizeof(ServerAddr);
    CommSock = accept(ListenningSock, (struct sockaddr *) &ServerAddr, &val);
    if (CommSock == INVALID_SOCKET) 
	{
		RETAILMSG(1,(TEXT("accept() failed.\r\n")));
	}		
    closesocket(ListenningSock);
		
	ioctlsocket(CommSock,FIONBIO,&enabled);
	
	dwLen=MAX_PATH; bRet=GetStdioPathW(0, szStdin, &dwLen);
	dwLen=MAX_PATH; bRet=GetStdioPathW(1, szStdout, &dwLen);
	dwLen=MAX_PATH; bRet=GetStdioPathW(2, szStderr, &dwLen);
	
	
	wsprintf(wzDeviceName,L"%s%02d:",NAME_BASE,i);
	
	// set the new ones
	SetStdioPathW(0, wzDeviceName);
	SetStdioPathW(1, wzDeviceName);
	SetStdioPathW(2, wzDeviceName);

	if (bUseTTY)
	{
		display_loginmsg(&(channel_lookup(s->chanid)->input));
	}
	
	bRet = CreateProcess(wzModulename, wzCmdLine, NULL,NULL,FALSE,0,NULL,NULL,NULL,&processInfo);

	if (bRet)
	{
		s->pid = processInfo.hProcess;
	}
	else
	{		
		//Creation failed. Close the socket. Everything else such as deinit of the driver will be taken care of later when we try to read/write  from/to the socket
		closesocket(CommSock);
		//Deactivate the driver
		DeactivateDevice(h);
		bResult = FALSE;
	}

	// restore std paths
	SetStdioPathW(0, szStdin);
	SetStdioPathW(1, szStdout);
	SetStdioPathW(2, szStderr);
	
	
	// Set interactive/non-interactive mode.
	packet_set_interactive(bUseTTY);
	
	session_set_fds(s, CommSock, CommSock,-1);// s->is_subsystem ? -1 : CommSock);

	return bResult;

}



/*
 * This is called to fork and execute a command.  If another command is
 * to be forced, execute that instead.
 */
void
do_exec(Session *s, const char *command)
{
	if (THREAD_LOCAL(forced_command)) {
		//JJH original_command = command;
		command = THREAD_LOCAL(forced_command);
		debug("Forced command '%.900s'", command);
	}

	if (command == NULL)
	{
		command = _PATH_CESHELL;
	}

	if (do_wince_exec(s, command, (s->ttyfd == -1) ? FALSE : TRUE) == FALSE)
	{
		session_close(s);
	}
//JJH 	original_command = NULL;

	/*
	 * Clear loginmsg: it's the child's responsibility to display
	 * it to the user, otherwise multiple sessions may accumulate
	 * multiple copies of the login messages.
	 */
	//JJH buffer_clear(&loginmsg);
}


static int
session_subsystem_req(Session *s)
{
#ifndef WINCE_PORT
	struct stat st;
#endif
	u_int len;
	int success = 0;
	char *cmd, *subsys = packet_get_string(&len);
	u_int i;

	packet_check_eom();
	logit("subsystem request for %.100s", subsys);

	for (i = 0; i < options.num_subsystems; i++) {
		if (strcmp(subsys, options.subsystem_name[i]) == 0) {
			cmd = options.subsystem_command[i];
#ifndef WINCE_PORT
			if (stat(cmd, &st) < 0) {
				error("subsystem: cannot stat %s: %s", cmd,
				    strerror(errno));
				break;
			}
#endif
			debug("subsystem: exec() %s", cmd);
			s->is_subsystem = 1;
			do_exec(s, cmd);
			success = 1;
			break;
		}
	}

	if (!success)
		logit("subsystem request for %.100s failed, subsystem not found",
		    subsys);

	xfree(subsys);
	return success;
}


static int
session_shell_req(Session *s)
{
	packet_check_eom();
	do_exec(s, NULL);
	return 1;
}

static int
session_exec_req(Session *s)
{
	u_int len;
	char *command = packet_get_string(&len);
	packet_check_eom();
	do_exec(s, command);
	xfree(command);
	return 1;
}


static int
session_pty_req(Session *s)
{
	u_int len;
	//JJH int n_bytes;

	if (THREAD_LOCAL(no_pty_flag)) {
		debug("Allocating a pty not permitted for this authentication.");
		return 0;
	}
	if (s->ttyfd != -1) {
		packet_disconnect("Protocol error: you already have a pty.");
		return 0;
	}

	s->term = packet_get_string(&len);

	if (THREAD_LOCAL(compat20)) {
		s->col = packet_get_int();
		s->row = packet_get_int();
	} else {
#ifdef WINCE_PORT
		ASSERT(0);
#else
		s->row = packet_get_int();
		s->col = packet_get_int();
#endif
	}
	s->xpixel = packet_get_int();
	s->ypixel = packet_get_int();

	if (strcmp(s->term, "") == 0) {
		xfree(s->term);
		s->term = NULL;
	}

#ifdef WINCE_PORT
	s->ttyfd = 1;	
	return 1;
#else
	/* Allocate a pty and open it. */
	debug("Allocating pty.");
	if (!PRIVSEP(pty_allocate(&s->ptyfd, &s->ttyfd, s->tty, sizeof(s->tty)))) {
		if (s->term)
			xfree(s->term);
		s->term = NULL;
		s->ptyfd = -1;
		s->ttyfd = -1;
		error("session_pty_req: session %d alloc failed", s->self);
		return 0;
	}
	debug("session_pty_req: session %d alloc %s", s->self, s->tty);

	/* for SSH1 the tty modes length is not given */
	if (!THREAD_LOCAL(compat20))
		n_bytes = packet_remaining();
	tty_parse_modes(s->ttyfd, &n_bytes);

	if (!use_privsep)
		pty_setowner(s->pw, s->tty);

	/* Set window size from the packet. */
	pty_change_window_size(s->ptyfd, s->row, s->col, s->xpixel, s->ypixel);

	packet_check_eom();
	session_proctitle(s);
	return 1;
#endif
	return 0;
}



int
session_input_channel_req(Channel *c, const char *rtype)
{
	int success = 0;
	Session *s;

	if ((s = session_by_channel(c->self)) == NULL) {
		logit("session_input_channel_req: no session %d req %.100s",
		    c->self, rtype);
		return 0;
	}
	debug("session_input_channel_req: session %d req %s", s->self, rtype);

	/*
	 * a session is in LARVAL state until a shell, a command
	 * or a subsystem is executed
	 */
	if (c->type == SSH_CHANNEL_LARVAL) {
		if (strcmp(rtype, "shell") == 0) {
			success = session_shell_req(s);
		} else if (strcmp(rtype, "exec") == 0) {
			success = session_exec_req(s);
		} else if (strcmp(rtype, "pty-req") == 0) {
			success =  session_pty_req(s);
		} else if (strcmp(rtype, "x11-req") == 0) {
			success = session_x11_req(s);
		} else if (strcmp(rtype, "auth-agent-req@openssh.com") == 0) {
			//JJH success = session_auth_agent_req(s);
			success = 0;
		} else if (strcmp(rtype, "subsystem") == 0) {
			success = session_subsystem_req(s);
		} else if (strcmp(rtype, "env") == 0) {
			success = session_env_req(s);
		}
	}
	if (strcmp(rtype, "window-change") == 0) {
		success = session_window_change_req(s);
	} else if (strcmp(rtype, "break") == 0) {
		success = session_break_req(s);
	}

	return success;
}

static void
session_exit_message(Session *s, int status)
{
	Channel *c;

	if ((c = channel_lookup(s->chanid)) == NULL)
		fatal("session_exit_message: session %d: no channel %d",
		    s->self, s->chanid);
	debug("session_exit_message: session %d channel %d pid %ld",
	    s->self, s->chanid, (long)s->pid);

#ifndef WINCE_PORT
	if (WIFEXITED(status)) 
#endif
	{
		channel_request_start(s->chanid, "exit-status", 0);
#ifdef WINCE_PORT
		packet_put_int(status);
#else
		packet_put_int(WEXITSTATUS(status));
#endif
		packet_send();
	}
#ifndef WINCE_PORT
	else if (WIFSIGNALED(status)) {
		channel_request_start(s->chanid, "exit-signal", 0);
		packet_put_cstring(sig2name(WTERMSIG(status)));
#ifdef WCOREDUMP
		packet_put_char(WCOREDUMP(status));
#else /* WCOREDUMP */
		packet_put_char(0);
#endif /* WCOREDUMP */
		packet_put_cstring("");
		packet_put_cstring("");
		packet_send();
	} 
	else 
	{
		/* Some weird exit cause.  Just exit. */
		packet_disconnect("wait returned status %04x.", status);
	}
#endif

	/* disconnect channel */
	debug("session_exit_message: release channel %d", s->chanid);

	/*
	 * Adjust cleanup callback attachment to send close messages when
	 * the channel gets EOF. The session will be then be closed 
	 * by session_close_by_channel when the childs close their fds.
	 */
	channel_register_cleanup(c->self, session_close_by_channel, 1);

	/*
	 * emulate a write failure with 'chan_write_failed', nobody will be
	 * interested in data we write.
	 */
	if (c->ostate != CHAN_OUTPUT_CLOSED)
	{
		chan_write_failed(c);
	}
	if (c->istate != CHAN_INPUT_CLOSED)
	{
		chan_read_failed(c);
	}
	
}

/*
 * Function to perform pty cleanup. Also called if we get aborted abnormally
 * (e.g., due to a dropped connection).
 */
void
session_pty_cleanup2(Session *s)
{
	if (s == NULL) {
		error("session_pty_cleanup: no session");
		return;
	}
	if (s->ttyfd == -1)
		return;

	debug("session_pty_cleanup: session %d release %s", s->self, s->tty);

#ifndef WINCE_PORT
	/* Record that the user has logged out. */
	if (s->pid != 0)
		record_logout(s->pid, s->tty, s->pw->pw_name);
#endif

	/* Release the pseudo-tty. */
	//JJH TODO pty_release(s->tty);

	/*
	 * Close the server side of the socket pairs.  We must do this after
	 * the pty cleanup, so that another process doesn't get this pty
	 * while we're still cleaning up.
	 */
//JJH ????	if (close(s->ptymaster) < 0)
//JJH ????		error("close(s->ptymaster/%d): %s", s->ptymaster, strerror(errno));

	/* unlink pty from session */
	s->ttyfd = -1;
}

void
session_pty_cleanup(Session *s)
{
	session_pty_cleanup2(s);
	DeactivateDevice(s->hSocketToFile);
}

void session_close_all_terminated_process(void)
{		
	int i;

	for (i = 0; i < MAX_SESSIONS; i++) 
	{
		if (THREAD_LOCAL(sessions)[i].used)
		{
			if (THREAD_LOCAL(sessions)[i].pid != INVALID_HANDLE_VALUE)
			{
				DWORD dwExitCode;
				BOOL bResult = GetExitCodeProcess(THREAD_LOCAL(sessions)[i].pid, &dwExitCode);
				
				if (bResult)
				{
					if (dwExitCode != STILL_ACTIVE)
					{
						Session *s = &THREAD_LOCAL(sessions)[i];
						RETAILMSG(1,(TEXT("Process 0x%x terminated\r\n"),THREAD_LOCAL(sessions)[i].pid));
						if (s->chanid != -1)
						{							
 							session_exit_message(s, dwExitCode);
						}						
						if (s->hSocketToFile != INVALID_HANDLE_VALUE)
						{
							session_pty_cleanup(s);
							s->pid = INVALID_HANDLE_VALUE;
						}
					}
				}
			}
		}
	}
}