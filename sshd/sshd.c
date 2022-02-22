/* This file is part of the open SSH port to Windows CE. It's not present in the original open SSH project.
*/

 /*
 * Copyright (c) 2000, 2003 Markus Friedl <markus@openbsd.org>
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


#include <windows.h>
#include "compat_ce.h"
#include "config.h"
#include "includes.h"

#include "sys\types.h"
#include "ssh.h"
#include "ssh2.h"
#include "log.h"

#include "servconf.h"
#include "pathnames.h"
#include "channels.h"
 
#include "openssl\evp.h"
#include "version.h"

#include "authfile.h"

#include "log.h"

#include "compat.h"

#include "packet.h"

#include "canohost.h"

#include "atomicio.h"

#include "misc.h"

#include "Auth.h"

#include "myproposal.h"

#include "dispatch.h"

#include "session.h"

#include <linklist.h>

#include "ThreadLocal.h"


#define CE_BANNER "Welcome to SSH server for CE !\r\nBased on OpenSSH 4.3\r\n"

//#undef SSHD_CHILD_THREAD_STACK_SIZE 
#define SSHD_CHILD_THREAD_STACK_SIZE (640*1024)

typedef struct {
	HANDLE hThread;
	int socket;
	LIST_ENTRY llist;
} T_SSH_CHILD_THREAD_INFO;


/*
 * The sockets that the server is listening
 */
#define	MAX_LISTEN_SOCKS	16
int listen_socks[MAX_LISTEN_SOCKS];
int num_listen_socks = 0;


/* Server configuration options. */
ServerOptions options;

/* Name of the server configuration file. */
static const char *config_file_name;

/*
 * Any really sensitive data in the application is contained in this
 * structure. The idea is that this structure could be locked into memory so
 * that the pages do not get written into swap.  However, there are some
 * problems. The private key contains BIGNUMs, and we do not (in principle)
 * have access to the internals of them, and locking just the structure is
 * not very useful.  Currently, memory locking is not implemented.
 */
struct {
	Key	**host_keys;		/* all private host keys */
	int	have_ssh2_key;
} sensitive_data;





static DWORD HandleConnection(void* pParam);
static void WaitForChildCompletion();
static void CloseAllChildConnections(LIST_ENTRY *pSSHChildList);
static void sshd_exchange_identification(int sock_in, int sock_out);
static void do_ssh2_kex();

// Start listenning for a socket
// in szPort : port number to be attached to
// out fd_set* is filled whith the socket we'll be listening to
// It returns the number of socket we're listenning to.

int StartListenning(ServerOptions *pOptions)
{
	
	int listen_sock;
	struct addrinfo *ai;
	int ret;
	char ntop[NI_MAXHOST], strport[NI_MAXSERV];

	num_listen_socks = 0;

	for (ai = pOptions->listen_addrs; ai; ai = ai->ai_next) 
	{
			if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
			{
				continue;
			}
			if (num_listen_socks >= MAX_LISTEN_SOCKS)
			{
				fatal("Too many listen sockets. "
				    "Enlarge MAX_LISTEN_SOCKS");
			}
			if ((ret = getnameinfo(ai->ai_addr, ai->ai_addrlen,
			    ntop, sizeof(ntop), strport, sizeof(strport),
			    NI_NUMERICHOST|NI_NUMERICSERV)) != 0) {
				error("getnameinfo failed: %.100s",
				    (ret != EAI_SYSTEM) ? __gai_strerror(ret) :
				    strerror(errno));
				continue;
			}
			/* Create socket for listening. */
			listen_sock = socket(ai->ai_family, ai->ai_socktype,
			    ai->ai_protocol);
			if (listen_sock < 0) {
				/* kernel may not support ipv6 */
				verbose("socket: %.100s", strerror(errno));
				continue;
			}
#ifndef WINCE_PORT
			if (set_nonblock(listen_sock) == -1) {
				close(listen_sock);
				continue;
			}

			/*
			 * Set socket options.
			 * Allow local port reuse in TIME_WAIT.
			 */
			if (__setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR,
			    &on, sizeof(on)) == -1)
				error("__setsockopt SO_REUSEADDR: %s", strerror(errno));
#endif
			debug("Bind to port %s on %s.", strport, ntop);

			/* Bind the socket to the desired port. */
			if (bind(listen_sock, ai->ai_addr, ai->ai_addrlen) < 0) {
				if (!ai->ai_next)
				    error("Bind to port %s on %s failed: %.200s.",
					    strport, ntop, strerror(errno));
				SocketClose(listen_sock);
				continue;
			}
			listen_socks[num_listen_socks] = listen_sock;
			num_listen_socks++;

			/* Start listening on the port. */
			logit("Server listening on %s port %s.", ntop, strport);
			if (listen(listen_sock, SSH_LISTEN_BACKLOG) < 0)
				fatal("listen: %.100s", strerror(errno));

		}
		freeaddrinfo(pOptions->listen_addrs);

		if (!num_listen_socks)
		{
			fatal("Cannot bind any address.");
		}

		return num_listen_socks;
}


/* Destroy the host keys.  They will no longer be needed. */
void
destroy_sensitive_data(void)
{
	int i;

	for (i = 0; i < options.num_host_key_files; i++) {
		if (sensitive_data.host_keys[i]) {
			key_free(sensitive_data.host_keys[i]);
			sensitive_data.host_keys[i] = NULL;
		}
	}	
}

CRITICAL_SECTION *g_csLockArray;

void DeleteCriticalSectionsForSSL(void)
{
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i=0; i<CRYPTO_num_locks(); i++)
		DeleteCriticalSection(&g_csLockArray[i]);
	free(g_csLockArray);
}

void WinCE_SSL_locking_callback(int mode, int type, const char *file, int line)
{
	if (mode & CRYPTO_LOCK)
	{
		EnterCriticalSection(&g_csLockArray[type]);
	}
	else
	{
		LeaveCriticalSection(&g_csLockArray[type]);
	}
}
void InitializeCriticalSectionsForSSL(void)
{
	int i;
	
	g_csLockArray=malloc(CRYPTO_num_locks() * sizeof(CRITICAL_SECTION));
	for (i=0; i<CRYPTO_num_locks(); i++)
	{
		InitializeCriticalSection(&g_csLockArray[i]);
	}
	
	CRYPTO_set_locking_callback(WinCE_SSL_locking_callback);
}



#ifdef WINCE_PORT
DWORD g_dwThreadLocalIndex;
T_SSHD_THREAD_LOCAL_VARIABLES* g_SeverLocalStorage;
#endif

void ServerMain(void)
{
	int socket;
	//int compteur;
	int i;
	Buffer cfg;
	Key *key;
	fd_set fdset;
	LIST_ENTRY SSHChildList;
	

	initPathNames();

	config_file_name = _PATH_SERVER_CONFIG_FILE;

	// Initialize "would-be global" variables for the main thread
	g_dwThreadLocalIndex = TlsAlloc();
	g_SeverLocalStorage = AllocateThreadLocalStorage(NULL);
	SET_THREAD_LOCAL(g_SeverLocalStorage);


	InitializeCriticalSectionsForSSL();

	//init the child list
	InitializeListHead(&SSHChildList);

	// Initialize configuration options to their default values.
	initialize_server_options(&options);

	log_init("SSHD", SYSLOG_LEVEL_DEBUG3, LOG_AUTH, TRUE);

	SSLeay_add_all_algorithms();

	// Fetch our configuration
	buffer_init(&cfg);

	load_server_config(config_file_name, &cfg);

	parse_server_config(&options,config_file_name, &cfg);

	buffer_free(&cfg);
	
	//Init Random 
	srand(GetTickCount());

	// Fill in default values for those options not explicitly set.
	fill_default_server_options(&options);

	// set default channel AF
	channel_set_af(options.address_family);

	// Show release number
	debug("sshd version %.100s", SSH_RELEASE);


	// load private host keys
	sensitive_data.host_keys = xmalloc(options.num_host_key_files * sizeof(Key *));

	for (i = 0; i < options.num_host_key_files; i++)
	{
		sensitive_data.host_keys[i] = NULL;
	}

	for (i = 0; i < options.num_host_key_files; i++) 
	{
		key = key_load_private(options.host_key_files[i], "", NULL);
		sensitive_data.host_keys[i] = key;
		if (key == NULL) {
			error("Could not load host key: %s",
			    options.host_key_files[i]);
			sensitive_data.host_keys[i] = NULL;
			continue;
		}
		switch (key->type) {
#ifdef WINCE_PORT
			case KEY_RSA1:
				ASSERT(0);
				break;
#else
		case KEY_RSA1:
			sensitive_data.ssh1_host_key = key;
			sensitive_data.have_ssh1_key = 1;
			break;
#endif
		case KEY_RSA:
		case KEY_DSA:
			sensitive_data.have_ssh2_key = 1;
			break;
		}
		debug("private host key: #%d type %d %s", i, key->type,
		    key_type(key));
	}



	if (!sensitive_data.have_ssh2_key) 
	{
		logit("Disabling protocol version 2. Could not load host key");
		fatal("sshd: since only protocol 2 is supported, this is fatal -- exiting.");
		ASSERT(0);
	}



	// Reinitialize the log
	// while dev kepp a maximum msg log_init("SSHD", options.log_level, options.log_facility, 1);

	// Initialize the random number generator.
	arc4random_stir();


	//Start Listenning for a socket
	StartListenning(&options);

	//for (compteur = 0;compteur < 4 ; compteur ++)
	for (;;)
	{
			
	// Wait for (at least) a connection to happen
	FD_ZERO(&fdset);	
	for (i = 0; i < num_listen_socks; i++)    // want to check all available sockets
	{
		FD_SET(listen_socks[i], &fdset);
	}

	if (select(num_listen_socks, &fdset, 0, 0, NULL) == SOCKET_ERROR)
	{
		debug2("ERROR: select() failed with error = %d\r\n", WSAGetLastError());
		ASSERT(0);
	}
	
	// Go through the set of listenning socket
	for (i = 0; i < num_listen_socks; i++) 
	{
		BOOL bError = FALSE;
		T_SSH_CHILD_THREAD_INFO *pThreadInfo;		
		int fromlen;
		SOCKADDR_STORAGE from;
		if (!FD_ISSET(listen_socks[i], &fdset))
		{
			 // No connection atempted, check the next ...
			continue;
		}
		
		pThreadInfo = malloc(sizeof(T_SSH_CHILD_THREAD_INFO));
		if (pThreadInfo == NULL)
		{
			fatal("ERROR : unable to allocate memory for child thread information\r\n");
			ASSERT(0);
		}
		memset(pThreadInfo,0,sizeof(T_SSH_CHILD_THREAD_INFO));
		
		
		

		//A connection was initiated, accept it.
		fromlen = sizeof(from);
		socket = accept(listen_socks[i], (struct sockaddr *)&from,&fromlen);
		if(socket == INVALID_SOCKET) 
		{
			debug2("ERROR: accept() failed with error = %d\r\n", WSAGetLastError());
			bError = TRUE;
		}
		else
		{
			HANDLE hThread;
			
			logit("Accepted TCP connection from socket 0x%08x\r\n", socket);

			// Create a separate thread that will handle the connection 
			// The thread is responsible to close its socket 
			
			hThread = CreateThread(NULL,
#ifdef SSHD_CHILD_THREAD_STACK_SIZE		
				SSHD_CHILD_THREAD_STACK_SIZE,
#else
				0,
#endif
				HandleConnection,			
				(PVOID) socket,
#ifdef SSHD_CHILD_THREAD_STACK_SIZE		
				STACK_SIZE_PARAM_IS_A_RESERVATION,
#else
				0,
#endif
				NULL
				);

			if (hThread)
			{
				pThreadInfo->hThread = hThread;
				pThreadInfo->socket = socket;
				InsertHeadList(&SSHChildList,&pThreadInfo->llist);
			}
			else
			{
				bError = TRUE;
			}
		}

		if (bError)
		{
			if (socket != INVALID_SOCKET)
			{
				shutdown(socket, SD_BOTH);
				SocketClose(socket);
			}
			free(pThreadInfo);
		}
		
	}
	}

	for(i = 0; i < num_listen_socks ; i++)
	{
		SocketClose(listen_socks[i]);
	}
	
	
	// wait for all child thread to terminate
	WaitForChildCompletion(&SSHChildList);

    

	destroy_sensitive_data();

	ReleaseThreadLocalStorage(g_SeverLocalStorage);

	TlsFree(g_dwThreadLocalIndex);

	DeleteCriticalSectionsForSSL();
}

static void WaitForChildCompletion(LIST_ENTRY *pSSHChildList)
{

	int nbThreads;
	PLIST_ENTRY     pEntry;
	T_SSH_CHILD_THREAD_INFO *pThreadInfo;
	
	if (pSSHChildList == NULL)
	{
		return;
	}


	do	
	{
		pEntry = pSSHChildList->Flink;	
		nbThreads = 0;
        Sleep(1000);
		while ( pEntry != pSSHChildList) 
		{			
			DWORD dwExitCode;
			nbThreads++;
            pThreadInfo = CONTAINING_RECORD( pEntry, T_SSH_CHILD_THREAD_INFO, llist);
            pEntry = pEntry->Flink;  // advance to next 
			if (GetExitCodeThread(pThreadInfo->hThread,&dwExitCode))
			{
				if (dwExitCode != STILL_ACTIVE)
				{
					// Remove the entry from the linked list
					RemoveEntryList(&pThreadInfo->llist);
					CloseHandle(pThreadInfo->hThread);
					free(pThreadInfo);
				}
			}
        }
		
		RETAILMSG(1,(TEXT("WaitForChildCompletion %d thread(s) running\r\n"),nbThreads));
	}while (nbThreads);
	RETAILMSG(1,(TEXT("WaitForChildCompletion complete\r\n")));
}


static void CloseAllChildConnections(LIST_ENTRY *pSSHChildList)
{	
	PLIST_ENTRY     pEntry;
	T_SSH_CHILD_THREAD_INFO *pThreadInfo;
	
	if (pSSHChildList == NULL)
	{
		return;
	}


	pEntry = pSSHChildList->Flink;	
       
	while ( pEntry != pSSHChildList) 
	{			
		pThreadInfo = CONTAINING_RECORD( pEntry, T_SSH_CHILD_THREAD_INFO, llist);
		shutdown(pThreadInfo->socket, SD_BOTH);
		SocketClose(pThreadInfo->socket);
		pEntry = pEntry->Flink;  // advance to next 			
    }
	
	RETAILMSG(1,(TEXT("CloseAllChildConnections complete\r\n")));
}

T_SSHD_THREAD_LOCAL_VARIABLES* g_pThreadLocal;

DWORD HandleConnection(void* pParam)
{	
	int sock = (int) pParam;
	Authctxt *authctxt;	
	// message to be displayed after login
	Buffer loginmsg;	
	int sock_in;
	int sock_out;
	int on=1;
	
	int remote_port;
	const char *remote_ip;
	
	T_SSHD_THREAD_LOCAL_VARIABLES* pThreadLocal;
	g_pThreadLocal = pThreadLocal = AllocateThreadLocalStorage(g_SeverLocalStorage);
	SET_THREAD_LOCAL(pThreadLocal);
			

	sock_out = sock_in = sock;

	// Register our connection.  This turns encryption off because we do not have a key.
	
	packet_set_connection(sock_in, sock_out);
	packet_set_server();


	// Set SO_KEEPALIVE if requested.
	if (options.tcp_keep_alive && packet_connection_is_on_socket() &&
	    __setsockopt(sock_in, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0)
		error("__setsockopt SO_KEEPALIVE: %.100s", strerror(errno));

	//Get the remote port
	if ((remote_port = get_remote_port()) < 0) {
		debug("get_remote_port failed");
		cleanup_exit(255);
	}

	remote_ip = get_canonical_hostname(0);


	// Log the connection.
	verbose("Connection from %.500s port %d", remote_ip, remote_port);

	//Here we should setup a timer so that we don't wait for authentification indefinitely
	// JJH TODO

	sshd_exchange_identification(sock_in, sock_out);

	packet_set_nonblocking();



	// allocate authentication context
	THREAD_LOCAL(the_authctxt) = authctxt = xmalloc(sizeof(*authctxt));
	memset(authctxt, 0, sizeof(*authctxt));

	authctxt->loginmsg = &loginmsg;

	
	// prepare buffer to collect messages to display to user after login
	buffer_init(&loginmsg);
	buffer_append(&loginmsg,CE_BANNER,strlen(CE_BANNER));

	// perform the key exchange
	// authenticate user and start session 
	if (THREAD_LOCAL(compat20)) {
		do_ssh2_kex();
		do_authentication2(authctxt);
	} else {
		ASSERT(0);
	}



	// Start session.
	do_authenticated(authctxt);

	

	// The connection has been terminated.
	verbose("Closing connection to %.100s", remote_ip);


#ifdef USE_PAM
	if (options.use_pam)
		finish_pam();
#endif /* USE_PAM */

	cleanup_exit(0);
	return 0;
}

static void sshd_exchange_identification(int sock_in, int sock_out)
{
	u_int i;	
	BOOL bSuccess = FALSE;
	int remote_major, remote_minor;
	int major, minor;
	char *s;
	char buf[256];			/* Must not be larger than remote_version. */
	char remote_version[256];	/* Must be at least as big as buf. */
	

	major = PROTOCOL_MAJOR_2;
	minor = PROTOCOL_MINOR_2;
	
	snprintf(buf, sizeof buf, "SSH-%d.%d-%.100s\n", major, minor, SSH_VERSION);
	if (THREAD_LOCAL(server_version_string) == NULL)
	{
		THREAD_LOCAL(server_version_string) = xstrdup(buf);
	}

	/* Send our protocol version identification. */
	if (atomicio(SocketWrite, sock_out, THREAD_LOCAL(server_version_string),
	    strlen(THREAD_LOCAL(server_version_string)))
	    != strlen(THREAD_LOCAL(server_version_string))) {
		logit("Could not write ident string to %s", get_remote_ipaddr());
		cleanup_exit(255);
	}

	/* Read other sides version identification. */
	memset(buf, 0, sizeof(buf));
	for (i = 0; i < sizeof(buf) - 1; i++) {
		if (atomicio(SocketRead, sock_in, &buf[i], 1) != 1) {
			logit("Did not receive identification string from %s",
			    get_remote_ipaddr());
			cleanup_exit(255);
		}
		if (buf[i] == '\r') {
			buf[i] = 0;
			/* Kludge for F-Secure Macintosh < 1.0.2 */
			if (i == 12 &&
			    strncmp(buf, "SSH-1.5-W1.0", 12) == 0)
				break;
			continue;
		}
		if (buf[i] == '\n') {
			buf[i] = 0;
			break;
		}
	}
	buf[sizeof(buf) - 1] = 0;
	THREAD_LOCAL(client_version_string) = xstrdup(buf);

	/*
	 * Check that the versions match.  In future this might accept
	 * several versions and set appropriate flags to handle them.
	 */
	if (sscanf(THREAD_LOCAL(client_version_string), "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		s = "Protocol mismatch.\n";
		(void) atomicio(SocketWrite, sock_out, s, strlen(s));
		SocketClose(sock_in);
		SocketClose(sock_out);
		logit("Bad protocol version identification '%.100s' from %s",
		    THREAD_LOCAL(client_version_string), get_remote_ipaddr());
		cleanup_exit(255);
	}
	debug("Client protocol version %d.%d; client software version %.100s",
	    remote_major, remote_minor, remote_version);

	compat_datafellows(remote_version);

	if (THREAD_LOCAL(datafellows) & SSH_BUG_PROBE) {
		logit("probed from %s with %s.  Don't panic.",
		    get_remote_ipaddr(), THREAD_LOCAL(client_version_string));
		cleanup_exit(255);
	}

	if (THREAD_LOCAL(datafellows) & SSH_BUG_SCANNER) {
		logit("scanned from %s with %s.  Don't panic.",
		    get_remote_ipaddr(), THREAD_LOCAL(client_version_string));
		cleanup_exit(255);
	}
	
	switch (remote_major) {
	case 1:
		if (remote_minor == 99) {
			if (options.protocol & SSH_PROTO_2)
			{
				enable_compat20();				
				bSuccess = TRUE;
			}
			break;
		}		
		packet_disconnect("Your ssh version is too old and is no longer supported.  Please install a newer version.");
		break;
	case 2:
		if (options.protocol & SSH_PROTO_2) {
			enable_compat20();	
			bSuccess = TRUE;
			break;
		}
		/* FALLTHROUGH */
	default:		
		break;
	}
	chop(THREAD_LOCAL(server_version_string));
	debug("Local version string %.200s", THREAD_LOCAL(server_version_string));

	if (bSuccess == FALSE) {
		s = "Protocol major versions differ.\n";
		(void) atomicio(SocketWrite, sock_out, s, strlen(s));
		SocketClose(sock_in);
		SocketClose(sock_out);
		logit("Protocol major versions differ for %s: %.200s vs. %.200s",
		    get_remote_ipaddr(),
		    THREAD_LOCAL(server_version_string), THREAD_LOCAL(client_version_string));
		cleanup_exit(255);
	}


}

static char *
list_hostkey_types(void)
{
	Buffer b;
	const char *p;
	char *ret;
	int i;

	buffer_init(&b);
	for (i = 0; i < options.num_host_key_files; i++) {
		Key *key = sensitive_data.host_keys[i];
		if (key == NULL)
			continue;
		switch (key->type) {
		case KEY_RSA:
		case KEY_DSA:
			if (buffer_len(&b) > 0)
				buffer_append(&b, ",", 1);
			p = key_ssh_name(key);
			buffer_append(&b, p, strlen(p));
			break;
		}
	}
	buffer_append(&b, "\0", 1);
	ret = xstrdup(buffer_ptr(&b));
	buffer_free(&b);
	debug("list_hostkey_types: %s", ret);
	return ret;
}

Key *
get_hostkey_by_type(int type)
{
	int i;

	for (i = 0; i < options.num_host_key_files; i++) {
		Key *key = sensitive_data.host_keys[i];
		if (key != NULL && key->type == type)
			return key;
	}
	return NULL;
}

Key *
get_hostkey_by_index(int ind)
{
	if (ind < 0 || ind >= options.num_host_key_files)
		return (NULL);
	return (sensitive_data.host_keys[ind]);
}

int
get_hostkey_index(Key *key)
{
	int i;

	for (i = 0; i < options.num_host_key_files; i++) {
		if (key == sensitive_data.host_keys[i])
			return (i);
	}
	return (-1);
}


// SSH2 key exchange: diffie-hellman-group1-sha1
 
static void do_ssh2_kex()
{
	Kex *kex;
	
	char *myproposal[PROPOSAL_MAX] = {
		KEX_DEFAULT_KEX,
		KEX_DEFAULT_PK_ALG,
		KEX_DEFAULT_ENCRYPT,
		KEX_DEFAULT_ENCRYPT,
		KEX_DEFAULT_MAC,
		KEX_DEFAULT_MAC,
		KEX_DEFAULT_COMP,
		KEX_DEFAULT_COMP,
		KEX_DEFAULT_LANG,
		KEX_DEFAULT_LANG
	};


	if (options.ciphers != NULL) {
		myproposal[PROPOSAL_ENC_ALGS_CTOS] =
		myproposal[PROPOSAL_ENC_ALGS_STOC] = options.ciphers;
	}
	myproposal[PROPOSAL_ENC_ALGS_CTOS] =
	    compat_cipher_proposal(myproposal[PROPOSAL_ENC_ALGS_CTOS]);
	myproposal[PROPOSAL_ENC_ALGS_STOC] =
	    compat_cipher_proposal(myproposal[PROPOSAL_ENC_ALGS_STOC]);

	if (options.macs != NULL) {
		myproposal[PROPOSAL_MAC_ALGS_CTOS] =
		myproposal[PROPOSAL_MAC_ALGS_STOC] = options.macs;
	}
	if (options.compression == COMP_NONE) {
		myproposal[PROPOSAL_COMP_ALGS_CTOS] =
		myproposal[PROPOSAL_COMP_ALGS_STOC] = "none";
	} else if (options.compression == COMP_DELAYED) {
		myproposal[PROPOSAL_COMP_ALGS_CTOS] =
		myproposal[PROPOSAL_COMP_ALGS_STOC] = "none,zlib@openssh.com";
	}
	
	myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] = list_hostkey_types();
	if (myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS] == NULL)
	{
		volatile DWORD i=0;
		i++;
	}

	/* start key exchange */
	kex = kex_setup(myproposal);
	kex->kex[KEX_DH_GRP1_SHA1] = kexdh_server;
	kex->kex[KEX_DH_GRP14_SHA1] = kexdh_server;
	kex->kex[KEX_DH_GEX_SHA1] = kexgex_server;
	kex->server = 1;
	kex->client_version_string=THREAD_LOCAL(client_version_string);
	kex->server_version_string=THREAD_LOCAL(server_version_string);
	kex->load_host_key=&get_hostkey_by_type;
	kex->host_key_index=&get_hostkey_index;

	THREAD_LOCAL(xxx_kex) = kex;

	dispatch_run(DISPATCH_BLOCK, &kex->done, kex);

	THREAD_LOCAL(session_id2) = kex->session_id;
	THREAD_LOCAL(session_id2_len) = kex->session_id_len;

#ifdef DEBUG_KEXDH
	/* send 1st encrypted/maced/compressed message */
	packet_start(SSH2_MSG_IGNORE);
	packet_put_cstring("markus");
	packet_send();
	packet_write_wait();
#endif

	//JJH added cleanup
	xfree(myproposal[PROPOSAL_SERVER_HOST_KEY_ALGS]);

	debug("KEX done");
}


void setproctitle(const char *fmt, ...)
{
}