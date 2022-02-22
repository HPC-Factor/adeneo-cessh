/*	$OpenBSD: pathnames.h,v 1.15 2004/07/11 17:48:47 deraadt Exp $	*/

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#define DEFAULT_SSHDIR		"/Hard Disk"

 /*
 * System-wide file containing host keys of known hosts.  This file should be
 * world-readable.
 */
#define INIT_VAL_PATH_SSH_SYSTEM_HOSTFILE	"/ssh_known_hosts"

/* backward compat for protocol 2 */
#define INIT_VAL_PATH_SSH_SYSTEM_HOSTFILE2	"/ssh_known_hosts2"
/*
 * Of these, ssh_host_key must be readable only by root, whereas ssh_config
 * should be world-readable.
 */
#define INIT_VAL_PATH_SERVER_CONFIG_FILE	"/sshd_config"
#define INIT_VAL_PATH_HOST_KEY_FILE			"/ssh_host_key"
#define INIT_VAL_PATH_HOST_DSA_KEY_FILE		"/ssh_host_dsa_key"
#define INIT_VAL_PATH_HOST_RSA_KEY_FILE		"/ssh_host_rsa_key"
#define INIT_VAL_PATH_DH_MODULI				"/moduli"
/* Backwards compatibility */
#define INIT_VAL_PATH_DH_PRIMES				"/primes"

/*
 * The directory in user\'s home directory in which the files reside. The
 * directory should be world-readable (though not all files are).
 */
#define _PATH_SSH_USER_DIR		".ssh"

/*
 * Per-user file containing host keys of known hosts.  This file need not be
 * readable by anyone except the user him/herself, though this does not
 * contain anything particularly secret.
 */
#define _PATH_SSH_USER_HOSTFILE		"~/.ssh/known_hosts"
/* backward compat for protocol 2 */
#define _PATH_SSH_USER_HOSTFILE2	"~/.ssh/known_hosts2"
/*
 * File containing a list of those rsa keys that permit logging in as this
 * user.  This file need not be readable by anyone but the user him/herself,
 * but does not contain anything particularly secret.  If the user\'s home
 * directory resides on an NFS volume where root is mapped to nobody, this
 * may need to be world-readable.  (This file is read by the daemon which is
 * running as root.)
 */
#define INIT_VAL_PATH_SSH_USER_PERMITTED_KEYS	"/authorized_keys" //".ssh/authorized_keys"

/* backward compat for protocol v2 */
#define INIT_VAL_PATH_SSH_USER_PERMITTED_KEYS2	"/authorized_keys2" //".ssh/authorized_keys2"

/*
 * Ssh-only version of /etc/hosts.equiv.  Additionally, the daemon may use
 * ~/.rhosts and /etc/hosts.equiv if rhosts authentication is enabled.
 */
#define INIT_VAL_PATH_SSH_HOSTS_EQUIV		"/shosts.equiv"
#define _PATH_RHOSTS_EQUIV		"/etc/hosts.equiv"


#define _PATH_SSH_SYSTEM_HOSTFILE		szPATH_SSH_SYSTEM_HOSTFILE
#define _PATH_SSH_SYSTEM_HOSTFILE2		szPATH_SSH_SYSTEM_HOSTFILE2
#define _PATH_SERVER_CONFIG_FILE		szPATH_SERVER_CONFIG_FILE
#define _PATH_HOST_KEY_FILE				szPATH_HOST_KEY_FILE		
#define _PATH_HOST_DSA_KEY_FILE			szPATH_HOST_DSA_KEY_FILE	
#define _PATH_HOST_RSA_KEY_FILE			szPATH_HOST_RSA_KEY_FILE	
#define _PATH_DH_MODULI					szPATH_DH_MODULI			
#define _PATH_SSH_HOSTS_EQUIV			szPATH_SSH_HOSTS_EQUIV		
#define _PATH_SSH_USER_PERMITTED_KEYS2	szPATH_SSH_USER_PERMITTED_KEYS2
#define _PATH_SSH_USER_PERMITTED_KEYS	szPATH_SSH_USER_PERMITTED_KEYS
#define _PATH_DH_PRIMES					szPATH_DH_PRIMES

extern char* szPATH_SSH_SYSTEM_HOSTFILE;
extern char* szPATH_SSH_SYSTEM_HOSTFILE2;
extern char* szPATH_SERVER_CONFIG_FILE;
extern char* szPATH_HOST_KEY_FILE;	
extern char* szPATH_HOST_DSA_KEY_FILE;
extern char* szPATH_HOST_RSA_KEY_FILE;
extern char* szPATH_DH_MODULI;		
extern char* szPATH_DH_PRIMES;
extern char* szPATH_SSH_HOSTS_EQUIV;
extern char* szPATH_SSH_USER_PERMITTED_KEYS2;
extern char* szPATH_SSH_USER_PERMITTED_KEYS;

extern void initPathNames(void);