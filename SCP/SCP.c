// SCP.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"



/*
 * scp - secure remote copy.  This is basically patched BSD rcp which
 * uses ssh to do the data transfer (instead of using rcmd).
 *
 * NOTE: This version should NOT be suid root.  (This uses ssh to
 * do the transfer and ssh has the necessary privileges.)
 *
 * 1995 Timo Rinne <tri@iki.fi>, Tatu Ylonen <ylo@cs.hut.fi>
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */
/*
 * Copyright (c) 1999 Theo de Raadt.  All rights reserved.
 * Copyright (c) 1999 Aaron Campbell.  All rights reserved.
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

/*
 * Parts from:
 *
 * Copyright (c) 1983, 1990, 1992, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "includes.h"
RCSID("$OpenBSD: scp.c,v 1.130 2006/01/31 10:35:43 djm Exp $");

#include "xmalloc.h"
#include "atomicio.h"
#include "pathnames.h"
#include "log.h"
#include "misc.h"
#include "stat.h"
#include "io.h"
#include "strings.h"


extern char *__progname;

void bwlimit(int);


/* Bandwidth limit */
off_t limit_rate = 0;

/* Name of current file being transferred. */
char *curfile;

/* This is set to non-zero to enable verbose mode. */
int verbose_mode = 0;

/* This is used to store the pid of ssh_program */
pid_t do_cmd_pid = -1;

int showprogress = 1;



typedef struct {
	size_t cnt;
	char *buf;
} BUF;

BUF *allocbuf(BUF *, int, int);
void lostconn(int);
void nospace(void);
int okname(char *);
void run_err(const char *,...);
void verifydir(char *);

struct passwd *pwd;
uid_t userid;
int errs, remin, remout;
int pflag, iamremote, iamrecursive, targetshouldbedirectory;

#define	CMDNEEDS	64
char cmd[CMDNEEDS];		/* must hold "rcp -r -p -d\0" */

int response(void);
void rsource(char *, struct stat *);
void sink(int, char *[]);
void source(int, char *[]);



#define STDIN	_fileno(stdin)
#define STDOUT	_fileno(stdout)


__declspec(dllimport) extern	char *optarg;
__declspec(dllimport) extern	int optind;

typedef struct {
	int d_ino;
	unsigned short	d_reclen;
	char d_name[MAX_PATH];
} dirent;

typedef struct {
	WCHAR* wsDirectorySearchStr;
	HANDLE hSearch;
} DIR;


void WChangeSlashToBackSlash(WCHAR* s)
{
	int i;
	if (s == NULL)
	{
		return;
	}
	for (i=wcslen(s)-1;i>=0;i--)
	{
		if (s[i] == L'/')
		{
			s[i] = L'\\';
		}
	}
}
void ChangeBackSlashToSlash(char* s)
{
	int i;
	if (s == NULL)
	{
		return;
	}
	for (i=strlen(s)-1;i>=0;i--)
	{
		if (s[i] == '\\')
		{
			s[i] = '/';
		}
	}
}
void ChangeSlashToBackSlash(char* s)
{
	int i;
	if (s == NULL)
	{
		return;
	}
	for (i=strlen(s)-1;i>=0;i--)
	{
		if (s[i] == '/')
		{
			s[i] = '\\';
		}
	}
}


DIR* opendir(char* path)
{
	DIR* result = NULL;
	int size;
	WCHAR wcResolved[MAX_PATH];
	WCHAR* wcPath = strdupAsciiToUnicode(path);
	if (CeGetCanonicalPathName(wcPath,wcResolved,sizeof(wcResolved),0) != 0)
	{				
		result = malloc(sizeof(DIR));
		WChangeSlashToBackSlash(wcResolved);
		size = sizeof(WCHAR) * (10 + wcslen(wcResolved));
		result->wsDirectorySearchStr = malloc(size);
		if (wcResolved[wcslen(wcResolved)-1] == L'\\')
		{
			wsprintf(result->wsDirectorySearchStr,L"%s*.*",wcResolved);
		}
		else
		{
			wsprintf(result->wsDirectorySearchStr,L"%s\\*.*",wcResolved);
		}

		result->hSearch = INVALID_HANDLE_VALUE;
	}
	free(wcPath);
	return result;
	
}

int closedir(DIR* dirp)
{
	if (dirp)
	{
		FindClose(dirp->hSearch);
		free(dirp->wsDirectorySearchStr);
		free(dirp);	
		return 0;
	}
	return ERROR_PATH_NOT_FOUND;
}


dirent *readdir(DIR* dirp)
{
	static dirent result;
	WIN32_FIND_DATA wfd;
	BOOL bFileFound = FALSE;
	
	if (dirp->hSearch == INVALID_HANDLE_VALUE)
	{
		dirp->hSearch = FindFirstFile (dirp->wsDirectorySearchStr, &wfd);
		if (dirp->hSearch != INVALID_HANDLE_VALUE)
		{
			bFileFound = TRUE;
		}			
	}
	else
	{
		bFileFound = FindNextFile (dirp->hSearch, &wfd);			
	}
	
	if (bFileFound)
	{
		
		unicodeToAscii(wfd.cFileName, result.d_name);
		result.d_ino = 1;
		result.d_reclen = sizeof(result.d_ino) + sizeof(result.d_reclen) + strlen(result.d_name) + 1;
		return &result;
	}
	else
	{
		
		return NULL;
	}
}


int
main(int argc, char **argv)
{
	int ch, fflag, tflag, status=0;
	double speed;
	char *endp;

	fflag = tflag = 0;
	while ((ch = getopt(argc, argv, "dfl:prtvBCc:i:P:q1246S:o:F:")) != -1)
		switch (ch) {
		/* User-visible flags. */
		case '1':
		case '2':
		case '4':
		case '6':
		case 'C':
			// JJH addargs(&args, "-%c", ch);
			break;
		case 'o':
		case 'c':
		case 'i':
		case 'F':
			// JJH addargs(&args, "-%c%s", ch, optarg);
			break;
		case 'P':
			//JJH addargs(&args, "-p%s", optarg);
			break;
		case 'B':
			// JJH addargs(&args, "-oBatchmode yes");
			break;
		case 'l':
			speed = strtod(optarg, &endp);
			if (!(speed <= 0 || *endp != '\0'))
			{
				limit_rate = (off_t) speed * 1024;
			}
			
			break;
		case 'p':
			pflag = 1;
			break;
		case 'r':
			iamrecursive = 1;
			break;
		case 'v':
			//JJH addargs(&args, "-v");
			verbose_mode = 1;
			break;
		case 'q':
			//JJH addargs(&args, "-q");
			showprogress = 0;
			break;

		/* Server options. */
		case 'd':
			targetshouldbedirectory = 1;
			break;
		case 'f':	/* "from" */
			iamremote = 1;
			fflag = 1;
			break;
		case 't':	/* "to" */
			iamremote = 1;
			tflag = 1;
#ifdef HAVE_CYGWIN
			setmode(0, O_BINARY);
#endif
			break;
		default:
			break;
		}
	argc -= (optind);
	argv += (optind);

/*
	if ((pwd = getpwuid(userid = getuid())) == NULL)
		fatal("unknown user %u", (u_int) userid);

	if (!isatty(STDERR_FILENO))
		showprogress = 0;
*/

	remin = (int)STDIN;
	remout = (int)STDOUT;

	if (fflag) {
		/* Follow "protocol", send data. */
		(void) response();
		source(argc, argv);
		exit(errs != 0);
	}
	if (tflag) {
		/* Receive data. */
		sink(argc, argv);
		exit(errs != 0);
	}
}



int WFD_to_stat(WIN32_FIND_DATA *wfd, struct stat* st)
{
	
	if (wfd == NULL || st == NULL)
	{
		SET_ERRNO( EINVAL );
		return -1;
	}

	
	st->st_dev = 0;
	st->st_ino = 0;
	st->st_mode = 0;

	
	

	if (wfd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		st->st_mode |= _S_IFDIR;
		st->st_mode |= S_IEXEC | S_IXGRP | S_IXOTH;	// search permission
	}
	else
	{
		st->st_mode |= S_IFREG;
		st->st_mode |= S_IEXEC | S_IXGRP | S_IXOTH;	// every file can be executed
	}
	st->st_mode |= S_IREAD | S_IROTH | S_IRGRP;	// TODO: assuming readable, but this may not be the case
	
	if (!(wfd->dwFileAttributes & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_INROM)))
	{
		st->st_mode |= S_IWRITE | S_IWGRP | S_IWOTH;
	}

	if (wfd->dwFileAttributes & (FILE_ATTRIBUTE_ROMMODULE))
	{
		st->st_mode &= ~(S_IREAD | S_IROTH | S_IRGRP | S_IWRITE | S_IWGRP | S_IWOTH);	// ROM module is executable
		st->st_mode |= S_IEXEC | S_IXGRP | S_IXOTH;	// ROM module is executable
	}

	st->st_nlink = 1;	// TODO: NTFS can have links, so get the correct value
	st->st_uid = 0;
	st->st_gid = 0;
	st->st_rdev = 0;
	st->st_size = wfd->nFileSizeLow;
	st->st_atime = ConvertWindowsToUnixTime(&wfd->ftLastAccessTime);
	st->st_mtime = ConvertWindowsToUnixTime(&wfd->ftLastWriteTime);
	st->st_ctime = ConvertWindowsToUnixTime(&wfd->ftCreationTime);

	return 0;
}

#define SCP_SEND_BLOCK_SIZE	2048
BOOL SCPSend(char* szFullPath, char* sName, struct stat* st)
{	
	BOOL bError = FALSE;
	static BUF buffer;
	char buf[SCP_SEND_BLOCK_SIZE];
	BUF *bp;
	int fd;
	int haderr,i,amt,result,statbytes;
	WCHAR* wFullPath = strdupAsciiToUnicode(szFullPath);
	
	//RETAILMSG(1,(TEXT("SCPSend : %s\r\n"),wFullPath));
	
	statbytes = 0;
	
	if ((fd = open(szFullPath, O_RDONLY))  != -1) 
	{
		
		if (pflag)
		{
		/*
		* Make it compatible with possible future
		* versions expecting microseconds.
			*/
			(void) snprintf(buf, sizeof buf, "T%lu 0 %lu 0\n",
				(u_long) st->st_mtime,
				(u_long) st->st_atime);
			(void) atomicio(vwrite, remout, buf, strlen(buf));
			if (response() < 0)
			{
				bError = TRUE;
			}
		}
		if (!bError)
		{
#define	FILEMODEMASK	(S_ISUID|S_ISGID|S_IRWXU|S_IRWXG|S_IRWXO)
			snprintf(buf, sizeof buf, "C%04o %lld %s\n",
				(u_int) (st->st_mode & FILEMODEMASK),
				(long)st->st_size, sName);
			if (verbose_mode) {
				fprintf(stderr, "Sending file modes: %s", buf);
			}
			
			(void) atomicio(vwrite, remout, buf, strlen(buf));
			
			if (response() < 0)
			{
				bError = TRUE;
			}
			if (!bError)
			{
				if ((bp = allocbuf(&buffer, fd, SCP_SEND_BLOCK_SIZE)) == NULL) 
				{
					if (fd != -1) {
						(void) close(fd);
						fd = -1;
						bError = TRUE;
					}
					
				}
				
				if (!bError)
				{
					if (showprogress)
					{
						//JJH	start_progress_meter(curfile, st->st_size, &statbytes);
					}
					/* Keep writing after an error so that we stay sync'd up. */
					for (haderr = i = 0; i < (off_t)st->st_size; i += bp->cnt) {
						amt = bp->cnt;
						if (i + amt > (off_t) st->st_size)
							amt = st->st_size - i;
						if (!haderr) {
							result = atomicio(read, fd, bp->buf, amt);
							if (result != amt)
								haderr = errno;
						}
						if (haderr)
							(void) atomicio(vwrite, remout, bp->buf, amt);
						else {
							result = atomicio(vwrite, remout, bp->buf, amt);
							if (result != amt)
								haderr = errno;
							statbytes += result;
						}
						if (limit_rate)
							bwlimit(amt);
					}
					if (showprogress)
					{
						//JJH 	stop_progress_meter();
					}
					
					if (fd != -1) {
						if (close(fd) < 0 && !haderr)
							haderr = errno;
						fd = -1;
					}
					if (!haderr)
						(void) atomicio(vwrite, remout, "", 1);
					else
						run_err("%s: %s", szFullPath, strerror(haderr));
					(void) response();
				}
			}
		}
	}



	free(wFullPath);	
	return !bError;
}

void getParentDirectoryName(char* dest, char* szName)
{
	//WCHAR* w1;
	//WCHAR* w2;
	DWORD dwIndex = strlen(szName);
	
	while (dwIndex && (szName[dwIndex] != '\\') && (szName[dwIndex] != '/') )
	{
		dwIndex--;
	}
	
	memcpy(dest,szName,dwIndex);
	dest[dwIndex]=0;
	
	/*
	w2 = strdupAsciiToUnicode(dest);
	w1 = strdupAsciiToUnicode(szName);
	RETAILMSG(1,(TEXT("getParentDirectoryName %s -> %s\r\n"),w1,w2));
	free(w1);
	free(w2);
	*/
}

void
source(int argc, char **argv)
{
	BOOL bNoMoreFile = FALSE;
	DWORD dwIndex =0;
	

	while (!bNoMoreFile)
	{
		if (dwIndex == argc)
		{
			// end of provided list of files
			bNoMoreFile = TRUE;
		}
		else
		{
			HANDLE h;
			WIN32_FIND_DATA fd;
			WCHAR* wName = strdupAsciiToUnicode(argv[dwIndex]);
			char* szDirectory = malloc(strlen(argv[dwIndex])+1);
			getParentDirectoryName(szDirectory,argv[dwIndex]);
			
			
			// Let's try to find matching fileS 
			h = FindFirstFile(wName,&fd);
			
			if (h != INVALID_HANDLE_VALUE)
			{
				struct stat st;
				char *szFullPath;	
				DWORD dirNameLength = strlen(szDirectory);
				szFullPath = malloc(dirNameLength + wcslen(fd.cFileName) + 2);
				if (szFullPath)
				{
					memcpy(szFullPath,szDirectory,dirNameLength);
					szFullPath[dirNameLength] = '\\';
					unicodeToAscii(fd.cFileName,&(szFullPath[dirNameLength+1]));

					WFD_to_stat(&fd,&st);
					// Send First file or directory
					if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
					{									
						rsource(szFullPath,&st);
					}
					else
					{
						SCPSend(szFullPath,&(szFullPath[dirNameLength+1]),&st);
					}

					free(szFullPath);
		
					// try to find another file matching the pattern
					while (FindNextFile(h,&fd))
					{					
						WFD_to_stat(&fd,&st);
						dirNameLength = strlen(szDirectory);
						szFullPath = malloc(dirNameLength + wcslen(fd.cFileName) + 2);
						if (szFullPath)
						{
							continue;
						}
						memcpy(szFullPath,szDirectory,dirNameLength);
						szFullPath[dirNameLength] = '\\';
						unicodeToAscii(fd.cFileName,&(szFullPath[dirNameLength+1]));
						// if a file is found, send it
						if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
						{
							WFD_to_stat(&fd,&st);
							rsource(szFullPath,&st);
						}
						else
						{
							SCPSend(szFullPath,&(szFullPath[dirNameLength+1]),&st);
						}
						free(szFullPath);					
					}
				}
			}

			FindClose(h);
			free(wName);
			free(szDirectory);
			dwIndex++;
		}
	}
}


void
rsource(char *name, struct stat *statp)
{

	DIR *dirp;
	dirent *dp;
	char *last, *vect[1], path[MAX_PATH];
	DWORD dwIndex = strlen(name);

	if (!(dirp = opendir(name))) {
		run_err("%s: %s", name, strerror(errno));
		return;
	}
	
	
	
	while (dwIndex && (name[dwIndex] != '\\') && (name[dwIndex] != '/') )
	{
		dwIndex--;
	}
	if ((name[dwIndex] != '\\') || (name[dwIndex] != '/'))
	{
		last = &(name[dwIndex+1]);
	}
	else
	{
		last = &(name[dwIndex]);;
	}
	

	if (pflag) {
		(void) snprintf(path, sizeof(path), "T%lu 0 %lu 0\n",
		    (u_long) statp->st_mtime,
		    (u_long) statp->st_atime);
		(void) atomicio(vwrite, remout, path, strlen(path));
		if (response() < 0) {
			closedir(dirp);
			return;
		}
	}
	(void) snprintf(path, sizeof path, "D%04o %d %.1024s\n",
	    (u_int) (statp->st_mode & FILEMODEMASK), 0, last);
	if (verbose_mode)
		fprintf(stderr, "Entering directory: %s", path);
	(void) atomicio(vwrite, remout, path, strlen(path));
	if (response() < 0) {
		closedir(dirp);
		return;
	}
	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_ino == 0)
			continue;
		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;
		if (strlen(name) + 1 + strlen(dp->d_name) >= sizeof(path) - 1) {
			run_err("%s/%s: name too long", name, dp->d_name);
			continue;
		}
		(void) snprintf(path, sizeof path, "%s/%s", name, dp->d_name);
		vect[0] = path;
		source(1, vect);
	}
	(void) closedir(dirp);
	(void) atomicio(vwrite, remout, "E\n", 2);
	(void) response();
	
}

void
bwlimit(int amount)
{
	/*
	static struct timeval bwstart, bwend;
	static int lamt, thresh = 16384;
	u_int64_t waitlen;
	struct timespec ts, rm;

	if (!timerisset(&bwstart)) {
		gettimeofday(&bwstart, NULL);
		return;
	}

	lamt += amount;
	if (lamt < thresh)
		return;

	gettimeofday(&bwend, NULL);
	timersub(&bwend, &bwstart, &bwend);
	if (!timerisset(&bwend))
		return;

	lamt *= 8;
	waitlen = (double)1000000L * lamt / limit_rate;

	bwstart.tv_sec = waitlen / 1000000L;
	bwstart.tv_usec = waitlen % 1000000L;

	if (timercmp(&bwstart, &bwend, >)) {
		timersub(&bwstart, &bwend, &bwend);

		// Adjust the wait time
		if (bwend.tv_sec) {
			thresh /= 2;
			if (thresh < 2048)
				thresh = 2048;
		} else if (bwend.tv_usec < 100) {
			thresh *= 2;
			if (thresh > 32768)
				thresh = 32768;
		}

		TIMEVAL_TO_TIMESPEC(&bwend, &ts);
		while (nanosleep(&ts, &rm) == -1) {
			if (errno != EINTR)
				break;
			ts = rm;
		}
	}

	lamt = 0;
	gettimeofday(&bwstart, NULL);
	*/
}

void
sink(int argc, char **argv)
{
	static BUF buffer;
	struct stat stb;
	enum {
		YES, NO, DISPLAYED
	} wrerr;
	BUF *bp;
	off_t i;
	size_t j, count;
	int amt, exists, first, mode, ofd, omode;
	off_t size, statbytes;
	int setimes, targisdir, wrerrno = 0;
	char ch, *cp, *np, *targ, *why, *vect[1], buf[2048];
	struct timeval tv[2];

#define	atime	tv[0]
#define	mtime	tv[1]
#define	SCREWUP(str)	{ why = str; goto screwup; }

	setimes = targisdir = 0;
	//mask = umask(0);	
	// if (!pflag)
	//	(void) umask(mask);
	//

	if (argc != 1) {
		run_err("ambiguous target");
		exit(1);
	}
	targ = *argv;
	if (targetshouldbedirectory)
		verifydir(targ);

	(void) atomicio(vwrite, remout, "", 1);
	if (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
		targisdir = 1;
	for (first = 1;; first = 0) {
		cp = buf;
		if (atomicio(read, remin, cp, 1) != 1)
			return;
		if (*cp++ == '\n')
			SCREWUP("unexpected <newline>");
		do {
			if (atomicio(read, remin, &ch, sizeof(ch)) != sizeof(ch))
				SCREWUP("lost connection");
			*cp++ = ch;
		} while (cp < &buf[sizeof(buf) - 1] && ch != '\n');
		*cp = 0;
		if (verbose_mode)
			fprintf(stderr, "Sink: %s", buf);

		if (buf[0] == '\01' || buf[0] == '\02') {
			if (iamremote == 0)
				(void) atomicio(vwrite, STDERR_FILENO,
				    buf + 1, strlen(buf + 1));
			if (buf[0] == '\02')
				exit(1);
			++errs;
			continue;
		}
		if (buf[0] == 'E') {
			(void) atomicio(vwrite, remout, "", 1);
			return;
		}
		if (ch == '\n')
			*--cp = 0;

		cp = buf;
		if (*cp == 'T') {
			setimes++;
			cp++;
			mtime.tv_sec = strtol(cp, &cp, 10);
			if (!cp || *cp++ != ' ')
				SCREWUP("mtime.sec not delimited");
			mtime.tv_usec = strtol(cp, &cp, 10);
			if (!cp || *cp++ != ' ')
				SCREWUP("mtime.usec not delimited");
			atime.tv_sec = strtol(cp, &cp, 10);
			if (!cp || *cp++ != ' ')
				SCREWUP("atime.sec not delimited");
			atime.tv_usec = strtol(cp, &cp, 10);
			if (!cp || *cp++ != '\0')
				SCREWUP("atime.usec not delimited");
			(void) atomicio(vwrite, remout, "", 1);
			continue;
		}
		if (*cp != 'C' && *cp != 'D') {
			/*
			 * Check for the case "rcp remote:foo\* local:bar".
			 * In this case, the line "No match." can be returned
			 * by the shell before the rcp command on the remote is
			 * executed so the ^Aerror_message convention isn't
			 * followed.
			 */
			if (first) {
				run_err("%s", cp);
				exit(1);
			}
			SCREWUP("expected control record");
		}
		mode = 0;
		for (++cp; cp < buf + 5; cp++) {
			if (*cp < '0' || *cp > '7')
				SCREWUP("bad mode");
			mode = (mode << 3) | (*cp - '0');
		}
		if (*cp++ != ' ')
			SCREWUP("mode not delimited");

		for (size = 0; isdigit(*cp);)
			size = size * 10 + (*cp++ - '0');
		if (*cp++ != ' ')
			SCREWUP("size not delimited");
		if ((strchr(cp, '/') != NULL) || (strcmp(cp, "..") == 0)) {
			run_err("error: unexpected filename: %s", cp);
			exit(1);
		}
		if (targisdir) {
			static char *namebuf;
			static size_t cursize;
			size_t need;

			need = strlen(targ) + strlen(cp) + 250;
			if (need > cursize) {
				if (namebuf)
					xfree(namebuf);
				namebuf = (char*) xmalloc(need);
				cursize = need;
			}
			(void) snprintf(namebuf, need, "%s%s%s", targ,
			    strcmp(targ, "/") ? "/" : "", cp);
			np = namebuf;
		} else
			np = targ;
		curfile = cp;
		exists = stat(np, &stb) == 0;
		if (buf[0] == 'D') {
			int mod_flag = pflag;
			if (!iamrecursive)
				SCREWUP("received directory without -r");
			if (exists) {
				if (!S_ISDIR(stb.st_mode)) {
					//JJH errno = ENOTDIR;
					SET_ERRNO(ENOENT);
					goto bad;
				}
				//if (pflag)
				//{
				//	(void) chmod(np, mode);
				//}

			} else {
				/* Handle copying from a read-only
				   directory */
				mod_flag = 1;
				if (mkdir(np, mode | S_IRWXU) < 0)
					goto bad;
			}
			vect[0] = xstrdup(np);
			sink(1, vect);
			if (setimes) {
				setimes = 0;
				/*
				if (utimes(vect[0], tv) < 0)
					run_err("%s: set times: %s",
					    vect[0], strerror(errno));
						*/

			}
			if (mod_flag)
			{
			//JJH 	(void) chmod(vect[0], mode);
			}
			if (vect[0])
				xfree(vect[0]);
			continue;
		}
		omode = mode;
		mode |= S_IWRITE;
		if ((ofd = open(np, O_WRONLY|O_CREAT /*JJH , mode*/)) == -1) {
bad:			run_err("%s: %s", np, strerror(errno));
			continue;
		}
		(void) atomicio(vwrite, remout, "", 1);
		if ((bp = allocbuf(&buffer, ofd, 4096)) == NULL) {
			(void) close(ofd);
			continue;
		}
		cp = bp->buf;
		wrerr = NO;

		statbytes = 0;
		if (showprogress)
		{
		//JJH	start_progress_meter(curfile, size, &statbytes);
		}
		for (count = i = 0; i < size; i += 4096) {
			amt = 4096;
			if (i + amt > size)
				amt = size - i;
			count += amt;
			do {
				j = atomicio(read, remin, cp, amt);
				if (j == 0) {
					run_err("%s", j ? strerror(errno) :
					    "dropped connection");
					exit(1);
				}
				amt -= j;
				cp += j;
				statbytes += j;
			} while (amt > 0);

			if (limit_rate)
				bwlimit(4096);

			if (count == bp->cnt) {
				/* Keep reading so we stay sync'd up. */
				if (wrerr == NO) {
					if (atomicio(vwrite, ofd, bp->buf,
					    count) != count) {
						wrerr = YES;
						wrerrno = errno;
					}
				}
				count = 0;
				cp = bp->buf;
			}
		}
		if (showprogress)
		{
		//JJH	stop_progress_meter();
		}
		if (count != 0 && wrerr == NO &&
		    atomicio(vwrite, ofd, bp->buf, count) != count) {
			wrerr = YES;
			wrerrno = errno;
		}
		if (wrerr == NO && ftruncate(ofd, size) != 0) {
			run_err("%s: truncate: %s", np, strerror(errno));
			wrerr = DISPLAYED;
		}

#ifndef WINCE_PORT
		if (pflag) {
			if (exists || omode != mode)
#ifdef HAVE_FCHMOD
				if (fchmod(ofd, omode)) {
#else // HAVE_FCHMOD
				if (chmod(np, omode)) {
#endif // HAVE_FCHMOD
					run_err("%s: set mode: %s",
					    np, strerror(errno));
					wrerr = DISPLAYED;
				}
		} else {
			if (!exists && omode != mode)
#ifdef HAVE_FCHMOD
				if (fchmod(ofd, omode & ~mask)) {
#else // HAVE_FCHMOD
				if (chmod(np, omode & ~mask)) {
#endif // HAVE_FCHMOD
					run_err("%s: set mode: %s",
					    np, strerror(errno));
					wrerr = DISPLAYED;
				}
		}
#endif
		if (close(ofd) == -1) {
			wrerr = YES;
			wrerrno = errno;
		}
		(void) response();
		if (setimes && wrerr == NO) {
			setimes = 0;
/* JJH
			if (utimes(np, tv) < 0) {
				run_err("%s: set times: %s",
				    np, strerror(errno));
				wrerr = DISPLAYED;
			}
*/

		}
		switch (wrerr) {
		case YES:
			run_err("%s: %s", np, strerror(wrerrno));
			break;
		case NO:
			(void) atomicio(vwrite, remout, "", 1);
			break;
		case DISPLAYED:
			break;
		}
	}
screwup:
	run_err("protocol error: %s", why);
	exit(1);
}

int
response(void)
{
	char ch, *cp, resp, rbuf[2048];

	if (atomicio(read, remin, &resp, sizeof(resp)) != sizeof(resp))
		lostconn(0);

	cp = rbuf;
	switch (resp) {
	case 0:		/* ok */
		return (0);
	default:
		*cp++ = resp;
		/* FALLTHROUGH */
	case 1:		/* error, followed by error msg */
	case 2:		/* fatal error, "" */
		do {
			if (atomicio(read, remin, &ch, sizeof(ch)) != sizeof(ch))
				lostconn(0);
			*cp++ = ch;
		} while (cp < &rbuf[sizeof(rbuf) - 1] && ch != '\n');

		if (!iamremote)
			(void) atomicio(vwrite, STDERR_FILENO, rbuf, cp - rbuf);
		++errs;
		if (resp == 1)
			return (-1);
		exit(1);
	}
	/* NOTREACHED */
	return 0;
}


void
run_err(const char *fmt,...)
{
	static FILE *fp;
	va_list ap;

	++errs;
	if (fp == NULL && !(fp = fdopen(remout, "w")))
		return;
	(void) fprintf(fp, "%c", 0x01);
	(void) fprintf(fp, "scp: ");
	va_start(ap, fmt);
	(void) vfprintf(fp, fmt, ap);
	va_end(ap);
	(void) fprintf(fp, "\n");
	(void) fflush(fp);

	if (!iamremote) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
	}
}

void
verifydir(char *cp)
{
	struct stat stb;

	if (!stat(cp, &stb)) {
		if (S_ISDIR(stb.st_mode))
			return;
		//JJH errno = ENOTDIR;
		SET_ERRNO(ENOENT);
	}
	run_err("%s: %s", cp, strerror(errno));
	//killchild(0);
}

int
okname(char *cp0)
{
	int c;
	char *cp;

	cp = cp0;
	do {
		c = (int)*cp;
		if (c & 0200)
			goto bad;
		if (!isalpha(c) && !isdigit(c)) {
			switch (c) {
			case '\'':
			case '"':
			case '`':
			case ' ':
			case '#':
				goto bad;
			default:
				break;
			}
		}
	} while (*++cp);
	return (1);

bad:	fprintf(stderr, "%s: invalid user name\n", cp0);
	return (0);
}

BUF *
allocbuf(BUF *bp, int fd, int blksize)
{
	size_t size;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
	struct stat stb;

	if (fstat(fd, &stb) < 0) {
		run_err("fstat: %s", strerror(errno));
		return (0);
	}
	size = roundup(stb.st_blksize, blksize);
	if (size == 0)
		size = blksize;
#else /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	size = blksize;
#endif /* HAVE_STRUCT_STAT_ST_BLKSIZE */
	if (bp->cnt >= size)
		return (bp);
	if (bp->buf == NULL)
		bp->buf = (char*) xmalloc(size);
	else
		bp->buf = (char*) xrealloc(bp->buf, size);
	memset(bp->buf, 0, size);
	bp->cnt = size;
	return (bp);
}

void
lostconn(int signo)
{
	if (!iamremote)
		write(STDERR_FILENO, "lost connection\n", 16);
	if (signo)
		_exit(1);
	else
		exit(1);
}

int _tmain(int argc, TCHAR *argv[], TCHAR *envp[])
{
	int i;
	char** _argv = (char**) malloc(argc * sizeof(char*));
	for (i=0;i<argc;i++)
	{
		_argv[i] = strdupUnicodeToAscii(argv[i]);
	}
    
	main(argc,_argv);
	
	for (i=0;i<argc;i++)
	{
		free(_argv[i]);
	}
	free(_argv);
    return 0;
}
