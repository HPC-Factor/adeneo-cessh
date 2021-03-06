/*
 * Copyright (c) 2000-2004 Markus Friedl.  All rights reserved.
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
RCSID("$OpenBSD: sftp-server.c,v 1.50 2006/01/02 01:20:31 djm Exp $");

#include "buffer.h"
#include "bufaux.h"
#include "getput.h"
#include "log.h"
#include "xmalloc.h"
#include "misc.h"

#include "sftp.h"
#include "sftp-common.h"

#include "io.h"
#include "stat.h"
#include "strings.h"

#include "SSHDeviceIoctl.h"

long_long i;

/* helper */
#define get_int64()			buffer_get_int64(&iqueue);
#define get_int()			buffer_get_int(&iqueue);
#define get_string(lenp)		buffer_get_string(&iqueue, lenp);
#define TRACE				debug

extern char *__progname;

/* input and output queue */
Buffer iqueue;
Buffer oqueue;

/* Version of client */
int version;

/* portable attributes, etc. */

typedef struct Stat Stat;

struct Stat {
	char *name;
	char *long_name;
	Attrib attrib;
};

static int
errno_to_portable(int unixerrno)
{
	int ret = 0;

	switch (unixerrno) {
	case 0:
		ret = SSH2_FX_OK;
		break;
	case ERROR_FILE_NOT_FOUND:
	case ERROR_PATH_NOT_FOUND:
	case ERROR_INVALID_HANDLE:
		ret = SSH2_FX_NO_SUCH_FILE;
		break;
	case ERROR_ACCESS_DENIED:
		ret = SSH2_FX_PERMISSION_DENIED;
		break;
	case EINVAL:
		ret = ERROR_INVALID_PARAMETER;
		break;
	default:
		ret = SSH2_FX_FAILURE;
		break;
	}
	return ret;
}

static int
flags_from_portable(int pflags)
{
	int flags = 0;

	if ((pflags & SSH2_FXF_READ) &&
	    (pflags & SSH2_FXF_WRITE)) {
		flags = O_RDWR;
	} else if (pflags & SSH2_FXF_READ) {
		flags = O_RDONLY;
	} else if (pflags & SSH2_FXF_WRITE) {
		flags = O_WRONLY;
	}
	if (pflags & SSH2_FXF_CREAT)
		flags |= O_CREAT;
	if (pflags & SSH2_FXF_TRUNC)
		flags |= O_TRUNC;
	if (pflags & SSH2_FXF_EXCL)
		flags |= O_EXCL;
	return flags;
}
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


static Attrib *
get_attrib(void)
{
	return decode_attrib(&iqueue);
}
typedef struct {
	WCHAR* wsDirectorySearchStr;
	HANDLE hSearch;
} DIR;
/* handle handles */

typedef struct Handle Handle;
struct Handle {
	int use;
	DIR *dirp;
	int fd;
	char *name;
};

enum {
	HANDLE_UNUSED,
	HANDLE_DIR,
	HANDLE_FILE
};

Handle	handles[100];

static void
handle_init(void)
{
	u_int i;

	for (i = 0; i < sizeof(handles)/sizeof(Handle); i++)
		handles[i].use = HANDLE_UNUSED;
}

static int
handle_new(int use, const char *name, int fd, DIR *dirp)
{
	u_int i;

	for (i = 0; i < sizeof(handles)/sizeof(Handle); i++) {
		if (handles[i].use == HANDLE_UNUSED) {
			handles[i].use = use;
			handles[i].dirp = dirp;
			handles[i].fd = fd;
			handles[i].name = xstrdup(name);
			return i;
		}
	}
	return -1;
}

static int
handle_is_ok(int i, int type)
{
	return i >= 0 && (u_int)i < sizeof(handles)/sizeof(Handle) &&
	    handles[i].use == type;
}

static int
handle_to_string(int handle, char **stringp, int *hlenp)
{
	if (stringp == NULL || hlenp == NULL)
		return -1;
	*stringp = xmalloc(sizeof(int32_t));
	PUT_32BIT(*stringp, handle);
	*hlenp = sizeof(int32_t);
	return 0;
}

static int
handle_from_string(const char *handle, u_int hlen)
{
	int val;

	if (hlen != sizeof(int32_t))
		return -1;
	val = GET_32BIT(handle);
	if (handle_is_ok(val, HANDLE_FILE) ||
	    handle_is_ok(val, HANDLE_DIR))
		return val;
	return -1;
}

static char *
handle_to_name(int handle)
{
	if (handle_is_ok(handle, HANDLE_DIR)||
	    handle_is_ok(handle, HANDLE_FILE))
		return handles[handle].name;
	return NULL;
}

static DIR *
handle_to_dir(int handle)
{
	if (handle_is_ok(handle, HANDLE_DIR))
		return handles[handle].dirp;
	return NULL;
}

static int
handle_to_fd(int handle)
{
	if (handle_is_ok(handle, HANDLE_FILE))
		return handles[handle].fd;
	return -1;
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


static int
handle_close(int handle)
{
	int ret = -1;

	if (handle_is_ok(handle, HANDLE_FILE)) {
		ret = close(handles[handle].fd);
		handles[handle].use = HANDLE_UNUSED;
		xfree(handles[handle].name);
	} else if (handle_is_ok(handle, HANDLE_DIR)) {
		ret = closedir(handles[handle].dirp);
		handles[handle].use = HANDLE_UNUSED;
		xfree(handles[handle].name);
	} else {
		SET_ERRNO(ENOENT);
	}
	return ret;
}

static int
get_handle(void)
{
	char *handle;
	int val = -1;
	u_int hlen;

	handle = get_string(&hlen);
	if (hlen < 256)
		val = handle_from_string(handle, hlen);
	xfree(handle);
	return val;
}

/* send replies */

static void
send_msg(Buffer *m)
{
	int mlen = buffer_len(m);

	buffer_put_int(&oqueue, mlen);
	buffer_append(&oqueue, buffer_ptr(m), mlen);
	buffer_consume(m, mlen);
}

static void
send_status(u_int32_t id, u_int32_t status)
{
	Buffer msg;
	const char *status_messages[] = {
		"Success",			/* SSH_FX_OK */
		"End of file",			/* SSH_FX_EOF */
		"No such file",			/* SSH_FX_NO_SUCH_FILE */
		"Permission denied",		/* SSH_FX_PERMISSION_DENIED */
		"Failure",			/* SSH_FX_FAILURE */
		"Bad message",			/* SSH_FX_BAD_MESSAGE */
		"No connection",		/* SSH_FX_NO_CONNECTION */
		"Connection lost",		/* SSH_FX_CONNECTION_LOST */
		"Operation unsupported",	/* SSH_FX_OP_UNSUPPORTED */
		"Unknown error"			/* Others */
	};

	TRACE("sent status id %u error %u", id, status);
	buffer_init(&msg);
	buffer_put_char(&msg, SSH2_FXP_STATUS);
	buffer_put_int(&msg, id);
	buffer_put_int(&msg, status);
	if (version >= 3) {
		buffer_put_cstring(&msg,
		    status_messages[MIN(status,SSH2_FX_MAX)]);
		buffer_put_cstring(&msg, "");
	}
	send_msg(&msg);
	buffer_free(&msg);
}
static void
send_data_or_handle(char type, u_int32_t id, const char *data, int dlen)
{
	Buffer msg;

	buffer_init(&msg);
	buffer_put_char(&msg, type);
	buffer_put_int(&msg, id);
	buffer_put_string(&msg, data, dlen);
	send_msg(&msg);
	buffer_free(&msg);
}

static void
send_data(u_int32_t id, const char *data, int dlen)
{
	TRACE("sent data id %u len %d", id, dlen);
	send_data_or_handle(SSH2_FXP_DATA, id, data, dlen);
}

static void
send_handle(u_int32_t id, int handle)
{
	char *string;
	int hlen;

	handle_to_string(handle, &string, &hlen);
	TRACE("sent handle id %u handle %d", id, handle);
	send_data_or_handle(SSH2_FXP_HANDLE, id, string, hlen);
	xfree(string);
}

static void
send_names(u_int32_t id, int count, const Stat *stats)
{
	Buffer msg;
	int i;

	buffer_init(&msg);
	buffer_put_char(&msg, SSH2_FXP_NAME);
	buffer_put_int(&msg, id);
	buffer_put_int(&msg, count);
	TRACE("sent names id %u count %d", id, count);
	for (i = 0; i < count; i++) {
		ChangeBackSlashToSlash(stats[i].name);
		ChangeBackSlashToSlash(stats[i].long_name);
		buffer_put_cstring(&msg, stats[i].name);
		buffer_put_cstring(&msg, stats[i].long_name);		
		encode_attrib(&msg, &stats[i].attrib);
	}
	send_msg(&msg);
	buffer_free(&msg);
}

static void
send_attrib(u_int32_t id, const Attrib *a)
{
	Buffer msg;

	TRACE("sent attrib id %u have 0x%x", id, a->flags);
	buffer_init(&msg);
	buffer_put_char(&msg, SSH2_FXP_ATTRS);
	buffer_put_int(&msg, id);
	encode_attrib(&msg, a);
	send_msg(&msg);
	buffer_free(&msg);
}

/* parse incoming */

static void
process_init(void)
{
	Buffer msg;

	version = get_int();
	TRACE("client version %d", version);
	buffer_init(&msg);
	buffer_put_char(&msg, SSH2_FXP_VERSION);
	buffer_put_int(&msg, SSH2_FILEXFER_VERSION);
	send_msg(&msg);
	buffer_free(&msg);
}

static void
process_open(void)
{
	u_int32_t id, pflags;
	Attrib *a;
	char *name;
	int handle, fd, flags, mode, status = SSH2_FX_FAILURE;

	id = get_int();
	name = get_string(NULL);
	pflags = get_int();		/* portable flags */
	a = get_attrib();
	flags = flags_from_portable(pflags);
	mode = (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) ? a->perm : 0666;
	TRACE("open id %u name %s flags %d mode 0%o", id, name, pflags, mode);
	ChangeSlashToBackSlash(name);	
	fd = open(name, flags);//JJH, mode);
	if (fd == -1) {
		status = errno_to_portable(errno);
	} else {
		handle = handle_new(HANDLE_FILE, name, fd, NULL);
		if (handle < 0) {
			close(fd);
		} else {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
	xfree(name);
}

static void
process_close(void)
{
	u_int32_t id;
	int handle, ret, status = SSH2_FX_FAILURE;

	id = get_int();
	handle = get_handle();
	TRACE("close id %u handle %d", id, handle);
	ret = handle_close(handle);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
}

static char read_buffer[64*1024];
static void
process_read(void)
{
	
	u_int32_t id, len;
	int handle, fd, ret, status = SSH2_FX_FAILURE;
	u_int64_t off;

	id = get_int();
	handle = get_handle();
	off = get_int64();
	len = get_int();

	TRACE("read id %u handle %d off %llu len %d", id, handle, off, len);
	if (len > sizeof(read_buffer)) {
		len = sizeof(read_buffer);
		logit("read change len %d", len);
	}
	fd = handle_to_fd(handle);
	if (fd != -1) {
		if (lseek(fd, (long)off, SEEK_SET) < 0) {
			error("process_read: seek failed");
			status = errno_to_portable(errno);
		} else {
			ret = read(fd, read_buffer, len);
			if (ret < 0) {
				status = errno_to_portable(errno);
			} else if (ret == 0) {
				status = SSH2_FX_EOF;
			} else {
				send_data(id, read_buffer, ret);
				status = SSH2_FX_OK;
			}
		}
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
}

static void
process_write(void)
{
	u_int32_t id;
	u_int64_t off;
	u_int len;
	int handle, fd, ret, status = SSH2_FX_FAILURE;
	char *data;

	id = get_int();
	handle = get_handle();
	off = get_int64();
	data = get_string(&len);

	TRACE("write id %u handle %d off %llu len %d", id, handle,
	    (long_long)off, len);
	fd = handle_to_fd(handle);
	if (fd != -1) {
		if (lseek(fd, (long) off, SEEK_SET) < 0) {
			status = errno_to_portable(errno);
			error("process_write: seek failed");
		} else {
/* XXX ATOMICIO ? */
			ret = write(fd, data, len);
			if (ret < 0) {
				error("process_write: write failed");
				status = errno_to_portable(errno);
			} else if ((size_t)ret == len) {
				status = SSH2_FX_OK;
			} else {
				logit("nothing at all written");
			}
		}
	}
	send_status(id, status);
	xfree(data);
}

static void
process_do_stat(int do_lstat)
{

	Attrib a;
	struct stat st;
	u_int32_t id;
	char *name;
	int ret;
	int status = SSH2_FX_FAILURE;

	id = get_int();
	name = get_string(NULL);
	ChangeSlashToBackSlash(name);

	TRACE("%sstat id %u name %s", do_lstat ? "l" : "", id, name);

	
	ret = do_lstat ? lstat(name, &st) : stat(name, &st);
	if (ret < 0) {
		status = errno_to_portable(errno);
	} else {
		stat_to_attrib(&st, &a);
		send_attrib(id, &a);
		status = SSH2_FX_OK;
	}
	

	if (status != SSH2_FX_OK)
		send_status(id, status);
	xfree(name);
}

static void
process_stat(void)
{
	process_do_stat(0);
}

static void
process_lstat(void)
{
	process_do_stat(1);
}

static void
process_fstat(void)
{
	Attrib a;
	struct stat st;
	u_int32_t id;
	int fd, ret, handle, status = SSH2_FX_FAILURE;

	id = get_int();
	handle = get_handle();
	TRACE("fstat id %u handle %d", id, handle);
	fd = handle_to_fd(handle);
	if (fd  >= 0) {
		ret = fstat(fd, &st);
		if (ret < 0) {
			status = errno_to_portable(errno);
		} else {
			stat_to_attrib(&st, &a);
			send_attrib(id, &a);
			status = SSH2_FX_OK;
		}
	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
}

static struct timeval *
attrib_to_tv(const Attrib *a)
{
	static struct timeval tv[2];

	tv[0].tv_sec = a->atime;
	tv[0].tv_usec = 0;
	tv[1].tv_sec = a->mtime;
	tv[1].tv_usec = 0;
	return tv;
}

static void
process_setstat(void)
{
	Attrib *a;
	u_int32_t id;
	char *name;
	int status = SSH2_FX_OK;
	int ret;

	id = get_int();
	name = get_string(NULL);
	ChangeSlashToBackSlash(name);

	a = get_attrib();
	TRACE("setstat id %u name %s", id, name);
	
	if (a->flags & SSH2_FILEXFER_ATTR_SIZE) 
	{
		ret = truncate(name, (long)a->size);
		if (ret == -1)
		{
			status = errno_to_portable(errno);
		}		
	}
	
	if (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) 
	{
		status = SSH2_FX_FAILURE;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) 
	{
		status = SSH2_FX_FAILURE;
	}
	if (a->flags & SSH2_FILEXFER_ATTR_UIDGID) 
	{
		status = SSH2_FX_FAILURE;
	}

	send_status(id, status);
	xfree(name);
}

static void
process_fsetstat(void)
{
	Attrib *a;
	u_int32_t id;
	int handle, fd;
	int ret;
	int status = SSH2_FX_OK;
	char *name;

	id = get_int();
	handle = get_handle();
	a = get_attrib();
	TRACE("fsetstat id %u handle %d", id, handle);
	fd = handle_to_fd(handle);
	name = handle_to_name(handle);
	if (fd < 0 || name == NULL) 
	{
		status = SSH2_FX_FAILURE;
	} 
	else 
	{

		if (a->flags & SSH2_FILEXFER_ATTR_SIZE) 
		{
			ret = ftruncate(fd, (long)a->size);
			if (ret == -1)
			{
				status = errno_to_portable(errno);
			}			
		}
		
		if (a->flags & SSH2_FILEXFER_ATTR_PERMISSIONS) 
		{
			status = SSH2_FX_FAILURE;			
		}
		if (a->flags & SSH2_FILEXFER_ATTR_ACMODTIME) 
		{
			status = SSH2_FX_FAILURE;			
		}
		if (a->flags & SSH2_FILEXFER_ATTR_UIDGID) 
		{
			status = SSH2_FX_FAILURE;			
		}
	}
	send_status(id, status);
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





static void
process_opendir(void)
{
	DIR *dirp = NULL;
	char *path;
	int handle, status = SSH2_FX_FAILURE;
	u_int32_t id;

	id = get_int();
	path = get_string(NULL);
	ChangeSlashToBackSlash(path);

	TRACE("opendir id %u path %s", id, path);	
	dirp = opendir(path);
	if (dirp == NULL) {
		status = errno_to_portable(errno);
	} else {
		handle = handle_new(HANDLE_DIR, path, 0, dirp);
		if (handle < 0) {
			closedir(dirp);
		} else {
			send_handle(id, handle);
			status = SSH2_FX_OK;
		}

	}
	if (status != SSH2_FX_OK)
		send_status(id, status);
	xfree(path);
}

#define MAX_ENTRY_PER_READDIR_CALL 100
extern int WFD_to_stat(WIN32_FIND_DATA *wfd, struct stat* st);

static void
process_readdir(void)
{
	BOOL bSendStatusEOF = FALSE;
	BOOL bSendStatusFailure = FALSE;
	DIR *dirp;
//	struct dirent *dp;
	char *path;
	int handle;
	u_int32_t id;

	id = get_int();
	handle = get_handle();
	TRACE("readdir id %u handle %d", id, handle);
	dirp = handle_to_dir(handle);
	path = handle_to_name(handle);
	if (dirp == NULL || path == NULL) {
		send_status(id, SSH2_FX_FAILURE);
	} else 
	{
		BOOL bFileFound = FALSE;
		int count = 0;
		WIN32_FIND_DATA wfd;
		int nstats = 10;
		Stat *stats;
		
		stats = malloc(nstats * sizeof(Stat));
		
		
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

		if (!bFileFound)
		{
			if (GetLastError() == ERROR_NO_MORE_FILES)
			{
				send_status(id, SSH2_FX_EOF);
			}
			else
			{
				send_status(id, SSH2_FX_FAILURE);
			}
		}


		while (bFileFound)
		{
			struct stat st;
			

			if (count >= nstats) 
			{
				nstats *= 2;
				stats = xrealloc(stats, nstats * sizeof(Stat));
			}

			WFD_to_stat(&wfd,&st);
			stat_to_attrib(&st,&stats[count].attrib);
			stats[count].name = strdupUnicodeToAscii(wfd.cFileName);
			stats[count].long_name = long_name(stats[count].name, &st);
			count++;

			if (FindNextFile(dirp->hSearch, &wfd) == FALSE)
			{
				bFileFound = FALSE;				
			}		

			
			if (count > MAX_ENTRY_PER_READDIR_CALL)
			{
				break;
			}
			
		}
		if (count)
		{
			send_names(id, count, stats);
			for (i = 0; i < count; i++) 
			{
				xfree(stats[i].name);
				xfree(stats[i].long_name);
			}
		}
		xfree(stats);	
	}
}

static void process_remove(void)
{
	char *name;
	u_int32_t id;
	int status = SSH2_FX_FAILURE;
	int ret;

	id = get_int();
	name = get_string(NULL);
	ChangeSlashToBackSlash(name);

	TRACE("remove id %u name %s", id, name);
	ret = unlink(name);
	status = (ret == -1) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	xfree(name);
}

static void
process_mkdir(void)
{
	Attrib *a;
	u_int32_t id;
	char *name;
	int status = SSH2_FX_FAILURE;
	int ret;

	
	id = get_int();
	name = get_string(NULL);
	ChangeSlashToBackSlash(name);

	a = get_attrib();	
	TRACE("mkdir id %u name %s ", id, name);
	
	ret = mkdir(name, 0);
	
	status = (ret) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	xfree(name);
}

static void
process_rmdir(void)
{
	u_int32_t id;
	char *name;
	int status;
	BOOL bRet;
	WCHAR* wzDirectoryName;

	id = get_int();
	name = get_string(NULL);
	ChangeSlashToBackSlash(name);

	TRACE("rmdir id %u name %s", id, name);
	
	wzDirectoryName = strdupAsciiToUnicode(name);
	bRet = RemoveDirectory(wzDirectoryName);
	free(wzDirectoryName);
		
	status = (bRet == FALSE) ? errno_to_portable(errno) : SSH2_FX_OK;
	send_status(id, status);
	xfree(name);
}





char szCurrentDirectory[MAX_PATH];

char * realpath(const char *path, char resolved[MAX_PATH])
{
	char* result = NULL;
	WCHAR wcResolved[MAX_PATH];
	WCHAR* wcPath = strdupAsciiToUnicode(path);
	if (CeGetCanonicalPathName(wcPath,wcResolved,sizeof(wcResolved),0) != 0)
	{		
		unicodeToAscii(wcResolved,resolved);		
		ChangeBackSlashToSlash(resolved);
		result = resolved;
	}
	free(wcPath);
	return result;
}

static void
process_realpath(void)
{
	char resolvedname[MAXPATHLEN];
	u_int32_t id;
	char *path;

	id = get_int();
	path = get_string(NULL);
	ChangeSlashToBackSlash(path);

	if (path[0] == '\0') {
		xfree(path);
		path = xstrdup(".");
	}
	TRACE("realpath id %u path %s", id, path);
	if (realpath(path, resolvedname) == NULL) {
		send_status(id, errno_to_portable(errno));
	} else {
		Stat s;
		attrib_clear(&s.attrib);
		s.name = s.long_name = resolvedname;
		send_names(id, 1, &s);
	}
	

	xfree(path);
}

static void
process_rename(void)
{
	u_int32_t id;
	char *oldpath, *newpath;
	WCHAR *woldpath, *wnewpath;
	int status;
//	struct stat sb;

	id = get_int();
	oldpath = get_string(NULL);
	newpath = get_string(NULL);
	ChangeSlashToBackSlash(oldpath);
	ChangeSlashToBackSlash(newpath);
	woldpath = strdupAsciiToUnicode(oldpath);
	wnewpath = strdupAsciiToUnicode(newpath);
	
	

	TRACE("rename id %u old %s new %s", id, oldpath, newpath);	

	if (MoveFile(woldpath, wnewpath) == FALSE)
	{
		status = errno_to_portable(errno);
	}	
	else
	{
		status = SSH2_FX_OK;
	}
		
	send_status(id, status);
	xfree(woldpath);
	xfree(wnewpath);
	xfree(oldpath);
	xfree(newpath);
}

static void
process_readlink(void)
{
	u_int32_t id;
//	int len;
//	char buf[MAXPATHLEN];
	char *path;

	id = get_int();
	path = get_string(NULL);
	TRACE("readlink id %u path %s", id, path);

	// Link are not supported on CE
	send_status(id, SSH2_FX_FAILURE); 

	xfree(path);
}

static void
process_symlink(void)
{
	u_int32_t id;
	char *oldpath, *newpath;

	id = get_int();
	oldpath = get_string(NULL);
	newpath = get_string(NULL);
	TRACE("symlink id %u old %s new %s", id, oldpath, newpath);

	// Link are not supported on CE
	send_status(id, SSH2_FX_FAILURE); 
	
	xfree(oldpath);
	xfree(newpath);
}

static void
process_extended(void)
{
	u_int32_t id;
	char *request;

	id = get_int();
	request = get_string(NULL);
	send_status(id, SSH2_FX_OP_UNSUPPORTED);		/* MUST */
	xfree(request);
}

/* stolen from ssh-agent */

static int
process(void)
{
	u_int msg_len;
	u_int buf_len;
	u_int consumed;
	u_int type;
	u_char *cp;

	buf_len = buffer_len(&iqueue);
	if (buf_len < 5)
		return 0;		/* Incomplete message. */
	cp = buffer_ptr(&iqueue);
	msg_len = GET_32BIT(cp);
	if (msg_len > SFTP_MAX_MSG_LENGTH) {
		error("bad message ");
		return 11;
	}
	if (buf_len < msg_len + 4)
		return 0;
	buffer_consume(&iqueue, 4);
	buf_len -= 4;
	type = buffer_get_char(&iqueue);
		switch (type) {
	case SSH2_FXP_INIT:
		process_init();
		break;
	case SSH2_FXP_OPEN:
		process_open();
		break;
	case SSH2_FXP_CLOSE:
		process_close();
		break;
	case SSH2_FXP_READ:
		process_read();
		break;
	case SSH2_FXP_WRITE:
		process_write();
		break;
	case SSH2_FXP_LSTAT:
		process_lstat();
		break;
	case SSH2_FXP_FSTAT:
		process_fstat();
		break;
	case SSH2_FXP_SETSTAT:
		process_setstat();
		break;
	case SSH2_FXP_FSETSTAT:
		process_fsetstat();
		break;
	case SSH2_FXP_OPENDIR:
		process_opendir();
		break;
	case SSH2_FXP_READDIR:
		process_readdir();
		break;
	case SSH2_FXP_REMOVE:
		process_remove();
		break;
	case SSH2_FXP_MKDIR:
		process_mkdir();
		break;
	case SSH2_FXP_RMDIR:
		process_rmdir();
		break;
	case SSH2_FXP_REALPATH:
		process_realpath();
		break;
	case SSH2_FXP_STAT:
		process_stat();
		break;
	case SSH2_FXP_RENAME:
		process_rename();
		break;
	case SSH2_FXP_READLINK:
		process_readlink();
		break;
	case SSH2_FXP_SYMLINK:
		process_symlink();
		break;
	case SSH2_FXP_EXTENDED:
		process_extended();
		break;
	default:
		error("Unknown message %d", type);
		break;
	}
	/* discard the remaining bytes from the current packet */
	if (buf_len < buffer_len(&iqueue))
		fatal("iqueue grows");
	consumed = buf_len - buffer_len(&iqueue);
	if (msg_len < consumed)
		fatal("msg_len %d < consumed %d", msg_len, consumed);
	if (msg_len > consumed)
		buffer_consume(&iqueue, msg_len - consumed);

	return 0;
}

#define STDIN	_fileno(stdin)
#define STDOUT	_fileno(stdout)



int
sftp_main()
{
	int result = 0;
//	fd_set *rset, *wset;
	//int in, out, max;
	ssize_t olen;//, set_size;
	DWORD dwSelectMask = (1<<0) | (1<<1);
	DWORD dwIsSet;

	strcpy(szCurrentDirectory,"/");

	/* Ensure that fds 0, 1 and 2 are open or directed to /dev/null */
	//sanitise_stdfd();

	/* XXX should use getopt */

//	__progname = ssh_get_progname(av[0]);
	handle_init();

#ifdef DEBUG_SFTP_SERVER
	log_init("sftp-server", SYSLOG_LEVEL_DEBUG1, SYSLOG_FACILITY_AUTH, 0);
#endif

//	in = dup(STDIN_FILENO);
//	out = dup(STDOUT_FILENO);

#ifdef HAVE_CYGWIN
	setmode(in, O_BINARY);
	setmode(out, O_BINARY);
#endif

/*
	max = 0;
	if (in > max)
		max = in;
	if (out > max)
		max = out;
*/
	
	buffer_init(&iqueue);
	buffer_init(&oqueue);

/*
	set_size = howmany(max + 1, NFDBITS) * sizeof(fd_mask);
	rset = (fd_set *)xmalloc(set_size);
	wset = (fd_set *)xmalloc(set_size);
*/

	for (;;) {
		/*
		memset(rset, 0, set_size);
		memset(wset, 0, set_size);

		FD_SET(in, rset);
		*/

		olen = buffer_len(&oqueue);
		/*
		if (olen > 0)
			FD_SET(out, wset);

		if (select(max+1, rset, wset, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			exit(2);
		}
*/
		if (olen)
		{
			dwSelectMask = INPUT_MASK | OUTPUT_MASK;
		}
		else
		{
			dwSelectMask = INPUT_MASK;
		}

		if (DeviceIoControl((HANDLE)STDIN,IOCTL_SELECT,&dwSelectMask,sizeof(dwSelectMask),&dwIsSet,sizeof(dwIsSet),NULL,NULL) == FALSE) 
		{			
			result = 2;
			break;
		}
		
		/* copy stdin to iqueue */
		//if (FD_ISSET(in, rset)) 
		if (dwIsSet & INPUT_MASK)
		{
			BOOL bRet;
			char buf[4*4096];
			DWORD dwNbRead;
			bRet = ReadFile((HANDLE)STDIN, buf, sizeof(buf),&dwNbRead,NULL);
			if (bRet == FALSE) {
				error("read error");
				result = 1;
				break;
			} else if (dwNbRead == 0) {
				debug("read eof");
				result = 0;
				break;
			} else  {
				buffer_append(&iqueue, buf, dwNbRead);
			}
		}
		/* send oqueue to stdout */
		//if (FD_ISSET(STDOUT, wset))
		if (dwIsSet & OUTPUT_MASK)
		{
			BOOL bRet;
			DWORD dwNbWritten;
			bRet = WriteFile((HANDLE)STDOUT, buffer_ptr(&oqueue), olen,&dwNbWritten,NULL);
			
			if (bRet == FALSE) {
		
				error("write error");
				result = 1;
				break;
			} else {
				buffer_consume(&oqueue, dwNbWritten);
			}
		}
		/* process requests from client */
		result = process();
		if (result)
		{
			break;
		}
	}

	buffer_free(&iqueue);
	buffer_free(&oqueue);
	return result;
}
