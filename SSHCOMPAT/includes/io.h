//-------------------------------------------------------------------------
// <copyright file="io.h" company="Adeneo">
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//    The use and distribution terms for this software are covered by the
//    Limited Permissive License (Ms-LPL) 
//    which can be found in the file LPL.txt at the root of this distribution.
//    By using this software in any fashion, you are agreeing to be bound by
//    the terms of this license.
//
//    The software is licensed "as-is."
//
//    You must not remove this notice, or any other, from this software.
// </copyright> 
//-------------------------------------------------------------------------

#ifndef __SSHCOMPAT__IO_H__
#define __SSHCOMPAT__IO_H__




#define _O_RDONLY	0x0001
#define _O_WRONLY	0x0002
#define _O_RDWR 	0x0004
#define _O_APPEND	0x0008
#define _O_CREAT	0x0100
#define _O_TRUNC	0x0200
#define _O_EXCL 	0x0400
#define _O_TEXT 	0x4000
#define _O_BINARY	0x8000


#define O_RDONLY	_O_RDONLY
#define O_WRONLY	_O_WRONLY
#define O_RDWR		_O_RDWR
#define O_APPEND	_O_APPEND
#define O_CREAT 	_O_CREAT
#define O_TRUNC 	_O_TRUNC
#define O_EXCL		_O_EXCL
#define O_TEXT		_O_TEXT
#define O_BINARY	_O_BINARY



#ifdef __cplusplus
extern "C" {
#endif

int 	_open(const char* filename, int flags);
FILE* 	_fdopen(int fildes, const char *mode);
int 	_wopen(const unsigned short* filename, int flags, int mode);
int 	_close(int fd);
long	_lseek(int fd, long offset, int whence);
int 	_read(int fd, void *buffer, unsigned int count);
int 	_write(int fd, const void *buffer, unsigned int count);
int 	_unlink(const char *pathname);
void 	_rewind(FILE *stream);
int 	_truncate(const char *path, long length);
int 	_ftruncate(int fd, long length);
int 	_mkdir(const char *pathname, int mode);


#ifdef __cplusplus
}
#endif

#define open _open
#define fdopen _fdopen
#define wopen _wopen
#define close _close
#define lseek _lseek
#define read _read
#define write _write
#define unlink _unlink
#define rewind _rewind
#define truncate _truncate
#define ftruncate _ftruncate
#define mkdir _mkdir


#endif // __SSHCOMPAT__IO_H__
