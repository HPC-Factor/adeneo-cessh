//-------------------------------------------------------------------------
// <copyright file="stat.h" company="Adeneo">
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


#ifndef __SSHCOMPAT__STAT_H__
#define __SSHCOMPAT__STAT_H__


#ifdef __cplusplus
extern "C" {
#endif

#define _S_IFMT     00170000
#define _S_IFDIR    00040000     
#define S_IFCHR     00020000     
#define S_IFIFO     00010000     
#define S_IFREG     00100000     
#define S_IREAD     00000400     
#define S_IWRITE    00000200     
#define S_IEXEC     00000100     
#define S_IFSOCK 	00140000
#define S_IFLNK  	00120000
#define S_IFBLK  	00060000
#define S_ISUID  	00004000
#define S_ISGID  	00002000
#define S_ISVTX  	00001000

# define S_IXUSR			0000100	/* execute/search permission, */
# define S_IXGRP			0000010	/* execute/search permission, */
# define S_IXOTH			0000001	/* execute/search permission, */
# define _S_IWUSR			0000200	/* write permission, */
# define S_IWUSR			_S_IWUSR	/* write permission, owner */
# define S_IWGRP			0000020	/* write permission, group */
# define S_IWOTH			0000002	/* write permission, other */
# define S_IRUSR			0000400	/* read permission, owner */
# define S_IRGRP			0000040	/* read permission, group */
# define S_IROTH			0000004	/* read permission, other */
# define S_IRWXU			0000700	/* read, write, execute */
# define S_IRWXG			0000070	/* read, write, execute */
# define S_IRWXO			0000007	/* read, write, execute */

struct stat
{
	unsigned int	st_dev;
	unsigned int	st_ino;
	unsigned short	st_mode;
	short			st_nlink;
	short			st_uid;
	short			st_gid;
	unsigned int	st_rdev;
	unsigned long	st_size;
	time_t			st_atime;
	time_t			st_mtime;
	time_t			st_ctime;
};


int stat(const char *szFileName, struct stat *buf);
int lstat(const char* szFileName, struct stat* st);
int fstat(int fd, struct stat* st);



#ifdef __cplusplus
}
#endif


#endif // __SSHCOMPAT__STAT_H__
