//-------------------------------------------------------------------------
// <copyright file="time.h" company="Adeneo">
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

#ifndef __SSHCOMPAT__TIME_H__
#define __SSHCOMPAT__TIME_H__

#include <windows.h>

struct tm
{
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
	int tm_wday;
	int tm_yday;
	int tm_isdst;
};



#ifdef __cplusplus
extern "C" {
#endif

struct tm* 	localtime(const time_t* clock,struct tm* pst_tm);
struct tm* 	gmtime(const time_t *clock,struct tm* pst_tm);
char * 		ctime(const time_t* t, char *cbuf);
char * 		asctime(struct tm *t, char *cbuf);
time_t 		ConvertWindowsToUnixTime(FILETIME* ft);
time_t		time(time_t* t);

#ifdef __cplusplus
}
#endif

#endif // __SSHCOMPAT__TIME_H__
