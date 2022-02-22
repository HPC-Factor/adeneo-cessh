//-------------------------------------------------------------------------
// <copyright file="time.c" company="Adeneo">
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
//-----------------------------------------------------------------------------
//! \addtogroup	SSHCOmpat
//! @{
//!
//! All rights reserved ADENEO SAS 2005
//!
//! \file		time.c
//!
//! \brief		
//!
//! 
//-----------------------------------------------------------------------------

// System include
#include <windows.h>
#include "time.h"
#include "errno.h"


static const char* Days[] = {
	"Sun","Mon","Tue","Wed","Thu","Fri","Sat"
};
static const char* Months[] = {
	"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"
};


static BOOL g_bInit = FALSE;
static FILETIME	ftDateZero;
static UINT64	ft64DateZero;

void initFileModule()
{
	static const SYSTEMTIME s ={
		1970,
		1,
		0, 
		1, 
		0, 
		0, 
		0, 
		0
	};
	// On UNIX system, the zero date is january 1st 1970
	SystemTimeToFileTime(&s,&ftDateZero);
	ft64DateZero = ((UINT64)ftDateZero.dwHighDateTime << 32) | ftDateZero.dwLowDateTime;
	g_bInit = TRUE;
}

time_t ConvertWindowsToUnixTime(FILETIME* ft)
{
	UINT64 ft64 = ((UINT64)ft->dwHighDateTime << 32) | ft->dwLowDateTime;

	if (!g_bInit)
	{
		initFileModule();
	}
	//ft64 = number of 100-nanosecond intervals since January 1, 1601.

	// sanity check
	if (ft64 < ft64DateZero)
	{
		SET_ERRNO( -1 );
		return -1;
	}	
	
	ft64 -= ft64DateZero; // ft64 = number of 100-nanosecond since  1 january 1970
	// divide ft by 10,000,000 to convert from 100-nanosecond units to seconds
	ft64 /= 10000000;

	// bound check result
	if (ft64 > 0xFFFFFFFF)
	{
		SET_ERRNO( -1 );
		return -1;		// value is too big to return in time_t
	}

	return (time_t)ft64;
}


FILETIME ConvertUnixTimeToWindowsFileTime (const time_t* unixFileTime)
{
	FILETIME ft;
	UINT64 ft64;

	if (!g_bInit)
	{
		initFileModule();
	}


	ft64 = *unixFileTime;
	ft64 *= 10000000;
	ft64 += ft64DateZero;
	ft.dwHighDateTime = (DWORD) (ft64 >> 32);
	ft.dwLowDateTime = (DWORD) (ft64 & 0xFFFFFFFF);

	return ft;
}

time_t time(time_t* t)
{
	SYSTEMTIME		stNow;
	FILETIME		ftNow;
	time_t			tt;

	// get system time
	GetSystemTime(&stNow);
	// convert it to file time 
	if (!SystemTimeToFileTime(&stNow, &ftNow))
	{
		SET_ERRNO( -1 );
		return -1;
	}
	// convert it to the unix-fashion time
	tt = ConvertWindowsToUnixTime(&ftNow);

	if (t != NULL)
		*t = tt;
	return tt;
}


int dayInYear(int year, int month, int day)
{
	int		result;
	int		i;
	BOOL	isLeapYear = FALSE;
	static const daysInMonth[12]={31,28,31,30,31,30,31,31,30,31,30,31};
	
	result = day-1;
	for (i=0;i<month;i++)
	{
		result += daysInMonth[i];
		
		if (i == 1)
		{
			//februray is a special case
			// check if february has 28 or 29 days
			if ((year % 4 == 0) && !(year % 100 == 0) && (year % 400 == 0))
			{
				result++;
			}			
		}
	}

	return result;
}



struct tm* gmtime(const time_t* unixFileTime,struct tm* pst_tm)
{
	FILETIME				ftUtc;	
	SYSTEMTIME				stUtc;

	if (unixFileTime == NULL)
		return NULL;	

	// convert unixFileTime (time_t) to FILETIME
	ftUtc = ConvertUnixTimeToWindowsFileTime(unixFileTime);

	// convert to SYSTEMTIME
	if (!FileTimeToSystemTime(&ftUtc, &stUtc))
		return NULL;

	// fill return structure
	pst_tm->tm_year = stUtc.wYear-1900;
	pst_tm->tm_mon = stUtc.wMonth-1;
	pst_tm->tm_mday = stUtc.wDay;
	pst_tm->tm_yday = dayInYear(stUtc.wYear, stUtc.wMonth-1, stUtc.wDay);	
	pst_tm->tm_wday = stUtc.wDayOfWeek;
	pst_tm->tm_hour = stUtc.wHour;
	pst_tm->tm_min = stUtc.wMinute;
	pst_tm->tm_sec = stUtc.wSecond;
	
	pst_tm->tm_isdst = 0;


	return pst_tm;
}


struct tm* localtime(const time_t* unixFileTime,struct tm* pst_tm)
{
	TIME_ZONE_INFORMATION	tzi;
	DWORD					tziResult;
	
	FILETIME				ftLocal;
	FILETIME				ftUtc;
	SYSTEMTIME				stLocal;

	if (unixFileTime == NULL)
		return NULL;	

	// convert unixFileTime (time_t) to FILETIME
	ftUtc = ConvertUnixTimeToWindowsFileTime(unixFileTime);


	if (!FileTimeToLocalFileTime(&ftUtc,&ftLocal))
	{
		return NULL;
	}

	// convert to SYSTEMTIME
	if (!FileTimeToSystemTime(&ftLocal, &stLocal))
	{
		return NULL;
	}

	// fill return structure
	pst_tm->tm_year = stLocal.wYear-1900;
	pst_tm->tm_mon = stLocal.wMonth-1;
	pst_tm->tm_mday = stLocal.wDay;
	pst_tm->tm_yday = dayInYear(stLocal.wYear, stLocal.wMonth-1, stLocal.wDay);	
	pst_tm->tm_wday = stLocal.wDayOfWeek;
	pst_tm->tm_hour = stLocal.wHour;
	pst_tm->tm_min = stLocal.wMinute;
	pst_tm->tm_sec = stLocal.wSecond;
	

	// determine if we're operating in daylight savings time
	tziResult = GetTimeZoneInformation(&tzi);

	if (tziResult == TIME_ZONE_ID_UNKNOWN)
		pst_tm->tm_isdst = -1;
	else if (tziResult == TIME_ZONE_ID_STANDARD)
		pst_tm->tm_isdst = 0;
	else if (tziResult == TIME_ZONE_ID_DAYLIGHT)
		pst_tm->tm_isdst = 1;


	return pst_tm;
}


char * asctime(struct tm *ptm, char *cbuf)
{
	sprintf(cbuf,"%s %s %2d %2d:%02d:%2d %4d\n",Days[ptm->tm_wday],Months[ptm->tm_mon],ptm->tm_mday,ptm->tm_hour,ptm->tm_min,ptm->tm_sec,ptm->tm_year+1900);
	return(cbuf);
}


char * ctime(const time_t* t, char *cbuf)
{
	struct tm st_tm;
	return(asctime(localtime(t,&st_tm),cbuf));
}


// End of Doxygen group SSHCompat
//! @}