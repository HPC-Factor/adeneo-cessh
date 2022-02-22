// SFTP.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

extern int sftp_main();
int _tmain(int argc, TCHAR *argv[], TCHAR *envp[])
{
    //_tprintf(_T("Hello World!\n"));
	sftp_main();
    return 0;
}

