// AddUser.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Ntlmssp.h"

int _tmain(int argc, TCHAR *argv[], TCHAR *envp[])
{
    NTLMSetUserInfo(argv[1],argv[2]);
    return 0;
}

