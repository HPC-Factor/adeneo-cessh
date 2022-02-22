/* This file is part of the open SSH port to Windows CE. It's not present in the original open SSH project.
*/
#include "windows.h"
#include "includes.h"
#include "pathnames.h"
#include "strings.h"


char* szPATH_SSH_SYSTEM_HOSTFILE;
char* szPATH_SSH_SYSTEM_HOSTFILE2;
char* szPATH_SERVER_CONFIG_FILE;
char* szPATH_HOST_KEY_FILE;	
char* szPATH_HOST_DSA_KEY_FILE;
char* szPATH_HOST_RSA_KEY_FILE;
char* szPATH_DH_MODULI;		
char* szPATH_DH_PRIMES;
char* szPATH_SSH_HOSTS_EQUIV;
char* szPATH_SSH_USER_PERMITTED_KEYS2;
char* szPATH_SSH_USER_PERMITTED_KEYS;






static LONG ReadRegistryString(HKEY hkeyRoot, LPCTSTR lpSubkey, LPCTSTR lpValueName, LPCTSTR buf,DWORD bufLen)
{
    HKEY hkey;
    LONG lRet;
//Open the registry
    lRet = RegOpenKeyEx(hkeyRoot,lpSubkey, 0, 0, &hkey);
    if (lRet == ERROR_SUCCESS)
    {
		DWORD dwBufLen = bufLen;
		DWORD dwType;
	//Read Value in the Registry: 
		lRet = RegQueryValueEx(hkey,lpValueName, NULL, &dwType, (LPBYTE) buf, &dwBufLen);		
	//Close
		RegCloseKey(hkey);    
	}
	return lRet;         
}

char* AppendSSHDirectory(char*szSSHDirectory, char* s)
{
	static char buf[MAX_PATH];
	sprintf(buf,"%s%s",szSSHDirectory,s);
	return buf;
}

void initPathNames()
{
	char* szSSHDirectory;
	WCHAR *wzSSHDirectory = malloc(MAX_PATH*sizeof(WCHAR));
	if (ReadRegistryString(HKEY_LOCAL_MACHINE,L"COMM\\SSHD",L"SSHRootDir",wzSSHDirectory,MAX_PATH*sizeof(WCHAR)) != ERROR_SUCCESS)
	{
		szSSHDirectory = xstrdup(DEFAULT_SSHDIR);
	}
	else
	{
		szSSHDirectory = strdupUnicodeToAscii(wzSSHDirectory);
	}
	free(wzSSHDirectory);


	szPATH_SSH_SYSTEM_HOSTFILE		= xstrdup(AppendSSHDirectory(szSSHDirectory, INIT_VAL_PATH_SSH_SYSTEM_HOSTFILE));
	szPATH_SSH_SYSTEM_HOSTFILE2		= xstrdup(AppendSSHDirectory(szSSHDirectory, INIT_VAL_PATH_SSH_SYSTEM_HOSTFILE2));
	szPATH_SERVER_CONFIG_FILE		= xstrdup(AppendSSHDirectory(szSSHDirectory, INIT_VAL_PATH_SERVER_CONFIG_FILE));
	szPATH_HOST_KEY_FILE			= xstrdup(AppendSSHDirectory(szSSHDirectory, INIT_VAL_PATH_HOST_KEY_FILE));
	szPATH_HOST_DSA_KEY_FILE		= xstrdup(AppendSSHDirectory(szSSHDirectory, INIT_VAL_PATH_HOST_DSA_KEY_FILE));
	szPATH_HOST_RSA_KEY_FILE		= xstrdup(AppendSSHDirectory(szSSHDirectory, INIT_VAL_PATH_HOST_RSA_KEY_FILE));
	szPATH_DH_MODULI				= xstrdup(AppendSSHDirectory(szSSHDirectory, INIT_VAL_PATH_DH_MODULI));
	szPATH_DH_PRIMES				= xstrdup(AppendSSHDirectory(szSSHDirectory, INIT_VAL_PATH_DH_PRIMES));
	szPATH_SSH_HOSTS_EQUIV			= xstrdup(AppendSSHDirectory(szSSHDirectory, INIT_VAL_PATH_SSH_HOSTS_EQUIV));
	szPATH_SSH_USER_PERMITTED_KEYS2 = xstrdup(AppendSSHDirectory(szSSHDirectory, INIT_VAL_PATH_SSH_USER_PERMITTED_KEYS2));
	szPATH_SSH_USER_PERMITTED_KEYS	= xstrdup(AppendSSHDirectory(szSSHDirectory, INIT_VAL_PATH_SSH_USER_PERMITTED_KEYS));

	free(szSSHDirectory);
}
