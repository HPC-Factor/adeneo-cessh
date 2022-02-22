#include "ThreadLocal.h"

T_SSHD_THREAD_LOCAL_VARIABLES* AllocateThreadLocalStorage(T_SSHD_THREAD_LOCAL_VARIABLES* pSourceStorage)
{
	T_SSHD_THREAD_LOCAL_VARIABLES* pStorage;
	
	pStorage = LocalAlloc(LMEM_FIXED,sizeof(T_SSHD_THREAD_LOCAL_VARIABLES));
	if (pStorage == NULL)
	{
		return NULL;
	}
	
	if (pSourceStorage)
	{
		memcpy(pStorage,pSourceStorage,sizeof(T_SSHD_THREAD_LOCAL_VARIABLES));		
	}	
	else	
	{
		//Clear the structure
		memset(pStorage,0,sizeof(T_SSHD_THREAD_LOCAL_VARIABLES));
		
		// Set non-zero variables
		memcpy(pStorage->ciphers,&ciphersInitValue,sizeof(ciphersInitValue));
		memcpy(pStorage->devices,&devicesInitValue,sizeof(devicesInitValue));
		pStorage->max_packet_size = 32768;
		pStorage->connection_out = -1;
		pStorage->connection_in = -1;	
		pStorage->remote_port = -1;
		pStorage->none_enabled = 1;
		pStorage->forced_tun_device = -1; 
		pStorage->IPv4or6 = AF_UNSPEC;
	}
	return pStorage;
}
