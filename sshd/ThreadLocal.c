#include "ThreadLocal.h"
#include "auth-options.h"

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
		//pStorage->none_enabled = 1;
		pStorage->forced_tun_device = -1; 
		pStorage->IPv4or6 = AF_UNSPEC;
	}
	return pStorage;
}



void ReleaseThreadLocalStorage(T_SSHD_THREAD_LOCAL_VARIABLES* pSourceStorage)
{
	
	XFREE_IF_NOT_NULL(pSourceStorage->server_version_string);
	XFREE_IF_NOT_NULL(pSourceStorage->client_version_string);
	XFREE_IF_NOT_NULL(pSourceStorage->session_id2);
	XFREE_IF_NOT_NULL(pSourceStorage->forced_command);

	XFREE_IF_NOT_NULL(pSourceStorage->attack_detector_hash);
	XFREE_IF_NOT_NULL(pSourceStorage->canonical_host_ip);
	XFREE_IF_NOT_NULL(pSourceStorage->remote_ip);
	XFREE_IF_NOT_NULL(pSourceStorage->canonical_host_name);
	
	
	while (pSourceStorage->custom_environment) {
		struct envstring *ce = pSourceStorage->custom_environment;
		pSourceStorage->custom_environment = ce->next;
		xfree(ce->s);
		xfree(ce);
	}

	
	XFREE_IF_NOT_NULL(pSourceStorage->xxx_kex);	
	XFREE_IF_NOT_NULL(pSourceStorage->the_authctxt);

	/* todo release what has to be released*/
	
	LocalFree(pSourceStorage);
}
