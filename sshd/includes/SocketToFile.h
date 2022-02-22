#define NAME_BASE L"SF"	//SF stands for for Socket-to-File


int CreateListeningSocket(SOCKET *pListenningSock,struct sockaddr_in *pAddr);
int FindFreeInstanceIndex();
void PrepareRegistryForInstance(DWORD dwIndex,DWORD dwLocalPort,WCHAR** wzKey, BOOL bUseTTY);
