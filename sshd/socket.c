/* This file is part of the open SSH port to Windows CE. It's not present in the original open SSH project.
*/

#include <windows.h>
#include "sys\socket.h"

size_t SocketRead(int s, void *buf, size_t len)
{
	 size_t result;
	 //RETAILMSG(1,(TEXT("SocketRead(%d,0x%x,%d)"),s,buf,len));
	 result = recv(s,buf,len,0);
	 //RETAILMSG(1,(TEXT("SocketRead(%d,0x%x,%d) returned %d"),s,buf,len,result));
	 return result; 
}
size_t SocketWrite(int s, void *buf, size_t len)
{
	size_t result;
	//RETAILMSG(1,(TEXT("SocketWrite(%d,0x%x,%d)"),s,buf,len));
	result = send(s,buf,len,0);
	//RETAILMSG(1,(TEXT("SocketWrite(%d,0x%x,%d) returned %d"),s,buf,len,result));
	return result;
}
