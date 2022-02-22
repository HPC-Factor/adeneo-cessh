#include <Winsock2.h>
#include <ws2tcpip.h>

#define __getsockopt(a,b,c,d,e) getsockopt((a),(b),(c),(char*)(d),(e))
#define __setsockopt(a,b,c,d,e) setsockopt((a),(b),(c),(char*)(d),(e))

#define SocketClose closesocket

#define socketpair(w,x,y,z) CreateSocketPair(z)
#ifdef __cplusplus
extern "C" {
#endif

size_t SocketRead(int s, void *buf, size_t len);
size_t SocketWrite(int s, void *buf, size_t len);
int CreateSocketPair(SOCKET *pair);

#ifdef __cplusplus
}
#endif

