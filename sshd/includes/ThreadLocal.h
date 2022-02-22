#ifndef _THREAD_LOCAL_H_
#define _THREAD_LOCAL_H_

#include "includes.h"
#include "openbsd-compat\sys-queue.h"
#include "openbsd-compat\openssl-compat.h"
#include "auth.h"
#include "channels.h"
#include "packet.h"
#include "session.h"
#include "dispatch.h"
#include "zlib.h"
#include "ssh.h"


#ifdef USE_CIPHER_ACSS	
#define MAX_CIPHER 19
#else
#define MAX_CIPHER 18
#endif

#ifdef MAX_AUTH_DEVICES
#error "MAX_AUTH_DEVICES should not be defined"
#endif
#define MAX_AUTH_DEVICES  4
#ifdef MAX_SESSIONS
#error "MAX_SESSIONS should not be defined"
#endif
#define MAX_SESSIONS 10

typedef struct {                      
Cipher ciphers[MAX_CIPHER]		;
KbdintDevice *devices[MAX_AUTH_DEVICES]	;

/* default maximum packet size (32768)*/                           
u_int max_packet_size      ;
/*
 * This variable contains the file descriptors used for communicating with
 * the other side.  connection_in is used for reading; connection_out for
 * writing.  These can be the same descriptor, in which case it is assumed to
 * be a socket.
 */
int connection_out         ;
int connection_in          ;

int remote_port            ;
//int none_enabled           ; /* authentication "none" is allowed only one time */ JJH todo : figure out what to do with that
int forced_tun_device      ; /* "tunnel=" option. */
int IPv4or6                ; /* AF_UNSPEC or AF_INET or AF_INET6 */

char* server_version_string; // Name of the server
u_int session_id2_len      ;
u_char * session_id2       ;
/*
 * the client's version string, passed by sshd2 in compat mode. if != NULL,
 * sshd will skip the version-number exchange
 */
char* client_version_string;

int did_channel_handler_init;                          

/*
* If this is true, all opens are permitted.  This is the case on the server
* on which we have to trust the client anyway, and the user could do
* anything after logging in anyway.
*/
int all_opens_permitted        ;
/* Number of permitted host/port pairs in the array. */
int num_permitted_opens        ;
/*
* Size of the channel array.  All slots of the array must always be
* initialized (at least the type field); unused slots set to NULL
*/
u_int channels_alloc       ;
/*
 * Pointer to an array containing all allocated channels.  The array is
 * dynamically extended as needed.
 */
Channel **channels         ;
int deflate_failed             ;
int inflate_failed             ;
int compress_init_recv_called  ;
int compress_init_send_called  ;
/* roundup current message to extra_pad bytes */
u_char extra_pad           ;
int packet_set_maxsize_called;
int packet_set_interactive_called;
int disconnecting          ;
u_int packet_length        ;
int rekeying               ;
/* Set to true if we are authenticated. */
int after_authentication       ;
/* Set to true if we are the server side. */
int server_side                ;
/* Set to true if the connection is interactive. */
int interactive_mode           ;
/* Flag indicating whether this module has been initialized. */
int initialized                ;
/* Flag indicating whether packet compression/decompression is enabled. */
int packet_compression         ;
int compression_buffer_ready   ;
/* Protocol flags for the remote side. */
u_int remote_protocol_flags	   ;
u_int16_t *attack_detector_hash;
u_int32_t attack_detector_hash_size;
int datafellows                ;
int compat20                   ;
int compat13                   ;
char *canonical_host_ip	       ;
char *remote_ip                ;
char *canonical_host_name        ;
struct envstring *custom_environment; /* "environment=" options. */
char* forced_command       		;/* "command=" option. */
/* Flags set authorized_keys flags */
int no_pty_flag                	;
int no_port_forwarding_flag    	;

int session_new_did_init       	;
int do_cleanup_called          	;
int child_terminated           	;/* The child has terminated. */
int client_alive_timeouts	;
int connection_closed		; /* Connection to client closed. */                      

Session	sessions[MAX_SESSIONS];
char host_hash_encoded[1024];
u_char kex_dh_hash_digest[EVP_MAX_MD_SIZE];
u_char kexgex_hash_digest[EVP_MAX_MD_SIZE];
int auth_debug_init		;
Buffer auth_debug		;
struct passwd fakePasswd;
dispatch_fn *dispatch[DISPATCH_MAX];
Newkeys *current_keys[MODE_MAX];
u_int64_t max_blocks_in		;
u_int64_t max_blocks_out	;
u_int32_t rekey_limit		;
struct packet_state p_read	; 
struct packet_state p_send	;
/* Scratch buffer for packet compression/decompression. */
Buffer compression_buffer   ;
/* Session key information for Encryption and MAC */
Newkeys *newkeys[MODE_MAX];
/* Buffer for the incoming packet currently being processed. */
Buffer incoming_packet      ;
/* Buffer for the partial outgoing packet being constructed. */
Buffer outgoing_packet      ;
/* Buffer for raw input data from the socket. */
Buffer input                      ;
/* Buffer for raw output data going to the socket. */
Buffer output                     ;
/* Encryption context for receiving data.  This is only used for decryption. */
CipherContext receive_context            ;
/* Encryption context for sending data.  This is only used for encryption. */
CipherContext send_context               ;
TAILQ_HEAD(OutPacketQueue, packet) outgoing;
z_stream outgoing_stream   ;
z_stream incoming_stream   ;
/* List of all permitted host/port pairs to connect. */
ForwardPermission permitted_opens[SSH_MAX_FORWARDS_PER_DIRECTION];
/*
 * 'channel_pre*' are called just before select() to add any bits relevant to
 * channels in the select bitmasks.
 */
chan_fn *channel_pre[SSH_CHANNEL_MAX_TYPE];
/*
 * 'channel_post*': perform any appropriate operations for channels which
 * have events pending.
 */
chan_fn *channel_post[SSH_CHANNEL_MAX_TYPE];
EVP_CIPHER acss_cipher     ;
EVP_CIPHER ssh1_3des       ;
EVP_CIPHER aes_ctr         ;
u_char mac_compute_m[EVP_MAX_MD_SIZE];
Kex *xxx_kex                    ;/* for rekeying XXX fixme */
Authctxt *the_authctxt;               
} T_SSHD_THREAD_LOCAL_VARIABLES;


extern DWORD g_dwThreadLocalIndex;
extern const KbdintDevice *devicesInitValue[MAX_AUTH_DEVICES];
extern const Cipher ciphersInitValue[MAX_CIPHER];
extern T_SSHD_THREAD_LOCAL_VARIABLES* AllocateThreadLocalStorage(T_SSHD_THREAD_LOCAL_VARIABLES* pSourceStorage);
extern void ReleaseThreadLocalStorage(T_SSHD_THREAD_LOCAL_VARIABLES* pSourceStorage);

#define THREAD_LOCAL(x) (((T_SSHD_THREAD_LOCAL_VARIABLES*) (TlsGetValue(g_dwThreadLocalIndex)))->##x)
#define SET_THREAD_LOCAL(x) TlsSetValue(g_dwThreadLocalIndex,(x))

#define XFREE_IF_NOT_NULL(x) if ((x) != NULL) xfree(x)

#endif _THREAD_LOCAL_H_