/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file contains code implementing the packet protocol and communication
 * with the other side.  This same code is used both on client and server side.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * SSH2 packet format added by Markus Friedl.
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"
RCSID("$OpenBSD: packet.c,v 1.120 2005/10/30 08:52:17 djm Exp $");

#include "openbsd-compat/sys-queue.h"

#include "xmalloc.h"
#include "buffer.h"
#include "packet.h"
#include "bufaux.h"
#include "crc32.h"
#include "getput.h"

#include "compress.h"
#include "deattack.h"
#include "channels.h"

#include "compat.h"
#include "ssh2.h"

#include "cipher.h"
#include "kex.h"
#include "mac.h"
#include "log.h"
#include "canohost.h"
#include "misc.h"
#include "ssh.h"

#include "ThreadLocal.h"

#ifdef PACKET_DEBUG
#define DBG(x) x
#else
#define DBG(x)
#endif

/*
 * This variable contains the file descriptors used for communicating with
 * the other side.  connection_in is used for reading; connection_out for
 * writing.  These can be the same descriptor, in which case it is assumed to
 * be a socket.
 */
//int connection_in = -1;
//int connection_out = -1;

/* Protocol flags for the remote side. */
//u_int remote_protocol_flags = 0;

/* Encryption context for receiving data.  This is only used for decryption. */
//CipherContext receive_context;

/* Encryption context for sending data.  This is only used for encryption. */
//CipherContext send_context;

/* Buffer for raw input data from the socket. */
//Buffer input;

/* Buffer for raw output data going to the socket. */
//Buffer output;

/* Buffer for the partial outgoing packet being constructed. */
//Buffer outgoing_packet;

/* Buffer for the incoming packet currently being processed. */
//Buffer incoming_packet;

/* Scratch buffer for packet compression/decompression. */
//Buffer THREAD_LOCAL(compression_buffer);
//int compression_buffer_ready = 0;

/* Flag indicating whether packet compression/decompression is enabled. */
//int packet_compression = 0;



/* Flag indicating whether this module has been initialized. */
//int initialized = 0;

/* Set to true if the connection is interactive. */
//int interactive_mode = 0;

/* Set to true if we are the server side. */
//int server_side = 0;

/* Set to true if we are authenticated. */
//int after_authentication = 0;

/* Session key information for Encryption and MAC */
//Newkeys *newkeys[MODE_MAX];

//struct packet_state p_read;
//struct packet_state p_send;

//u_int64_t max_blocks_in, max_blocks_out;
//u_int32_t rekey_limit;

/* Session key for protocol v1 */
//u_char ssh1_key[SSH_SESSION_KEY_LENGTH];
//u_int ssh1_keylen;

/* roundup current message to extra_pad bytes */
//u_char extra_pad = 0;



/*
 * Sets the descriptors used for communication.  Disables encryption until
 * packet_set_encryption_key is called.
 */
void
packet_set_connection(int fd_in, int fd_out)
{
	Cipher *none = cipher_by_name("none");

	if (none == NULL)
		fatal("packet_set_connection: cannot load cipher 'none'");
	THREAD_LOCAL(connection_in) = fd_in;
	THREAD_LOCAL(connection_out) = fd_out;
	cipher_init(&THREAD_LOCAL(send_context), none, (const u_char *)"",
	    0, NULL, 0, CIPHER_ENCRYPT);
	cipher_init(&THREAD_LOCAL(receive_context), none, (const u_char *)"",
	    0, NULL, 0, CIPHER_DECRYPT);
	THREAD_LOCAL(newkeys)[MODE_IN] = THREAD_LOCAL(newkeys)[MODE_OUT] = NULL;
	if (!THREAD_LOCAL(initialized)) {
		THREAD_LOCAL(initialized) = 1;		
		buffer_init(&THREAD_LOCAL(input));
		buffer_init(&THREAD_LOCAL(output));
		buffer_init(&THREAD_LOCAL(outgoing_packet));
		buffer_init(&THREAD_LOCAL(incoming_packet));
		TAILQ_INIT(&THREAD_LOCAL(outgoing));
	}
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

int
packet_connection_is_on_socket(void)
{
	struct sockaddr_storage from, to;
	socklen_t fromlen, tolen;

	/* filedescriptors in and out are the same, so it's a socket */
	if (THREAD_LOCAL(connection_in) == THREAD_LOCAL(connection_out))
		return 1;
	fromlen = sizeof(from);
	memset(&from, 0, sizeof(from));
	if (getpeername(THREAD_LOCAL(connection_in), (struct sockaddr *)&from, &fromlen) < 0)
		return 0;
	tolen = sizeof(to);
	memset(&to, 0, sizeof(to));
	if (getpeername(THREAD_LOCAL(connection_out), (struct sockaddr *)&to, &tolen) < 0)
		return 0;
	if (fromlen != tolen || memcmp(&from, &to, fromlen) != 0)
		return 0;
	if (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		return 0;
	return 1;
}

/*
 * Exports an IV from the CipherContext required to export the key
 * state back from the unprivileged child to the privileged parent
 * process.
 */

void
packet_get_keyiv(int mode, u_char *iv, u_int len)
{
	CipherContext *cc;

	if (mode == MODE_OUT)
		cc = &THREAD_LOCAL(send_context);
	else
		cc = &THREAD_LOCAL(receive_context);

	cipher_get_keyiv(cc, iv, len);
}

int
packet_get_keycontext(int mode, u_char *dat)
{
	CipherContext *cc;

	if (mode == MODE_OUT)
		cc = &THREAD_LOCAL(send_context);
	else
		cc = &THREAD_LOCAL(receive_context);

	return (cipher_get_keycontext(cc, dat));
}

void
packet_set_keycontext(int mode, u_char *dat)
{
	CipherContext *cc;

	if (mode == MODE_OUT)
		cc = &THREAD_LOCAL(send_context);
	else
		cc = &THREAD_LOCAL(receive_context);

	cipher_set_keycontext(cc, dat);
}

int
packet_get_keyiv_len(int mode)
{
	CipherContext *cc;

	if (mode == MODE_OUT)
		cc = &THREAD_LOCAL(send_context);
	else
		cc = &THREAD_LOCAL(receive_context);

	return (cipher_get_keyiv_len(cc));
}
void
packet_set_iv(int mode, u_char *dat)
{
	CipherContext *cc;

	if (mode == MODE_OUT)
		cc = &THREAD_LOCAL(send_context);
	else
		cc = &THREAD_LOCAL(receive_context);

	cipher_set_keyiv(cc, dat);
}
int
packet_get_ssh1_cipher(void)
{
	return (cipher_get_number(THREAD_LOCAL(receive_context).cipher));
}

void
packet_get_state(int mode, u_int32_t *seqnr, u_int64_t *blocks, u_int32_t *packets)
{
	struct packet_state *state;

	state = (mode == MODE_IN) ? &THREAD_LOCAL(p_read) : &THREAD_LOCAL(p_send);
	*seqnr = state->seqnr;
	*blocks = state->blocks;
	*packets = state->packets;
}

void
packet_set_state(int mode, u_int32_t seqnr, u_int64_t blocks, u_int32_t packets)
{
	struct packet_state *state;

	state = (mode == MODE_IN) ? &THREAD_LOCAL(p_read) : &THREAD_LOCAL(p_send);
	state->seqnr = seqnr;
	state->blocks = blocks;
	state->packets = packets;
}

/* returns 1 if connection is via ipv4 */

int
packet_connection_is_ipv4(void)
{
	struct sockaddr_storage to;
	socklen_t tolen = sizeof(to);

	memset(&to, 0, sizeof(to));
	if (getsockname(THREAD_LOCAL(connection_out), (struct sockaddr *)&to, &tolen) < 0)
		return 0;
	if (to.ss_family == AF_INET)
		return 1;
#ifdef IPV4_IN_IPV6
	if (to.ss_family == AF_INET6 &&
	    IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)&to)->sin6_addr))
		return 1;
#endif
	return 0;
}

/* Sets the connection into non-blocking mode. */

void
packet_set_nonblocking(void)
{
	/* Set the socket into non-blocking mode. */
	set_nonblock(THREAD_LOCAL(connection_in));

	if (THREAD_LOCAL(connection_out) != THREAD_LOCAL(connection_in))
		set_nonblock(THREAD_LOCAL(connection_out));
}

/* Returns the socket used for reading. */

int
packet_get_connection_in(void)
{
	return THREAD_LOCAL(connection_in);
}

/* Returns the descriptor used for writing. */

int
packet_get_connection_out(void)
{
	return THREAD_LOCAL(connection_out);
}

/* Closes the connection and clears and frees internal data structures. */

void
packet_close(void)
{
	if (!THREAD_LOCAL(initialized))
		return;
	THREAD_LOCAL(initialized) = 0;
	if (THREAD_LOCAL(connection_in) == THREAD_LOCAL(connection_out)) {
		shutdown(THREAD_LOCAL(connection_out), SHUT_RDWR);
		SocketClose(THREAD_LOCAL(connection_out));
	} else {
		SocketClose(THREAD_LOCAL(connection_in));
		SocketClose(THREAD_LOCAL(connection_out));
	}
	buffer_free(&THREAD_LOCAL(input));
	buffer_free(&THREAD_LOCAL(output));
	buffer_free(&THREAD_LOCAL(outgoing_packet));
	buffer_free(&THREAD_LOCAL(incoming_packet));
	if (THREAD_LOCAL(compression_buffer_ready)) {
		buffer_free(&THREAD_LOCAL(compression_buffer));
		buffer_compress_uninit();
	}
	cipher_cleanup(&THREAD_LOCAL(send_context));
	cipher_cleanup(&THREAD_LOCAL(receive_context));
}

/* Sets remote side protocol flags. */

void
packet_set_protocol_flags(u_int protocol_flags)
{
	THREAD_LOCAL(remote_protocol_flags) = protocol_flags;
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
packet_get_protocol_flags(void)
{
	return THREAD_LOCAL(remote_protocol_flags);
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

static void
packet_init_compression(void)
{
	if (THREAD_LOCAL(compression_buffer_ready) == 1)
		return;
	THREAD_LOCAL(compression_buffer_ready) = 1;
	buffer_init(&THREAD_LOCAL(compression_buffer));
}

void
packet_start_compression(int level)
{
	if (THREAD_LOCAL(packet_compression) && !THREAD_LOCAL(compat20))
		fatal("Compression already enabled.");
	THREAD_LOCAL(packet_compression) = 1;
	packet_init_compression();
	buffer_compress_init_send(level);
	buffer_compress_init_recv();
}


/* Start constructing a packet to send. */
void
packet_start(u_char type)
{
	u_char buf[9];
	int len;

	DBG(debug("packet_start[%d]", type));
	len = THREAD_LOCAL(compat20) ? 6 : 9;
	memset(buf, 0, len - 1);
	buf[len - 1] = type;
	buffer_clear(&THREAD_LOCAL(outgoing_packet));
	buffer_append(&THREAD_LOCAL(outgoing_packet), buf, len);
}

/* Append payload. */
void
packet_put_char(int value)
{
	char ch = value;

	buffer_append(&THREAD_LOCAL(outgoing_packet), &ch, 1);
}
void
packet_put_int(u_int value)
{
	buffer_put_int(&THREAD_LOCAL(outgoing_packet), value);
}
void
packet_put_string(const void *buf, u_int len)
{
	buffer_put_string(&THREAD_LOCAL(outgoing_packet), buf, len);
}
void
packet_put_cstring(const char *str)
{
	buffer_put_cstring(&THREAD_LOCAL(outgoing_packet), str);
}
void
packet_put_raw(const void *buf, u_int len)
{
	buffer_append(&THREAD_LOCAL(outgoing_packet), buf, len);
}
void
packet_put_bignum(BIGNUM * value)
{
	buffer_put_bignum(&THREAD_LOCAL(outgoing_packet), value);
}
void
packet_put_bignum2(BIGNUM * value)
{
	buffer_put_bignum2(&THREAD_LOCAL(outgoing_packet), value);
}

/*
 * Finalizes and sends the packet.  If the encryption key has been set,
 * encrypts the packet before sending.
 */

static void
packet_send1(void)
{
	u_char buf[8], *cp;
	int i, padding, len;
	u_int checksum;
	u_int32_t rnd = 0;

	/*
	 * If using packet compression, compress the payload of the outgoing
	 * packet.
	 */
	if (THREAD_LOCAL(packet_compression)) {
		buffer_clear(&THREAD_LOCAL(compression_buffer));
		/* Skip padding. */
		buffer_consume(&THREAD_LOCAL(outgoing_packet), 8);
		/* padding */
		buffer_append(&THREAD_LOCAL(compression_buffer), "\0\0\0\0\0\0\0\0", 8);
		buffer_compress(&THREAD_LOCAL(outgoing_packet), &THREAD_LOCAL(compression_buffer));
		buffer_clear(&THREAD_LOCAL(outgoing_packet));
		buffer_append(&THREAD_LOCAL(outgoing_packet), buffer_ptr(&THREAD_LOCAL(compression_buffer)),
		    buffer_len(&THREAD_LOCAL(compression_buffer)));
	}
	/* Compute packet length without padding (add checksum, remove padding). */
	len = buffer_len(&THREAD_LOCAL(outgoing_packet)) + 4 - 8;

	/* Insert padding. Initialized to zero in packet_start1() */
	padding = 8 - len % 8;
	if (!THREAD_LOCAL(send_context).plaintext) {
		cp = buffer_ptr(&THREAD_LOCAL(outgoing_packet));
		for (i = 0; i < padding; i++) {
			if (i % 4 == 0)
				rnd = arc4random();
			cp[7 - i] = rnd & 0xff;
			rnd >>= 8;
		}
	}
	buffer_consume(&THREAD_LOCAL(outgoing_packet), 8 - padding);

	/* Add check bytes. */
	checksum = ssh_crc32(buffer_ptr(&THREAD_LOCAL(outgoing_packet)),
	    buffer_len(&THREAD_LOCAL(outgoing_packet)));
	PUT_32BIT(buf, checksum);
	buffer_append(&THREAD_LOCAL(outgoing_packet), buf, 4);

#ifdef PACKET_DEBUG
	fprintf(stderr, "packet_send plain: ");
	buffer_dump(&THREAD_LOCAL(outgoing_packet));
#endif

	/* Append to output. */
	PUT_32BIT(buf, len);
	buffer_append(&THREAD_LOCAL(output), buf, 4);
	cp = buffer_append_space(&THREAD_LOCAL(output), buffer_len(&THREAD_LOCAL(outgoing_packet)));
	cipher_crypt(&THREAD_LOCAL(send_context), cp, buffer_ptr(&THREAD_LOCAL(outgoing_packet)),
	    buffer_len(&THREAD_LOCAL(outgoing_packet)));

#ifdef PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	buffer_dump(&THREAD_LOCAL(output));
#endif

	buffer_clear(&THREAD_LOCAL(outgoing_packet));

	/*
	 * Note that the packet is now only buffered in output.  It won't be
	 * actually sent until packet_write_wait or packet_write_poll is
	 * called.
	 */
}

void
set_newkeys(int mode)
{
	Enc *enc;
	Mac *mac;
	Comp *comp;
	CipherContext *cc;
	u_int64_t *max_blocks;
	int crypt_type;

	debug2("set_newkeys: mode %d", mode);

	if (mode == MODE_OUT) {
		cc = &THREAD_LOCAL(send_context);
		crypt_type = CIPHER_ENCRYPT;
		THREAD_LOCAL(p_send).packets = 0;
		THREAD_LOCAL(p_send).blocks = 0;
		max_blocks = &THREAD_LOCAL(max_blocks_out);
	} else {
		cc = &THREAD_LOCAL(receive_context);
		crypt_type = CIPHER_DECRYPT;
		THREAD_LOCAL(p_read).packets = 0;
		THREAD_LOCAL(p_read).blocks = 0;
		max_blocks = &THREAD_LOCAL(max_blocks_in);
	}
	if (THREAD_LOCAL(newkeys)[mode] != NULL) {
		debug("set_newkeys: rekeying");
		cipher_cleanup(cc);
		enc  = &THREAD_LOCAL(newkeys)[mode]->enc;
		mac  = &THREAD_LOCAL(newkeys)[mode]->mac;
		comp = &THREAD_LOCAL(newkeys)[mode]->comp;
		memset(mac->key, 0, mac->key_len);
		xfree(enc->name);
		xfree(enc->iv);
		xfree(enc->key);
		xfree(mac->name);
		xfree(mac->key);
		xfree(comp->name);
		xfree(THREAD_LOCAL(newkeys)[mode]);
	}
	THREAD_LOCAL(newkeys)[mode] = kex_get_newkeys(mode);
	if (THREAD_LOCAL(newkeys)[mode] == NULL)
		fatal("newkeys: no keys for mode %d", mode);
	enc  = &THREAD_LOCAL(newkeys)[mode]->enc;
	mac  = &THREAD_LOCAL(newkeys)[mode]->mac;
	comp = &THREAD_LOCAL(newkeys)[mode]->comp;
	if (mac->md != NULL)
		mac->enabled = 1;
	DBG(debug("cipher_init_context: %d", mode));
	cipher_init(cc, enc->cipher, enc->key, enc->key_len,
	    enc->iv, enc->block_size, crypt_type);
	/* Deleting the keys does not gain extra security */
	/* memset(enc->iv,  0, enc->block_size);
	   memset(enc->key, 0, enc->key_len); */
	if ((comp->type == COMP_ZLIB ||
	    (comp->type == COMP_DELAYED && THREAD_LOCAL(after_authentication))) &&
	    comp->enabled == 0) {
		packet_init_compression();
		if (mode == MODE_OUT)
			buffer_compress_init_send(6);
		else
			buffer_compress_init_recv();
		comp->enabled = 1;
	}
	/*
	 * The 2^(blocksize*2) limit is too expensive for 3DES,
	 * blowfish, etc, so enforce a 1GB limit for small blocksizes.
	 */
	if (enc->block_size >= 16)
		*max_blocks = (u_int64_t)1 << (enc->block_size*2);
	else
		*max_blocks = ((u_int64_t)1 << 30) / enc->block_size;
	if (THREAD_LOCAL(rekey_limit))
		*max_blocks = MIN(*max_blocks, THREAD_LOCAL(rekey_limit) / enc->block_size);
}

/*
 * Delayed compression for SSH2 is enabled after authentication:
 * This happans on the server side after a SSH2_MSG_USERAUTH_SUCCESS is sent,
 * and on the client side after a SSH2_MSG_USERAUTH_SUCCESS is received.
 */
static void
packet_enable_delayed_compress(void)
{
	Comp *comp = NULL;
	int mode;

	/*
	 * Remember that we are past the authentication step, so rekeying
	 * with COMP_DELAYED will turn on compression immediately.
	 */
	THREAD_LOCAL(after_authentication) = 1;
	for (mode = 0; mode < MODE_MAX; mode++) {
		comp = &THREAD_LOCAL(newkeys)[mode]->comp;
		if (comp && !comp->enabled && comp->type == COMP_DELAYED) {
			packet_init_compression();
			if (mode == MODE_OUT)
				buffer_compress_init_send(6);
			else
				buffer_compress_init_recv();
			comp->enabled = 1;
		}
	}
}

/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
static void
packet_send2_wrapped(void)
{
	u_char type, *cp, *macbuf = NULL;
	u_char padlen, pad;
	u_int packet_length = 0;
	u_int i, len;
	u_int32_t rnd = 0;
	Enc *enc   = NULL;
	Mac *mac   = NULL;
	Comp *comp = NULL;
	int block_size;

	if (THREAD_LOCAL(newkeys)[MODE_OUT] != NULL) {
		enc  = &THREAD_LOCAL(newkeys)[MODE_OUT]->enc;
		mac  = &THREAD_LOCAL(newkeys)[MODE_OUT]->mac;
		comp = &THREAD_LOCAL(newkeys)[MODE_OUT]->comp;
	}
	block_size = enc ? enc->block_size : 8;

	cp = buffer_ptr(&THREAD_LOCAL(outgoing_packet));
	type = cp[5];

#ifdef PACKET_DEBUG
	fprintf(stderr, "plain:     ");
	buffer_dump(&THREAD_LOCAL(outgoing_packet));
#endif

	if (comp && comp->enabled) {
		len = buffer_len(&THREAD_LOCAL(outgoing_packet));
		/* skip header, compress only payload */
		buffer_consume(&THREAD_LOCAL(outgoing_packet), 5);
		buffer_clear(&THREAD_LOCAL(compression_buffer));
		buffer_compress(&THREAD_LOCAL(outgoing_packet), &THREAD_LOCAL(compression_buffer));
		buffer_clear(&THREAD_LOCAL(outgoing_packet));
		buffer_append(&THREAD_LOCAL(outgoing_packet), "\0\0\0\0\0", 5);
		buffer_append(&THREAD_LOCAL(outgoing_packet), buffer_ptr(&THREAD_LOCAL(compression_buffer)),
		    buffer_len(&THREAD_LOCAL(compression_buffer)));
		DBG(debug("compression: raw %d compressed %d", len,
		    buffer_len(&THREAD_LOCAL(outgoing_packet))));
	}

	/* sizeof (packet_len + pad_len + payload) */
	len = buffer_len(&THREAD_LOCAL(outgoing_packet));

	/*
	 * calc size of padding, alloc space, get random data,
	 * minimum padding is 4 bytes
	 */
	padlen = block_size - (len % block_size);
	if (padlen < 4)
		padlen += block_size;
	if (THREAD_LOCAL(extra_pad)) {
		/* will wrap if extra_pad+padlen > 255 */
		THREAD_LOCAL(extra_pad)  = roundup(THREAD_LOCAL(extra_pad), block_size);
		pad = THREAD_LOCAL(extra_pad) - ((len + padlen) % THREAD_LOCAL(extra_pad));
		debug3("packet_send2: adding %d (len %d padlen %d THREAD_LOCAL(extra_pad) %d)",
		    pad, len, padlen, THREAD_LOCAL(extra_pad));
		padlen += pad;
		THREAD_LOCAL(extra_pad) = 0;
	}
	cp = buffer_append_space(&THREAD_LOCAL(outgoing_packet), padlen);
	if (enc && !THREAD_LOCAL(send_context).plaintext) {
		/* random padding */
		for (i = 0; i < padlen; i++) {
			if (i % 4 == 0)
				rnd = arc4random();
			cp[i] = rnd & 0xff;
			rnd >>= 8;
		}
	} else {
		/* clear padding */
		memset(cp, 0, padlen);
	}
	/* packet_length includes payload, padding and padding length field */
	packet_length = buffer_len(&THREAD_LOCAL(outgoing_packet)) - 4;
	cp = buffer_ptr(&THREAD_LOCAL(outgoing_packet));
	PUT_32BIT(cp, packet_length);
	cp[4] = padlen;
	DBG(debug("send: len %d (includes padlen %d)", packet_length+4, padlen));

	/* compute MAC over seqnr and packet(length fields, payload, padding) */
	if (mac && mac->enabled) {
		macbuf = mac_compute(mac, THREAD_LOCAL(p_send).seqnr,
		    buffer_ptr(&THREAD_LOCAL(outgoing_packet)),
		    buffer_len(&THREAD_LOCAL(outgoing_packet)));
		DBG(debug("done calc MAC out #%d", THREAD_LOCAL(p_send).seqnr));
	}
	/* encrypt packet and append to output buffer. */
	cp = buffer_append_space(&THREAD_LOCAL(output), buffer_len(&THREAD_LOCAL(outgoing_packet)));
	cipher_crypt(&THREAD_LOCAL(send_context), cp, buffer_ptr(&THREAD_LOCAL(outgoing_packet)),
	    buffer_len(&THREAD_LOCAL(outgoing_packet)));
	/* append unencrypted MAC */
	if (mac && mac->enabled)
		buffer_append(&THREAD_LOCAL(output), (char *)macbuf, mac->mac_len);
#ifdef PACKET_DEBUG
	fprintf(stderr, "encrypted: ");
	buffer_dump(&THREAD_LOCAL(output));
#endif
	/* increment sequence number for outgoing packets */
	if (++THREAD_LOCAL(p_send).seqnr == 0)
		logit("outgoing seqnr wraps around");
	if (++THREAD_LOCAL(p_send).packets == 0)
		if (!(THREAD_LOCAL(datafellows) & SSH_BUG_NOREKEY))
			fatal("XXX too many packets with same key");
	THREAD_LOCAL(p_send).blocks += (packet_length + 4) / block_size;
	buffer_clear(&THREAD_LOCAL(outgoing_packet));

	if (type == SSH2_MSG_NEWKEYS)
		set_newkeys(MODE_OUT);
	else if (type == SSH2_MSG_USERAUTH_SUCCESS && THREAD_LOCAL(server_side))
		packet_enable_delayed_compress();
}

#ifdef WINCE_PORT
//	int rekeying = 0;
#endif

static void
packet_send2(void)
{
#ifndef WINCE_PORT
	static int rekeying = 0;
#endif

	struct packet *p;
	u_char type, *cp;

	cp = buffer_ptr(&THREAD_LOCAL(outgoing_packet));
	type = cp[5];

	/* during rekeying we can only send key exchange messages */
	if (THREAD_LOCAL(rekeying)) {
		if (!((type >= SSH2_MSG_TRANSPORT_MIN) &&
		    (type <= SSH2_MSG_TRANSPORT_MAX))) {
			debug("enqueue packet: %u", type);
			p = xmalloc(sizeof(*p));
			p->type = type;
			memcpy(&p->payload, &THREAD_LOCAL(outgoing_packet), sizeof(Buffer));
			buffer_init(&THREAD_LOCAL(outgoing_packet));
			TAILQ_INSERT_TAIL(&THREAD_LOCAL(outgoing), p, next);
			return;
		}
	}

	/* rekeying starts with sending KEXINIT */
	if (type == SSH2_MSG_KEXINIT)
		THREAD_LOCAL(rekeying) = 1;

	packet_send2_wrapped();

	/* after a NEWKEYS message we can send the complete queue */
	if (type == SSH2_MSG_NEWKEYS) {
		THREAD_LOCAL(rekeying) = 0;
		while ((p = TAILQ_FIRST(&THREAD_LOCAL(outgoing)))) {
			type = p->type;
			debug("dequeue packet: %u", type);
			buffer_free(&THREAD_LOCAL(outgoing_packet));
			memcpy(&THREAD_LOCAL(outgoing_packet), &p->payload,
			    sizeof(Buffer));
			TAILQ_REMOVE(&THREAD_LOCAL(outgoing), p, next);
			xfree(p);
			packet_send2_wrapped();
		}
	}
}

void
packet_send(void)
{
	if (THREAD_LOCAL(compat20))
		packet_send2();
	else
		packet_send1();
	DBG(debug("packet_send done"));
}

/*
 * Waits until a packet has been received, and returns its type.  Note that
 * no other data is processed until this returns, so this function should not
 * be used during the interactive session.
 */

int
packet_read_seqnr(u_int32_t *seqnr_p)
{
	int type, len;
	fd_set fdset;
	fd_set *setp = &fdset;
	char buf[8192];
	DBG(debug("packet_read()"));

	/* Since we are blocking, ensure that all written packets have been sent. */
	packet_write_wait();

	/* Stay in the loop until we have received a complete packet. */
	for (;;) {
		/* Try to read a packet from the buffer. */
		type = packet_read_poll_seqnr(seqnr_p);
#ifdef WINCE_PORT
#else
		if (!THREAD_LOCAL(compat20) && (
		    type == SSH_SMSG_SUCCESS
		    || type == SSH_SMSG_FAILURE
		    || type == SSH_CMSG_EOF
		    || type == SSH_CMSG_EXIT_CONFIRMATION))
			packet_check_eom();
#endif
		/* If we got a packet, return it. */
		if (type != SSH_MSG_NONE) {			
			return type;
		}
		/*
		 * Otherwise, wait for some data to arrive, add it to the
		 * buffer, and try again.
		 */
		FD_ZERO(setp);
		FD_SET(THREAD_LOCAL(connection_in), setp);

		/* Wait for some data to arrive. */
		while (select(0 /*ignored on CE*/, setp, NULL, NULL, NULL) == -1 &&
		    (h_errno == EAGAIN || h_errno == EINTR))
			;

		/* Read data from the socket. */
		len = SocketRead(THREAD_LOCAL(connection_in), buf, sizeof(buf));
		if (len == 0) {
			logit("Connection closed by %.200s", get_remote_ipaddr());
			cleanup_exit(255);
		}
		if (len < 0)
		{
			fatal("Read from socket failed: %.100s", strerror(errno));
			cleanup_exit(255);
		}
		/* Append it to the buffer. */
		packet_process_incoming(buf, len);
	}
	/* NOTREACHED */
}

int
packet_read(void)
{
	return packet_read_seqnr(NULL);
}

/*
 * Waits until a packet has been received, verifies that its type matches
 * that given, and gives a fatal error and exits if there is a mismatch.
 */

void
packet_read_expect(int expected_type)
{
	int type;

	type = packet_read();
	if (type != expected_type)
		packet_disconnect("Protocol error: expected packet type %d, got %d",
		    expected_type, type);
}

/* Checks if a full packet is available in the data received so far via
 * packet_process_incoming.  If so, reads the packet; otherwise returns
 * SSH_MSG_NONE.  This does not wait for data from the connection.
 *
 */

#ifdef WINCE_PORT
	//u_int packet_length = 0;
#endif

static int
packet_read_poll2(u_int32_t *seqnr_p)
{
#ifndef WINCE_PORT
	static u_int packet_length = 0;
#endif

	u_int padlen, need;
	u_char *macbuf, *cp, type;
	u_int maclen, block_size;
	Enc *enc   = NULL;
	Mac *mac   = NULL;
	Comp *comp = NULL;

	if (THREAD_LOCAL(newkeys)[MODE_IN] != NULL) {
		enc  = &THREAD_LOCAL(newkeys)[MODE_IN]->enc;
		mac  = &THREAD_LOCAL(newkeys)[MODE_IN]->mac;
		comp = &THREAD_LOCAL(newkeys)[MODE_IN]->comp;
	}
	maclen = mac && mac->enabled ? mac->mac_len : 0;
	block_size = enc ? enc->block_size : 8;

	if (THREAD_LOCAL(packet_length) == 0) {
		/*
		 * check if input size is less than the cipher block size,
		 * decrypt first block and extract length of incoming packet
		 */
		if (buffer_len(&THREAD_LOCAL(input)) < block_size)
			return SSH_MSG_NONE;
		buffer_clear(&THREAD_LOCAL(incoming_packet));
		cp = buffer_append_space(&THREAD_LOCAL(incoming_packet), block_size);
		cipher_crypt(&THREAD_LOCAL(receive_context), cp, buffer_ptr(&THREAD_LOCAL(input)),
		    block_size);
		cp = buffer_ptr(&THREAD_LOCAL(incoming_packet));
		THREAD_LOCAL(packet_length) = GET_32BIT(cp);
		if (THREAD_LOCAL(packet_length) < 1 + 4 || THREAD_LOCAL(packet_length) > 256 * 1024) {
#ifdef PACKET_DEBUG
			buffer_dump(&THREAD_LOCAL(incoming_packet));
#endif
			packet_disconnect("Bad packet length %u.", THREAD_LOCAL(packet_length));
		}
		DBG(debug("THREAD_LOCAL(input): packet len %u", THREAD_LOCAL(packet_length)+4));
		buffer_consume(&THREAD_LOCAL(input), block_size);
	}
	/* we have a partial packet of block_size bytes */
	need = 4 + THREAD_LOCAL(packet_length) - block_size;
	DBG(debug("partial packet %d, need %d, maclen %d", block_size,
	    need, maclen));
	if (need % block_size != 0)
		fatal("padding error: need %d block %d mod %d",
		    need, block_size, need % block_size);
	/*
	 * check if the entire packet has been received and
	 * decrypt into incoming_packet
	 */
	if (buffer_len(&THREAD_LOCAL(input)) < need + maclen)
		return SSH_MSG_NONE;
#ifdef PACKET_DEBUG
	fprintf(stderr, "read_poll enc/full: ");
	buffer_dump(&THREAD_LOCAL(input));
#endif
	cp = buffer_append_space(&THREAD_LOCAL(incoming_packet), need);
	cipher_crypt(&THREAD_LOCAL(receive_context), cp, buffer_ptr(&THREAD_LOCAL(input)), need);
	buffer_consume(&THREAD_LOCAL(input), need);
	/*
	 * compute MAC over seqnr and packet,
	 * increment sequence number for incoming packet
	 */
	if (mac && mac->enabled) {
		macbuf = mac_compute(mac, THREAD_LOCAL(p_read).seqnr,
		    buffer_ptr(&THREAD_LOCAL(incoming_packet)),
		    buffer_len(&THREAD_LOCAL(incoming_packet)));
		if (memcmp(macbuf, buffer_ptr(&THREAD_LOCAL(input)), mac->mac_len) != 0)
			packet_disconnect("Corrupted MAC on input.");
		DBG(debug("MAC #%d ok", THREAD_LOCAL(p_read).seqnr));
		buffer_consume(&THREAD_LOCAL(input), mac->mac_len);
	}
	if (seqnr_p != NULL)
		*seqnr_p = THREAD_LOCAL(p_read).seqnr;
	if (++THREAD_LOCAL(p_read).seqnr == 0)
		logit("incoming seqnr wraps around");
	if (++THREAD_LOCAL(p_read).packets == 0)
		if (!(THREAD_LOCAL(datafellows) & SSH_BUG_NOREKEY))
			fatal("XXX too many packets with same key");
	THREAD_LOCAL(p_read).blocks += (THREAD_LOCAL(packet_length) + 4) / block_size;

	/* get padlen */
	cp = buffer_ptr(&THREAD_LOCAL(incoming_packet));
	padlen = cp[4];
	DBG(debug("input: padlen %d", padlen));
	if (padlen < 4)
		packet_disconnect("Corrupted padlen %d on input.", padlen);

	/* skip packet size + padlen, discard padding */
	buffer_consume(&THREAD_LOCAL(incoming_packet), 4 + 1);
	buffer_consume_end(&THREAD_LOCAL(incoming_packet), padlen);

	DBG(debug("input: len before de-compress %d", buffer_len(&THREAD_LOCAL(incoming_packet))));
	if (comp && comp->enabled) {
		buffer_clear(&THREAD_LOCAL(compression_buffer));
		buffer_uncompress(&THREAD_LOCAL(incoming_packet), &THREAD_LOCAL(compression_buffer));
		buffer_clear(&THREAD_LOCAL(incoming_packet));
		buffer_append(&THREAD_LOCAL(incoming_packet), buffer_ptr(&THREAD_LOCAL(compression_buffer)),
		    buffer_len(&THREAD_LOCAL(compression_buffer)));
		DBG(debug("input: len after de-compress %d",
		    buffer_len(&THREAD_LOCAL(incoming_packet))));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	type = buffer_get_char(&THREAD_LOCAL(incoming_packet));
	if (type < SSH2_MSG_MIN || type >= SSH2_MSG_LOCAL_MIN)
		packet_disconnect("Invalid ssh2 packet type: %d", type);
	if (type == SSH2_MSG_NEWKEYS)
		set_newkeys(MODE_IN);
	else if (type == SSH2_MSG_USERAUTH_SUCCESS && !THREAD_LOCAL(server_side))
		packet_enable_delayed_compress();
#ifdef PACKET_DEBUG
	fprintf(stderr, "read/plain[%d]:\r\n", type);
	buffer_dump(&THREAD_LOCAL(incoming_packet));
#endif
	/* reset for next packet */
	THREAD_LOCAL(packet_length) = 0;
	return type;
}

int
packet_read_poll_seqnr(u_int32_t *seqnr_p)
{
	u_int reason, seqnr;
	u_char type;
	char *msg;

	for (;;) {
		if (THREAD_LOCAL(compat20)) {
			type = packet_read_poll2(seqnr_p);
			if (type)
				DBG(debug("received packet type %d", type));
			switch (type) {
			case SSH2_MSG_IGNORE:
				break;
			case SSH2_MSG_DEBUG:
				packet_get_char();
				msg = packet_get_string(NULL);
				debug("Remote: %.900s", msg);
				xfree(msg);
				msg = packet_get_string(NULL);
				xfree(msg);
				break;
			case SSH2_MSG_DISCONNECT:
				reason = packet_get_int();
				msg = packet_get_string(NULL);
				logit("Received disconnect from %s: %u: %.400s",
				    get_remote_ipaddr(), reason, msg);
				xfree(msg);
				cleanup_exit(255);
				break;
			case SSH2_MSG_UNIMPLEMENTED:
				seqnr = packet_get_int();
				debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
				    seqnr);
				break;
			default:
				return type;
				break;
			}
		} else {
#ifdef WINCE_PORT
			ASSERT(0);
#else				
			type = packet_read_poll1();
			switch (type) {
			case SSH_MSG_IGNORE:
				break;
			case SSH_MSG_DEBUG:
				msg = packet_get_string(NULL);
				debug("Remote: %.900s", msg);
				xfree(msg);
				break;
			case SSH_MSG_DISCONNECT:
				msg = packet_get_string(NULL);
				logit("Received disconnect from %s: %.400s",
				    get_remote_ipaddr(), msg);
				cleanup_exit(255);
				xfree(msg);
				break;
			default:
				if (type)
					DBG(debug("received packet type %d", type));
				return type;
				break;

			}
#endif		
		}
	}
}

int
packet_read_poll(void)
{
	return packet_read_poll_seqnr(NULL);
}

/*
 * Buffers the given amount of input characters.  This is intended to be used
 * together with packet_read_poll.
 */

void
packet_process_incoming(const char *buf, u_int len)
{
	buffer_append(&THREAD_LOCAL(input), buf, len);
}

/* Returns a character from the packet. */

u_int
packet_get_char(void)
{
	char ch;

	buffer_get(&THREAD_LOCAL(incoming_packet), &ch, 1);
	return (u_char) ch;
}

/* Returns an integer from the packet data. */

u_int
packet_get_int(void)
{
	return buffer_get_int(&THREAD_LOCAL(incoming_packet));
}

/*
 * Returns an arbitrary precision integer from the packet data.  The integer
 * must have been initialized before this call.
 */

void
packet_get_bignum(BIGNUM * value)
{
	buffer_get_bignum(&THREAD_LOCAL(incoming_packet), value);
}

void
packet_get_bignum2(BIGNUM * value)
{
	buffer_get_bignum2(&THREAD_LOCAL(incoming_packet), value);
}

void *
packet_get_raw(u_int *length_ptr)
{
	u_int bytes = buffer_len(&THREAD_LOCAL(incoming_packet));

	if (length_ptr != NULL)
		*length_ptr = bytes;
	return buffer_ptr(&THREAD_LOCAL(incoming_packet));
}

int
packet_remaining(void)
{
	return buffer_len(&THREAD_LOCAL(incoming_packet));
}

/*
 * Returns a string from the packet data.  The string is allocated using
 * xmalloc; it is the responsibility of the calling program to free it when
 * no longer needed.  The length_ptr argument may be NULL, or point to an
 * integer into which the length of the string is stored.
 */

void *
packet_get_string(u_int *length_ptr)
{
	return buffer_get_string(&THREAD_LOCAL(incoming_packet), length_ptr);
}

/*
 * Sends a diagnostic message from the server to the client.  This message
 * can be sent at any time (but not while constructing another message). The
 * message is printed immediately, but only if the client is being executed
 * in verbose mode.  These messages are primarily intended to ease debugging
 * authentication problems.   The length of the formatted message must not
 * exceed 1024 bytes.  This will automatically call packet_write_wait.
 */

void
packet_send_debug(const char *fmt,...)
{
	char buf[1024];
	va_list args;

	if (THREAD_LOCAL(compat20) && (THREAD_LOCAL(datafellows) & SSH_BUG_DEBUG))
		return;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (THREAD_LOCAL(compat20)) {
		packet_start(SSH2_MSG_DEBUG);
		packet_put_char(0);	/* bool: always display */
		packet_put_cstring(buf);
		packet_put_cstring("");
	} else {
#ifdef WINCE_PORT
		ASSERT(0);
#else
		packet_start(SSH_MSG_DEBUG);
		packet_put_cstring(buf);
#endif
	}
	packet_send();
	packet_write_wait();
}

/*
 * Logs the error plus constructs and sends a disconnect packet, closes the
 * connection, and exits.  This function never returns. The error message
 * should not contain a newline.  The length of the formatted message must
 * not exceed 1024 bytes.
 */

#ifdef WINCE_PORT
	//int disconnecting = 0;
#endif

void
packet_disconnect(const char *fmt,...)
{
	char buf[1024];
	va_list args;
#ifndef WINCE_PORT
	static int disconnecting = 0;
#endif
	

	if (THREAD_LOCAL(disconnecting))	/* Guard against recursive invocations. */
		fatal("packet_disconnect called recursively.");
	THREAD_LOCAL(disconnecting) = 1;

	/*
	 * Format the message.  Note that the caller must make sure the
	 * message is of limited size.
	 */
	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	/* Display the error locally */
	logit("Disconnecting: %.100s", buf);

	/* Send the disconnect message to the other side, and wait for it to get sent. */
	if (THREAD_LOCAL(compat20)) {
		packet_start(SSH2_MSG_DISCONNECT);
		packet_put_int(SSH2_DISCONNECT_PROTOCOL_ERROR);
		packet_put_cstring(buf);
		packet_put_cstring("");
	} else {
#ifdef WINCE_PORT
		ASSERT(0);
#else
		packet_start(SSH_MSG_DISCONNECT);
		packet_put_cstring(buf);
#endif
	}
	packet_send();
	packet_write_wait();

	/* Stop listening for connections. */
	channel_close_all();

	/* Close the connection. */
	packet_close();
	cleanup_exit(255);
}

/* Checks if there is any buffered output, and tries to write some of the output. */

void
packet_write_poll(void)
{
	int len = buffer_len(&THREAD_LOCAL(output));

	if (len > 0) {
		len = SocketWrite(THREAD_LOCAL(connection_out), buffer_ptr(&THREAD_LOCAL(output)), len);
		if (len <= 0) {
			if (errno == EAGAIN)
				return;
			else
				fatal("Write failed: %.100s", strerror(errno));
		}
		buffer_consume(&THREAD_LOCAL(output), len);
	}
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */

void
packet_write_wait(void)
{
	fd_set setp;

	packet_write_poll();
	while (packet_have_data_to_write()) {
		FD_ZERO(&setp);
		FD_SET(THREAD_LOCAL(connection_out), &setp);
		while (select(0/*ignored on CE*/, NULL, &setp, NULL, NULL) == -1 &&
		    (errno == EAGAIN || errno == EINTR))
			;
		packet_write_poll();
	}	
}

/* Returns true if there is buffered data to write to the connection. */

int
packet_have_data_to_write(void)
{
	return buffer_len(&THREAD_LOCAL(output)) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

int
packet_not_very_much_data_to_write(void)
{
	if (THREAD_LOCAL(interactive_mode))
		return buffer_len(&THREAD_LOCAL(output)) < 16384;
	else
		return buffer_len(&THREAD_LOCAL(output)) < 128 * 1024;
}


static void
packet_set_tos(int interactive)
{
#if defined(IP_TOS) && !defined(IP_TOS_IS_BROKEN)
	int tos = interactive ? IPTOS_LOWDELAY : IPTOS_THROUGHPUT;

	if (!packet_connection_is_on_socket() ||
	    !packet_connection_is_ipv4())
		return;
	if (__setsockopt(connection_in, IPPROTO_IP, IP_TOS, &tos,
	    sizeof(tos)) < 0)
		error("__setsockopt IP_TOS %d: %.100s:",
		    tos, strerror(errno));
#endif
}

/* Informs that the current session is interactive.  Sets IP flags for that. */

#ifdef WINCE_PORT
//	int packet_set_interactive_called = 0;
#endif

void
packet_set_interactive(int interactive)
{
#ifndef WINCE_PORT
	static int packet_set_interactive_called = 0;
#endif

	if (THREAD_LOCAL(packet_set_interactive_called))
		return;
	THREAD_LOCAL(packet_set_interactive_called) = 1;

	/* Record that we are in interactive mode. */
	THREAD_LOCAL(interactive_mode) = interactive;

	/* Only set socket options if using a socket.  */
	if (!packet_connection_is_on_socket())
		return;
	if (interactive)
		set_nodelay(THREAD_LOCAL(connection_in));
	packet_set_tos(interactive);
}

/* Returns true if the current connection is interactive. */

int
packet_is_interactive(void)
{
	return THREAD_LOCAL(interactive_mode);
}


#ifdef WINCE_PORT
	//int packet_set_maxsize_called = 0;
#endif
int
packet_set_maxsize(u_int s)
{
#ifndef WINCE_PORT
	static int packet_set_maxsize_called = 0;
#endif

	if (THREAD_LOCAL(packet_set_maxsize_called)) {
		logit("packet_set_maxsize: called twice: old %d new %d",
		    THREAD_LOCAL(max_packet_size), s);
		return -1;
	}
	if (s < 4 * 1024 || s > 1024 * 1024) {
		logit("packet_set_maxsize: bad size %d", s);
		return -1;
	}
	THREAD_LOCAL(packet_set_maxsize_called) = 1;
	debug("packet_set_maxsize: setting to %d", s);
	THREAD_LOCAL(max_packet_size) = s;
	return s;
}

/* roundup current message to pad bytes */
void
packet_add_padding(u_char pad)
{
	THREAD_LOCAL(extra_pad) = pad;
}

/*
 * 9.2.  Ignored Data Message
 *
 *   byte      SSH_MSG_IGNORE
 *   string    data
 *
 * All implementations MUST understand (and ignore) this message at any
 * time (after receiving the protocol version). No implementation is
 * required to send them. This message can be used as an additional
 * protection measure against advanced traffic analysis techniques.
 */
void
packet_send_ignore(int nbytes)
{
	u_int32_t rnd = 0;
	int i;

#ifdef WINCE_PORT
	packet_start(SSH2_MSG_IGNORE);
#else
	packet_start(THREAD_LOCAL(compat20) ? SSH2_MSG_IGNORE : SSH_MSG_IGNORE);
#endif
	packet_put_int(nbytes);
	for (i = 0; i < nbytes; i++) {
		if (i % 4 == 0)
			rnd = arc4random();
		packet_put_char(rnd & 0xff);
		rnd >>= 8;
	}
}

#define MAX_PACKETS	(1U<<31)
int
packet_need_rekeying(void)
{
	if (THREAD_LOCAL(datafellows) & SSH_BUG_NOREKEY)
		return 0;
	return
	    (THREAD_LOCAL(p_send).packets > MAX_PACKETS) ||
	    (THREAD_LOCAL(p_read).packets > MAX_PACKETS) ||
	    (THREAD_LOCAL(max_blocks_out) && (THREAD_LOCAL(p_send).blocks > THREAD_LOCAL(max_blocks_out))) ||
	    (THREAD_LOCAL(max_blocks_in)  && (THREAD_LOCAL(p_read).blocks > THREAD_LOCAL(max_blocks_in)));
}

void
packet_set_rekey_limit(u_int32_t bytes)
{
	THREAD_LOCAL(rekey_limit) = bytes;
}

void
packet_set_server(void)
{
	THREAD_LOCAL(server_side) = 1;
}

void
packet_set_authenticated(void)
{
	THREAD_LOCAL(after_authentication) = 1;
}
