/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Interface to packet compression for ssh.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#include "includes.h"
RCSID("$OpenBSD: compress.c,v 1.21 2004/01/13 19:45:15 markus Exp $");
#include "sys/types.h"

#include "log.h"
#include "buffer.h"
#include "zlib.h"
#include "compress.h"

#include "ThreadLocal.h"


//z_stream incoming_stream;
//z_stream outgoing_stream;
//int compress_init_send_called = 0;
//int compress_init_recv_called = 0;
//int inflate_failed = 0;
//int deflate_failed = 0;

/*
 * Initializes compression; level is compression level from 1 to 9
 * (as in gzip).
 */

void
buffer_compress_init_send(int level)
{
	if (THREAD_LOCAL(compress_init_send_called) == 1)
		deflateEnd(&THREAD_LOCAL(outgoing_stream));
	THREAD_LOCAL(compress_init_send_called) = 1;
	debug("Enabling compression at level %d.", level);
	if (level < 1 || level > 9)
		fatal("Bad compression level %d.", level);
	deflateInit(&THREAD_LOCAL(outgoing_stream), level);
}
void
buffer_compress_init_recv(void)
{
	if (THREAD_LOCAL(compress_init_recv_called) == 1)
		inflateEnd(&THREAD_LOCAL(incoming_stream));
	THREAD_LOCAL(compress_init_recv_called) = 1;
	inflateInit(&THREAD_LOCAL(incoming_stream));
}

/* Frees any data structures allocated for compression. */

void
buffer_compress_uninit(void)
{
	debug("compress outgoing: raw data %llu, compressed %llu, factor %.2f",
	    (unsigned_long_long)THREAD_LOCAL(outgoing_stream).total_in,
	    (unsigned_long_long)THREAD_LOCAL(outgoing_stream).total_out,
	    THREAD_LOCAL(outgoing_stream).total_in == 0 ? 0.0 :
	    (double) THREAD_LOCAL(outgoing_stream).total_out / THREAD_LOCAL(outgoing_stream).total_in);
	debug("compress incoming: raw data %llu, compressed %llu, factor %.2f",
	    (unsigned_long_long)THREAD_LOCAL(incoming_stream).total_out,
	    (unsigned_long_long)THREAD_LOCAL(incoming_stream).total_in,
	    THREAD_LOCAL(incoming_stream).total_out == 0 ? 0.0 :
	    (double) THREAD_LOCAL(incoming_stream).total_in / THREAD_LOCAL(incoming_stream).total_out);
	if (THREAD_LOCAL(compress_init_recv_called) == 1 && THREAD_LOCAL(inflate_failed) == 0)
		inflateEnd(&THREAD_LOCAL(incoming_stream));
	if (THREAD_LOCAL(compress_init_send_called) == 1 && THREAD_LOCAL(deflate_failed) == 0)
		deflateEnd(&THREAD_LOCAL(outgoing_stream));
}

/*
 * Compresses the contents of input_buffer into output_buffer.  All packets
 * compressed using this function will form a single compressed data stream;
 * however, data will be flushed at the end of every call so that each
 * output_buffer can be decompressed independently (but in the appropriate
 * order since they together form a single compression stream) by the
 * receiver.  This appends the compressed data to the output buffer.
 */

void
buffer_compress(Buffer * input_buffer, Buffer * output_buffer)
{
	u_char buf[4096];
	int status;

	/* This case is not handled below. */
	if (buffer_len(input_buffer) == 0)
		return;

	/* Input is the contents of the input buffer. */
	THREAD_LOCAL(outgoing_stream).next_in = buffer_ptr(input_buffer);
	THREAD_LOCAL(outgoing_stream).avail_in = buffer_len(input_buffer);

	/* Loop compressing until deflate() returns with avail_out != 0. */
	do {
		/* Set up fixed-size output buffer. */
		THREAD_LOCAL(outgoing_stream).next_out = buf;
		THREAD_LOCAL(outgoing_stream).avail_out = sizeof(buf);

		/* Compress as much data into the buffer as possible. */
		status = deflate(&THREAD_LOCAL(outgoing_stream), Z_PARTIAL_FLUSH);
		switch (status) {
		case Z_OK:
			/* Append compressed data to output_buffer. */
			buffer_append(output_buffer, buf,
			    sizeof(buf) - THREAD_LOCAL(outgoing_stream).avail_out);
			break;
		default:
			THREAD_LOCAL(deflate_failed) = 1;
			fatal("buffer_compress: deflate returned %d", status);
			/* NOTREACHED */
		}
	} while (THREAD_LOCAL(outgoing_stream).avail_out == 0);
}

/*
 * Uncompresses the contents of input_buffer into output_buffer.  All packets
 * uncompressed using this function will form a single compressed data
 * stream; however, data will be flushed at the end of every call so that
 * each output_buffer.  This must be called for the same size units that the
 * buffer_compress was called, and in the same order that buffers compressed
 * with that.  This appends the uncompressed data to the output buffer.
 */

void
buffer_uncompress(Buffer * input_buffer, Buffer * output_buffer)
{
	u_char buf[4096];
	int status;

	THREAD_LOCAL(incoming_stream).next_in = buffer_ptr(input_buffer);
	THREAD_LOCAL(incoming_stream).avail_in = buffer_len(input_buffer);

	for (;;) {
		/* Set up fixed-size output buffer. */
		THREAD_LOCAL(incoming_stream).next_out = buf;
		THREAD_LOCAL(incoming_stream).avail_out = sizeof(buf);

		status = inflate(&THREAD_LOCAL(incoming_stream), Z_PARTIAL_FLUSH);
		switch (status) {
		case Z_OK:
			buffer_append(output_buffer, buf,
			    sizeof(buf) - THREAD_LOCAL(incoming_stream).avail_out);
			break;
		case Z_BUF_ERROR:
			/*
			 * Comments in zlib.h say that we should keep calling
			 * inflate() until we get an error.  This appears to
			 * be the error that we get.
			 */
			return;
		default:
			THREAD_LOCAL(inflate_failed) = 1;
			fatal("buffer_uncompress: inflate returned %d", status);
			/* NOTREACHED */
		}
	}
}
