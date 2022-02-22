/*	$OpenBSD: includes.h,v 1.22 2006/01/01 08:59:27 stevesk Exp $	*/

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file includes most of the needed system headers.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef INCLUDES_H
#define INCLUDES_H


#include "stdlib.h"
#include <windows.h>




#define RCSID(msg) \
static /**/const char *const rcsid[] = { (const char *)rcsid, "\100(#)" msg }


#include "openssl\opensslv.h"

#include "config.h"
#include "compat_ce.h"
#include <sys\types.h>

#include "sys\socket.h"
#include "openbsd-compat\fake-rfc2553.h"


#include "defines.h"

#include "abort.h"
#include "strerror.h"

#include "xmalloc.h"

#include "kex.h"

#include "mac.h"

#include "pwd.h"


#include "perror.h"
#include "strerror.h"
#include "errno.h"


#include "openbsd-compat\vis.h"

#include "openbsd-compat/openbsd-compat.h"

#endif /* INCLUDES_H */
