/*
 * random.c
 *		Acquire randomness from system.  For seeding RNG.
 *
 * Copyright (c) 2001 Marko Kreen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * contrib/pgcrypto/random.c
 */

#include <errno.h>
#include <time.h>
#include "fortuna_c.h"
#include "px.h"

/* how many bytes to ask from system random provider */
#define RND_BYTES  32

/*
 * Try to read from /dev/urandom or /dev/random on these OS'es.
 *
 * The list can be pretty liberal, as the device not existing
 * is expected event.
 */

#ifdef __riscos

/*
 * On RISC OS the CryptRandom module provides the system randomness. If it
 * is not available, we fall back to mixing in whatever varying state we can
 * read from the timers and the OS, which is weak but better than nothing.
 */
#include "kernel.h"
#include "swis.h"

/* Not present in all swis.h headers */
#ifndef CryptRandom_Block
#define CryptRandom_Block 0x51983
#endif

#else

#define TRY_DEV_RANDOM

#include <fcntl.h>
#include <unistd.h>

#endif

#ifdef TRY_DEV_RANDOM

int
safe_read(int fd, void *buf, size_t count)
{
	int			done = 0;
	char	   *p = buf;
	int			res;

	while (count)
	{
		res = read(fd, p, count);
		if (res <= 0)
		{
			if (errno == EINTR)
				continue;
			return PXE_DEV_READ_ERROR;
		}
		p += res;
		done += res;
		count -= res;
	}
	return done;
}

uint8 *
try_dev_random(uint8 *dst)
{
	int			fd;
	int			res;

	fd = open("/dev/urandom", O_RDONLY, 0);
	if (fd == -1)
	{
		fd = open("/dev/random", O_RDONLY, 0);
		if (fd == -1)
			return dst;
	}
	res = safe_read(fd, dst, RND_BYTES);
	close(fd);
	if (res > 0)
		dst += res;
	return dst;
}

#endif   /* TRY_DEV_RANDOM */

#ifdef __riscos

/*
 * Use CryptRandom_Block to fill RND_BYTES bytes.
 * Returns the new end of the data, or dst if the module was not available.
 */
uint8 *
try_cryptrandom(uint8 *dst)
{
	_kernel_oserror *err;

	err = _swix(CryptRandom_Block, _INR(0, 1), dst, RND_BYTES);
	if (err != NULL)
		return dst;
	return dst + RND_BYTES;
}

/*
 * Fallback when CryptRandom is not present: collect the values of the
 * timers and the pointer state, and the address of a local variable.
 * This offers little entropy, but the Fortuna generator will accumulate it.
 */
uint8 *
try_timers(uint8 *dst)
{
	uint32		words[RND_BYTES / 4];
	uint32		local = 0;
	uint32		t = 0;
	uint32		mouse[4] = {0, 0, 0, 0};
	int			i;

	memset(words, 0, sizeof(words));

	_swix(OS_ReadMonotonicTime, _OUT(0), &t);
	words[0] = t;
	words[1] = (uint32) time(NULL);
	words[2] = (uint32) clock();
	words[3] = (uint32) (size_t) &local;

	/* Pointer x, y, buttons and the time of the last button change */
	_swix(OS_Mouse, _OUTR(0, 3), &mouse[0], &mouse[1], &mouse[2], &mouse[3]);
	for (i = 0; i < 4; i++)
		words[4 + i] = mouse[i];

	memcpy(dst, words, sizeof(words));
	return dst + sizeof(words);
}

#endif   /* __riscos */

/*
 * try to extract some randomness for initial seeding
 *
 * dst should have room for 1024 bytes.
 */
unsigned
px_acquire_system_randomness(uint8 *dst)
{
	uint8	   *p = dst;

#ifdef __riscos
	p = try_cryptrandom(p);
	if (p == dst)
		p = try_timers(p);
#else
	p = try_dev_random(p);
#endif
	return p - dst;
}
