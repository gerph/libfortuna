/*	$OpenBSD: sha2.c,v 1.6 2004/05/03 02:57:36 millert Exp $	*/

/*
 * FILE:	sha2.c
 * AUTHOR:	Aaron D. Gifford <me@aarongifford.com>
 *
 * Copyright (c) 2000-2001, Aaron D. Gifford
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
 * 3. Neither the name of the copyright holder nor the names of contributors
 *	  may be used to endorse or promote products derived from this software
 *	  without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $From: sha2.c,v 1.1 2001/11/08 00:01:51 adg Exp adg $
 *
 * contrib/pgcrypto/sha2.c
 */

#ifndef __riscos
#include <sys/param.h>
#endif

#include "fortuna_c.h"
#include "sha2.h"


/* Types come from fortuna_c.h; a 64-bit word may be a hi/lo pair of 32-bit values */
typedef uint8 sha2_byte;			/* Exactly 1 byte */
typedef uint32 sha2_word32;			/* Exactly 4 bytes */
typedef fortuna_uint64 sha2_word64;	/* Exactly 8 bytes */

/*
 * UNROLLED TRANSFORM LOOP NOTE:
 * You can define SHA2_UNROLL_TRANSFORM to use the unrolled transform
 * loop version for the hash transform rounds (defined using macros
 * later in this file).  Either define on the command line, for example:
 *
 *	 cc -DSHA2_UNROLL_TRANSFORM -o sha2 sha2.c sha2prog.c
 *
 * or define below:
 *
 *	 #define SHA2_UNROLL_TRANSFORM
 *
 */

/*** SHA-256/384/512 Various Length Definitions ***********************/
/* NOTE: Most of these are in sha2.h */
#define SHA256_SHORT_BLOCK_LENGTH	(SHA256_BLOCK_LENGTH - 8)
#define SHA384_SHORT_BLOCK_LENGTH	(SHA384_BLOCK_LENGTH - 16)
#define SHA512_SHORT_BLOCK_LENGTH	(SHA512_BLOCK_LENGTH - 16)


/*** BYTE ORDER AND 64-BIT COUNTER HELPERS ***************************/
/*
 * The digests and message lengths are big-endian, so they are written a byte
 * at a time. This does not depend on the host byte order.
 */
static void
sha2_put_be32(uint8 *dst, sha2_word32 v)
{
	dst[0] = (uint8) (v >> 24);
	dst[1] = (uint8) (v >> 16);
	dst[2] = (uint8) (v >> 8);
	dst[3] = (uint8) v;
}

static void
sha2_put_be64(uint8 *dst, const sha2_word64 *v)
{
#ifdef FORTUNA_32BIT_ONLY
	sha2_put_be32(dst, v->hi);
	sha2_put_be32(dst + 4, v->lo);
#else
	sha2_put_be32(dst, (sha2_word32) (*v >> 32));
	sha2_put_be32(dst + 4, (sha2_word32) *v);
#endif
}

/* Number of bytes held in the current block, given a count of bits */
static size_t
sha2_bc_used(const sha2_word64 *bc, size_t blocklen)
{
#ifdef FORTUNA_32BIT_ONLY
	/* The block length divides 2^32, so the low word is sufficient */
	return (bc->lo >> 3) % blocklen;
#else
	return (size_t) ((*bc >> 3) % blocklen);
#endif
}

/* Add a number of bytes to a 64-bit count of bits */
static void
sha2_bc_add(sha2_word64 *bc, size_t bytes)
{
#ifdef FORTUNA_32BIT_ONLY
	sha2_word32 lo = bc->lo;

	bc->lo += (sha2_word32) (bytes << 3);
	bc->hi += (sha2_word32) (bytes >> 29) + (bc->lo < lo);
#else
	*bc += (sha2_word64) bytes << 3;
#endif
}

/*
 * Add a number of bytes to an unsigned 128-bit count of bits (represented
 * using a two-element array of 64-bit words, low word first). On 32-bit
 * systems the count cannot exceed 64 bits, so the upper word is not used.
 */
static void
sha2_bc_add128(sha2_word64 *bc, size_t bytes)
{
#ifdef FORTUNA_32BIT_ONLY
	sha2_bc_add(&bc[0], bytes);
#else
	sha2_word64 n = (sha2_word64) bytes << 3;

	bc[0] += n;
	if (bc[0] < n)
		bc[1]++;
#endif
}

/*** THE SIX LOGICAL FUNCTIONS ****************************************/
/*
 * Bit shifting and rotation (used by the six SHA-XYZ logical functions:
 *
 *   NOTE:  The naming of R and S appears backwards here (R is a SHIFT and
 *   S is a ROTATION) because the SHA-256/384/512 description document
 *   (see http://csrc.nist.gov/cryptval/shs/sha256-384-512.pdf) uses this
 *   same "backwards" definition.
 */
/* Shift-right (used in SHA-256, SHA-384, and SHA-512): */
#define R(b,x) 		((x) >> (b))
/* 32-bit Rotate-right (used in SHA-256): */
#define S32(b,x)	(((x) >> (b)) | ((x) << (32 - (b))))
#ifndef FORTUNA_32BIT_ONLY
/* 64-bit Rotate-right (used in SHA-384 and SHA-512): */
#define S64(b,x)	(((x) >> (b)) | ((x) << (64 - (b))))
#endif

/* Two of six logical functions used in SHA-256, SHA-384, and SHA-512: */
#define Ch(x,y,z)	(((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)	(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

/* Four of six logical functions used in SHA-256: */
#define Sigma0_256(x)	(S32(2,  (x)) ^ S32(13, (x)) ^ S32(22, (x)))
#define Sigma1_256(x)	(S32(6,  (x)) ^ S32(11, (x)) ^ S32(25, (x)))
#define sigma0_256(x)	(S32(7,  (x)) ^ S32(18, (x)) ^ R(3 ,   (x)))
#define sigma1_256(x)	(S32(17, (x)) ^ S32(19, (x)) ^ R(10,   (x)))

#ifndef FORTUNA_32BIT_ONLY
/* Four of six logical functions used in SHA-384 and SHA-512: */
#define Sigma0_512(x)	(S64(28, (x)) ^ S64(34, (x)) ^ S64(39, (x)))
#define Sigma1_512(x)	(S64(14, (x)) ^ S64(18, (x)) ^ S64(41, (x)))
#define sigma0_512(x)	(S64( 1, (x)) ^ S64( 8, (x)) ^ R( 7,   (x)))
#define sigma1_512(x)	(S64(19, (x)) ^ S64(61, (x)) ^ R( 6,   (x)))
#else
/*
 * Without a native 64-bit type, the SHA-384 and SHA-512 arithmetic is
 * performed on hi/lo pairs. The rotations used are never by 0 or 32, and
 * the shifts are always by fewer than 32.
 */
#define K64(hi,lo)	{ hi, lo }

static sha2_word64
add64(sha2_word64 a, sha2_word64 b)
{
	sha2_word64 r;

	r.lo = a.lo + b.lo;
	r.hi = a.hi + b.hi + (r.lo < a.lo);
	return r;
}

static sha2_word64
rotr64(sha2_word64 x, int n)
{
	sha2_word64 r;

	if (n < 32)
	{
		r.hi = (x.hi >> n) | (x.lo << (32 - n));
		r.lo = (x.lo >> n) | (x.hi << (32 - n));
	}
	else
	{
		n -= 32;
		r.hi = (x.lo >> n) | (x.hi << (32 - n));
		r.lo = (x.hi >> n) | (x.lo << (32 - n));
	}
	return r;
}

static sha2_word64
shr64(sha2_word64 x, int n)
{
	sha2_word64 r;

	r.hi = x.hi >> n;
	r.lo = (x.lo >> n) | (x.hi << (32 - n));
	return r;
}

static sha2_word64
xor3_64(sha2_word64 a, sha2_word64 b, sha2_word64 c)
{
	sha2_word64 r;

	r.hi = a.hi ^ b.hi ^ c.hi;
	r.lo = a.lo ^ b.lo ^ c.lo;
	return r;
}

static sha2_word64
Ch64(sha2_word64 x, sha2_word64 y, sha2_word64 z)
{
	sha2_word64 r;

	r.hi = Ch(x.hi, y.hi, z.hi);
	r.lo = Ch(x.lo, y.lo, z.lo);
	return r;
}

static sha2_word64
Maj64(sha2_word64 x, sha2_word64 y, sha2_word64 z)
{
	sha2_word64 r;

	r.hi = Maj(x.hi, y.hi, z.hi);
	r.lo = Maj(x.lo, y.lo, z.lo);
	return r;
}

#define Sigma0_512(x)	xor3_64(rotr64((x), 28), rotr64((x), 34), rotr64((x), 39))
#define Sigma1_512(x)	xor3_64(rotr64((x), 14), rotr64((x), 18), rotr64((x), 41))
#define sigma0_512(x)	xor3_64(rotr64((x),  1), rotr64((x),  8), shr64((x), 7))
#define sigma1_512(x)	xor3_64(rotr64((x), 19), rotr64((x), 61), shr64((x), 6))
#endif

/*** INTERNAL FUNCTION PROTOTYPES *************************************/
/* NOTE: These should not be accessed directly from outside this
 * library -- they are intended for private internal visibility/use
 * only.
 */
static void SHA512_Last(SHA512_CTX*);
static void SHA256_Transform(SHA256_CTX*, const uint8*);
static void SHA512_Transform(SHA512_CTX*, const uint8*);

/*** SHA-XYZ INITIAL HASH VALUES AND CONSTANTS ************************/
/* Hash constant words K for SHA-256: */
const sha2_word32 K256[64] = {
	0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
	0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
	0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
	0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
	0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
	0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
	0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
	0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
	0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
	0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
	0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
	0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
	0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
	0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
	0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
	0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

/* Initial hash value H for SHA-224: */
const sha2_word32 sha224_initial_hash_value[8] = {
	0xc1059ed8U,
	0x367cd507U,
	0x3070dd17U,
	0xf70e5939U,
	0xffc00b31U,
	0x68581511U,
	0x64f98fa7U,
	0xbefa4fa4U
};

/* Initial hash value H for SHA-256: */
static const sha2_word32 sha256_initial_hash_value[8] = {
	0x6a09e667U,
	0xbb67ae85U,
	0x3c6ef372U,
	0xa54ff53aU,
	0x510e527fU,
	0x9b05688cU,
	0x1f83d9abU,
	0x5be0cd19U
};

#ifndef FORTUNA_32BIT_ONLY
/* A 64-bit constant, given as its high and low 32-bit words */
#define K64(hi,lo)	(((sha2_word64)(hi) << 32) | (lo))
#endif

/* Hash constant words K for SHA-384 and SHA-512: */
static const sha2_word64 K512[80] = {
	K64(0x428a2f98U, 0xd728ae22U), K64(0x71374491U, 0x23ef65cdU),
	K64(0xb5c0fbcfU, 0xec4d3b2fU), K64(0xe9b5dba5U, 0x8189dbbcU),
	K64(0x3956c25bU, 0xf348b538U), K64(0x59f111f1U, 0xb605d019U),
	K64(0x923f82a4U, 0xaf194f9bU), K64(0xab1c5ed5U, 0xda6d8118U),
	K64(0xd807aa98U, 0xa3030242U), K64(0x12835b01U, 0x45706fbeU),
	K64(0x243185beU, 0x4ee4b28cU), K64(0x550c7dc3U, 0xd5ffb4e2U),
	K64(0x72be5d74U, 0xf27b896fU), K64(0x80deb1feU, 0x3b1696b1U),
	K64(0x9bdc06a7U, 0x25c71235U), K64(0xc19bf174U, 0xcf692694U),
	K64(0xe49b69c1U, 0x9ef14ad2U), K64(0xefbe4786U, 0x384f25e3U),
	K64(0x0fc19dc6U, 0x8b8cd5b5U), K64(0x240ca1ccU, 0x77ac9c65U),
	K64(0x2de92c6fU, 0x592b0275U), K64(0x4a7484aaU, 0x6ea6e483U),
	K64(0x5cb0a9dcU, 0xbd41fbd4U), K64(0x76f988daU, 0x831153b5U),
	K64(0x983e5152U, 0xee66dfabU), K64(0xa831c66dU, 0x2db43210U),
	K64(0xb00327c8U, 0x98fb213fU), K64(0xbf597fc7U, 0xbeef0ee4U),
	K64(0xc6e00bf3U, 0x3da88fc2U), K64(0xd5a79147U, 0x930aa725U),
	K64(0x06ca6351U, 0xe003826fU), K64(0x14292967U, 0x0a0e6e70U),
	K64(0x27b70a85U, 0x46d22ffcU), K64(0x2e1b2138U, 0x5c26c926U),
	K64(0x4d2c6dfcU, 0x5ac42aedU), K64(0x53380d13U, 0x9d95b3dfU),
	K64(0x650a7354U, 0x8baf63deU), K64(0x766a0abbU, 0x3c77b2a8U),
	K64(0x81c2c92eU, 0x47edaee6U), K64(0x92722c85U, 0x1482353bU),
	K64(0xa2bfe8a1U, 0x4cf10364U), K64(0xa81a664bU, 0xbc423001U),
	K64(0xc24b8b70U, 0xd0f89791U), K64(0xc76c51a3U, 0x0654be30U),
	K64(0xd192e819U, 0xd6ef5218U), K64(0xd6990624U, 0x5565a910U),
	K64(0xf40e3585U, 0x5771202aU), K64(0x106aa070U, 0x32bbd1b8U),
	K64(0x19a4c116U, 0xb8d2d0c8U), K64(0x1e376c08U, 0x5141ab53U),
	K64(0x2748774cU, 0xdf8eeb99U), K64(0x34b0bcb5U, 0xe19b48a8U),
	K64(0x391c0cb3U, 0xc5c95a63U), K64(0x4ed8aa4aU, 0xe3418acbU),
	K64(0x5b9cca4fU, 0x7763e373U), K64(0x682e6ff3U, 0xd6b2b8a3U),
	K64(0x748f82eeU, 0x5defb2fcU), K64(0x78a5636fU, 0x43172f60U),
	K64(0x84c87814U, 0xa1f0ab72U), K64(0x8cc70208U, 0x1a6439ecU),
	K64(0x90befffaU, 0x23631e28U), K64(0xa4506cebU, 0xde82bde9U),
	K64(0xbef9a3f7U, 0xb2c67915U), K64(0xc67178f2U, 0xe372532bU),
	K64(0xca273eceU, 0xea26619cU), K64(0xd186b8c7U, 0x21c0c207U),
	K64(0xeada7dd6U, 0xcde0eb1eU), K64(0xf57d4f7fU, 0xee6ed178U),
	K64(0x06f067aaU, 0x72176fbaU), K64(0x0a637dc5U, 0xa2c898a6U),
	K64(0x113f9804U, 0xbef90daeU), K64(0x1b710b35U, 0x131c471bU),
	K64(0x28db77f5U, 0x23047d84U), K64(0x32caab7bU, 0x40c72493U),
	K64(0x3c9ebe0aU, 0x15c9bebcU), K64(0x431d67c4U, 0x9c100d4cU),
	K64(0x4cc5d4beU, 0xcb3e42b6U), K64(0x597f299cU, 0xfc657e2aU),
	K64(0x5fcb6fabU, 0x3ad6faecU), K64(0x6c44198cU, 0x4a475817U)
};

/* Initial hash value H for SHA-384 */
static const sha2_word64 sha384_initial_hash_value[8] = {
	K64(0xcbbb9d5dU, 0xc1059ed8U),
	K64(0x629a292aU, 0x367cd507U),
	K64(0x9159015aU, 0x3070dd17U),
	K64(0x152fecd8U, 0xf70e5939U),
	K64(0x67332667U, 0xffc00b31U),
	K64(0x8eb44a87U, 0x68581511U),
	K64(0xdb0c2e0dU, 0x64f98fa7U),
	K64(0x47b5481dU, 0xbefa4fa4U)
};

/* Initial hash value H for SHA-512 */
static const sha2_word64 sha512_initial_hash_value[8] = {
	K64(0x6a09e667U, 0xf3bcc908U),
	K64(0xbb67ae85U, 0x84caa73bU),
	K64(0x3c6ef372U, 0xfe94f82bU),
	K64(0xa54ff53aU, 0x5f1d36f1U),
	K64(0x510e527fU, 0xade682d1U),
	K64(0x9b05688cU, 0x2b3e6c1fU),
	K64(0x1f83d9abU, 0xfb41bd6bU),
	K64(0x5be0cd19U, 0x137e2179U)
};


/*** SHA-256: *********************************************************/
void
SHA256_Init(SHA256_CTX *context)
{
	if (context == NULL)
		return;
	memcpy(context->state, sha256_initial_hash_value, SHA256_DIGEST_LENGTH);
	memset(context->buffer, 0, SHA256_BLOCK_LENGTH);
	memset(&context->bitcount, 0, sizeof(context->bitcount));
}

#ifdef SHA2_UNROLL_TRANSFORM

/* Unrolled SHA-256 round macros: */

#define ROUND256_0_TO_15(a,b,c,d,e,f,g,h) do {					\
	W256[j] = (sha2_word32)data[3] | ((sha2_word32)data[2] << 8) |		\
		((sha2_word32)data[1] << 16) | ((sha2_word32)data[0] << 24);		\
	data += 4;								\
	T1 = (h) + Sigma1_256((e)) + Ch((e), (f), (g)) + K256[j] + W256[j]; \
	(d) += T1;								\
	(h) = T1 + Sigma0_256((a)) + Maj((a), (b), (c));			\
	j++;									\
} while(0)

#define ROUND256(a,b,c,d,e,f,g,h) do {						\
	s0 = W256[(j+1)&0x0f];							\
	s0 = sigma0_256(s0);							\
	s1 = W256[(j+14)&0x0f];							\
	s1 = sigma1_256(s1);							\
	T1 = (h) + Sigma1_256((e)) + Ch((e), (f), (g)) + K256[j] +		\
		 (W256[j&0x0f] += s1 + W256[(j+9)&0x0f] + s0);			\
	(d) += T1;								\
	(h) = T1 + Sigma0_256((a)) + Maj((a), (b), (c));			\
	j++;									\
} while(0)

static void
SHA256_Transform(SHA256_CTX *context, const uint8 *data)
{
	sha2_word32		a,
				b,
				c,
				d,
				e,
				f,
				g,
				h,
				s0,
				s1;
	sha2_word32		T1,
			   *W256;
	int			j;

	W256 = (sha2_word32 *) context->buffer;

	/* Initialize registers with the prev. intermediate value */
	a = context->state[0];
	b = context->state[1];
	c = context->state[2];
	d = context->state[3];
	e = context->state[4];
	f = context->state[5];
	g = context->state[6];
	h = context->state[7];

	j = 0;
	do
	{
		/* Rounds 0 to 15 (unrolled): */
		ROUND256_0_TO_15(a, b, c, d, e, f, g, h);
		ROUND256_0_TO_15(h, a, b, c, d, e, f, g);
		ROUND256_0_TO_15(g, h, a, b, c, d, e, f);
		ROUND256_0_TO_15(f, g, h, a, b, c, d, e);
		ROUND256_0_TO_15(e, f, g, h, a, b, c, d);
		ROUND256_0_TO_15(d, e, f, g, h, a, b, c);
		ROUND256_0_TO_15(c, d, e, f, g, h, a, b);
		ROUND256_0_TO_15(b, c, d, e, f, g, h, a);
	} while (j < 16);

	/* Now for the remaining rounds to 64: */
	do
	{
		ROUND256(a, b, c, d, e, f, g, h);
		ROUND256(h, a, b, c, d, e, f, g);
		ROUND256(g, h, a, b, c, d, e, f);
		ROUND256(f, g, h, a, b, c, d, e);
		ROUND256(e, f, g, h, a, b, c, d);
		ROUND256(d, e, f, g, h, a, b, c);
		ROUND256(c, d, e, f, g, h, a, b);
		ROUND256(b, c, d, e, f, g, h, a);
	} while (j < 64);

	/* Compute the current intermediate hash value */
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;

	/* Clean up */
	a = b = c = d = e = f = g = h = T1 = 0;
}
#else							/* SHA2_UNROLL_TRANSFORM */

static void
SHA256_Transform(SHA256_CTX *context, const uint8 *data)
{
	sha2_word32		a,
				b,
				c,
				d,
				e,
				f,
				g,
				h,
				s0,
				s1;
	sha2_word32		T1,
				T2,
			   *W256;
	int			j;

	W256 = (sha2_word32 *) context->buffer;

	/* Initialize registers with the prev. intermediate value */
	a = context->state[0];
	b = context->state[1];
	c = context->state[2];
	d = context->state[3];
	e = context->state[4];
	f = context->state[5];
	g = context->state[6];
	h = context->state[7];

	j = 0;
	do
	{
		W256[j] = (sha2_word32) data[3] | ((sha2_word32) data[2] << 8) |
			((sha2_word32) data[1] << 16) | ((sha2_word32) data[0] << 24);
		data += 4;
		/* Apply the SHA-256 compression function to update a..h */
		T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] + W256[j];
		T2 = Sigma0_256(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;

		j++;
	} while (j < 16);

	do
	{
		/* Part of the message block expansion: */
		s0 = W256[(j + 1) & 0x0f];
		s0 = sigma0_256(s0);
		s1 = W256[(j + 14) & 0x0f];
		s1 = sigma1_256(s1);

		/* Apply the SHA-256 compression function to update a..h */
		T1 = h + Sigma1_256(e) + Ch(e, f, g) + K256[j] +
			(W256[j & 0x0f] += s1 + W256[(j + 9) & 0x0f] + s0);
		T2 = Sigma0_256(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;

		j++;
	} while (j < 64);

	/* Compute the current intermediate hash value */
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;

	/* Clean up */
	a = b = c = d = e = f = g = h = T1 = T2 = 0;
}
#endif   /* SHA2_UNROLL_TRANSFORM */

void
SHA256_Update(SHA256_CTX *context, const uint8 *data, size_t len)
{
	size_t		freespace,
				usedspace;

	/* Calling with no data is valid (we do nothing) */
	if (len == 0)
		return;

	usedspace = sha2_bc_used(&context->bitcount, SHA256_BLOCK_LENGTH);
	if (usedspace > 0)
	{
		/* Calculate how much free space is available in the buffer */
		freespace = SHA256_BLOCK_LENGTH - usedspace;

		if (len >= freespace)
		{
			/* Fill the buffer completely and process it */
			memcpy(&context->buffer[usedspace], data, freespace);
			sha2_bc_add(&context->bitcount, freespace);
			len -= freespace;
			data += freespace;
			SHA256_Transform(context, context->buffer);
		}
		else
		{
			/* The buffer is not yet full */
			memcpy(&context->buffer[usedspace], data, len);
			sha2_bc_add(&context->bitcount, len);
			/* Clean up: */
			usedspace = freespace = 0;
			return;
		}
	}
	while (len >= SHA256_BLOCK_LENGTH)
	{
		/* Process as many complete blocks as we can */
		SHA256_Transform(context, data);
		sha2_bc_add(&context->bitcount, SHA256_BLOCK_LENGTH);
		len -= SHA256_BLOCK_LENGTH;
		data += SHA256_BLOCK_LENGTH;
	}
	if (len > 0)
	{
		/* There's left-overs, so save 'em */
		memcpy(context->buffer, data, len);
		sha2_bc_add(&context->bitcount, len);
	}
	/* Clean up: */
	usedspace = freespace = 0;
}

void
SHA256_Last(SHA256_CTX *context)
{
	unsigned int usedspace;

	usedspace = sha2_bc_used(&context->bitcount, SHA256_BLOCK_LENGTH);
	if (usedspace > 0)
	{
		/* Begin padding with a 1 bit: */
		context->buffer[usedspace++] = 0x80;

		if (usedspace <= SHA256_SHORT_BLOCK_LENGTH)
		{
			/* Set-up for the last transform: */
			memset(&context->buffer[usedspace], 0, SHA256_SHORT_BLOCK_LENGTH - usedspace);
		}
		else
		{
			if (usedspace < SHA256_BLOCK_LENGTH)
			{
				memset(&context->buffer[usedspace], 0, SHA256_BLOCK_LENGTH - usedspace);
			}
			/* Do second-to-last transform: */
			SHA256_Transform(context, context->buffer);

			/* And set-up for the last transform: */
			memset(context->buffer, 0, SHA256_SHORT_BLOCK_LENGTH);
		}
	}
	else
	{
		/* Set-up for the last transform: */
		memset(context->buffer, 0, SHA256_SHORT_BLOCK_LENGTH);

		/* Begin padding with a 1 bit: */
		*context->buffer = 0x80;
	}
	/* Set the bit count: */
	sha2_put_be64(&context->buffer[SHA256_SHORT_BLOCK_LENGTH], &context->bitcount);

	/* Final transform: */
	SHA256_Transform(context, context->buffer);
}

void
SHA256_Final(uint8 digest[], SHA256_CTX *context)
{
	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != NULL)
	{
		SHA256_Last(context);

		{
			/* Output the state as big-endian words */
			int			j;

			for (j = 0; j < 8; j++)
			{
				sha2_put_be32(&digest[j * 4], context->state[j]);
			}
		}
	}

	/* Clean up state data: */
	memset(context, 0, sizeof(*context));
}


/*** SHA-512: *********************************************************/
void
SHA512_Init(SHA512_CTX *context)
{
	if (context == NULL)
		return;
	memcpy(context->state, sha512_initial_hash_value, SHA512_DIGEST_LENGTH);
	memset(context->buffer, 0, SHA512_BLOCK_LENGTH);
	memset(context->bitcount, 0, sizeof(context->bitcount));
}

#if defined(SHA2_UNROLL_TRANSFORM) && !defined(FORTUNA_32BIT_ONLY)

/* Unrolled SHA-512 round macros: */

#define ROUND512_0_TO_15(a,b,c,d,e,f,g,h) do {					\
	W512[j] = (sha2_word64)data[7] | ((sha2_word64)data[6] << 8) |		\
		((sha2_word64)data[5] << 16) | ((sha2_word64)data[4] << 24) |		\
		((sha2_word64)data[3] << 32) | ((sha2_word64)data[2] << 40) |		\
		((sha2_word64)data[1] << 48) | ((sha2_word64)data[0] << 56);		\
	data += 8;								\
	T1 = (h) + Sigma1_512((e)) + Ch((e), (f), (g)) + K512[j] + W512[j]; \
	(d) += T1;								\
	(h) = T1 + Sigma0_512((a)) + Maj((a), (b), (c));			\
	j++;									\
} while(0)


#define ROUND512(a,b,c,d,e,f,g,h) do {						\
	s0 = W512[(j+1)&0x0f];							\
	s0 = sigma0_512(s0);							\
	s1 = W512[(j+14)&0x0f];							\
	s1 = sigma1_512(s1);							\
	T1 = (h) + Sigma1_512((e)) + Ch((e), (f), (g)) + K512[j] +		\
			 (W512[j&0x0f] += s1 + W512[(j+9)&0x0f] + s0);			\
	(d) += T1;								\
	(h) = T1 + Sigma0_512((a)) + Maj((a), (b), (c));			\
	j++;									\
} while(0)

static void
SHA512_Transform(SHA512_CTX *context, const uint8 *data)
{
	sha2_word64		a,
				b,
				c,
				d,
				e,
				f,
				g,
				h,
				s0,
				s1;
	sha2_word64		T1,
			   *W512 = (sha2_word64 *) context->buffer;
	int			j;

	/* Initialize registers with the prev. intermediate value */
	a = context->state[0];
	b = context->state[1];
	c = context->state[2];
	d = context->state[3];
	e = context->state[4];
	f = context->state[5];
	g = context->state[6];
	h = context->state[7];

	j = 0;
	do
	{
		ROUND512_0_TO_15(a, b, c, d, e, f, g, h);
		ROUND512_0_TO_15(h, a, b, c, d, e, f, g);
		ROUND512_0_TO_15(g, h, a, b, c, d, e, f);
		ROUND512_0_TO_15(f, g, h, a, b, c, d, e);
		ROUND512_0_TO_15(e, f, g, h, a, b, c, d);
		ROUND512_0_TO_15(d, e, f, g, h, a, b, c);
		ROUND512_0_TO_15(c, d, e, f, g, h, a, b);
		ROUND512_0_TO_15(b, c, d, e, f, g, h, a);
	} while (j < 16);

	/* Now for the remaining rounds up to 79: */
	do
	{
		ROUND512(a, b, c, d, e, f, g, h);
		ROUND512(h, a, b, c, d, e, f, g);
		ROUND512(g, h, a, b, c, d, e, f);
		ROUND512(f, g, h, a, b, c, d, e);
		ROUND512(e, f, g, h, a, b, c, d);
		ROUND512(d, e, f, g, h, a, b, c);
		ROUND512(c, d, e, f, g, h, a, b);
		ROUND512(b, c, d, e, f, g, h, a);
	} while (j < 80);

	/* Compute the current intermediate hash value */
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;

	/* Clean up */
	a = b = c = d = e = f = g = h = T1 = 0;
}
#elif defined(FORTUNA_32BIT_ONLY)

/* SHA-512 on hi/lo pairs of 32-bit words (no unrolled form is provided) */
static void
SHA512_Transform(SHA512_CTX *context, const uint8 *data)
{
	sha2_word64		a,
				b,
				c,
				d,
				e,
				f,
				g,
				h,
				s0,
				s1;
	sha2_word64		T1,
				T2,
			   *W512 = (sha2_word64 *) context->buffer;
	int			j;

	/* Initialize registers with the prev. intermediate value */
	a = context->state[0];
	b = context->state[1];
	c = context->state[2];
	d = context->state[3];
	e = context->state[4];
	f = context->state[5];
	g = context->state[6];
	h = context->state[7];

	j = 0;
	do
	{
		W512[j].hi = ((sha2_word32) data[0] << 24) | ((sha2_word32) data[1] << 16) |
			((sha2_word32) data[2] << 8) | (sha2_word32) data[3];
		W512[j].lo = ((sha2_word32) data[4] << 24) | ((sha2_word32) data[5] << 16) |
			((sha2_word32) data[6] << 8) | (sha2_word32) data[7];
		data += 8;
		/* Apply the SHA-512 compression function to update a..h */
		T1 = add64(add64(h, Sigma1_512(e)), add64(Ch64(e, f, g), add64(K512[j], W512[j])));
		T2 = add64(Sigma0_512(a), Maj64(a, b, c));
		h = g;
		g = f;
		f = e;
		e = add64(d, T1);
		d = c;
		c = b;
		b = a;
		a = add64(T1, T2);

		j++;
	} while (j < 16);

	do
	{
		/* Part of the message block expansion: */
		s0 = sigma0_512(W512[(j + 1) & 0x0f]);
		s1 = sigma1_512(W512[(j + 14) & 0x0f]);
		W512[j & 0x0f] = add64(W512[j & 0x0f],
							   add64(s1, add64(W512[(j + 9) & 0x0f], s0)));

		/* Apply the SHA-512 compression function to update a..h */
		T1 = add64(add64(h, Sigma1_512(e)),
				   add64(Ch64(e, f, g), add64(K512[j], W512[j & 0x0f])));
		T2 = add64(Sigma0_512(a), Maj64(a, b, c));
		h = g;
		g = f;
		f = e;
		e = add64(d, T1);
		d = c;
		c = b;
		b = a;
		a = add64(T1, T2);

		j++;
	} while (j < 80);

	/* Compute the current intermediate hash value */
	context->state[0] = add64(context->state[0], a);
	context->state[1] = add64(context->state[1], b);
	context->state[2] = add64(context->state[2], c);
	context->state[3] = add64(context->state[3], d);
	context->state[4] = add64(context->state[4], e);
	context->state[5] = add64(context->state[5], f);
	context->state[6] = add64(context->state[6], g);
	context->state[7] = add64(context->state[7], h);

	/* Clean up */
	memset(&T1, 0, sizeof(T1));
	memset(&T2, 0, sizeof(T2));
}
#else							/* SHA2_UNROLL_TRANSFORM */

static void
SHA512_Transform(SHA512_CTX *context, const uint8 *data)
{
	sha2_word64		a,
				b,
				c,
				d,
				e,
				f,
				g,
				h,
				s0,
				s1;
	sha2_word64		T1,
				T2,
			   *W512 = (sha2_word64 *) context->buffer;
	int			j;

	/* Initialize registers with the prev. intermediate value */
	a = context->state[0];
	b = context->state[1];
	c = context->state[2];
	d = context->state[3];
	e = context->state[4];
	f = context->state[5];
	g = context->state[6];
	h = context->state[7];

	j = 0;
	do
	{
		W512[j] = (sha2_word64) data[7] | ((sha2_word64) data[6] << 8) |
			((sha2_word64) data[5] << 16) | ((sha2_word64) data[4] << 24) |
			((sha2_word64) data[3] << 32) | ((sha2_word64) data[2] << 40) |
			((sha2_word64) data[1] << 48) | ((sha2_word64) data[0] << 56);
		data += 8;
		/* Apply the SHA-512 compression function to update a..h */
		T1 = h + Sigma1_512(e) + Ch(e, f, g) + K512[j] + W512[j];
		T2 = Sigma0_512(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;

		j++;
	} while (j < 16);

	do
	{
		/* Part of the message block expansion: */
		s0 = W512[(j + 1) & 0x0f];
		s0 = sigma0_512(s0);
		s1 = W512[(j + 14) & 0x0f];
		s1 = sigma1_512(s1);

		/* Apply the SHA-512 compression function to update a..h */
		T1 = h + Sigma1_512(e) + Ch(e, f, g) + K512[j] +
			(W512[j & 0x0f] += s1 + W512[(j + 9) & 0x0f] + s0);
		T2 = Sigma0_512(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;

		j++;
	} while (j < 80);

	/* Compute the current intermediate hash value */
	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;

	/* Clean up */
	a = b = c = d = e = f = g = h = T1 = T2 = 0;
}
#endif   /* SHA2_UNROLL_TRANSFORM */

void
SHA512_Update(SHA512_CTX *context, const uint8 *data, size_t len)
{
	size_t		freespace,
				usedspace;

	/* Calling with no data is valid (we do nothing) */
	if (len == 0)
		return;

	usedspace = sha2_bc_used(&context->bitcount[0], SHA512_BLOCK_LENGTH);
	if (usedspace > 0)
	{
		/* Calculate how much free space is available in the buffer */
		freespace = SHA512_BLOCK_LENGTH - usedspace;

		if (len >= freespace)
		{
			/* Fill the buffer completely and process it */
			memcpy(&context->buffer[usedspace], data, freespace);
			sha2_bc_add128(context->bitcount, freespace);
			len -= freespace;
			data += freespace;
			SHA512_Transform(context, context->buffer);
		}
		else
		{
			/* The buffer is not yet full */
			memcpy(&context->buffer[usedspace], data, len);
			sha2_bc_add128(context->bitcount, len);
			/* Clean up: */
			usedspace = freespace = 0;
			return;
		}
	}
	while (len >= SHA512_BLOCK_LENGTH)
	{
		/* Process as many complete blocks as we can */
		SHA512_Transform(context, data);
		sha2_bc_add128(context->bitcount, SHA512_BLOCK_LENGTH);
		len -= SHA512_BLOCK_LENGTH;
		data += SHA512_BLOCK_LENGTH;
	}
	if (len > 0)
	{
		/* There's left-overs, so save 'em */
		memcpy(context->buffer, data, len);
		sha2_bc_add128(context->bitcount, len);
	}
	/* Clean up: */
	usedspace = freespace = 0;
}

static void
SHA512_Last(SHA512_CTX *context)
{
	unsigned int usedspace;

	usedspace = sha2_bc_used(&context->bitcount[0], SHA512_BLOCK_LENGTH);
	if (usedspace > 0)
	{
		/* Begin padding with a 1 bit: */
		context->buffer[usedspace++] = 0x80;

		if (usedspace <= SHA512_SHORT_BLOCK_LENGTH)
		{
			/* Set-up for the last transform: */
			memset(&context->buffer[usedspace], 0, SHA512_SHORT_BLOCK_LENGTH - usedspace);
		}
		else
		{
			if (usedspace < SHA512_BLOCK_LENGTH)
			{
				memset(&context->buffer[usedspace], 0, SHA512_BLOCK_LENGTH - usedspace);
			}
			/* Do second-to-last transform: */
			SHA512_Transform(context, context->buffer);

			/* And set-up for the last transform: */
			memset(context->buffer, 0, SHA512_BLOCK_LENGTH - 2);
		}
	}
	else
	{
		/* Prepare for final transform: */
		memset(context->buffer, 0, SHA512_SHORT_BLOCK_LENGTH);

		/* Begin padding with a 1 bit: */
		*context->buffer = 0x80;
	}
	/* Store the length of input data (in bits): */
	sha2_put_be64(&context->buffer[SHA512_SHORT_BLOCK_LENGTH], &context->bitcount[1]);
	sha2_put_be64(&context->buffer[SHA512_SHORT_BLOCK_LENGTH + 8], &context->bitcount[0]);

	/* Final transform: */
	SHA512_Transform(context, context->buffer);
}

void
SHA512_Final(uint8 digest[], SHA512_CTX *context)
{
	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != NULL)
	{
		SHA512_Last(context);

		/* Save the hash data for output: */
		{
			/* Output the state as big-endian words */
			int			j;

			for (j = 0; j < 8; j++)
			{
				sha2_put_be64(&digest[j * 8], &context->state[j]);
			}
		}
	}

	/* Zero out state data */
	memset(context, 0, sizeof(*context));
}


/*** SHA-384: *********************************************************/
void
SHA384_Init(SHA384_CTX *context)
{
	if (context == NULL)
		return;
	memcpy(context->state, sha384_initial_hash_value, SHA512_DIGEST_LENGTH);
	memset(context->buffer, 0, SHA384_BLOCK_LENGTH);
	memset(context->bitcount, 0, sizeof(context->bitcount));
}

void
SHA384_Update(SHA384_CTX *context, const uint8 *data, size_t len)
{
	SHA512_Update((SHA512_CTX *) context, data, len);
}

void
SHA384_Final(uint8 digest[], SHA384_CTX *context)
{
	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != NULL)
	{
		SHA512_Last((SHA512_CTX *) context);

		/* Save the hash data for output: */
		{
			/* Output the state as big-endian words */
			int			j;

			for (j = 0; j < 6; j++)
			{
				sha2_put_be64(&digest[j * 8], &context->state[j]);
			}
		}
	}

	/* Zero out state data */
	memset(context, 0, sizeof(*context));
}

/*** SHA-224: *********************************************************/
void
SHA224_Init(SHA224_CTX *context)
{
	if (context == NULL)
		return;
	memcpy(context->state, sha224_initial_hash_value, SHA256_DIGEST_LENGTH);
	memset(context->buffer, 0, SHA256_BLOCK_LENGTH);
	memset(&context->bitcount, 0, sizeof(context->bitcount));
}

void
SHA224_Update(SHA224_CTX *context, const uint8 *data, size_t len)
{
	SHA256_Update((SHA256_CTX *) context, data, len);
}

void
SHA224_Final(uint8 digest[], SHA224_CTX *context)
{
	/* If no digest buffer is passed, we don't bother doing this: */
	if (digest != NULL)
	{
		SHA256_Last(context);

		{
			/* Output the state as big-endian words (only 7 are kept) */
			sha2_byte	full[SHA256_DIGEST_LENGTH];
			int			j;

			for (j = 0; j < 8; j++)
			{
				sha2_put_be32(&full[j * 4], context->state[j]);
			}
			memcpy(digest, full, SHA224_DIGEST_LENGTH);
		}
	}

	/* Clean up state data: */
	memset(context, 0, sizeof(*context));
}
