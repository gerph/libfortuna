/*-------------------------------------------------------------------------
 *
 * c.h
 *	  Fundamental C definitions.  This is included by every .c file in
 *	  PostgreSQL (via either postgres.h or postgres_fe.h, as appropriate).
 *
 *	  Note that the definitions here are not intended to be exposed to clients
 *	  of the frontend interface libraries --- so we don't worry much about
 *	  polluting the namespace with lots of stuff...
 *
 *
 * Portions Copyright (c) 1996-2012, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/c.h
 *
 *-------------------------------------------------------------------------
 */
/*
 *----------------------------------------------------------------
 *	 TABLE OF CONTENTS
 *
 *		When adding stuff to this file, please try to put stuff
 *		into the relevant section, or add new sections as appropriate.
 *
 *	  section	description
 *	  -------	------------------------------------------------
 *		0)		pg_config.h and standard system headers
 *		1)		hacks to cope with non-ANSI C compilers
 *		2)		bool, true, false, TRUE, FALSE, NULL
 *		3)		standard system types
 *		4)		IsValid macros for system types
 *		5)		offsetof, lengthof, endof, alignment
 *		6)		widely useful macros
 *		7)		random stuff
 *		8)		system-specific hacks
 *
 * NOTE: since this file is included by both frontend and backend modules, it's
 * almost certainly wrong to put an "extern" declaration here.	typedefs and
 * macros are the kind of thing that might go here.
 *
 *----------------------------------------------------------------
 */
#ifndef C_H
#define C_H



#ifndef __riscos
#include <sys/types.h>
#endif
#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>


typedef signed char int8;		/* == 8 bits */
typedef signed short int16;		/* == 16 bits */
typedef signed int int32;		/* == 32 bits */

typedef unsigned char uint8;	/* == 8 bits */
typedef unsigned short uint16;	/* == 16 bits */
typedef unsigned int uint32;	/* == 32 bits */

typedef uint8 bits8;			/* >= 8 bits */
typedef uint16 bits16;			/* >= 16 bits */
typedef uint32 bits32;			/* >= 32 bits */

/*
 * RISC OS: the 32-bit Norcroft compiler has no usable 64-bit integer type.
 * Note that __riscos is also defined for 64-bit builds, so the 32-bit case
 * must exclude __riscos64 explicitly. Code needing 64-bit arithmetic must
 * use hi/lo pairs of 32-bit values when FORTUNA_32BIT_ONLY is defined.
 * Defining FORTUNA_FORCE_32BIT selects that code on any platform, for testing.
 */
#if (defined(__riscos) && !defined(__riscos64)) || defined(FORTUNA_FORCE_32BIT)
#define FORTUNA_32BIT_ONLY
#endif

#ifdef FORTUNA_32BIT_ONLY
/* No native 64-bit integer: a 64-bit value is held as a pair of 32-bit words */
typedef struct fortuna_uint64_s
{
	uint32 hi;
	uint32 lo;
} fortuna_uint64;
#else
#ifdef __riscos64
typedef long long int int64;
typedef unsigned long long int uint64;
#else
typedef long int int64;
typedef unsigned long int uint64;
#endif
typedef uint64 fortuna_uint64;
#endif

/*
 * A 64-bit counter overlaid on bytes, used for the message length in the
 * SHA-1 and MD5 contexts. On a 32-bit-only system it is held as two 32-bit
 * words, low word first (the target is little-endian).
 * FORTUNA_CTR_ADD adds a number of bytes (as a count of bits) to the counter.
 */
#ifdef FORTUNA_32BIT_ONLY
typedef uint32 fortuna_ctr64[2];
#define FORTUNA_CTR_ADD(ctr, bytes) \
	do { \
		uint32 fortuna_lo_ = (ctr)[0]; \
		(ctr)[0] += (uint32) (bytes) << 3; \
		(ctr)[1] += ((uint32) (bytes) >> 29) + ((ctr)[0] < fortuna_lo_); \
	} while (0)
#else
typedef uint64 fortuna_ctr64[1];
#define FORTUNA_CTR_ADD(ctr, bytes) \
	((ctr)[0] += (uint64) (bytes) * 8)
#endif

typedef int16 int2;
typedef int32 int4;
typedef float float4;
typedef double float8;


#endif
