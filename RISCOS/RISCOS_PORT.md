# RISC OS Port Report

## Overview

- Project: `Fortuna`
- Type: `library` (library port selected for this run)
- Source root: `.`
- Output tree: `RISCOS`

## Name And Type

- Inferred name: `Fortuna` (explicit --name override, confidence: high)
- Project mode: library port

## Sources And Entry Points

- Library source files: 8
  - src/blf.c
  - src/fortuna.c
  - src/internal.c
  - src/md5.c
  - src/px.c
  - src/random.c
  - src/sha1.c
  - src/sha2.c

- Entry point sources: 1
  - `src/rijndael.c` -> command source (contains `main()`)

## Headers And Makefiles

- Exported headers:
  - blf
  - fortuna
  - fortuna_c
  - internal
  - md5
  - px
  - rijndael
  - sha1
  - sha2

- Compile-time headers:
  - src/blf.h
  - src/fortuna.h
  - src/fortuna_c.h
  - src/internal.h
  - src/md5.h
  - src/px.h
  - src/rijndael.h
  - src/sha1.h
  - src/sha2.h

- Generated command makefiles:
  - MakefileRijndael,fe1

## Build Commands

- Run these commands from the source root to build each component:
  - `cd RISCOS && riscos-amu export`
  - `cd RISCOS && riscos-amu -f MakefileRijndael,fe1`

## External Libraries

- None discovered by the current heuristics

## Portability Warnings

- src/fortuna.c: uses designated initialisers
- src/internal.c: uses designated initialisers
- src/random.c: uses Unix file/process APIs such as `open()`, `read()`, `stat()`, or `lseek()`
- src/random.c: appears to use POSIX-style filename paths or filename construction with `snprintf()` or `sprintf()` and / separators; RISC OS filename conventions may need updating
- src/random.c: includes Unix/POSIX headers that usually need replacement on RISC OS
- src/sha2.c: uses designated initialisers
- src/fortuna_c.h: uses 64-bit integer types that are not portable to 32-bit Norcroft
- src/fortuna_c.h: includes Unix/POSIX headers that usually need replacement on RISC OS
- src/md5.h: uses 64-bit integer types that are not portable to 32-bit Norcroft
- src/px.h: includes Unix/POSIX headers that usually need replacement on RISC OS
- src/sha1.h: uses 64-bit integer types that are not portable to 32-bit Norcroft

## Confidence Notes

- Project name: high confidence from explicit --name override.
- Source discovery: autodiscovered source directory.
- Entry points: high confidence because the scanner only classifies sources that contain `main()`.
- Dependencies: medium confidence because they are inferred from headers and link flags.
- Portability warnings: high confidence because they come from direct pattern matches in the source.
- Command makefiles: high confidence because they were generated from each discovered command source.

