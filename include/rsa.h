#ifndef RSA_H
#define RSA_H

#include "types.h"

/* GMP supplies the arithmetic. The sieve and Miller-Rabin are in rsa.c,
 * the same split as the BigInteger example from the handout. */

/* Widths are fixed because build.py mirrors this header by hand: long is 64
 * bits under LP64 and 32 under LLP64, and the mismatch would reach the
 * runtime rather than the compiler. */

i32 rsa_is_probable_prime(const u8 *n_be, usize len, i32 rounds);
usize rsa_small_prime_count(void); /* also forces the table to be built */
u32 rsa_sieve_limit(void);
u32 rsa_window(void);
i32 rsa_online_cores(void);

#endif // RSA_H
