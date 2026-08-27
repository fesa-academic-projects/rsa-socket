#ifndef RSA_H
#define RSA_H

#include "types.h"

/* GMP supplies the arithmetic. The sieve, Miller-Rabin, the search, the
 * modular inverse and the CRT are in rsa.c, the same split as the
 * BigInteger example from the handout. */

/* Widths are fixed because build.py mirrors this header by hand: long is 64
 * bits under LP64 and 32 under LLP64, and the mismatch would reach the
 * runtime rather than the compiler. */

typedef struct rsa_key rsa_key;
typedef struct rsa_keygen rsa_keygen;

/* Split in two so the search can overlap with the socket. bits is the size
 * of the modulus; threads = 0 means one worker per core. */
rsa_keygen *rsa_keygen_start(u32 bits, u32 e, i32 threads);
rsa_key *rsa_keygen_join(rsa_keygen *kg);
void rsa_free(rsa_key *k);

/* Public half. The modulus is big-endian, rsa_modulus_bytes long. */
usize rsa_modulus_bytes(const rsa_key *k);
void rsa_export_modulus(const rsa_key *k, u8 *out);
u32 rsa_exponent(const rsa_key *k);

/* c = m^e mod n under the peer's key. Writes n_len bytes. 0 on success. */
i32 rsa_encrypt(const u8 *n_be, usize n_len, u32 e, const u8 *msg, usize msg_len, u8 *out);

/* m = c^d mod n through the CRT. *out_len is capacity in, length out. */
i32 rsa_decrypt(const rsa_key *k, const u8 *ct, usize ct_len, u8 *out, usize *out_len);

/* The same without the CRT: the benchmark measures what the CRT saves. */
i32 rsa_decrypt_plain(const rsa_key *k, const u8 *ct, usize ct_len, u8 *out, usize *out_len);

/* Decimal form of 'p' 'q' 'n' 'd'. Free with rsa_string_free. */
char *rsa_component(const rsa_key *k, char which);
void rsa_string_free(char *s);

/* Search statistics, for the report. */
u64 rsa_stat_candidates(const rsa_key *k);
u64 rsa_stat_sieved(const rsa_key *k);
i32 rsa_stat_threads(const rsa_key *k);

i32 rsa_is_probable_prime(const u8 *n_be, usize len, i32 rounds);
usize rsa_small_prime_count(void); /* also forces the table to be built */
u32 rsa_sieve_limit(void);
u32 rsa_window(void);
i32 rsa_online_cores(void);

#endif // RSA_H
