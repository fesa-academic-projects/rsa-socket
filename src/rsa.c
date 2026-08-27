#include "rsa.h"

#include <gmp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* A random odd near 2^2048 is prime with probability 1/710, so the naive
 * loop pays 710 exponentiations of 2.5 ms each. Sieving to 2^20 leaves 8.1%
 * of the odds and cuts that to 58. Past 2^22 the remainders cost more than
 * the exponentiations they save. */
#define DEFAULT_SIEVE_LIMIT (1u << 20) /* small primes used to pre-filter   */
#define DEFAULT_WINDOW 4096u           /* odd candidates per sieved interval */
#define EXTRA_ROUNDS 3                 /* rounds after the base-2 filter     */

static u32 *g_small;
static usize g_small_n;
static u32 g_limit;
static u32 g_window;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;

/* strtoul returns unsigned long; bounded here before it narrows. */
static u32 env_uint(const char *name, u32 fallback) {
  const char *s = getenv(name);
  unsigned long v;
  char *end;

  if (!s || !*s)
    return fallback;
  v = strtoul(s, &end, 0);
  if (*end || v < 16 || v > (1ul << 26))
    return fallback;
  return (u32)v;
}

/* Sieve of Eratosthenes over the odd numbers: index i holds 2i+1. */
static void build_small_primes(void) {
  u8 *odd;
  usize half, i, count = 0, k = 0;

  g_limit = env_uint("RSA_SIEVE_LIMIT", DEFAULT_SIEVE_LIMIT);
  g_window = env_uint("RSA_WINDOW", DEFAULT_WINDOW);

  half = g_limit / 2;
  odd = malloc(half);
  if (!odd)
    return;
  memset(odd, 1, half);
  odd[0] = 0; /* 1 is not prime */
  for (i = 1; (2 * i + 1) * (2 * i + 1) < g_limit; i++) {
    u64 p, m;
    if (!odd[i])
      continue;
    p = 2 * i + 1;
    for (m = p * p; m < g_limit; m += 2 * p)
      odd[m / 2] = 0;
  }
  for (i = 1; i < half; i++)
    count += odd[i];
  g_small = malloc(count * sizeof *g_small);
  if (!g_small) {
    free(odd);
    return;
  }
  for (i = 1; i < half; i++)
    if (odd[i])
      g_small[k++] = (u32)(2 * i + 1);
  g_small_n = count;
  free(odd);
}

usize rsa_small_prime_count(void) {
  pthread_once(&g_once, build_small_primes);
  return g_small_n + 1; /* the table holds odd primes; 2 is implicit */
}

u32 rsa_sieve_limit(void) {
  pthread_once(&g_once, build_small_primes);
  return g_limit;
}

u32 rsa_window(void) {
  pthread_once(&g_once, build_small_primes);
  return g_window;
}

i32 rsa_online_cores(void) {
  long n = sysconf(_SC_NPROCESSORS_ONLN); /* POSIX fixes the return type */
  return n > 0 ? (i32)n : 1;
}

static i32 random_base(mpz_t out, FILE *ur) {
  u8 buf[32];

  if (fread(buf, 1, sizeof buf, ur) != sizeof buf)
    return -1;
  buf[0] |= 0x80;
  mpz_import(out, sizeof buf, 1, 1, 0, 0, buf);
  return 0;
}

/* n-1 = d*2^s with d odd. A prime has only 1 and -1 as square roots of 1,
 * so a^d, a^2d, ... must reach 1 through n-1. Returns 0 on composite. */
static i32 mr_round(const mpz_t n, const mpz_t nm1, const mpz_t d, mp_bitcnt_t s, const mpz_t a,
                    mpz_t x) {
  mp_bitcnt_t i;

  mpz_powm(x, a, d, n);
  if (mpz_cmp_ui(x, 1) == 0 || mpz_cmp(x, nm1) == 0)
    return 1;
  for (i = 1; i < s; i++) {
    mpz_mul(x, x, x);
    mpz_mod(x, x, n);
    if (mpz_cmp(x, nm1) == 0)
      return 1;
  }
  return 0;
}

i32 rsa_is_probable_prime(const u8 *n_be, usize len, i32 rounds) {
  mpz_t n, nm1, d, x, a;
  mp_bitcnt_t s;
  i32 i, ok = 1;
  FILE *ur;

  mpz_inits(n, nm1, d, x, a, NULL);
  mpz_import(n, len, 1, 1, 0, 0, n_be);
  if (mpz_cmp_ui(n, 3) <= 0) {
    ok = mpz_cmp_ui(n, 1) > 0;
    mpz_clears(n, nm1, d, x, a, NULL);
    return ok;
  }
  if (mpz_even_p(n)) {
    mpz_clears(n, nm1, d, x, a, NULL);
    return 0;
  }
  mpz_sub_ui(nm1, n, 1);
  s = mpz_scan1(nm1, 0);
  mpz_fdiv_q_2exp(d, nm1, s);

  mpz_set_ui(a, 2);
  ok = mr_round(n, nm1, d, s, a, x);
  ur = ok && rounds > 1 ? fopen("/dev/urandom", "rb") : NULL;
  for (i = 1; ok && i < rounds && ur; i++) {
    if (random_base(a, ur) != 0)
      break;
    mpz_mod(a, a, nm1);
    if (mpz_cmp_ui(a, 2) < 0)
      mpz_set_ui(a, 2);
    ok = mr_round(n, nm1, d, s, a, x);
  }
  if (ur)
    fclose(ur);
  mpz_clears(n, nm1, d, x, a, NULL);
  return ok;
}
