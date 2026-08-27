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

/* Odd, with the top two bits set so that p*q has exactly 2*bits bits. */
static i32 random_odd(mpz_t out, u32 bits, FILE *ur) {
  u8 buf[512];
  usize nbytes = bits / 8;

  if (bits % 8 || nbytes == 0 || nbytes > sizeof buf)
    return -1;
  if (fread(buf, 1, nbytes, ur) != nbytes)
    return -1;
  buf[0] |= 0xC0;
  buf[nbytes - 1] |= 0x01;
  mpz_import(out, nbytes, 1, 1, 0, 0, buf);
  return 0;
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

/* Extended Euclid, so the key schedule owes nothing to mpz_invert. */
static i32 mod_inverse(mpz_t out, const mpz_t a, const mpz_t m) {
  mpz_t r0, r1, s0, s1, q;
  i32 ok;

  mpz_init_set(r0, m);
  mpz_init_set(r1, a);
  mpz_init_set_ui(s0, 0);
  mpz_init_set_ui(s1, 1);
  mpz_init(q);
  while (mpz_sgn(r1) != 0) {
    mpz_fdiv_q(q, r0, r1);
    mpz_submul(r0, q, r1);
    mpz_swap(r0, r1);
    mpz_submul(s0, q, s1);
    mpz_swap(s0, s1);
  }
  ok = mpz_cmp_ui(r0, 1) == 0;
  if (ok)
    mpz_mod(out, s0, m);
  mpz_clears(r0, r1, s0, s1, q, NULL);
  return ok;
}

struct rsa_key {
  mpz_t n, e, d, p, q, dp, dq, qinv;
  u64 cand, sieved;
  i32 threads;
};

struct rsa_keygen {
  u32 bits; /* per prime */
  u32 e;
  i32 nthreads;
  pthread_t *tid;
  pthread_mutex_t lock;
  mpz_t found[2];
  i32 nfound;
  _Atomic i32 stop;
  u64 cand, sieved;
};

/* Fermat's method factors n at once when |p-q| is small, so the primes come
 * from independent intervals and this says so rather than assuming it. */
static i32 far_enough(const mpz_t a, const mpz_t b, u32 bits) {
  mpz_t d;
  i32 ok;

  mpz_init(d);
  mpz_sub(d, a, b);
  mpz_abs(d, d);
  ok = mpz_sizeinbase(d, 2) > bits / 2;
  mpz_clear(d);
  return ok;
}

static void *worker(void *arg) {
  struct rsa_keygen *kg = arg;
  FILE *ur;
  mpz_t base, cand, nm1, d, x, a;
  u8 *sieve;
  u64 local_cand = 0, local_sieved = 0;
  u32 window;

  pthread_once(&g_once, build_small_primes);
  window = g_window;
  ur = fopen("/dev/urandom", "rb");
  sieve = malloc(window);
  if (!ur || !sieve || !g_small) {
    if (ur)
      fclose(ur);
    free(sieve);
    return NULL;
  }
  mpz_inits(base, cand, nm1, d, x, a, NULL);

  while (!kg->stop) {
    usize j;
    u32 i;

    if (random_odd(base, kg->bits, ur) != 0)
      break;

    /* base + 2i = 0 (mod p) when i = -base * 2^-1, and 2^-1 is (p+1)/2. */
    memset(sieve, 1, window);
    for (j = 0; j < g_small_n; j++) {
      u64 p = g_small[j];
      u64 r = mpz_fdiv_ui(base, (unsigned long)p);
      u64 i0 = ((p - r) % p) * ((p + 1) / 2) % p;
      for (; i0 < window; i0 += p)
        sieve[i0] = 0;
    }

    for (i = 0; i < window && !kg->stop; i++) {
      i32 r, ok;

      if (!sieve[i]) {
        local_sieved++;
        continue;
      }
      mpz_add_ui(cand, base, (unsigned long)(2u * i));
      mpz_sub_ui(nm1, cand, 1);
      /* d exists only when gcd(e, phi) = 1, and e is prime. */
      if (mpz_fdiv_ui(nm1, (unsigned long)kg->e) == 0)
        continue;

      {
        mp_bitcnt_t s = mpz_scan1(nm1, 0);
        mpz_fdiv_q_2exp(d, nm1, s);

        /* Base 2 removes nearly every composite for one exponentiation. */
        local_cand++;
        mpz_set_ui(a, 2);
        if (!mr_round(cand, nm1, d, s, a, x))
          continue;

        ok = 1;
        for (r = 0; r < EXTRA_ROUNDS && ok; r++) {
          if (random_base(a, ur) != 0) {
            ok = 0;
            break;
          }
          mpz_mod(a, a, nm1);
          if (mpz_cmp_ui(a, 2) < 0)
            mpz_set_ui(a, 2);
          ok = mr_round(cand, nm1, d, s, a, x);
        }
        if (!ok)
          continue;
      }

      pthread_mutex_lock(&kg->lock);
      if (kg->nfound == 0 || (kg->nfound == 1 && far_enough(cand, kg->found[0], kg->bits))) {
        mpz_set(kg->found[kg->nfound++], cand);
        if (kg->nfound == 2)
          kg->stop = 1;
      }
      pthread_mutex_unlock(&kg->lock);
      break; /* a fresh interval for the next prime, never a neighbour */
    }
  }

  pthread_mutex_lock(&kg->lock);
  kg->cand += local_cand;
  kg->sieved += local_sieved;
  pthread_mutex_unlock(&kg->lock);

  mpz_clears(base, cand, nm1, d, x, a, NULL);
  free(sieve);
  fclose(ur);
  return NULL;
}

rsa_keygen *rsa_keygen_start(u32 bits, u32 e, i32 threads) {
  struct rsa_keygen *kg;
  i32 i;

  if (bits < 512 || bits % 16 || e < 3)
    return NULL;
  kg = calloc(1, sizeof *kg);
  if (!kg)
    return NULL;
  kg->bits = bits / 2;
  kg->e = e;
  kg->nthreads = threads > 0 ? threads : rsa_online_cores();
  mpz_inits(kg->found[0], kg->found[1], NULL);
  pthread_mutex_init(&kg->lock, NULL);
  kg->tid = calloc((usize)kg->nthreads, sizeof *kg->tid);
  if (!kg->tid) {
    free(kg);
    return NULL;
  }
  for (i = 0; i < kg->nthreads; i++) {
    if (pthread_create(&kg->tid[i], NULL, worker, kg) != 0) {
      kg->nthreads = i;
      break;
    }
  }
  return kg;
}

rsa_key *rsa_keygen_join(rsa_keygen *kg) {
  rsa_key *k;
  mpz_t phi, pm1, qm1;
  i32 i;

  if (!kg)
    return NULL;
  for (i = 0; i < kg->nthreads; i++)
    pthread_join(kg->tid[i], NULL);

  k = NULL;
  if (kg->nfound == 2) {
    k = calloc(1, sizeof *k);
  }
  if (k) {
    mpz_inits(k->n, k->e, k->d, k->p, k->q, k->dp, k->dq, k->qinv, NULL);
    mpz_inits(phi, pm1, qm1, NULL);

    mpz_set(k->p, kg->found[0]);
    mpz_set(k->q, kg->found[1]);
    if (mpz_cmp(k->p, k->q) < 0) /* the CRT below wants p > q */
      mpz_swap(k->p, k->q);

    mpz_mul(k->n, k->p, k->q); /* etapa 1: N = p.q            */
    mpz_sub_ui(pm1, k->p, 1);
    mpz_sub_ui(qm1, k->q, 1);
    mpz_mul(phi, pm1, qm1);              /* etapa 2: phi(N)             */
    mpz_set_ui(k->e, kg->e);             /* etapa 3: e coprime to phi   */
    if (!mod_inverse(k->d, k->e, phi)) { /* etapa 4: e.d = 1 mod phi(N) */
      mpz_clears(k->n, k->e, k->d, k->p, k->q, k->dp, k->dq, k->qinv, NULL);
      free(k);
      k = NULL;
    } else {
      mpz_mod(k->dp, k->d, pm1);
      mpz_mod(k->dq, k->d, qm1);
      mod_inverse(k->qinv, k->q, k->p);
      k->cand = kg->cand;
      k->sieved = kg->sieved;
      k->threads = kg->nthreads;
    }
    mpz_clears(phi, pm1, qm1, NULL);
  }

  mpz_clears(kg->found[0], kg->found[1], NULL);
  pthread_mutex_destroy(&kg->lock);
  free(kg->tid);
  free(kg);
  return k;
}

void rsa_free(rsa_key *k) {
  if (!k)
    return;
  mpz_clears(k->n, k->e, k->d, k->p, k->q, k->dp, k->dq, k->qinv, NULL);
  free(k);
}

usize rsa_modulus_bytes(const rsa_key *k) { return k ? (mpz_sizeinbase(k->n, 2) + 7) / 8 : 0; }

void rsa_export_modulus(const rsa_key *k, u8 *out) {
  usize len = rsa_modulus_bytes(k), cnt = mpz_sizeinbase(k->n, 256);

  memset(out, 0, len);
  mpz_export(out + (len - cnt), NULL, 1, 1, 0, 0, k->n);
}

u32 rsa_exponent(const rsa_key *k) { return k ? (u32)mpz_get_ui(k->e) : 0; }

static void export_fixed(u8 *out, usize len, const mpz_t v) {
  usize cnt = mpz_sizeinbase(v, 256);

  memset(out, 0, len);
  if (cnt <= len && mpz_sgn(v) != 0)
    mpz_export(out + (len - cnt), NULL, 1, 1, 0, 0, v);
}

i32 rsa_encrypt(const u8 *n_be, usize n_len, u32 e, const u8 *msg, usize msg_len, u8 *out) {
  mpz_t n, m, c;
  i32 rc = 0;

  mpz_inits(n, m, c, NULL);
  mpz_import(n, n_len, 1, 1, 0, 0, n_be);
  mpz_import(m, msg_len, 1, 1, 0, 0, msg);
  if (mpz_sgn(n) == 0 || mpz_cmp(m, n) >= 0)
    rc = -1; /* textbook RSA: the message is one integer and must be < n */
  else {
    mpz_powm_ui(c, m, (unsigned long)e, n);
    export_fixed(out, n_len, c);
  }
  mpz_clears(n, m, c, NULL);
  return rc;
}

/* Two exponentiations with half sized operands instead of one full sized,
 * which make bench measures at 4.3 ms against 16.5 ms. */
i32 rsa_decrypt(const rsa_key *k, const u8 *ct, usize ct_len, u8 *out, usize *out_len) {
  mpz_t c, m1, m2, h, m;
  usize cnt;
  i32 rc = 0;

  if (!k || !out_len)
    return -1;
  mpz_inits(c, m1, m2, h, m, NULL);
  mpz_import(c, ct_len, 1, 1, 0, 0, ct);
  if (mpz_cmp(c, k->n) >= 0)
    rc = -1;
  else {
    mpz_powm(m1, c, k->dp, k->p);
    mpz_powm(m2, c, k->dq, k->q);
    mpz_sub(h, m1, m2);
    mpz_mul(h, h, k->qinv);
    mpz_mod(h, h, k->p);
    mpz_mul(m, h, k->q);
    mpz_add(m, m, m2);

    cnt = mpz_sizeinbase(m, 256);
    if (cnt > *out_len)
      rc = -1;
    else {
      mpz_export(out, &cnt, 1, 1, 0, 0, m);
      *out_len = mpz_sgn(m) ? cnt : 0;
    }
  }
  mpz_clears(c, m1, m2, h, m, NULL);
  return rc;
}

i32 rsa_decrypt_plain(const rsa_key *k, const u8 *ct, usize ct_len, u8 *out, usize *out_len) {
  mpz_t c, m;
  usize cnt;
  i32 rc = 0;

  if (!k || !out_len)
    return -1;
  mpz_inits(c, m, NULL);
  mpz_import(c, ct_len, 1, 1, 0, 0, ct);
  mpz_powm(m, c, k->d, k->n);
  cnt = mpz_sizeinbase(m, 256);
  if (cnt > *out_len)
    rc = -1;
  else {
    mpz_export(out, &cnt, 1, 1, 0, 0, m);
    *out_len = mpz_sgn(m) ? cnt : 0;
  }
  mpz_clears(c, m, NULL);
  return rc;
}

char *rsa_component(const rsa_key *k, char which) {
  const mpz_t *v;

  if (!k)
    return NULL;
  switch (which) {
  case 'p':
    v = &k->p;
    break;
  case 'q':
    v = &k->q;
    break;
  case 'n':
    v = &k->n;
    break;
  case 'd':
    v = &k->d;
    break;
  default:
    return NULL;
  }
  return mpz_get_str(NULL, 10, *v);
}

void rsa_string_free(char *s) {
  void (*freefn)(void *, usize);

  if (!s)
    return;
  mp_get_memory_functions(NULL, NULL, &freefn);
  freefn(s, strlen(s) + 1);
}

u64 rsa_stat_candidates(const rsa_key *k) { return k ? k->cand : 0; }
u64 rsa_stat_sieved(const rsa_key *k) { return k ? k->sieved : 0; }
i32 rsa_stat_threads(const rsa_key *k) { return k ? k->threads : 0; }
