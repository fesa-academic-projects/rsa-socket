"""Compile src/rsa.c into the Python module python/_rsa."""

import os

from cffi import FFI

ROOT = os.path.dirname(os.path.abspath(__file__))

ffi = FFI()

# cffi does not run the preprocessor: declarations only, no #include.
# This block is a copy of include/rsa.h with the comments removed. cffi
# takes typedefs, so the aliases from include/types.h cross the boundary
# with the declarations. test_all.py expands them on both sides and fails
# if the two drift apart, which is only meaningful because the aliases
# name a width: unsigned long here and unsigned long there can still be
# two different widths.
# no representation in cffi.
ffi.cdef("""
    typedef uint8_t u8;
    typedef uint32_t u32;
    typedef uint64_t u64;
    typedef int32_t i32;
    typedef size_t usize;

    typedef struct rsa_key rsa_key;
    typedef struct rsa_keygen rsa_keygen;

    rsa_keygen *rsa_keygen_start(u32 bits, u32 e, i32 threads);
    rsa_key *rsa_keygen_join(rsa_keygen *kg);
    void rsa_free(rsa_key *k);

    usize rsa_modulus_bytes(const rsa_key *k);
    void rsa_export_modulus(const rsa_key *k, u8 *out);
    u32 rsa_exponent(const rsa_key *k);

    i32 rsa_encrypt(const u8 *n_be, usize n_len, u32 e, const u8 *msg,
                    usize msg_len, u8 *out);
    i32 rsa_decrypt(const rsa_key *k, const u8 *ct, usize ct_len, u8 *out,
                    usize *out_len);
    i32 rsa_decrypt_plain(const rsa_key *k, const u8 *ct, usize ct_len, u8 *out,
                          usize *out_len);

    char *rsa_component(const rsa_key *k, char which);
    void rsa_string_free(char *s);

    u64 rsa_stat_candidates(const rsa_key *k);
    u64 rsa_stat_sieved(const rsa_key *k);
    i32 rsa_stat_threads(const rsa_key *k);

    i32 rsa_is_probable_prime(const u8 *n_be, usize len, i32 rounds);
    usize rsa_small_prime_count(void);
    u32 rsa_sieve_limit(void);
    u32 rsa_window(void);
    i32 rsa_online_cores(void);
""")

# Absolute paths: tmpdir changes the working directory of the compilation.
ffi.set_source(
    "_rsa",
    '#include "rsa.h"',
    sources=[os.path.join(ROOT, "src", "rsa.c")],
    include_dirs=[os.path.join(ROOT, "include")],
    libraries=["gmp"],
    extra_compile_args=["-O2", "-std=c11", "-Wall", "-Wextra", "-pthread"],
    extra_link_args=["-pthread"],
)

if __name__ == "__main__":
    ffi.compile(tmpdir=os.path.join(ROOT, "python"), verbose=True)
