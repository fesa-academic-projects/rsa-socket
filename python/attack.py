"""Attacks on the parameters the generator does not choose.

Run against real 4096 bit moduli from src/rsa.c, so the README is not asking
anyone to take its word for it.
"""

import time
from math import isqrt

import rsa


def integer_root(n, k):
    """Largest x with x^k <= n, by bisection."""
    if n < 2:
        return n
    hi = 1 << (n.bit_length() // k + 1)
    lo = 0
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid**k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo


def fermat_factor(n, limit=1 << 16):
    """n = a^2 - b^2. From ceil(sqrt(n)) it takes about (p-q)^2/(8 sqrt n) steps."""
    a = isqrt(n)
    if a * a < n:
        a += 1
    for step in range(1, limit + 1):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b, step
        a += 1
    return None


def next_prime(n):
    n |= 1
    while not rsa.is_probable_prime(n, 4):
        n += 2
    return n


print("=" * 72)
print("1. p and q from the same interval: Fermat factors the modulus")
print("=" * 72)

key = rsa.keygen()
p = key.component("p")
q = next_prime(p + 2)  # what taking both primes from one sieved window buys
n = p * q
print(f"p and q are {p.bit_length()} bits each, |p-q| = {q - p}")

start = time.perf_counter()
result = fermat_factor(n)
elapsed = (time.perf_counter() - start) * 1000
assert result and sorted(result[:2]) == sorted((p, q))
print(
    f"factored a {n.bit_length()} bit modulus in {result[2]} step(s), {elapsed:.1f} ms"
)
print("the private key follows from p and q in microseconds\n")

# The real key, generated from independent intervals, does not budge.
real_n = key.component("n")
start = time.perf_counter()
print(
    f"same attack on the real modulus, |p-q| = {abs(p - key.component('q')).bit_length()}"
    f" bits: ",
    end="",
    flush=True,
)
print(
    f"{'factored' if fermat_factor(real_n, 1 << 14) else 'no factor'} after "
    f"{1 << 14} steps ({(time.perf_counter() - start) * 1000:.0f} ms)\n"
)

print("=" * 72)
print("2. e = 3 on a short message: the cube root gives it back, no key needed")
print("=" * 72)

message = rsa.STANDARD_MESSAGE.encode("utf-8")
public_e3 = (3).to_bytes(4, "big") + key.modulus  # same modulus, e = 3
ciphertext = rsa.encrypt(public_e3, message)
c = int.from_bytes(ciphertext, "big")
m = int.from_bytes(message, "big")

print(
    f"the message is {m.bit_length()} bits, m^3 is {c.bit_length()} bits, "
    f"n is {real_n.bit_length()} bits"
)
print("m^3 < n, so the modular reduction never happens and C is a plain cube")
recovered = integer_root(c, 3)
assert recovered == m
print(
    f"recovered: {recovered.to_bytes((recovered.bit_length() + 7) // 8, 'big').decode()}"
)
print("\ne = 65537 makes the cube wrap around the modulus, which is why the")
print("generator uses it. Padding is the actual fix; textbook RSA has none.\n")

print("=" * 72)
print("3. no padding: the ciphertext is a fingerprint of the message")
print("=" * 72)

first = rsa.encrypt(key.public, message)
second = rsa.encrypt(key.public, message)
print(f"the same message encrypts to the same 512 bytes twice: {first == second}")
guess = rsa.encrypt(key.public, rsa.STANDARD_MESSAGE.upper().encode())
print(
    f"anyone holding the public key can confirm a guessed plaintext by "
    f"encrypting it: {guess != first}, and the upper case answer is exactly "
    f"such a guess"
)
