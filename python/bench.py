"""What each idea in the search is worth, measured here.

    python3 python/bench.py [--quick]

Every row generates a full key pair. The pure Python rows are the same
algorithm written the obvious way.
"""

import secrets
import statistics
import sys
import time

import rsa

BITS = 2048
SMALL_LIMIT = 1 << 16


def small_primes(limit):
    sieve = bytearray([1]) * limit
    sieve[0] = sieve[1] = 0
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            sieve[i * i :: i] = bytearray(len(sieve[i * i :: i]))
    return [i for i in range(3, limit) if sieve[i]]


SMALL = small_primes(SMALL_LIMIT)


def random_odd(bits):
    return secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1


def miller_rabin(n, bases):
    d, s = n - 1, 0
    while not d & 1:
        d >>= 1
        s += 1
    for a in bases:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def py_naive():
    """One Miller-Rabin round on every odd candidate."""
    while True:
        n = random_odd(BITS)
        if miller_rabin(n, (2, 3, 5, 7)):
            return n


def py_trial():
    """Divide by the primes below 2^16 first, exponentiate only if it survives."""
    while True:
        n = random_odd(BITS)
        if any(n % p == 0 for p in SMALL):
            continue
        if miller_rabin(n, (2,)) and miller_rabin(n, (3, 5, 7)):
            return n


def timed(fn, runs):
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        times.append((time.perf_counter() - start) * 1000)
    return statistics.median(times), statistics.mean(times)


def main(argv):
    quick = "--quick" in argv
    info = rsa.sieve_info()
    print(
        f"{info['cores']} cores, sieve to {info['limit']}, "
        f"{info['primes']} small primes, window {info['window']}\n"
    )

    rows = []
    if not quick:
        rows.append(
            (
                "pure Python, Miller-Rabin on every odd",
                lambda: (py_naive(), py_naive()),
                1,
            )
        )
        rows.append(
            (
                "pure Python, trial division then Miller-Rabin",
                lambda: (py_trial(), py_trial()),
                2,
            )
        )
    rows.append(("C core, one thread", lambda: rsa.keygen(threads=1), 8))
    rows.append((f"C core, {info['cores']} threads", lambda: rsa.keygen(), 8))

    print(f"{'':<46} {'median':>10} {'mean':>10} {'speedup':>9}")
    baseline = None
    for label, fn, runs in rows:
        median, mean = timed(fn, runs)
        baseline = baseline or mean
        print(f"{label:<46} {median:>8.0f} ms {mean:>8.0f} ms {baseline / mean:>8.1f}x")

    print("\nA key pair needs two primes, so the mean is twice the cost of one.")
    print("The spread is wide by nature: the search is memoryless, so the time")
    print("to a hit is exponential and the time to a pair is Erlang-2.\n")

    # What one round trip costs once the keys exist.
    key = rsa.keygen()
    message = rsa.STANDARD_MESSAGE.encode("utf-8")
    ciphertext = rsa.encrypt(key.public, message)
    for label, fn, runs in [
        ("encrypt, e = 65537", lambda: rsa.encrypt(key.public, message), 200),
        ("decrypt through the CRT", lambda: key.decrypt(ciphertext), 40),
        ("decrypt as C^d mod N", lambda: key.decrypt(ciphertext, crt=False), 20),
    ]:
        median, mean = timed(fn, runs)
        print(f"{label:<46} {median:>8.2f} ms {mean:>8.2f} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
