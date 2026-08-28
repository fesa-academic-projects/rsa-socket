"""Key generation, the cipher, primality, the ABI and the socket pair."""

import os
import re
import subprocess
import sys
import time

import rsa

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


HEADER = open(os.path.join(ROOT, "include", "rsa.h")).read()

ALIAS = dict(
    (alias, base)
    for base, alias in re.findall(
        r"^typedef\s+(\w+)\s+(\w+)\s*;",
        open(os.path.join(ROOT, "include", "types.h")).read(),
        flags=re.M,
    )
)


def expand(text):
    """Resolve the aliases, so widths are compared and not spellings."""
    return re.sub(r"\b(\w+)\b", lambda m: ALIAS.get(m.group(1), m.group(1)), text)


def declarations(text):
    """Declarations with comments and layout removed."""
    text = re.sub(r"/\*.*?\*/", " ", expand(text), flags=re.S)
    text = re.sub(r"//.*$", " ", text, flags=re.M)
    text = re.sub(r"^\s*#.*$", " ", text, flags=re.M)
    out = set()
    for decl in text.split(";"):
        decl = " ".join(decl.split())
        if "(" in decl or decl.startswith("typedef struct"):
            out.add(decl)
    return out


# Two hand kept copies of one ABI. Both sides are expanded through types.h
# first, so u32 here and uint32_t there count as agreement.
USED = {a for a in ALIAS if re.search(rf"\b{a}\b", HEADER)}
assert USED and all(re.fullmatch(r"u?int\d+_t|size_t", ALIAS[a]) for a in USED), {
    a: ALIAS[a] for a in USED
}
header = declarations(HEADER)
build = open(os.path.join(ROOT, "build.py")).read()
cdef = declarations(build[build.index('ffi.cdef("""') + 12 : build.index('""")')])
assert header == cdef, "header and cdef disagree:\n" + "\n".join(sorted(header ^ cdef))
assert not any(re.search(r"\b(long|short)\b", d) for d in header), header
print(
    f"abi: {len(USED)} aliases, {len(header)} declarations, header and cdef "
    f"agree, no platform dependent widths"
)

info = rsa.sieve_info()
assert info["primes"] == 82025, info  # primes below 2^20
print(
    f"sieve: {info['primes']} small primes below {info['limit']}, "
    f"window {info['window']}, {info['cores']} cores"
)

# Miller-Rabin against known cases, Carmichael numbers included.
for n, expected in [
    (2, True),
    (3, True),
    (4, False),
    (97, True),
    (561, False),
    (1105, False),
    (2147483647, True),
    (1000003, True),
    (1000000, False),
    (3215031751, False),
]:
    assert rsa.is_probable_prime(n) == expected, n
print("primality: ok on the known cases")

key = rsa.keygen()
p, q, n, d, e = (
    key.component("p"),
    key.component("q"),
    key.component("n"),
    key.component("d"),
    key.e,
)

assert p.bit_length() == 2048 and q.bit_length() == 2048, (
    p.bit_length(),
    q.bit_length(),
)
assert n.bit_length() == 4096, n.bit_length()
assert p * q == n
assert rsa.is_probable_prime(p) and rsa.is_probable_prime(q)
assert (
    p != q and abs(p - q).bit_length() > 1024
)  # Fermat factorisation needs them close
assert (e * d) % ((p - 1) * (q - 1)) == 1  # etapa 4 of the handout
print(f"key: n has {n.bit_length()} bits, e = {e}, e.d = 1 mod phi(N)")

# The cipher, both ways, on the sentence the assignment fixes.
msg = rsa.STANDARD_MESSAGE.encode("utf-8")
ct = rsa.encrypt(key.public, msg)
assert len(ct) == key.size
assert key.decrypt(ct) == msg
assert key.decrypt(ct, crt=False) == msg  # the CRT agrees with c^d mod n
print(
    f"cipher: {len(msg)} bytes through a {len(ct) * 8} bit block, CRT and plain agree"
)

# Accents and an empty message, since the block is just an integer.
for text in ("Ola, acao 123", "a", "x" * 400):
    blob = text.encode("utf-8")
    assert key.decrypt(rsa.encrypt(key.public, blob)) == blob, text
print("cipher: ok on utf-8 and on a full block")

# A message larger than the modulus has to be refused, not silently wrapped.
try:
    rsa.encrypt(key.public, b"\xff" * 512)
except ValueError:
    print("cipher: a message wider than n is refused")
else:
    raise AssertionError("oversized message was accepted")

# The real pair, over a real socket.
env = dict(os.environ, HOST="127.0.0.1")
server = subprocess.Popen(
    [sys.executable, os.path.join(HERE, "Simple_tcpServer.py")],
    stdout=subprocess.PIPE,
    text=True,
    env=env,
)
time.sleep(2)
client = subprocess.run(
    [sys.executable, os.path.join(HERE, "Simple_tcpClient.py")],
    capture_output=True,
    text=True,
    env=env,
)
server_out = server.communicate(timeout=60)[0]

assert rsa.STANDARD_MESSAGE.upper() in client.stdout, client.stdout + client.stderr
assert rsa.STANDARD_MESSAGE in server_out, server_out
# Both directions: Bob answers Alice, then Alice answers Bob.
assert "Received from Make Upper Case Server" in client.stdout, client.stdout
assert "Received from Make Upper Case Client" in server_out, server_out
rtt = [line for line in client.stdout.splitlines() if line.startswith("RTT")]
print(f"socket: both directions carried the sentence encrypted, {rtt[0]}")
