"""Marshalling over src/rsa.c. cffi is the bridge, not a crypto library."""

from _rsa import ffi, lib

MODULUS_BITS = 4096
PUBLIC_EXPONENT = 65537

# The sentence the assignment fixes.
STANDARD_MESSAGE = (
    "The information security is of significant importance "
    "to ensure the privacy of communications"
)


class Key:
    """A key pair. The private half never leaves the C side."""

    def __init__(self, ptr):
        if ptr == ffi.NULL:
            raise RuntimeError("key generation failed")
        self._k = ffi.gc(ptr, lib.rsa_free)
        self.size = lib.rsa_modulus_bytes(self._k)
        self.e = lib.rsa_exponent(self._k)

    @property
    def modulus(self) -> bytes:
        buf = ffi.new("uint8_t[]", self.size)
        lib.rsa_export_modulus(self._k, buf)
        return bytes(ffi.buffer(buf, self.size))

    @property
    def public(self) -> bytes:
        """Wire form of the public key: e then n, both big-endian."""
        return self.e.to_bytes(4, "big") + self.modulus

    def decrypt(self, ciphertext: bytes, crt: bool = True) -> bytes:
        out = ffi.new("uint8_t[]", self.size)
        length = ffi.new("usize *", self.size)
        fn = lib.rsa_decrypt if crt else lib.rsa_decrypt_plain
        if fn(self._k, ciphertext, len(ciphertext), out, length) != 0:
            raise ValueError("decryption failed")
        return bytes(ffi.buffer(out, length[0]))

    def component(self, which: str) -> int:
        """One of 'p', 'q', 'n', 'd' as an integer. e is rsa.Key.e."""
        s = lib.rsa_component(self._k, which.encode())
        if s == ffi.NULL:
            raise ValueError(which)
        try:
            return int(ffi.string(s))
        finally:
            lib.rsa_string_free(s)

    @property
    def stats(self):
        return {
            "candidates": lib.rsa_stat_candidates(self._k),
            "sieved": lib.rsa_stat_sieved(self._k),
            "threads": lib.rsa_stat_threads(self._k),
        }


def keygen_start(bits: int = MODULUS_BITS, e: int = PUBLIC_EXPONENT, threads: int = 0):
    """Spawn the search and return at once, so it can overlap with the socket."""
    handle = lib.rsa_keygen_start(bits, e, threads)
    if handle == ffi.NULL:
        raise RuntimeError("could not start key generation")
    return handle


def keygen_join(handle) -> Key:
    return Key(lib.rsa_keygen_join(handle))


def keygen(bits: int = MODULUS_BITS, e: int = PUBLIC_EXPONENT, threads: int = 0) -> Key:
    return keygen_join(keygen_start(bits, e, threads))


def parse_public(blob: bytes):
    """Inverse of Key.public. Returns (e, n_bytes)."""
    if len(blob) < 5:
        raise ValueError("public key too short")
    return int.from_bytes(blob[:4], "big"), blob[4:]


def encrypt(public: bytes, message: bytes) -> bytes:
    """c = m^e mod n under someone else's public key."""
    e, modulus = parse_public(public)
    out = ffi.new("uint8_t[]", len(modulus))
    if lib.rsa_encrypt(modulus, len(modulus), e, message, len(message), out) != 0:
        raise ValueError("message does not fit in the modulus")
    return bytes(ffi.buffer(out, len(modulus)))


def is_probable_prime(n: int, rounds: int = 4) -> bool:
    blob = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return bool(lib.rsa_is_probable_prime(blob, len(blob), rounds))


def sieve_info():
    return {
        "limit": lib.rsa_sieve_limit(),
        "primes": lib.rsa_small_prime_count(),
        "window": lib.rsa_window(),
        "cores": lib.rsa_online_cores(),
    }
