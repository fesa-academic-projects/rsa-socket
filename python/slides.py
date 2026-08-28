"""The worked example from the handout, then the same four steps at 4096 bits."""

import rsa

p, q = 3, 5
n = p * q  # etapa 1: N = 15
phi = (p - 1) * (q - 1)  # etapa 2: phi(N) = 8
e = 7  # etapa 3: gcd(7, 8) = 1
d = 15  # etapa 4: 7 * 15 mod 8 = 1

assert rsa.is_probable_prime(p) and rsa.is_probable_prime(q)
assert e * d % phi == 1

plain = ord("C") - ord("A") + 1  # C is the third letter, so 3
cipher = pow(plain, e, n)  # 3^7 mod 15 = 12
back = pow(cipher, d, n)  # 12^15 mod 15 = 3

print(f"p = {p}, q = {q}, N = {n}, phi(N) = {phi}, e = {e}, d = {d}")
print(
    f"public  ({e},{n}):  C = P^e mod N  ->  {plain}^{e} mod {n} = {cipher}"
    f"  ->  '{chr(ord('A') + cipher - 1)}'"
)
print(
    f"private ({d},{n}):  P = C^d mod N  ->  {cipher}^{d} mod {n} = {back}"
    f"  ->  '{chr(ord('A') + back - 1)}'"
)
assert (cipher, back) == (12, 3)
print("matches the handout\n")

# 15 = 7 mod phi(N), so the handout's d and the smallest one are one key.
assert 7 * 7 % phi == 1
print("note: d = 7 is the same key, since 15 = 7 mod phi(N)\n")

# The same steps at the size the assignment asks for.
key = rsa.keygen()
big_p, big_q, big_n, big_d = (
    key.component("p"),
    key.component("q"),
    key.component("n"),
    key.component("d"),
)
assert big_p * big_q == big_n
assert key.e * big_d % ((big_p - 1) * (big_q - 1)) == 1
print(
    f"4096 bits: p and q have {big_p.bit_length()} bits each, "
    f"N has {big_n.bit_length()}, e = {key.e}, d has {big_d.bit_length()} bits"
)

message = rsa.STANDARD_MESSAGE.encode("utf-8")
ciphertext = rsa.encrypt(key.public, message)
print(f"P = {int.from_bytes(message, 'big')}")
print(f"C = {int.from_bytes(ciphertext, 'big')}")
print(f"decrypted: {key.decrypt(ciphertext).decode('utf-8')}")
