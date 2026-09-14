# rsa-socket

RSA with 4096 bit keys over a TCP socket. The key generation, the primality
test and the cipher are in C and are called from Python through cffi. GMP
supplies arbitrary precision arithmetic and nothing else, the same division
of labour as the `BigInteger` example handed out with the assignment.

Built on the `Simple_tcpClient.py` and `Simple_tcpServer.py` files from
class, kept untouched in `original/` so the modification shows up as a diff.

```
Bob:   generates (e, n) and d, sends (e, n) in the clear
Alice: generates her own pair while the handshake is running
Alice: C = P^e mod N with Bob's key      ->  sends the sentence
Bob:   P = C^d mod N with the CRT, upper cases it, encrypts under Alice's key
Alice: decrypts, prints, stops the clock
Bob:   sends a sentence of his own, Alice returns it in upper case
```

Both ends run the same service, so the traffic goes both ways. Only the first
exchange is on the clock, since the RTT the assignment asks for starts at the
first line of the client.

Alice is the client, Bob is the server, port 1300.

## Assignment steps

| step | what it asks | where it lives |
|---|---|---|
| 1 | run the class files on two machines and watch the traffic | `original/`, captured in `captures/` |
| 2 | key generation on both ends | `src/rsa.c`: `rsa_keygen_start`, `rsa_keygen_join` |
| 3 | keys of 4096 bits | `rsa.MODULUS_BITS`, two primes of 2048 bits |
| 4 | public keys exchanged in the clear over TCP | `python/wire.py`, frame type `0x01` |
| 5 | Wireshark evidence of every stage | `captures/` |
| RTT | first line of the code to the uppercase text on screen | `T0` and `T1` in the client |

## Layout

| path | role |
|---|---|
| `include/types.h` | the type aliases, shared with dh-caesar-socket |
| `include/rsa.h`, `src/rsa.c` | sieve, Miller-Rabin, threaded search, key schedule, CRT |
| `build.py` | cffi compiles the C into `python/_rsa` |
| `python/rsa.py` | thin Python layer over the C module |
| `python/wire.py` | framing over the TCP stream |
| `python/Simple_tcpClient.py` | Alice, the class client with RSA added |
| `python/Simple_tcpServer.py` | Bob, the class server with RSA added |
| `python/slides.py` | reproduces the worked example from the handout |
| `python/bench.py` | what each idea in the search is worth |
| `python/attack.py` | breaks the parameter choices we did not make |
| `python/test_all.py` | end to end test |
| `original/` | the class files, untouched |
| `captures/` | Wireshark evidence |

## Building and running

```sh
xbps-install -S python3-devel gcc gmp-devel          # Void
apk add python3-dev py3-cffi py3-setuptools gcc musl-dev make gmp-dev   # Alpine
apt install python3-dev python3-cffi gcc libgmp-dev  # Debian, Ubuntu

make          # build the extension
make test     # primality, key schedule, cipher and a real socket round trip
make slides   # check against the handout
make bench    # measure the search on this machine
make attack   # break the parameter choices we did not make
make diff     # what changed from the class files
```

```sh
# Bob
python3 python/Simple_tcpServer.py

# Alice
HOST=<bob's address> python3 python/Simple_tcpClient.py
```

The class client hardcodes the server address; this one reads `HOST` from the
environment, so a DHCP change does not mean editing the file. `THREADS`
overrides the worker count, which defaults to one per online core. Either end
takes its own sentence as the first argument. The server handles one
connection and exits, matching the original.

## Wire protocol

Every frame is a type byte, a four byte big endian length and the payload.
TCP is a byte stream: one `recv` can return half a public key or two frames
at once, so the length prefix is what makes the boundaries real.

```
Alice (client)                                   Bob (server)
   |<---- 0x01 PUBKEY  e (4 B) + n (512 B) ---------|
   |----- 0x02 MESSAGE ciphertext (512 B) --------->|
   |----- 0x01 PUBKEY  e (4 B) + n (512 B) -------->|
   |<---- 0x03 REPLY   ciphertext (512 B) ----------|
   |<---- 0x02 MESSAGE ciphertext (512 B) ----------|
   |----- 0x03 REPLY   ciphertext (512 B) --------->|
```

The message leaves before Alice's own key is ready, because Bob only needs
her public key to encrypt the answer. That is why the second and third frames
are far apart in time while everything else is adjacent.

## Where the time goes

A 4096 bit key pair means two primes of 2048 bits. Everything else in the
round trip is noise. Measured on the demo machine, an Alpine guest with four
vCPUs pinned to the four physical cores of a 4 GHz laptop:

| step | cost |
|---|---|
| one Miller-Rabin round at 2048 bits | 2.4 ms |
| Miller-Rabin rounds per key pair | 116 on average |
| key pair, one thread | 302 ms |
| key pair, four threads | 114 ms median, 130 ms mean |
| building the table of small primes | 2 ms, once |
| encryption, e = 65537 | 0.08 ms |
| decryption through the CRT | 7.8 ms |
| decryption as C^d mod N | 28 ms |

So the round trip is the search for the primes plus about 10 ms. What the
search does about it:

1. **Sieve the interval instead of testing candidates one by one.** A random
   odd number near 2^2048 is prime with probability 2/ln(2^2048) = 1/710, so
   the naive loop pays 710 exponentiations per prime. Pick one random odd
   base, mark every candidate `base + 2i` that a prime below 2^20 divides,
   and only 8.1% survive, which brings it down to about 58. The sieve costs
   one word sized remainder per small prime, roughly 4 ms per interval.
2. **Base 2 first.** One Miller-Rabin round with base 2 removes essentially
   every composite that survives the sieve. The other three rounds only ever
   run on the winner.
3. **One thread per core, first two hits win.** The search is memoryless, so
   T threads on independent intervals cut the mean by T. The threads live in
   C: gmpy2 and CPython hold the GIL during big integer work, so Python
   threads would not have helped.
4. **Generate while the socket is busy.** `rsa_keygen_start` returns as soon
   as the workers are running. The connect, the exchange of Bob's key and the
   encryption of the sentence all happen while the primes are still being
   looked for.
5. **`TCP_NODELAY` on both ends.** Without it Nagle plus delayed ACK can add
   40 ms to a small write, which would be a third of the budget.
6. **CRT on the way back**, two exponentiations with half sized operands
   instead of one full sized, 7.8 ms against 28 ms on the demo machine.
   `make bench` prints both.
7. **Nothing printed before the clock stops.** A terminal takes tens of
   milliseconds to swallow a 1234 digit modulus, more than the exchange it
   describes. The keys and the ciphertext are written at the end.

`RSA_SIEVE_LIMIT` and `RSA_WINDOW` tune the first item without recompiling.
Measured on the demo machine at four threads, 2^18 and 2^20 come out level
and 2^22 loses, so the default stays at 2^20. The optimum drifts down as the
thread count rises, since each worker pays for its own sieve while the
exponentiations it saves are divided across all of them.

## Choices worth defending

**p and q come from independent intervals.** Taking both from one sieved
window would save 4 ms and hand out a modulus that Fermat's method factors on
the spot: try `a = ceil(sqrt(n))`, `a+1`, ... until `a^2 - n` is a square,
which succeeds immediately when `|p-q|` is small. `far_enough` in `rsa.c`
states the requirement instead of assuming it, and `attack.py` factors such a
modulus in one step to show what it is worth.

**e = 65537, not 3.** The sentence is 93 bytes, so P is 744 bits. With e = 3
the cube would be 2228 bits, less than the 4096 bit modulus, so `C = P^3`
without any reduction and an integer cube root recovers the message with no
key at all. `attack.py` does exactly that.

**phi(N) = (p-1)(q-1), following the handout.** The Carmichael function
lcm(p-1, q-1) yields a smaller d, which makes no difference here because the
CRT exponents `dp` and `dq` are what actually get used.

**Textbook RSA, as the assignment describes it.** No padding, so the same
message always produces the same ciphertext, the cipher is malleable, and a
short guessable message can be confirmed by anyone holding the public key.
OAEP is what a real implementation uses. Nothing here is production grade.

**Fixed width types on the cffi boundary.** cffi mirrors `include/rsa.h`
without running the preprocessor, so the header and the `cdef` in `build.py`
are two hand kept copies of one ABI with nothing but their spelling to agree
on. `long` is 64 bits under LP64 and 32 under LLP64, so a declaration written
that way can agree on one machine and disagree on the next, and the
disagreement arrives as a corrupted argument rather than as a compiler error.
Every type here carries its width in its name through `include/types.h`, the
header this repository shares with dh-caesar-socket: `u8`, `u32`, `u64`, `i32`
for the return codes and the counts, `usize` for the lengths. Inside `rsa.c`
the only survivors are the ones GMP and POSIX fix themselves, `mp_bitcnt_t`
and the `unsigned long` of the word sized entry points, and those are cast at
the call. `test_all.py` expands the aliases on both sides, compares the header
against the `cdef`, and fails if they drift or if a platform dependent width
reappears.

**The private key never leaves C.** `rsa_component` will print it, which is
useful in a demo and nowhere else.

## Evidence

`captures/etapa1-etapa5.pcapng` holds both runs. Display filter:

```
tcp.port == 1300 && tcp.len > 0
```

Step 1, the class files, one TCP stream, everything in plain text:

| frame | direction | payload | what it is |
|---|---|---|---|
| 4 | Alice to Bob | 5 B | the sentence, readable on the wire |
| 6 | Bob to Alice | 5 B | the same in upper case, still readable |

Step 5, the same service with RSA, six frames on one connection:

| frame | t | direction | payload | what it is |
|---|---|---|---|---|
| 14 | 0.0 ms | Bob to Alice | 521 B | `0x01` Bob's public key, in the clear |
| 16 | 1.0 ms | Alice to Bob | 517 B | `0x02` the sentence, encrypted |
| 18 | 63.5 ms | Alice to Bob | 521 B | `0x01` Alice's public key, in the clear |
| 20 | 64.4 ms | Bob to Alice | 517 B | `0x03` the answer, encrypted |
| 21 | 66.5 ms | Bob to Alice | 517 B | `0x02` Bob's own sentence, encrypted |
| 23 | 131.1 ms | Alice to Bob | 517 B | `0x03` Alice's answer, encrypted |

The gaps say where the time goes. Bob answers 0.9 ms after Alice's public key
lands, and Alice puts her message on the wire 1.0 ms after Bob's key arrives.
The 62.5 ms between frames 16 and 18 is the search for her primes, and it is
the whole round trip. Nothing else on this timeline is worth optimising.

The 64.6 ms before frame 23 is not the protocol either: on that run Alice was
still printing her key dump when Bob's sentence arrived. The client now writes
all of it after the connection closes, which is what the last commit changed.

The public keys are readable in `Follow TCP Stream`. Frame 14 carries the type
byte `0x01`, a length of 516, then four bytes `00 01 00 01`, which is 65537,
then 512 bytes of modulus. Read as a big-endian integer they give exactly the
4096 bit `n` that Bob printed, which is step 4 shown rather than asserted.

The client on that run reported:

```
RTT: 82.8 ms
  key generation       73.9 ms   (4 threads, 58 Miller-Rabin tests, 683 candidates removed by the sieve)
  import + connect      9.6 ms   (overlapped with the search)
  encrypt and send      1.9 ms   (overlapped with the search)
  answer round          1.1 ms
  decrypt (CRT)         7.8 ms
```

That run was a lucky draw: 58 Miller-Rabin tests against a mean of 116, so the
search finished in half its usual time. The honest figure is the distribution,
not the best sample. With four threads the key pair takes 114 ms at the median
and 130 ms at the mean, which puts the round trip near 125 ms typical and 83 ms
at the good end. The spread is not noise in the measurement: the search is
memoryless, so the time to one prime is exponential and the time to a pair is
Erlang-2, whose standard deviation is 71% of its mean.

Nothing is printed between the first line of the client and the answer. The
keys and the ciphertext are written after the clock stops, because a terminal
takes tens of milliseconds to swallow four thousand digits and that would sit
inside the number the assignment asks for. An earlier capture showed exactly
that: 14.6 ms spent printing Bob's modulus before the message went out, and
36 ms printing Alice's own key before her answer was read.

## License

BSD 3-Clause. See `LICENSE`; contributors are listed in `AUTHORS`.

`original/` holds the class handout files, which are the professor's work and
are kept only as the starting point the assignment asks us to modify.
