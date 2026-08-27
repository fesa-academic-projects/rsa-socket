"""Framing over the TCP stream: type byte, four byte length, payload.

TCP carries bytes, not messages: one recv may return half a public key or
two frames at once.
"""

PUBKEY = 0x01  # e (4 bytes) followed by n, both big-endian, in the clear
MESSAGE = 0x02  # ciphertext, one modulus wide, either direction
REPLY = 0x03  # ciphertext of the uppercase answer, either direction

NAMES = {PUBKEY: "PUBKEY", MESSAGE: "MESSAGE", REPLY: "REPLY"}


def send_frame(sock, kind: int, payload: bytes) -> int:
    frame = bytes([kind]) + len(payload).to_bytes(4, "big") + payload
    sock.sendall(frame)
    return len(frame)


def recv_exactly(sock, size: int) -> bytes:
    chunks = []
    got = 0
    while got < size:
        chunk = sock.recv(size - got)
        if not chunk:
            raise ConnectionError("peer closed the connection")
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def recv_frame(sock, expect: int = None):
    head = recv_exactly(sock, 5)
    kind = head[0]
    length = int.from_bytes(head[1:], "big")
    if length > 1 << 20:
        raise ValueError(f"frame too large: {length}")
    payload = recv_exactly(sock, length) if length else b""
    if expect is not None and kind != expect:
        raise ValueError(f"expected {NAMES.get(expect)}, got {NAMES.get(kind, kind)}")
    return kind, payload
