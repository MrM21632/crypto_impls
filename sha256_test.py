#!/usr/bin/env python3
# Test script in Python to verify my logic actually works.

from typing import List


# fmt: off
initialization_vector = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]
round_constants = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]
# fmt: on


def add_mod32(*args):
    return sum(args) % (2 ** 32)

def rotr32(x: int, n: int) -> int:
    assert x < 2 ** 32, f"{x} is too large for 32-bit right-rotate"
    left, right = x << (32 - n), x >> n
    return add_mod32(left, right)


def sum0(x: int) -> int:
    return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22)

def sum1(x: int) -> int:
    return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25)

def sigma0(x: int) -> int:
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3)

def sigma1(x: int) -> int:
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10)

def choose(x: int, y: int, z: int) -> int:
    return (x & y) ^ ((~x) & z)

def major(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)


def compress(chunk: bytes, state: List[int]) -> List[int]:
    assert len(chunk) == 64, f"Invalid chunk length: {len(chunk)}"

    w = []
    for i in range(16):
        w.append(int.from_bytes(chunk[(i * 4):(i * 4 + 4)]))
    for i in range(16, 64):
        w.append(add_mod32(w[i - 16] + sigma0(w[i - 15]) + w[i - 7] + sigma1(w[i - 2])))
    
    scratch = state[:]
    for i in range(64):
        tmp1 = add_mod32(
            scratch[7],
            sum1(scratch[4]),
            choose(scratch[4], scratch[5], scratch[6]),
            w[i],
            round_constants[i],
        )
        tmp2 = add_mod32(
            sum0(scratch[0]),
            major(scratch[0], scratch[1], scratch[2]),
        )

        scratch[7] = scratch[6]
        scratch[6] = scratch[5]
        scratch[5] = scratch[4]
        scratch[4] = add_mod32(scratch[3], tmp1)
        scratch[3] = scratch[2]
        scratch[2] = scratch[1]
        scratch[1] = scratch[0]
        scratch[0] = add_mod32(tmp1, tmp2)
    
    return [add_mod32(x, y) for x, y in zip(state, scratch)]


def pad_message(message: bytes) -> bytes:
    length = len(message)
    remaining_bytes = (length + 8) % 64
    reqd_padding_bytes = 64 - remaining_bytes
    zero_bytes = reqd_padding_bytes - 1
    encoded_length = (length << 3).to_bytes(8)

    return message + b"\x80" + (b"\0" * zero_bytes) + encoded_length


def digest_message(message: str) -> None:
    padded_message = pad_message(message)
    assert len(padded_message) % 64 == 0, "Padding resulted in invalid chunk"
    state = initialization_vector[:]

    i = 0
    while i < len(padded_message):
        chunk = padded_message[i:i + 64]
        state = compress(chunk, state)
        i += 64
    
    print(f"{message}:\n\t{b''.join(s.to_bytes(4) for s in state).hex()}")


if __name__ == "__main__":
    test_messages = [
        # e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        "".encode(),
        # ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
        "a".encode(),
        # ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        "abc".encode(),
        # f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650
        "message digest".encode(),
        # 05c6e08f1d9fdafa03147fcb8f82f124c76d2f70e3d989dc8aadb5e7d7450bec
        "the quick brown fox jumps over the lazy dog".encode(),
        # 18e8d559417db8a93707c11b11bb90b56638049a5994006ed4b2705e4d86587f
        "the quick brown fox jumps over the lazy dog.".encode(),
        # 71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73
        "abcdefghijklmnopqrstuvwxyz".encode(),
        # 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".encode(),
    ]

    for message in test_messages:
        digest_message(message)
