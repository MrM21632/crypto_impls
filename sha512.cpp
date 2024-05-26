#include "sha512.hpp"
#include <cassert>


uint64_t rotr64(uint64_t x, uint64_t n) {
    assert(n < 64);
    if (!n) return x;
    return (x >> n) | (x << (64 - n));
}


SHA512::SHA512(std::array<uint64_t, 8> init_vectors) : state(init_vectors) {}

SHA512Impl::SHA512Impl() : SHA512::SHA512(sha512_init_vectors) {}

SHA384Impl::SHA384Impl() : SHA512::SHA512(sha384_init_vectors) {}

SHA512t224Impl::SHA512t224Impl() : SHA512::SHA512(sha512t224_init_vectors) {}

SHA512t256Impl::SHA512t256Impl() : SHA512::SHA512(sha512t256_init_vectors) {}


uint64_t SHA512::choose(uint64_t x, uint64_t y, uint64_t z) {
    return z ^ (x & (y ^ x));
}

uint64_t SHA512::major(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint64_t SHA512::sum0(uint64_t a) {
    return rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
}

uint64_t SHA512::sum1(uint64_t e) {
    return rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
}

uint64_t SHA512::sigma0(uint64_t x) {
    return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
}

uint64_t SHA512::sigma1(uint64_t x) {
    return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
}


std::vector<uint8_t> SHA512::pad_message(std::string message) {
    std::vector<uint8_t> result;
    for (std::string::iterator it = message.begin(); it != message.end(); ++it) {
        result.push_back((uint8_t) *it);
    }
    size_t remainder = message.size() % (size_t) 128;
    // Accounts for 16 bytes from length, plus the one bit and corresponding zeroes.
    size_t num_zero_bytes = 111 - remainder;

    // Note: in this case, we're limited by the bounds of size_t, which should be 64 bits on macOS if I'm not mistaken.
    // Because of this, the top 8 bytes of the length will always be zeroes.
    result.push_back((uint8_t) 0x80);
    for (size_t i = 0; i < num_zero_bytes + 8; ++i) {
        result.push_back(0);
    }

    uint64_t length = (uint64_t) message.size();
    for (int i = 0; i < 8; ++i) {
        result.push_back((uint8_t)(length >> (8 * (8 - i - 1)) & 0xff));
    }

    return result;
}


void SHA512::compress(std::array<uint8_t, 128> chunk) {
    // Construct the message schedule array
    std::array<uint64_t, 80> w = {};
    for (int i = 0; i < 16; ++i) {
        w[i] = (
            (uint64_t) chunk[i * 8 + 0] << 56 |
            (uint64_t) chunk[i * 8 + 1] << 48 |
            (uint64_t) chunk[i * 8 + 2] << 40 |
            (uint64_t) chunk[i * 8 + 3] << 32 |
            (uint64_t) chunk[i * 8 + 4] << 24 |
            (uint64_t) chunk[i * 8 + 5] << 16 |
            (uint64_t) chunk[i * 8 + 6] <<  8 |
            (uint64_t) chunk[i * 8 + 7]
        );
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = w[i - 16] + sigma0(w[i - 15]) + w[i - 7] + sigma1(w[i - 2]);
    }

    // Compress!
    std::array<uint64_t, 8> s = state;
    for (int i = 0; i < 80; ++i) {
        uint64_t tmp1 = s[7] + sum1(s[4]) + choose(s[4], s[5], s[6]) + sha512_round_constants[i] + w[i];
        uint64_t tmp2 = sum0(s[0]) + major(s[0], s[1], s[2]);

        s[7] = s[6];
        s[6] = s[5];
        s[5] = s[4];
        s[4] = s[3] + tmp1;
        s[3] = s[2];
        s[2] = s[1];
        s[1] = s[0];
        s[0] = tmp1 + tmp2;
    }

    state[0] += s[0];
    state[1] += s[1];
    state[2] += s[2];
    state[3] += s[3];
    state[4] += s[4];
    state[5] += s[5];
    state[6] += s[6];
    state[7] += s[7];
}

std::array<uint64_t, 8> SHA512::digest_message(std::string message) {
    std::vector<uint8_t> bytes = pad_message(message);

    for (size_t offset = 0; offset < bytes.size(); offset += 128) {
        std::array<uint8_t, 128> chunk;
        for (int i = 0; i < 128; ++i) {
            chunk[i] = bytes[offset + i];
        }
        compress(chunk);
    }

    return state;
}
