#include "sha256.hpp"
#include <cassert>


uint32_t rotr32(uint32_t x, uint32_t n) {
    assert(n < 32);
    if (!n) return x;
    return (x >> n) | (x << (32 - n));
}


SHA256::SHA256(std::array<uint32_t, 8> init_vectors) : state(init_vectors) {}

SHA256Impl::SHA256Impl() : SHA256::SHA256(sha256_init_vectors) {}

SHA224Impl::SHA224Impl() : SHA256::SHA256(sha224_init_vectors) {}


uint32_t SHA256::choose(uint32_t x, uint32_t y, uint32_t z) {
    return z ^ (x & (y ^ x));
}

uint32_t SHA256::major(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t SHA256::sum0(uint32_t a) {
    return rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
}

uint32_t SHA256::sum1(uint32_t e) {
    return rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
}

uint32_t SHA256::sigma0(uint32_t x) {
    return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3);
}

uint32_t SHA256::sigma1(uint32_t x) {
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}


std::vector<uint8_t> SHA256::pad_message(std::string message) {
    std::vector<uint8_t> result;
    for (std::string::iterator it = message.begin(); it != message.end(); ++it) {
        result.push_back((uint8_t) *it);
    }
    size_t remainder = message.size() % (size_t) 64;
    size_t num_zero_bytes = 55 - remainder;  // Accounts for 8 bytes from length, plus the one bit and corresponding zeroes.

    result.push_back((uint8_t) 0x80);
    for (int i = 0; i < num_zero_bytes; ++i) {
        result.push_back(0);
    }

    uint64_t length = (uint64_t) message.size();
    for (int i = 0; i < 8; ++i) {
        result.push_back((uint8_t)(length >> (8 * (8 - i - 1)) & 0xff));
    }

    return result;
}


void SHA256::compress(std::array<uint8_t, 64> chunk) {
    // Construct the message schedule array
    std::array<uint32_t, 64> w = {};
    for (int i = 0; i < 16; ++i) {
        w[i] = (
            (uint32_t) chunk[i * 4 + 0] << 24 |
            (uint32_t) chunk[i * 4 + 1] << 16 |
            (uint32_t) chunk[i * 4 + 2] <<  8 |
            (uint32_t) chunk[i * 4 + 3]
        );
    }
    for (int i = 16; i < 64; ++i) {
        w[i] = w[i - 16] + sigma0(w[i - 15]) + w[i - 7] + sigma1(w[i - 2]);
    }

    // Compress!
    std::array<uint32_t, 8> s = state;
    for (int i = 0; i < 64; ++i) {
        uint32_t tmp1 = s[7] + sum1(s[4]) + choose(s[4], s[5], s[6]) + sha256_round_constants[i] + w[i];
        uint32_t tmp2 = sum0(s[0]) + major(s[0], s[1], s[2]);

        s[7] = s[6];
        s[6] = s[5];
        s[5] = s[4];
        s[4] = s[3] + tmp1;
        s[3] = s[2];
        s[2] = s[1];
        s[1] = s[0];
        s[0] = tmp1 + tmp2;
    }

    // Update algorithm state
    state[0] += s[0];
    state[1] += s[1];
    state[2] += s[2];
    state[3] += s[3];
    state[4] += s[4];
    state[5] += s[5];
    state[6] += s[6];
    state[7] += s[7];
}
