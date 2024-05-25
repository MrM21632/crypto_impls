#include "sha256.hpp"
#include <cassert>


uint32_t rotr32(uint32_t x, uint32_t n) {
    assert(n < 32);
    if (!n) return x;
    return (x >> n) | (x << (32 - n));
}


SHA256::SHA256(std::array<uint32_t, 8> &init_vectors) : state(init_vectors) {}

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


void SHA256::compress(std::array<uint32_t, 16> &chunk) {
    // Construct the message schedule array
    std::array<uint32_t, 64> w = {};
    for (int i = 0; i < 16; ++i) {
        w[i] = chunk[i];
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

    state[0] += s[0];
    state[1] += s[1];
    state[2] += s[2];
    state[3] += s[3];
    state[4] += s[4];
    state[5] += s[5];
    state[6] += s[6];
    state[7] += s[7];
}
