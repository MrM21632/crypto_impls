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
