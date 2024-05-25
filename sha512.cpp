#include "sha512.hpp"
#include <cassert>


uint64_t rotr64(uint64_t x, uint64_t n) {
    assert(n < 64);
    if (!n) return x;
    return (x >> n) | (x << (64 - n));
}


SHA512::SHA512(std::array<uint64_t, 8> &init_vectors) : state(init_vectors) {}

SHA512Impl::SHA512Impl() : SHA512::SHA512(sha512_init_vectors) {}

SHA384Impl::SHA384Impl() : SHA512::SHA512(sha384_init_vectors) {}


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
