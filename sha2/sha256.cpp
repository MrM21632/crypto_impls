#include "sha256.hpp"
#include <cassert>
#include <iostream>


// Round constants for SHA-224 and SHA-256.
std::array<uint32_t, 64> sha256_round_constants({
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
});

// Initialization vectors for SHA-256.
std::array<uint32_t, 8> sha256_init_vector({
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
});

// Initialization vectors for SHA-224.
std::array<uint32_t, 8> sha224_init_vector({
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
});


uint32_t rotr32(uint32_t x, uint32_t n) {
    assert(n < 32);
    if (!n) return x;
    return (x >> n) | (x << (32 - n));
}

std::array<uint8_t, 8> uint64_to_bytes(uint64_t length) {
    std::array<uint8_t, 8> result;
    for (int i = 7; i >= 0; --i) {
        result[7 - i] = (length >> (8 * i)) & 0xff;
    }

    return result;
}


SHA256::SHA256(std::array<uint32_t, 8> init_vector) : init_vector(init_vector) {}

SHA256Impl::SHA256Impl() : SHA256::SHA256(sha256_init_vector) {}

SHA224Impl::SHA224Impl() : SHA256::SHA256(sha224_init_vector) {}


uint32_t SHA256::choose(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ ((~x) & z);
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


void SHA256::compress(std::array<uint8_t, 64> chunk) {
    // Construct the message schedule array
    std::array<uint32_t, 64> w;
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
    for (int i = 0; i < 8; ++i) {
        state[i] += s[i];
    }
}


std::vector<uint8_t> SHA256::pad_message(std::string message) {
    std::vector<uint8_t> result;
    for (auto &c : message) {
        result.push_back(c);
    }
    size_t length = message.size();
    size_t remaining_bytes = (length + 8) % 64;
    size_t required_padding_bytes = 64 - remaining_bytes;
    size_t zero_bytes = required_padding_bytes - 1;

    result.push_back(0x80);
    for (size_t i = 0; i < zero_bytes; ++i) {
        result.push_back(0x00);
    }

    std::array<uint8_t, 8> encoded_length = uint64_to_bytes((uint64_t) length << 3);
    for (int i = 0; i < 8; ++i) {
        result.push_back(encoded_length[i]);
    }

    return result;
}


std::array<uint32_t, 8> SHA256::digest_message(std::string message) {
    std::vector<uint8_t> padded_message = pad_message(message);
    state = init_vector;
    
    for (size_t offset = 0; offset < padded_message.size(); offset += 64) {
        std::array<uint8_t, 64> chunk;
        for (int i = 0; i < 64; ++i) {
            chunk[i] = padded_message[offset + i];
        }
        compress(chunk);
    }

    return state;
}
