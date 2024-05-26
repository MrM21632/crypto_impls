#include "sha256.hpp"
#include <cassert>


// Round constants for SHA-224 and SHA-256.
std::array<uint32_t, 64> sha256_round_constants({
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL,
});

// Initialization vectors for SHA-256.
std::array<uint32_t, 8> sha256_init_vectors({
    0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
    0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL,
});

// Initialization vectors for SHA-224.
std::array<uint32_t, 8> sha224_init_vectors({
    0xc1059ed8UL, 0x367cd507UL, 0x3070dd17UL, 0xf70e5939UL,
    0xffc00b31UL, 0x68581511UL, 0x64f98fa7UL, 0xbefa4fa4UL,
});


uint32_t rotr32(uint32_t x, uint32_t n) {
    assert(n < 32);
    if (!n) return x;
    return (x >> n) | (x << (32 - n));
}


SHA256::SHA256(std::array<uint32_t, 8> init_vectors) : state(init_vectors) {}

SHA256Impl::SHA256Impl() : SHA256::SHA256(sha256_init_vectors) {}

SHA224Impl::SHA224Impl() : SHA256::SHA256(sha224_init_vectors) {}


uint32_t SHA256::choose(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ ((~x) & z);
}

uint32_t SHA256::major(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t SHA256::sum0(uint32_t a) {
    return rotr32(a, 2UL) ^ rotr32(a, 13UL) ^ rotr32(a, 22UL);
}

uint32_t SHA256::sum1(uint32_t e) {
    return rotr32(e, 6UL) ^ rotr32(e, 11UL) ^ rotr32(e, 25UL);
}

uint32_t SHA256::sigma0(uint32_t x) {
    return rotr32(x, 7UL) ^ rotr32(x, 18UL) ^ (x >> 3UL);
}

uint32_t SHA256::sigma1(uint32_t x) {
    return rotr32(x, 17UL) ^ rotr32(x, 19UL) ^ (x >> 10UL);
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
    state[0] += s[0];
    state[1] += s[1];
    state[2] += s[2];
    state[3] += s[3];
    state[4] += s[4];
    state[5] += s[5];
    state[6] += s[6];
    state[7] += s[7];
}


std::vector<uint8_t> SHA256::pad_message(std::string message) {
    std::vector<uint8_t> result;
    for (auto &c : message) {
        result.push_back((uint8_t) c);
    }
    
    // Remember: size() returns number of bytes.
    // TODO: Technically this approach limits us to 2^61 bytes in length.
    uint64_t encoded_length = (uint64_t) message.size() << 3;

    result.push_back((uint8_t) 0x80);
    while ((result.size() + 8) % 64 != 0) {
        result.push_back((uint8_t) 0x00);
    }

    // Append the encoded length in big-endian order.
    for (int i = 7; i >= 0; --i) {
        uint8_t new_byte = encoded_length >> (8 * i) & 0xff;
        result.push_back((uint8_t) new_byte);
    }

    return result;
}


std::array<uint32_t, 8> SHA256::digest_message(std::string message) {
    std::vector<uint8_t> padded_message = pad_message(message);
    for (size_t offset = 0; offset < padded_message.size(); offset += 64) {
        std::array<uint8_t, 64> chunk;
        for (int i = 0; i < 64; ++i) {
            chunk[i] = padded_message[offset + i];
        }
        compress(chunk);
    }

    return state;
}
