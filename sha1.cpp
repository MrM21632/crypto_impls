#include "sha1.hpp"
#include <cassert>


// Initialization vector for SHA-1.
std::array<uint32_t, 5> sha1_init_vector({
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0,
});


uint32_t rotl32(uint32_t x, uint32_t n) {
    assert(n < 32);
    if (!n) return x;
    return (x << n) | (x >> (32 - n));
}

std::array<uint8_t, 8> uint64_to_bytes(uint64_t length) {
    std::array<uint8_t, 8> result;
    for (int i = 7; i >= 0; --i) {
        result[7 - i] = (length >> (8 * i)) & 0xff;
    }

    return result;
}


SHA1::SHA1(std::array<uint32_t, 5> init_vector) : init_vector(init_vector) {}

SHA1Impl::SHA1Impl() : SHA1::SHA1(sha1_init_vector) {}


uint32_t SHA1::choose(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ ((~x) & z);
}

uint32_t SHA1::major(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t SHA1::parity(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}


void SHA1::compress(std::array<uint8_t, 64> chunk) {
    // Construct the message schedule array
    std::array<uint32_t, 80> w;
    for (int i = 0; i < 16; ++i) {
        w[i] = (
            (uint32_t) chunk[i * 4 + 0] << 24 |
            (uint32_t) chunk[i * 4 + 1] << 16 |
            (uint32_t) chunk[i * 4 + 2] <<  8 |
            (uint32_t) chunk[i * 4 + 3]
        );
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = rotl32((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1);
    }

    // Compress!
    std::array<uint32_t, 5> s = state;
    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i >= 0 && i <= 19) {
            f = choose(s[1], s[2], s[3]);
            k = 0x5a827999;
        }
        else if (i >= 20 && i <= 39) {
            f = parity(s[1], s[2], s[3]);
            k = 0x6ed9eba1;
        }
        else if (i >= 40 && i <= 59) {
            f = major(s[1], s[2], s[3]);
            k = 0x8f1bbcdc;
        }
        else {  // 60 <= i <= 79
            f = parity(s[1], s[2], s[3]);
            k = 0xca62c1d6;
        }

        uint32_t tmp = rotl32(s[0], 5) + f + k + s[4] + w[i];
        s[4] = s[3];
        s[3] = s[2];
        s[2] = rotl32(s[1], 30);
        s[1] = s[0];
        s[0] = tmp;
    }

    // Update algorithm state
    for (int i = 0; i < 5; ++i) {
        state[i] += s[i];
    }
}


std::vector<uint8_t> SHA1::pad_message(std::string message) {
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


std::array<uint32_t, 5> SHA1::digest_message(std::string message) {
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