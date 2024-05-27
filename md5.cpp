#include "md5.hpp"
#include <cassert>


// Round constants for MD5.
std::array<uint32_t, 64> md5_round_constants({
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
});

// Shift constants for MD5.
std::array<uint32_t, 64> md5_shift_constants({
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
});

// Initialization vector for MD5.
std::array<uint32_t, 4> md5_init_vector({
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476,
});


uint32_t rotl32(uint32_t x, uint32_t n) {
    assert(n < 32);
    if (!n) return x;
    return (x << n) | (x >> (32 - n));
}

std::array<uint8_t, 8> uint64_to_bytes(uint64_t length) {
    std::array<uint8_t, 8> result;
    for (int i = 0; i < 8; ++i) {
        result[i] = length & 0xff;
        length >>= 8;
    }

    return result;
}


MD5::MD5(std::array<uint32_t, 4> init_vector) : init_vector(init_vector) {}

MD5Impl::MD5Impl() : MD5::MD5(md5_init_vector) {}


uint32_t MD5::choose(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ ((~x) & z);
}

uint32_t MD5::h(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}

uint32_t MD5::i(uint32_t x, uint32_t y, uint32_t z) {
    return y ^ (x | (~z));
}


void MD5::compress(std::array<uint8_t, 64> chunk) {
    // Construct the message schedule array
    std::array<uint32_t, 16> m;
    for (int i = 0; i < 16; ++i) {
        m[i] = (
            (uint32_t) chunk[i * 4 + 0]       |
            (uint32_t) chunk[i * 4 + 1] << 8  |
            (uint32_t) chunk[i * 4 + 2] << 16 |
            (uint32_t) chunk[i * 4 + 3] << 24
        );
    }

    // Compress!
    std::array<uint32_t, 4> s = state;
    for (int j = 0; j < 64; ++j) {
        uint32_t f, g;
        if (j >= 0 && j <= 15) {
            f = choose(s[1], s[2], s[3]);
            g = j;
        }
        else if (j >= 16 && j <= 31) {
            f = choose(s[3], s[1], s[2]);
            g = (5 * j + 1) % 16;
        }
        else if (j >= 32 && j <= 47) {
            f = h(s[1], s[2], s[3]);
            g = (3 * j + 5) % 16;
        }
        else {  // 48 <= j <= 63
            f = i(s[1], s[2], s[3]);
            g = (7 * j) % 16;
        }

        f += s[0] + md5_round_constants[j] + m[g];
        s[0] = s[3];
        s[3] = s[2];
        s[2] = s[1];
        s[1] += rotl32(f, md5_shift_constants[j]);
    }

    // Update algorithm state
    for (int i = 0; i < 4; ++i) {
        state[i] += s[i];
    }
}


std::vector<uint8_t> MD5::pad_message(std::string message) {
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


std::array<uint32_t, 4> MD5::digest_message(std::string message) {
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
