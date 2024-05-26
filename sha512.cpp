#include "sha512.hpp"
#include <cassert>


// Round constants for SHA-384 and SHA-512.
std::array<uint64_t, 80> sha512_round_constants({
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL,
    0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 0x983e5152ee66dfabULL,
    0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL,
    0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL,
    0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL,
    0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
});

// Initialization vectors for SHA-512.
std::array<uint64_t, 8> sha512_init_vectors({
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL, 
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
});

// Initialization vectors for SHA-384.
std::array<uint64_t, 8> sha384_init_vectors({
    0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL, 
    0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL, 0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL,
});

// Initialization vectors for SHA-512/224.
std::array<uint64_t, 8> sha512t224_init_vectors({
    0x8C3D37C819544DA2ULL, 0x73E1996689DCD4D6ULL, 0x1DFAB7AE32FF9C82ULL, 0x679DD514582F9FCFULL,
    0x0F6D2B697BD44DA8ULL, 0x77E36F7304C48942ULL, 0x3F9D85A86A1D36C8ULL, 0x1112E6AD91D692A1ULL,
});

// Initialization vectors for SHA-512/256.
std::array<uint64_t, 8> sha512t256_init_vectors({
    0x22312194FC2BF72CULL, 0x9F555FA3C84C64C2ULL, 0x2393B86B6F53B151ULL, 0x963877195940EABDULL,
    0x96283EE2A88EFFE3ULL, 0xBE5E1E2553863992ULL, 0x2B0199FC2C85B8AAULL, 0x0EB72DDC81C52CA2ULL,
});


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
    return (x & y) ^ ((~x) & z);
}

uint64_t SHA512::major(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint64_t SHA512::sum0(uint64_t a) {
    return rotr64(a, 28ULL) ^ rotr64(a, 34ULL) ^ rotr64(a, 39ULL);
}

uint64_t SHA512::sum1(uint64_t e) {
    return rotr64(e, 14ULL) ^ rotr64(e, 18ULL) ^ rotr64(e, 41ULL);
}

uint64_t SHA512::sigma0(uint64_t x) {
    return rotr64(x, 1ULL) ^ rotr64(x, 8ULL) ^ (x >> 7ULL);
}

uint64_t SHA512::sigma1(uint64_t x) {
    return rotr64(x, 19ULL) ^ rotr64(x, 61ULL) ^ (x >> 6ULL);
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


std::string SHA512::pad_message(std::string message) {
    // Remember: size() returns number of bytes.
    // TODO: Technically this approach limits us to 2^61 bytes in length.
    uint64_t encoded_length = (uint64_t) message.size() << 3;

    message.push_back((char) 0x80);
    while ((message.size() + 16) % 128 != 0) {
        message.push_back((char) 0x00);
    }

    // Append the encoded length in big-endian order.
    // Assuming little-endian order on your system, this is trivial to do.
    for (int i = 0; i < 8; ++i) {
        message.push_back((char) 0x00);
    }
    for (int i = 0; i < 8; ++i, encoded_length >>= 8) {
        message.push_back((char)(encoded_length & 0xffULL));
    }

    return message;
}


std::array<uint64_t, 8> SHA512::digest_message(std::string message) {
    std::string padded_message = pad_message(message);
    for (size_t offset = 0; offset < padded_message.size(); offset += 128) {
        std::array<uint8_t, 128> chunk;
        for (int i = 0; i < 128; ++i) {
            chunk[i] = padded_message[offset + i];
        }
        compress(chunk);
    }

    return state;
}
