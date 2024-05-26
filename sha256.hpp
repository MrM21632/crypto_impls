#ifndef MRM21632_SHA256_HPP_
#define MRM21632_SHA256_HPP_

#include <array>
#include <cstdint>
#include <string>
#include <vector>


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


// Baseline implementation of the SHA-256 and derived hash functions.
class SHA256 {
private:
    std::array<uint32_t, 8> &state;  // Initialization vectors, and final state

    // Ch(e, f, g)
    uint32_t choose(uint32_t, uint32_t, uint32_t);
    // Maj(a, b, c)
    uint32_t major(uint32_t, uint32_t, uint32_t);

    // Σ0(a)
    uint32_t sum0(uint32_t);
    // Σ1(e)
    uint32_t sum1(uint32_t);

    // σ0(w)
    uint32_t sigma0(uint32_t);
    // σ1(w)
    uint32_t sigma1(uint32_t);

    // Execute a compression round. Accepts a 512-bit chunk of the padded message as input.
    void compress(std::array<uint8_t, 64>&);
public:
    SHA256(std::array<uint32_t, 8>&);
    std::vector<uint32_t>& digest_message(std::string &message);
};


// Implementation of SHA-256.
class SHA256Impl : public SHA256 {
public:
    SHA256Impl();
};

// Implementation of SHA-224.
class SHA224Impl : public SHA256 {
public:
    SHA224Impl();
};

#endif  // MRM21632_SHA256_HPP_
