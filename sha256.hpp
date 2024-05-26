#ifndef MRM21632_SHA256_HPP_
#define MRM21632_SHA256_HPP_

#include <array>
#include <cstdint>
#include <string>
#include <vector>


// Baseline implementation of the SHA-256 and derived hash functions.
class SHA256 {
private:
    std::array<uint32_t, 8> state;  // Initialization vectors, and final state

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

    // Pad the string into a list of bytes.
    std::vector<uint8_t> pad_message(std::string);
    // Execute a compression round. Accepts a 512-bit chunk of the padded message as input.
    void compress(std::array<uint8_t, 64>);
public:
    SHA256(std::array<uint32_t, 8>);
    std::array<uint32_t, 8> digest_message(std::string);
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
